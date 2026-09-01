"""
crew_network.py — Multi-agent chẩn đoán mạng.
- Kỹ sư vận hành mạng: có 3 tool SSH read-only, tự quyết định thiết bị +
  lệnh cần chạy dựa trên câu hỏi, thu thập dữ liệu.
- Agent báo cáo: tổng hợp dữ liệu thành câu trả lời tiếng Việt, kèm raw config.

LLM: dùng API cloud (Claude hoặc OpenAI) thay vì Ollama local — hợp lý khi
máy không có GPU rời, không cần tự host model. Chọn nhà cung cấp qua biến
môi trường LLM_PROVIDER trong file .env ("anthropic" hoặc "openai").

Lưu ý riêng tư: khi dùng API cloud, nội dung câu hỏi + raw config thiết bị
(vd running-config) sẽ được gửi ra ngoài LAN tới nhà cung cấp API — khác với
bản chạy Ollama local trước đó (dữ liệu không rời máy). Với lab cá nhân thì
thường không vấn đề gì, nhưng nếu sau này áp dụng vào mạng thật có dữ liệu
nhạy cảm thì cần cân nhắc lại.
"""

import os
from dotenv import load_dotenv
from crewai import Agent, Task, Crew, Process, LLM

from network_tools import run_show_command, list_available_devices, count_up_ports
from network_write_tools import list_vlans, check_port_status, list_free_ports, assign_access_port
from network_monitoring_tools import check_device_health, check_interface_errors

load_dotenv()  # phòng trường hợp import module này trước network_tools

# ---------------------------------------------------------------------------
# Cấu hình LLM — đọc từ .env, KHÔNG hard-code API key trong code.
# ---------------------------------------------------------------------------

LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "anthropic").strip().lower()

# Model mặc định cho mỗi nhà cung cấp — ưu tiên model rẻ/nhanh vì đây là tác
# vụ gọi tool + tóm tắt tiếng Việt, không cần model top-tier. Override bằng
# MODEL_NAME trong .env nếu muốn đổi (vd nâng cấp nếu agent hay chọn sai
# tool/thiết bị).
_DEFAULT_MODELS = {
    "anthropic": "claude-haiku-4-5-20251001",
    "openai": "gpt-5-mini",
}
_API_KEY_ENV_VAR = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
}

# Validate provider NGAY tại đây (không đợi tới check_llm_ready()) — vì nếu
# để provider sai lọt xuống dòng khởi tạo LLM(...) bên dưới, CrewAI/LiteLLM
# sẽ crash với thông báo lỗi rất khó hiểu (nói về native provider/litellm
# package thay vì nói thẳng "provider sai").
if LLM_PROVIDER not in _DEFAULT_MODELS:
    raise RuntimeError(
        f"LLM_PROVIDER='{LLM_PROVIDER}' không hợp lệ trong .env — chỉ hỗ trợ "
        "'anthropic' (Claude) hoặc 'openai'. Sửa lại giá trị này rồi chạy lại."
    )

MODEL_NAME = os.environ.get("MODEL_NAME") or _DEFAULT_MODELS[LLM_PROVIDER]

# Tùy chọn: trỏ sang endpoint OpenAI-compatible KHÁC thay vì OpenAI thật —
# vd FPT AI Marketplace (mkp-api.fptcloud.com), Azure OpenAI, hoặc bất kỳ
# dịch vụ nào dùng chung định dạng API OpenAI. Chỉ áp dụng khi
# LLM_PROVIDER=openai. Để trống nếu dùng OpenAI thật.
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "").strip()

if OPENAI_BASE_URL and LLM_PROVIDER != "openai":
    raise RuntimeError(
        "OPENAI_BASE_URL chỉ dùng được khi LLM_PROVIDER=openai trong .env "
        "(vì endpoint đó phải nói cùng ngôn ngữ API với OpenAI)."
    )
if OPENAI_BASE_URL and not os.environ.get("MODEL_NAME"):
    raise RuntimeError(
        "Đang dùng OPENAI_BASE_URL tùy chỉnh nhưng MODEL_NAME để trống — "
        "model mặc định 'gpt-5-mini' không tồn tại trên endpoint khác OpenAI "
        "thật. Điền đúng tên model mà endpoint đó cung cấp vào MODEL_NAME "
        "trong .env (hỏi bên cấp API key nếu không chắc tên chính xác)."
    )


def check_llm_ready() -> None:
    """Báo lỗi rõ ràng bằng tiếng Việt nếu thiếu API key, thay vì để lỗi
    401/authentication khó hiểu văng ra từ CrewAI/LiteLLM giữa chừng lúc
    đang chạy crew."""
    key_var = _API_KEY_ENV_VAR[LLM_PROVIDER]
    if not os.environ.get(key_var):
        console_url = (
            "https://console.anthropic.com/settings/keys"
            if LLM_PROVIDER == "anthropic"
            else "https://platform.openai.com/api-keys"
        )
        raise RuntimeError(
            f"Thiếu {key_var} trong .env — lấy API key tại {console_url} "
            "rồi điền vào .env trước khi chạy."
        )


# temperature thấp (0.3) vì đây là tác vụ kỹ thuật cần chính xác, không cần
# sáng tạo — khác với 1 crew tư vấn chung có thể dùng temperature cao hơn.
_llm_kwargs = {"model": f"{LLM_PROVIDER}/{MODEL_NAME}", "temperature": 0.3}
if OPENAI_BASE_URL:
    _llm_kwargs["base_url"] = OPENAI_BASE_URL
llm = LLM(**_llm_kwargs)


# ---------------------------------------------------------------------------
# Agent permission model — 2 explicit tiers, named accordingly:
#   READ  : engineer_agent, monitor_agent — read-only tools (SSH "show"
#           only), used for querying/diagnosing information.
#   WRITE : technical_agent               — the only agent with a tool that
#           can change device config, and even then only 1 action (assign
#           an access port to an EXISTING VLAN — see network_write_tools.py).
#           It has NO create_vlan tool: it can only inspect current state
#           (list_vlans, check_port_status, list_free_ports) and, if valid,
#           assign — and even that last step is gated by a mandatory
#           human yes/no confirmation printed on the console before any
#           write command reaches the device (see assign_access_port_text
#           in network_write_tools.py — the gate lives in code, not in
#           agent behavior).
# report_agent holds no device tools at all (zero permission) — it only
# synthesizes text from data the other agents already collected.
# ---------------------------------------------------------------------------

engineer_agent = Agent(
    role="Network Engineer Agent",
    goal=(
        "Identify the correct network device and 'show' command to run "
        "based on the user's question, then SSH in to collect accurate "
        "data."
    ),
    backstory=(
        "You are an experienced network operations engineer working with "
        "Cisco IOS. When you're not sure of the exact device name (e.g. "
        "the user says 'access switch 1'), you use the device-listing tool "
        "first to look up the correct name. For questions about port "
        "counts, you ALWAYS use the dedicated counting tool instead of "
        "counting from raw text yourself — manual counting is error-prone."
    ),
    tools=[list_available_devices, run_show_command, count_up_ports],
    llm=llm,
    verbose=True,
    allow_delegation=False,
)

report_agent = Agent(
    role="Reporting Agent",
    goal=(
        "Synthesize the collected technical data into a clear, easy to "
        "understand English answer for the end user."
    ),
    backstory=(
        "You receive raw/analyzed data from the network engineer and "
        "rewrite it as a natural English answer. Always include a 'Raw "
        "Configuration' section quoting the relevant raw_output so the "
        "user can cross-check it themselves, not just a bare conclusion."
    ),
    llm=llm,
    verbose=True,
    allow_delegation=False,
)


technical_agent = Agent(
    role="Network Technical Agent (Port Assignment Only)",
    goal=(
        "Assign an existing access port to an existing VLAN exactly as "
        "requested, but ONLY after verifying the VLAN already exists and "
        "checking the port's current state — never creating VLANs, never "
        "touching routing/IP, and never sending a write command without "
        "the administrator's explicit go-ahead."
    ),
    backstory=(
        "You are a network operations technician with permission to "
        "assign access ports to VLANs — and nothing else. You have NO "
        "tool to create a VLAN: your available tools only let you look, "
        "then, if it's actually valid, assign. When you receive a "
        "request (e.g. 'assign VLAN 60 to port Ethernet0/1 on some access "
        "switch'), you follow this order every time: (1) if the device "
        "name is vague, use the device-listing tool to find the exact "
        "name; (2) call list_vlans to check whether the target VLAN "
        "already exists on that device — if it doesn't, you cannot "
        "proceed, stop and report that a VLAN must be created first by "
        "someone with that permission; (3) call check_port_status on the "
        "target port to see its current mode (access/trunk) and VLAN, so "
        "you understand what you're about to change; (4) only then call "
        "assign_access_port. That tool itself will print a summary and "
        "pause for the administrator to type yes/no on the console before "
        "it sends anything to the real device — if the administrator "
        "declines, the tool returns a 'cancelled' result, which is a "
        "normal outcome to report back, not an error. After a successful "
        "assignment, always read the verify section of the result "
        "carefully to confirm the port actually came up (status up) — "
        "don't just trust that the command ran without error."
    ),
    tools=[list_available_devices, list_vlans, check_port_status, list_free_ports, assign_access_port],
    llm=llm,
    verbose=True,
    allow_delegation=False,
)


monitor_agent = Agent(
    role="Network Monitor Agent",
    goal=(
        "Monitor device health (CPU, memory, interface errors), using "
        "metrics and alert status already computed in code — never "
        "guessing."
    ),
    backstory=(
        "You are a network monitoring agent — you use tools that read "
        "real CPU/RAM/interface-error data from devices. Alert thresholds "
        "(ok/warning/critical) are PRE-COMPUTED in code and included "
        "directly in the tool's result (the 'status' field) — you do not "
        "subjectively judge whether a number is high or low, you only "
        "read that field."
    ),
    tools=[check_device_health, check_interface_errors, list_available_devices],
    llm=llm,
    verbose=True,
    allow_delegation=False,
)


def build_crew(question: str) -> Crew:
    task_collect = Task(
        description=(
            f'User question: "{question}"\n\n'
            "Identify the relevant network device (use the device-listing "
            "tool if you're not sure of the exact name) and the "
            "appropriate 'show' command to run. If the question is about "
            "counting/number of ports that are up, you MUST use the "
            "dedicated port-counting tool instead of counting from raw "
            "text yourself."
        ),
        expected_output=(
            "JSON data with the accurate figures (if any) and the raw "
            "raw_output relevant to the question."
        ),
        agent=engineer_agent,
    )

    task_report = Task(
        description=(
            "Based on the data collected in the previous step, write a "
            f'complete English answer to the question: "{question}"\n'
            "Include the accurate figures (if any) and a 'Raw "
            "Configuration' section quoting the relevant raw_output."
        ),
        expected_output=(
            "A natural English answer with accurate figures and the raw "
            "configuration excerpt attached."
        ),
        agent=report_agent,
        context=[task_collect],
    )

    return Crew(
        agents=[engineer_agent, report_agent],
        tasks=[task_collect, task_report],
        process=Process.sequential,
        verbose=True,
    )


def build_provision_crew(ticket_description: str) -> Crew:
    """Crew that handles VLAN/port assignment tickets — WRITES config,
    unlike build_crew() (read-only). technical_agent has NO create_vlan
    tool: it can only inspect current state (list_vlans, check_port_status,
    list_free_ports) and assign an access port to a VLAN that already
    exists. Even the assign step itself is gated by a mandatory human
    yes/no confirmation printed on the console before any write command
    reaches the device (see assign_access_port_text in
    network_write_tools.py) — the crew/task text below cannot bypass that
    gate, it lives in code."""
    task_configure = Task(
        description=(
            f'Ticket request: "{ticket_description}"\n\n'
            "Extract the device name, physical port name, and target VLAN "
            "from the request above (use the device-listing tool if the "
            "device name is vague). Call list_vlans on that device first "
            "to confirm the target VLAN already exists — you have NO tool "
            "to create one, so if it doesn't exist, stop and report that "
            "instead of attempting anything further. Call check_port_status "
            "on the target port to see its current mode/VLAN before "
            "changing anything. Only then call assign_access_port — it "
            "will pause for the administrator's yes/no confirmation on the "
            "console before sending anything to the device, and may come "
            "back with status 'cancelled' if declined; that is a valid "
            "outcome to report, not an error. If the assignment went "
            "through, read the verify section of the result carefully to "
            "confirm the port is actually up."
        ),
        expected_output=(
            "JSON data showing the VLAN/port checks performed and the "
            "final result: either commands_issued with the verify status, "
            "or a 'cancelled' status, or an error explaining why the "
            "request could not proceed (e.g. VLAN doesn't exist)."
        ),
        agent=technical_agent,
    )

    task_report_configure = Task(
        description=(
            "Based on the result from the previous step, write a "
            "complete English report on ticket: "
            f'"{ticket_description}"\n'
            "State clearly what was found (did the VLAN already exist? "
            "what was the port's state beforehand?) and the final "
            "outcome: if assigned, report the real port status after "
            "configuration (based on verify_status/verify_switchport) "
            "confirming the port is actually ready to use, not just "
            "'command ran successfully' — and state whether the "
            "configuration was saved to startup-config (config_saved "
            "field); if config_saved is false, warn clearly that the "
            "change is only in running-config and will be LOST on a "
            "device reload. If the administrator declined "
            "the confirmation (status 'cancelled'), report that plainly "
            "— it is not an error, just a decision. If there was a real "
            "error (e.g. device not writable, VLAN doesn't exist, VLAN "
            "blocked), explain the reason clearly in plain English "
            "instead of just returning the raw error JSON."
        ),
        expected_output=(
            "An English report describing the checks performed and the "
            "final outcome (assigned / cancelled by administrator / "
            "blocked), with the real port status for cross-checking when "
            "applicable."
        ),
        agent=report_agent,
        context=[task_configure],
    )

    return Crew(
        agents=[technical_agent, report_agent],
        tasks=[task_configure, task_report_configure],
        process=Process.sequential,
        verbose=True,
    )


def build_monitoring_crew(request: str) -> Crew:
    """Monitor -> Decide crew (MAPE loop: Monitor -> Analyze -> Decide).
    monitor_agent only reads metrics + status already computed in code;
    report_agent (reused) reads that status and proposes a concrete action
    — it does NOT judge the metrics itself, only interprets the result
    code has already produced."""
    task_monitor = Task(
        description=(
            f'Monitoring request: "{request}"\n\n'
            "Identify the device(s) to check (use the device-listing tool "
            "if you're not sure of the exact name), then call the health "
            "check tool (CPU/RAM) and/or the interface error check tool "
            "as appropriate for the request."
        ),
        expected_output=(
            "JSON data with CPU/RAM/interface error figures and the "
            "(ok/warning/critical) status already computed in code."
        ),
        agent=monitor_agent,
    )

    task_decide = Task(
        description=(
            "Based on the monitoring data from the previous step, write "
            f'an English report for the request: "{request}"\n'
            "Read the 'status' field already present in the data "
            "(ok/warning/critical) exactly as given — do NOT subjectively "
            "judge whether a figure is high or low. If status is "
            "'warning' or 'critical', CLEARLY propose the appropriate "
            "next action (e.g. high CPU -> suggest checking which "
            "process is loading it, CRC errors on a port -> suggest "
            "checking the physical cable). If status is 'ok', confirm the "
            "device is operating normally and no further action is "
            "needed."
        ),
        expected_output=(
            "An English report with a clear status and a concrete "
            "recommended action if needed."
        ),
        agent=report_agent,
        context=[task_monitor],
    )

    return Crew(
        agents=[monitor_agent, report_agent],
        tasks=[task_monitor, task_decide],
        process=Process.sequential,
        verbose=True,
    )