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
from typing import Literal, Optional
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from crewai import Agent, Task, Crew, Process, LLM

from network_tools import run_show_command, list_available_devices, count_up_ports
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
#   WRITE : NO agent holds a write tool. technical_agent only INTERPRETS a
#           port/VLAN ticket into structured parameters (device, interface,
#           vlan_id, access|tag). main_network.py then calls the write
#           function (assign_access_port_text / tag_vlan_on_port_text in
#           network_write_tools.py) itself, on the MAIN thread. Reasons:
#           - CrewAI 1.15 runs tools in worker threads under a live Rich
#             console, so the yes/no input() of the write tool could get
#             hidden/stuck there;
#           - the agent kept taking detours (list_free_ports...) and could
#             loop. LLM decides parameters, code executes.
#           The write functions check that the VLAN exists, classify the
#           port's current state (free / other VLAN / connected / trunk),
#           and gate every write behind a human confirmation.
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
    role="Network Technical Agent (Ticket Interpretation)",
    goal=(
        "Turn a free-text port/VLAN ticket into exact parameters: device "
        "name, physical interface, VLAN ID and mode (access or tag)."
    ),
    backstory=(
        "You read port/VLAN tickets written by network admins, often short "
        "and in Vietnamese, e.g. 'gán port e0/2 của switch acc04 cho vlan "
        "30' or 'tag vlan 30 vào e1/1 trên Switch_Acc003'. You use the "
        "device-listing tool once to map a vague device name (e.g. 'acc04', "
        "'switch access 4') to the exact inventory name (e.g. "
        "'Switch_Acc004'). You do NOT configure anything and do NOT inspect "
        "ports — the system does that after you, with its own checks and "
        "an administrator confirmation."
    ),
    tools=[list_available_devices],
    llm=llm,
    verbose=True,
    allow_delegation=False,
    max_iter=4,
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


class PortVlanRequest(BaseModel):
    """Tham số đã tách từ 1 ticket gán/tag VLAN cho cổng."""
    device_name: Optional[str] = Field(None, description="Exact device name from inventory, e.g. 'Switch_Acc004'")
    interface: Optional[str] = Field(None, description="Physical interface as written, e.g. 'e0/2' or 'Ethernet0/2'")
    vlan_id: Optional[int] = Field(None, description="Target VLAN ID")
    mode: Literal["access", "tag"] = Field("access", description="'tag' if the ticket says tag/tagged/trunk, else 'access'")
    error: str = Field("", description="Non-empty if any field cannot be determined from the ticket: say which one")


def build_ticket_parse_crew(ticket_description: str) -> Crew:
    """Crew 1 agent, CHỈ đọc hiểu ticket -> PortVlanRequest. Không có tool
    ghi nào ở đây: main_network.py nhận tham số này rồi tự gọi hàm ghi (có
    kiểm tra + xác nhận của quản trị viên) trên luồng chính."""
    task_parse = Task(
        description=(
            f'Ticket request: "{ticket_description}"\n\n'
            "Extract: the exact device name (call the device-listing tool "
            "once if the ticket uses a short/vague name like 'acc04'), the "
            "physical interface, the VLAN ID, and the mode ('tag' if the "
            "ticket says tag/tagged/trunk, otherwise 'access'). Do not "
            "guess: if something is missing from the ticket, leave it null "
            "and explain in 'error'."
        ),
        expected_output="A PortVlanRequest object.",
        agent=technical_agent,
        output_pydantic=PortVlanRequest,
    )
    return Crew(
        agents=[technical_agent],
        tasks=[task_parse],
        process=Process.sequential,
        verbose=True,
    )


def build_provision_report_crew(ticket_description: str, write_result_json: str) -> Crew:
    """report_agent viết báo cáo từ JSON kết quả của hàm ghi (đã chạy xong
    trong main_network.py) — agent không có tool, chỉ diễn giải."""
    task_report_configure = Task(
        description=(
            f'Ticket: "{ticket_description}"\n\n'
            "Result of the port/VLAN change, produced by the system:\n"
            f"{write_result_json}\n\n"
            "Write a complete English report on this ticket. State clearly "
            "what was found (did the VLAN exist? was the port free, or "
            "already in another VLAN / connected / a trunk — see "
            "port_before.in_use_reasons?) and the final outcome by "
            "'status': 'applied' -> report the real port state after the "
            "change (port_after / verify_switchport / verify_status), not "
            "just 'command ran successfully'; 'applied_but_not_verified' "
            "-> warn clearly that the port does NOT show the requested "
            "state and quote verify_switchport; 'already_configured' -> "
            "say nothing needed to change; 'cancelled' -> the "
            "administrator declined, not an error; 'blocked'/'error' -> "
            "explain the reason in plain English (e.g. VLAN doesn't exist, "
            "device not writable, routed port). When a change was applied, "
            "state whether it was saved to startup-config (config_saved); "
            "if false, warn that the change will be LOST on reload."
        ),
        expected_output=(
            "An English report describing the checks performed and the "
            "final outcome (applied / already configured / cancelled by "
            "administrator / blocked), with the real port status for "
            "cross-checking when applicable."
        ),
        agent=report_agent,
    )
    return Crew(
        agents=[report_agent],
        tasks=[task_report_configure],
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