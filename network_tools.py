"""
network_tools.py — Kết nối SSH tới thiết bị mạng (Cisco IOS) qua Netmiko,
parse output bằng TextFSM (ntc-templates), cung cấp tool cho CrewAI agent.

AN TOÀN: chỉ cho phép lệnh bắt đầu bằng "show" (read-only). Việc chặn này
nằm ở TẦNG CODE, không phụ thuộc vào việc model có "cư xử đúng" hay không —
kể cả nếu agent bị model "ảo giác" ra lệnh config, tool sẽ từ chối thực thi
trước khi chạm tới thiết bị thật.

Khuyến nghị bổ sung (lớp phòng thủ độc lập với code): tạo 1 tài khoản SSH
riêng trên thiết bị thật, giới hạn privilege level thấp chỉ đủ chạy show.
"""

import os
import re
import json
import time
import yaml
from dotenv import load_dotenv
from netmiko import ConnectHandler
from ntc_templates.parse import parse_output
from crewai.tools import tool

load_dotenv()  # đọc file .env nếu có, không lỗi nếu thiếu

INVENTORY_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "inventory.yaml"
)

# File log audit — mỗi lần gọi tool ghi thêm 1 dòng JSON vào đây, đọc lại
# được sau khi chạy xong (kể cả sau khi tắt terminal). Đây là cách tôi chọn
# thay cho global variable: không có rủi ro bị nhiều lần gọi ghi đè lẫn
# nhau, và còn nguyên vẹn cả sau khi process kết thúc — global variable
# trong RAM thì mất ngay khi chương trình thoát.
CALL_LOG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "tool_calls.log"
)


def _log_call(device_name: str, command: str, status: str, elapsed: float, detail: str = "") -> None:
    """Ghi 1 dòng JSON vào tool_calls.log. Không bao giờ để lỗi ghi log làm
    crash tool chính — log chỉ là phụ trợ debug, không phải logic cốt lõi."""
    try:
        entry = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "device": device_name,
            "command": command,
            "status": status,  # "ok" | "error"
            "elapsed_sec": round(elapsed, 2),
            "detail": detail[:200],  # cắt bớt nếu quá dài, chỉ cần đủ để nhận diện lỗi
        }
        with open(CALL_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass  # ghi log lỗi thì bỏ qua, không được làm hỏng tool chính

# Chỉ cho phép lệnh "show ..." (không phân biệt hoa/thường). Mọi lệnh khác
# (configure terminal, no shutdown, write erase, reload, ...) bị từ chối
# ngay tại đây, bất kể model sinh ra lệnh gì.
ALLOWED_COMMAND_RE = re.compile(r"^\s*show\b", re.IGNORECASE)

# Redact credential thật trước khi raw_output rời khỏi _run_raw — vì lệnh
# "show running-config"/"show startup-config" (đều hợp lệ, bắt đầu bằng
# "show") có thể lộ enable secret, password VTY/console, hay SNMP community
# string. Dữ liệu này sẽ được agent đưa thẳng vào prompt gửi ra API LLM cloud
# (kể cả endpoint bên thứ 3 ngoài Anthropic/OpenAI, tuỳ cấu hình
# OPENAI_BASE_URL) — nên chặn ở đây, tại nguồn, thay vì tin agent sẽ tự biết
# không trích dẫn lại các dòng đó. Chỉ redact phần giá trị bí mật, giữ
# nguyên cấu trúc dòng để vẫn đọc được ngữ cảnh (loại secret, có cấu hình
# hay không) khi chẩn đoán.
_SECRET_LINE_PATTERNS = [
    # "enable secret 5 $1$...", "enable password 7 104D000A0618"
    re.compile(r"(?im)^(\s*enable\s+(?:secret|password)\s+(?:\d+\s+)?)(\S+)\s*$"),
    # " password 7 08351E1A0725" (dưới line con/vty), " password cisco"
    re.compile(r"(?im)^(\s*password\s+(?:\d+\s+)?)(\S+)\s*$"),
    # "username admin privilege 15 secret 5 $1$..."
    re.compile(r"(?im)^(\s*username\s+\S+.*?\b(?:secret|password)\s+(?:\d+\s+)?)(\S+)\s*$"),
    # "snmp-server community public RO"
    re.compile(r"(?im)^(\s*snmp-server\s+community\s+)(\S+)"),
    # "tacacs-server key ...", "radius-server key ..."
    re.compile(r"(?im)^(\s*(?:tacacs-server|radius-server)\s+key\s+(?:\d+\s+)?)(\S+)\s*$"),
    # "key-string <secret>" (key chain authentication)
    re.compile(r"(?im)^(\s*key-string\s+)(\S+)\s*$"),
    # "ppp pap sent-username X password Y" / "ppp chap password Y"
    re.compile(r"(?im)^(\s*ppp\s+(?:pap|chap)\s+.*?password\s+)(\S+)\s*$"),
]


def _redact_secrets(text: str) -> str:
    """Thay giá trị bí mật trên các dòng cấu hình nhạy cảm bằng
    '[REDACTED]', giữ nguyên phần còn lại của dòng. Không có match thì trả
    về nguyên văn — lệnh show thường (vd 'show vlan brief') không có dòng
    nào khớp nên không bị ảnh hưởng."""
    for pattern in _SECRET_LINE_PATTERNS:
        text = pattern.sub(lambda m: m.group(1) + "[REDACTED]", text)
    return text


def _load_devices() -> dict:
    with open(INVENTORY_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get("devices", {})


def _device_params(device_name: str) -> dict:
    devices = _load_devices()
    if device_name not in devices:
        available = ", ".join(devices.keys()) or "(inventory rỗng)"
        raise ValueError(
            f"Không tìm thấy thiết bị '{device_name}' trong inventory.yaml. "
            f"Thiết bị có sẵn: {available}"
        )
    dev = devices[device_name]

    username = dev.get("username") or os.environ.get("NETWORK_USERNAME")
    password = dev.get("password") or os.environ.get("NETWORK_PASSWORD")
    secret = (
        dev.get("secret")
        or os.environ.get("NETWORK_ENABLE_SECRET")
        or password
    )

    if not username or not password:
        raise ValueError(
            "Thiếu NETWORK_USERNAME/NETWORK_PASSWORD — kiểm tra file .env "
            "(copy từ .env.example rồi điền thật)."
        )

    return {
        "device_type": dev.get("device_type", "cisco_ios"),
        "host": dev["host"],
        "username": username,
        "password": password,
        "secret": secret,
        # Timeout tường minh — mặc định Netmiko khá dài (có thể "treo" lâu
        # không rõ đang chờ gì). Đặt ngắn lại để lỗi hiện ra nhanh, dễ chẩn
        # đoán (vd hết VTY line trên switch sẽ timeout ở bước kết nối/login,
        # không phải ở bước chạy lệnh).
        "conn_timeout": 10,     # timeout mở kết nối TCP
        "auth_timeout": 15,     # timeout chờ login (username/password)
        "banner_timeout": 15,   # timeout chờ banner lúc mới kết nối
        "timeout": 15,          # timeout chờ phản hồi khi chạy lệnh
    }


def _run_raw(device_name: str, command: str) -> dict:
    """Chạy 1 lệnh show trên thiết bị. Trả về dict {raw_output, parsed}.
    parsed có thể là None nếu ntc-templates không có template phù hợp cho
    lệnh này — vẫn còn raw_output để đọc bình thường."""
    if not ALLOWED_COMMAND_RE.match(command):
        raise PermissionError(
            f"Lệnh '{command}' bị từ chối — tool này chỉ cho phép lệnh bắt "
            "đầu bằng 'show' (read-only)."
        )

    params = _device_params(device_name)
    platform = params["device_type"]
    t0 = time.monotonic()
    print(
        f"[network_tools] → Kết nối {device_name} ({params['host']}, "
        f"{platform}) để chạy: {command!r}"
    )

    try:
        with ConnectHandler(**params) as conn:
            elapsed_connect = time.monotonic() - t0
            print(f"[network_tools]   Đã kết nối sau {elapsed_connect:.1f}s, đang chạy lệnh...")
            if params.get("secret"):
                try:
                    conn.enable()
                except Exception as e:
                    print(f"[network_tools]   enable() lỗi (bỏ qua): {e}")

            raw_output = conn.send_command(command)
            raw_output = _redact_secrets(raw_output)
    except Exception as e:
        elapsed = time.monotonic() - t0
        print(f"[network_tools] ✗ LỖI sau {elapsed:.1f}s trên {device_name}: {e}")
        _log_call(device_name, command, "error", elapsed, detail=str(e))
        raise

    elapsed_total = time.monotonic() - t0
    print(f"[network_tools] ✓ Xong {device_name} sau {elapsed_total:.1f}s, {len(raw_output)} ký tự output")
    _log_call(device_name, command, "ok", elapsed_total, detail=f"{len(raw_output)} ky tu")

    # Parse offline bằng ntc-templates thay vì gọi lại SSH lần 2 — chỉ mất
    # 1 round-trip SSH cho mỗi lệnh.
    parsed = None
    try:
        parsed = parse_output(platform=platform, command=command, data=raw_output)
        if not parsed:
            parsed = None
    except Exception:
        parsed = None

    return {"raw_output": raw_output, "parsed": parsed}


def get_available_devices_text() -> str:
    devices = _load_devices()
    if not devices:
        return "inventory.yaml chưa có thiết bị nào."
    lines = [f"- {name} ({info.get('host', '?')})" for name, info in devices.items()]
    return "Thiết bị có sẵn:\n" + "\n".join(lines)


def _extract_status_rows(parsed_rows: list) -> list:
    """Chuẩn hoá tên field: các version ntc-templates/IOS khác nhau đôi khi
    trả tên cột khác nhau (intf/interface, status/link_status). Đây là điểm
    dễ vỡ nhất khi đổi version IOS — chuẩn hoá ở 1 chỗ để dễ sửa."""
    normalized = []
    for row in parsed_rows:
        name = row.get("intf") or row.get("interface") or row.get("port")
        status = row.get("status") or row.get("link_status")
        normalized.append({"name": name, "status": str(status or "").strip().lower()})
    return normalized


# ---------------------------------------------------------------------------
# Tool cho CrewAI agent. Docstring của mỗi tool chính là thứ LLM đọc để
# quyết định khi nào gọi tool nào — viết rõ ràng, cụ thể.
# ---------------------------------------------------------------------------


def run_show_command_text(device_name: str, command: str) -> str:
    """Logic thật của 'chạy lệnh show' — hàm PLAIN, gọi tay trực tiếp được
    (vd để test độc lập: `python -c "from network_tools import
    run_show_command_text; print(run_show_command_text(...))"`). Bản
    `@tool` bên dưới chỉ là lớp bọc mỏng để agent dùng, KHÔNG gọi tay được
    trực tiếp vì đã bị crewai biến thành Tool object."""
    try:
        result = _run_raw(device_name, command)
        return json.dumps(
            {
                "device": device_name,
                "command": command,
                "raw_output": result["raw_output"],
                "parsed": result["parsed"],
            },
            ensure_ascii=False,
            indent=2,
        )
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)


def count_up_ports_text(device_name: str) -> str:
    """Logic thật của 'đếm port up' — hàm PLAIN, gọi tay trực tiếp được,
    cùng lý do như `run_show_command_text` ở trên."""
    try:
        result = _run_raw(device_name, "show ip interface brief")
        parsed = result["parsed"]
        if not parsed:
            return json.dumps(
                {
                    "error": (
                        "Không parse được output bằng TextFSM (thiếu template "
                        "phù hợp, hoặc version IOS trả format khác chuẩn). "
                        "Xem raw_output để tự kiểm tra thay vì tin số đếm."
                    ),
                    "raw_output": result["raw_output"],
                },
                ensure_ascii=False,
            )

        rows = _extract_status_rows(parsed)
        up_ports = [r["name"] for r in rows if r["status"] == "up"]

        return json.dumps(
            {
                "device": device_name,
                "total_ports": len(rows),
                "up_count": len(up_ports),
                "up_ports": up_ports,
            },
            ensure_ascii=False,
            indent=2,
        )
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Tool cho CrewAI agent. Docstring của mỗi tool chính là thứ LLM đọc để
# quyết định khi nào gọi tool nào — viết rõ ràng, cụ thể. Mỗi tool chỉ gọi
# lại hàm PLAIN tương ứng ở trên — KHÔNG viết logic trực tiếp trong này,
# để giữ được khả năng gọi tay/test độc lập qua hàm plain.
# ---------------------------------------------------------------------------


@tool("Danh sách thiết bị mạng khả dụng")
def list_available_devices() -> str:
    """Trả về danh sách tên thiết bị (switch/router) có trong inventory.yaml
    kèm IP quản trị. Dùng tool này đầu tiên khi chưa chắc tên thiết bị chính
    xác trong câu hỏi là gì (vd người dùng nói "switch access 1" nhưng tên
    thật trong inventory là "access-sw-1")."""
    return get_available_devices_text()


@tool("Chạy lệnh show trên thiết bị mạng")
def run_show_command(device_name: str, command: str) -> str:
    """SSH vào thiết bị mạng và chạy 1 lệnh 'show' (chỉ cho phép lệnh show,
    lệnh khác sẽ bị từ chối ở tầng code trước khi chạm tới thiết bị). Trả về
    JSON gồm raw_output (text gốc, luôn có) và parsed (dữ liệu có cấu trúc
    nếu TextFSM có template phù hợp, có thể là null).

    Args:
        device_name: Tên thiết bị đúng như trong inventory.yaml (vd: access-sw-1).
        command: Lệnh show cần chạy (vd: 'show ip interface brief',
            'show running-config', 'show vlan brief').
    """
    return run_show_command_text(device_name, command)


@tool("Đếm số port đang up trên thiết bị")
def count_up_ports(device_name: str) -> str:
    """Đếm CHÍNH XÁC số port đang ở trạng thái 'up' trên 1 thiết bị, bằng
    cách parse 'show ip interface brief' qua TextFSM rồi đếm bằng code
    (len(...)) — không để LLM tự đếm từ text dài, vì model nhỏ rất dễ đếm
    sai. Dùng tool này cho MỌI câu hỏi liên quan tới số lượng/đếm port.

    Args:
        device_name: Tên thiết bị đúng như trong inventory.yaml.

    Trả về: JSON gồm total_ports, up_count, up_ports (danh sách tên port).
    """
    return count_up_ports_text(device_name)