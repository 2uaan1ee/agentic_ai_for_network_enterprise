"""
network_monitoring_tools.py — Tool GIÁM SÁT (Monitoring): đọc CPU/RAM/Disk/
lỗi interface trên thiết bị, áp dụng ngưỡng cảnh báo CỐ ĐỊNH TRONG CODE
(không để LLM tự phán đoán "cao" hay "thấp") — đúng triết lý xuyên suốt dự
án: số liệu/quyết định định lượng do code tính, LLM chỉ diễn giải + đề xuất
hành động dựa trên kết quả code đã tính sẵn (giống hệt cách count_up_ports
đếm port bằng code thay vì để LLM tự đếm).

CHỈ ĐỌC — dùng lại nguyên vẹn cơ chế whitelist "chỉ lệnh show" của
network_tools.py (qua _run_raw), không có rủi ro an toàn nào khác.

⚠️ Regex dựa trên format chuẩn IOS ổn định qua nhiều version (CPU/memory đã
test thành công trên Switch_Core_SW111 thật). Riêng DISK (`show flash`)
CHƯA test trên thiết bị thật — nếu báo lỗi "Không parse được", dán
raw_output để chỉnh lại regex `_DISK_RE` cho khớp đúng format image bạn
dùng.
"""

import re
import json
from crewai.tools import tool

from network_tools import _run_raw

# Ngưỡng cảnh báo — chỉnh tại đây nếu cần, không phải sửa logic khác.
CPU_WARNING_PCT = 50
CPU_CRITICAL_PCT = 80
MEM_WARNING_PCT = 75
MEM_CRITICAL_PCT = 90
DISK_WARNING_PCT = 75
DISK_CRITICAL_PCT = 90

# Dòng chuẩn IOS: "CPU utilization for five seconds: 5%/2%; one minute: 8%; five minutes: 10%"
_CPU_RE = re.compile(
    r"CPU utilization for five seconds:\s*(\d+)%/(\d+)%;\s*"
    r"one minute:\s*(\d+)%;\s*five minutes:\s*(\d+)%",
    re.IGNORECASE,
)
# Dòng chuẩn IOS: "Processor Pool Total: 234881024 Used: 84213248 Free: 150667776"
_MEM_RE = re.compile(
    r"Processor Pool Total:\s*(\d+)\s+Used:\s*(\d+)\s+Free:\s*(\d+)",
    re.IGNORECASE,
)
# Dòng chuẩn IOS cuối "show flash": "123456 bytes total (65432 bytes free)"
_DISK_RE = re.compile(
    r"([\d]+)\s*bytes total\s*\(([\d]+)\s*bytes free\)",
    re.IGNORECASE,
)
# Dòng chuẩn IOS trong "show interfaces <intf>":
#   "0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored"
#   "0 output errors, 0 collisions, 0 interface resets"
_INPUT_ERR_RE = re.compile(r"(\d+)\s+input errors,\s*(\d+)\s+CRC", re.IGNORECASE)
_OUTPUT_ERR_RE = re.compile(r"(\d+)\s+output errors,\s*(\d+)\s+collisions", re.IGNORECASE)


def _status_from_pct(pct: float, warn: float, crit: float) -> str:
    if pct >= crit:
        return "critical"
    if pct >= warn:
        return "warning"
    return "ok"


def check_device_health_text(device_name: str) -> str:
    """Kiểm tra CPU + memory + disk trên 1 thiết bị, áp dụng ngưỡng cảnh
    báo cố định trong code. Hàm PLAIN, gọi tay được để test độc lập."""
    try:
        cpu_result = _run_raw(device_name, "show processes cpu")
        mem_result = _run_raw(device_name, "show processes memory")
        disk_result = _run_raw(device_name, "show flash")

        report = {"device": device_name}

        cpu_match = _CPU_RE.search(cpu_result["raw_output"])
        if cpu_match:
            five_sec, five_sec_interrupt, one_min, five_min = map(int, cpu_match.groups())
            report["cpu"] = {
                "five_sec_pct": five_sec,
                "one_min_pct": one_min,
                "five_min_pct": five_min,
                "status": _status_from_pct(five_min, CPU_WARNING_PCT, CPU_CRITICAL_PCT),
            }
        else:
            report["cpu"] = {
                "error": "Không parse được dòng 'CPU utilization' — kiểm tra lại raw_output",
                "raw_output": cpu_result["raw_output"][:500],
            }

        mem_match = _MEM_RE.search(mem_result["raw_output"])
        if mem_match:
            total, used, free = map(int, mem_match.groups())
            used_pct = round(used / total * 100, 1) if total else 0.0
            report["memory"] = {
                "total_bytes": total,
                "used_bytes": used,
                "free_bytes": free,
                "used_pct": used_pct,
                "status": _status_from_pct(used_pct, MEM_WARNING_PCT, MEM_CRITICAL_PCT),
            }
        else:
            report["memory"] = {
                "error": "Không parse được dòng 'Processor Pool Total' — kiểm tra lại raw_output",
                "raw_output": mem_result["raw_output"][:500],
            }

        disk_match = _DISK_RE.search(disk_result["raw_output"])
        if disk_match:
            total, free = map(int, disk_match.groups())
            used = total - free
            used_pct = round(used / total * 100, 1) if total else 0.0
            report["disk"] = {
                "total_bytes": total,
                "used_bytes": used,
                "free_bytes": free,
                "used_pct": used_pct,
                "status": _status_from_pct(used_pct, DISK_WARNING_PCT, DISK_CRITICAL_PCT),
            }
        else:
            report["disk"] = {
                "error": "Không parse được dòng 'bytes total (... bytes free)' — kiểm tra lại raw_output",
                "raw_output": disk_result["raw_output"][:500],
            }

        return json.dumps(report, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)


def check_interface_errors_text(device_name: str, interface: str) -> str:
    """Kiểm tra số lỗi (input/output errors, CRC, collision) trên 1 cổng cụ
    thể qua 'show interfaces <intf>'. Hàm PLAIN, gọi tay được."""
    try:
        result = _run_raw(device_name, f"show interfaces {interface}")
        raw = result["raw_output"]

        report = {"device": device_name, "interface": interface}
        total_errors = 0

        input_match = _INPUT_ERR_RE.search(raw)
        if input_match:
            report["input_errors"] = int(input_match.group(1))
            report["crc_errors"] = int(input_match.group(2))
            total_errors += report["input_errors"] + report["crc_errors"]

        output_match = _OUTPUT_ERR_RE.search(raw)
        if output_match:
            report["output_errors"] = int(output_match.group(1))
            report["collisions"] = int(output_match.group(2))
            total_errors += report["output_errors"] + report["collisions"]

        if not input_match and not output_match:
            report["error"] = "Không parse được dòng lỗi — kiểm tra lại raw_output"
            report["raw_output"] = raw[:800]
        else:
            report["status"] = "warning" if total_errors > 0 else "ok"

        return json.dumps(report, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Tool cho CrewAI agent — cùng pattern plain/tool-wrapper như network_tools.py
# ---------------------------------------------------------------------------


@tool("Kiểm tra sức khoẻ thiết bị (CPU/RAM/Disk)")
def check_device_health(device_name: str) -> str:
    """Kiểm tra CPU, memory, và disk (flash) hiện tại trên 1 thiết bị, trả
    về số liệu CHÍNH XÁC (tính bằng code, không phải LLM ước lượng) kèm
    trạng thái cảnh báo (ok/warning/critical) theo ngưỡng cố định cho từng
    mục — đọc đúng trường 'status' đã có sẵn, không tự phán đoán số liệu
    cao/thấp.

    Args:
        device_name: Tên thiết bị đúng như trong inventory.yaml.
    """
    return check_device_health_text(device_name)


@tool("Kiểm tra lỗi trên 1 cổng mạng")
def check_interface_errors(device_name: str, interface: str) -> str:
    """Kiểm tra số lỗi (input/output errors, CRC, collision) trên 1 cổng cụ
    thể — dùng khi nghi ngờ cổng có vấn đề vật lý (cáp, kết nối chập chờn).

    Args:
        device_name: Tên thiết bị đúng như trong inventory.yaml.
        interface: Tên cổng (vd 'Ethernet1/0').
    """
    return check_interface_errors_text(device_name, interface)