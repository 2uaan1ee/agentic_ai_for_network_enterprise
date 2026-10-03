"""
main_network.py — Chạy crew chẩn đoán/vận hành mạng tương tác.

2 chế độ:
1. Hỏi thông tin (read-only) — như cũ, agent tự SSH/Telnet đọc dữ liệu.
2. Xử lý ticket cấp phát VLAN/port (CÓ GHI cấu hình, quyền giới hạn) —
   chỉ gán access / tag VLAN đã có lên cổng, không tạo VLAN, không đụng
   được routing/IP. Xem
   network_write_tools.py để biết chi tiết các lớp kiểm soát.

Mọi tương tác (cả 2 chế độ) tự động lưu vào qa_log.md (append) — dùng để
track lại kết quả test, đưa thẳng vào report.

Ngoài ra MỖI LẦN CHẠY chương trình được lưu vào 1 file riêng trong thư
mục output/ (cạnh file này): output/lan_1.md, output/lan_2.md, ... Khi khởi
động, chương trình xem file lan_N.md có số lớn nhất trong output/ rồi lấy
N+1 (chưa có file nào thì là lan_1). Mọi câu hỏi/trả lời trong lần chạy đó
được ghi NỐI TIẾP vào file này — file của các lần chạy trước không bao giờ
bị ghi đè.
"""

import os
import re
import time
from crew_network import (
    build_crew,
    build_monitoring_crew,
    build_provision_report_crew,
    build_ticket_parse_crew,
    check_llm_ready,
)
from network_tools import _load_devices, get_available_devices_text
from network_write_tools import assign_access_port_text, tag_vlan_on_port_text

QA_LOG_PATH = "qa_log.md"
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
_RUN_FILE_RE = re.compile(r"^lan_(\d+)\.md$", re.IGNORECASE)

# File output của lần chạy hiện tại + số lượt hỏi đã ghi vào đó. Được
# chọn 1 lần lúc khởi động (_init_run_file), file chỉ thực sự được tạo khi
# có lượt hỏi đầu tiên — mở chương trình rồi thoát ngay thì không sinh ra
# file rỗng.
_run_number = None
_run_entry_count = 0


def _next_run_number() -> int:
    """Số lần chạy tiếp theo = số lớn nhất trong các file lan_N.md đang có
    trong output/ + 1. Chưa có file nào -> 1."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    numbers = [
        int(m.group(1))
        for name in os.listdir(OUTPUT_DIR)
        if (m := _RUN_FILE_RE.match(name))
    ]
    return max(numbers, default=0) + 1


def _run_file_path() -> str:
    return os.path.join(OUTPUT_DIR, f"lan_{_run_number}.md")


def _init_run_file() -> None:
    global _run_number, _run_entry_count
    _run_number = _next_run_number()
    _run_entry_count = 0
    print(f"Lần chạy này sẽ lưu vào output/lan_{_run_number}.md")


def _task_outputs(result) -> list:
    """Lấy output thô của từng task (vd JSON kết quả tool của agent kỹ
    thuật) từ CrewOutput — hữu ích khi cần dùng lại dữ liệu gốc, không chỉ
    câu trả lời cuối. Không có thì trả list rỗng."""
    outputs = []
    for t in getattr(result, "tasks_output", None) or []:
        outputs.append((str(getattr(t, "agent", "") or "?").strip(), getattr(t, "raw", "") or ""))
    return outputs


def _save_output_file(kind: str, request: str, answer: str, ok: bool, result=None, steps=None) -> None:
    """Ghi nối 1 lượt hỏi/đáp vào file lan_N.md của lần chạy hiện tại.
    steps: list (tên bước, output thô) thêm vào trước output các task của
    result (vd JSON kết quả hàm ghi cấu hình). Không bao giờ để lỗi ghi
    file làm crash chương trình chính."""
    global _run_number, _run_entry_count
    try:
        if _run_number is None:
            _init_run_file()

        lines = []
        if _run_entry_count == 0:
            # Lượt đầu tiên: tạo file bằng mode "x" để chắc chắn không ghi
            # đè file cũ — nếu lan_N.md bỗng đã tồn tại (vd 2 cửa sổ chạy
            # cùng lúc) thì lấy số mới.
            while True:
                try:
                    with open(_run_file_path(), "x", encoding="utf-8") as f:
                        f.write(
                            f"# Lần chạy {_run_number}\n\n"
                            f"- **Bắt đầu:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                        )
                    break
                except FileExistsError:
                    _run_number = _next_run_number()

        _run_entry_count += 1
        lines += [
            "",
            "---",
            "",
            f"## Lượt {_run_entry_count} — {kind}",
            "",
            f"- **Thời gian:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"- **Trạng thái:** {'OK' if ok else 'LỖI'}",
            "",
            "### Câu hỏi",
            "",
            request,
            "",
            "### Trả lời",
            "",
            answer,
            "",
        ]
        task_outputs = list(steps or []) + (_task_outputs(result) if result is not None else [])
        if task_outputs:
            lines += ["### Output từng bước (raw)", ""]
            for i, (agent, raw) in enumerate(task_outputs, 1):
                # 4 backtick để không vỡ khung nếu raw có sẵn ``` bên trong.
                lines += [f"#### Bước {i} — {agent}", "", "````", raw, "````", ""]

        with open(_run_file_path(), "a", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"[main_network] Đã lưu lượt {_run_entry_count} vào output/lan_{_run_number}.md")
    except Exception as e:
        print(f"[main_network] Không lưu được file output ({e}), bỏ qua.")


def _log_entry(kind: str, request: str, answer: str) -> None:
    """Ghi 1 mục vào qa_log.md dạng markdown, append thêm vào cuối file.
    kind: 'Hỏi thông tin' hoặc 'Ticket cấu hình' — để phân biệt khi đọc lại
    log sau này. Không bao giờ để lỗi ghi log làm crash chương trình chính."""
    try:
        with open(QA_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"\n## [{kind}] {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Yêu cầu:** {request}\n\n")
            f.write(f"**Kết quả:**\n\n{answer}\n\n---\n")
    except Exception as e:
        print(f"[main_network] Không ghi được vào {QA_LOG_PATH} ({e}), bỏ qua.")


def _run_crew_safely(crew, kind: str, request: str, result_header: str) -> None:
    """Chạy crew.kickoff() có bọc try/except — lỗi giữa chừng (API rate
    limit/timeout, key sai, SSH timeout, thiết bị không phản hồi...) chỉ in
    ra và quay lại vòng lặp nhập liệu, KHÔNG làm crash cả REPL như trước
    (trước đây crew.kickoff() không có try/except nào bao quanh). Log lại
    cả trường hợp lỗi vào qa_log.md để biết đã hỏi gì lúc gặp sự cố, không
    chỉ log khi thành công."""
    try:
        result = crew.kickoff()
    except KeyboardInterrupt:
        # Ctrl+C khi crew đang chạy chỉ dừng yêu cầu này, không thoát cả
        # chương trình (Ctrl+C ở dấu nhắc nhập liệu vẫn thoát như cũ).
        print("\n[main_network] Đã dừng yêu cầu này (Ctrl+C).\n")
        _log_entry(kind, request, "ĐÃ DỪNG (Ctrl+C)")
        _save_output_file(kind, request, "ĐÃ DỪNG (Ctrl+C)", ok=False)
        return
    except Exception as e:
        print(f"\n[main_network] LỖI khi xử lý yêu cầu: {e}\n")
        _log_entry(kind, request, f"LỖI: {e}")
        _save_output_file(kind, request, f"LỖI: {e}", ok=False)
        return

    print(f"\n{result_header}")
    print(result)
    print()
    _log_entry(kind, request, str(result))
    _save_output_file(kind, request, str(result), ok=True, result=result)


# Nhận diện câu "muốn đổi cấu hình VLAN cho cổng" gõ nhầm vào chế độ hỏi
# thông tin (read-only). Cần đủ 3 thứ: chữ 'vlan <số>', 1 tên cổng (e0/2,
# Ethernet1/0...) và 1 động từ hành động — để câu hỏi thuần tuý như "e0/2
# đang thuộc vlan nào?" không bị bắt nhầm.
_VLAN_NUM_RE = re.compile(r"\bvlan\s*\d+", re.IGNORECASE)
_PORT_RE = re.compile(r"\b(?:e|et|eth|ether|ethernet)\s*\d+/\d+", re.IGNORECASE)
_ACTION_RE = re.compile(
    r"\b(?:gán|gan|assign|tag|tagged|trunk|đổi|doi|chuyển|chuyen|set|"
    r"cấu hình|cau hinh|config|thêm|them|làm giùm|lam gium|làm giúp|lam giup)\b"
    r"|\baccess\s+vlan\b",
    re.IGNORECASE,
)


def _looks_like_port_vlan_change(text: str) -> bool:
    return bool(_VLAN_NUM_RE.search(text) and _PORT_RE.search(text) and _ACTION_RE.search(text))


_TICKET_VLAN_RE = re.compile(r"\bvlan\s*(\d+)", re.IGNORECASE)
_TICKET_PORT_RE = re.compile(r"\b((?:e|et|eth|ether|ethernet)\s*\d+/\d+)", re.IGNORECASE)
_TICKET_TAG_RE = re.compile(r"\b(?:tag|tagged|trunk)\b", re.IGNORECASE)
_TICKET_ACC_RE = re.compile(r"\bacc(?:ess)?\s*[_-]?\s*0*(\d+)\b", re.IGNORECASE)


def _resolve_device(text: str):
    """Tìm tên thiết bị trong ticket: tên đầy đủ (Switch_Acc004) hoặc viết
    tắt kiểu 'acc04', 'acc 4', 'access 4'. Chỉ trả về khi khớp ĐÚNG 1 thiết
    bị, còn lại trả None để nhờ agent đọc hiểu."""
    devices = list(_load_devices().keys())
    lowered = text.lower()
    exact = [d for d in devices if d.lower() in lowered]
    if len(exact) == 1:
        return exact[0]
    m = _TICKET_ACC_RE.search(text)
    if m:
        number = int(m.group(1))
        hits = []
        for d in devices:
            dm = re.search(r"(\d+)$", d)
            if "acc" in d.lower() and dm and int(dm.group(1)) == number:
                hits.append(d)
        if len(hits) == 1:
            return hits[0]
    return None


def _parse_ticket_locally(ticket: str):
    """Tách device/cổng/VLAN/mode bằng regex — đủ cho các câu thường gặp
    ('gán port e0/2 của switch acc04 cho vlan 30'). Thiếu bất kỳ phần nào
    thì trả None để nhờ agent đọc hiểu."""
    vlan = _TICKET_VLAN_RE.search(ticket)
    port = _TICKET_PORT_RE.search(ticket)
    device = _resolve_device(ticket)
    if not (vlan and port and device):
        return None
    return {
        "device_name": device,
        "interface": port.group(1),
        "vlan_id": int(vlan.group(1)),
        "mode": "tag" if _TICKET_TAG_RE.search(ticket) else "access",
    }


def _handle_provision_ticket(ticket: str) -> None:
    """Luồng xử lý ticket gán/tag VLAN:
    1. Tách tham số (regex; không đủ thì nhờ technical_agent đọc hiểu).
    2. Gọi hàm ghi NGAY TRÊN LUỒNG CHÍNH — hàm này tự kiểm tra VLAN tồn
       tại, trạng thái cổng, rồi hỏi quản trị viên xác nhận. Không để agent
       gọi tool ghi vì CrewAI chạy tool trong thread phụ, câu hỏi yes/no có
       thể bị khung log che/treo, và agent hay đi đường vòng.
    3. report_agent viết báo cáo từ JSON kết quả."""
    kind = "Ticket cấu hình"
    steps = []
    try:
        req = _parse_ticket_locally(ticket)
        if req is None:
            print("[main_network] Chưa tự tách đủ thiết bị/cổng/VLAN — nhờ agent đọc hiểu ticket...")
            parsed = build_ticket_parse_crew(ticket).kickoff().pydantic
            if parsed is None or parsed.error or not (parsed.device_name and parsed.interface and parsed.vlan_id):
                reason = (parsed.error if parsed is not None and parsed.error else
                          "không xác định được đủ thiết bị, cổng và VLAN")
                msg = (f"Không xử lý được ticket: {reason}. Hãy ghi rõ, vd "
                       "'access vlan 30 vào e0/2 trên Switch_Acc004'.")
                print(f"\n=== KẾT QUẢ ===\n{msg}\n")
                _log_entry(kind, ticket, msg)
                _save_output_file(kind, ticket, msg, ok=False)
                return
            req = parsed.model_dump()

        print(
            f"\n[main_network] Hiểu yêu cầu: {req['mode'].upper()} VLAN {req['vlan_id']} "
            f"trên cổng {req['interface']} của {req['device_name']}"
        )
        write_fn = tag_vlan_on_port_text if req["mode"] == "tag" else assign_access_port_text
        write_result = write_fn(req["device_name"], req["interface"], int(req["vlan_id"]))
        steps.append(("Kết quả kiểm tra + cấu hình (code)", write_result))
    except KeyboardInterrupt:
        print("\n[main_network] Đã dừng yêu cầu này (Ctrl+C).\n")
        _log_entry(kind, ticket, "ĐÃ DỪNG (Ctrl+C)")
        _save_output_file(kind, ticket, "ĐÃ DỪNG (Ctrl+C)", ok=False, steps=steps)
        return
    except Exception as e:
        print(f"\n[main_network] LỖI khi xử lý ticket: {e}\n")
        _log_entry(kind, ticket, f"LỖI: {e}")
        _save_output_file(kind, ticket, f"LỖI: {e}", ok=False, steps=steps)
        return

    # Việc ghi (nếu có) đã xong — lỗi ở bước viết báo cáo không được làm
    # mất kết quả, nên khi đó in thẳng JSON kết quả.
    result = None
    try:
        result = build_provision_report_crew(ticket, write_result).kickoff()
        answer = str(result)
    except KeyboardInterrupt:
        answer = "(Đã dừng bước viết báo cáo — kết quả gốc:)\n\n" + write_result
    except Exception as e:
        answer = f"(Không viết được báo cáo: {e} — kết quả gốc:)\n\n" + write_result

    print(f"\n=== KẾT QUẢ ===\n{answer}\n")
    _log_entry(kind, ticket, answer)
    _save_output_file(kind, ticket, answer, ok=True, result=result, steps=steps)


def _run_read_mode() -> None:
    print(get_available_devices_text())
    print("\nGõ câu hỏi của bạn, hoặc 'back' để quay lại menu.\n")
    while True:
        question = input("Câu hỏi: ").strip()
        if question.lower() in ("back", "exit", "quit", "thoat"):
            break
        if not question:
            continue

        # Chế độ này chỉ có agent read-only — nếu người dùng thật ra muốn
        # gán/tag VLAN thì agent chỉ biết đọc config rồi bảo tự gõ lệnh.
        # Hỏi để chuyển sang luồng cấu hình (vẫn qua đủ bước kiểm tra và
        # xác nhận trong tool ghi).
        if _looks_like_port_vlan_change(question):
            answer = input(
                "Yêu cầu này có vẻ là GÁN/TAG VLAN cho cổng (cần ghi cấu hình) "
                "— chuyển sang chế độ xử lý ticket cấu hình? (yes/no): "
            ).strip().lower()
            if answer in ("y", "yes"):
                _handle_provision_ticket(question)
                continue

        crew = build_crew(question)
        _run_crew_safely(crew, "Hỏi thông tin", question, "=== TRẢ LỜI ===")


def _run_provision_mode() -> None:
    print(get_available_devices_text())
    print(
        "\n⚠️  Chế độ này SẼ GHI cấu hình thật lên thiết bị (writable: true "
        "trong inventory.yaml). Chỉ giới hạn ở gán access / tag VLAN ĐÃ CÓ "
        "lên cổng vật lý — không tạo VLAN mới."
    )
    print(
        "Ví dụ: 'access vlan 30 vào e1/0 trên Switch_Acc003', 'tag vlan 30 "
        "vào e1/1 trên Switch_Acc003'. Gõ 'back' để quay lại menu.\n"
    )
    while True:
        ticket = input("Ticket: ").strip()
        if ticket.lower() in ("back", "exit", "quit", "thoat"):
            break
        if not ticket:
            continue

        _handle_provision_ticket(ticket)


def _run_monitoring_mode() -> None:
    print(get_available_devices_text())
    print(
        "\nMô tả thiết bị cần giám sát (vd 'kiểm tra CPU/RAM/Disk của "
        "Switch_Core_SW111', 'kiểm tra lỗi trên Ethernet1/0 của "
        "Switch_Acc003'), hoặc 'back' để quay lại menu.\n"
    )
    while True:
        request = input("Giám sát: ").strip()
        if request.lower() in ("back", "exit", "quit", "thoat"):
            break
        if not request:
            continue

        crew = build_monitoring_crew(request)
        _run_crew_safely(crew, "Giám sát", request, "=== KẾT QUẢ ===")


if __name__ == "__main__":
    check_llm_ready()

    print("=== Multi-Agent Vận hành mạng ===")
    print(f"Mọi tương tác sẽ tự động lưu vào {QA_LOG_PATH}")
    _init_run_file()
    print()

    while True:
        print("1. Hỏi thông tin (read-only)")
        print("2. Xử lý ticket cấp phát VLAN/port (có ghi cấu hình)")
        print("3. Giám sát sức khoẻ thiết bị (CPU/RAM/lỗi interface)")
        print("0. Thoát")
        choice = input("Chọn: ").strip()

        if choice == "1":
            _run_read_mode()
        elif choice == "2":
            _run_provision_mode()
        elif choice == "3":
            _run_monitoring_mode()
        elif choice == "0" or choice.lower() in ("exit", "quit", "thoat"):
            print("Tạm biệt!")
            break
        else:
            print("Lựa chọn không hợp lệ, thử lại.\n")