"""
main_network.py — Chạy crew chẩn đoán/vận hành mạng tương tác.

2 chế độ:
1. Hỏi thông tin (read-only) — như cũ, agent tự SSH/Telnet đọc dữ liệu.
2. Xử lý ticket cấp phát VLAN/port (CÓ GHI cấu hình, quyền giới hạn) —
   chỉ tạo VLAN + gán access port, không đụng được routing/IP. Xem
   network_write_tools.py để biết chi tiết các lớp kiểm soát.

Mọi tương tác (cả 2 chế độ) tự động lưu vào qa_log.md (append) — dùng để
track lại kết quả test, đưa thẳng vào report.
"""

import time
from crew_network import build_crew, build_provision_crew, build_monitoring_crew, check_llm_ready
from network_tools import get_available_devices_text

QA_LOG_PATH = "qa_log.md"


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
        raise
    except Exception as e:
        print(f"\n[main_network] LỖI khi xử lý yêu cầu: {e}\n")
        _log_entry(kind, request, f"LỖI: {e}")
        return

    print(f"\n{result_header}")
    print(result)
    print()
    _log_entry(kind, request, str(result))


def _run_read_mode() -> None:
    print(get_available_devices_text())
    print("\nGõ câu hỏi của bạn, hoặc 'back' để quay lại menu.\n")
    while True:
        question = input("Câu hỏi: ").strip()
        if question.lower() in ("back", "exit", "quit", "thoat"):
            break
        if not question:
            continue

        crew = build_crew(question)
        _run_crew_safely(crew, "Hỏi thông tin", question, "=== TRẢ LỜI ===")


def _run_provision_mode() -> None:
    print(get_available_devices_text())
    print(
        "\n⚠️  Chế độ này SẼ GHI cấu hình thật lên thiết bị (writable: true "
        "trong inventory.yaml). Chỉ giới hạn ở tạo VLAN + gán access port."
    )
    print(
        "Mô tả ticket đầy đủ (tên thiết bị, tên cổng, VLAN/phòng ban), hoặc "
        "'back' để quay lại menu.\n"
    )
    while True:
        ticket = input("Ticket: ").strip()
        if ticket.lower() in ("back", "exit", "quit", "thoat"):
            break
        if not ticket:
            continue

        crew = build_provision_crew(ticket)
        _run_crew_safely(crew, "Ticket cấu hình", ticket, "=== KẾT QUẢ ===")


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
    print(f"Mọi tương tác sẽ tự động lưu vào {QA_LOG_PATH}\n")

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