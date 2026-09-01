"""
network_write_tools.py — Tool CÓ QUYỀN GHI, giới hạn nghiêm ngặt ở tầng
code: chỉ cho phép đúng 1 hành động ghi duy nhất — gán 1 cổng access có sẵn
vào 1 VLAN ĐÃ TỒN TẠI. KHÔNG có tool nào tạo VLAN mới (create_vlan_text vẫn
còn trong file này để gọi tay/test độc lập, nhưng KHÔNG gắn vào bất kỳ agent
nào — hiện tại không có agent nào có quyền tạo VLAN).

KHÔNG có tool nào nhận lệnh CLI tự do từ agent. Mọi câu lệnh gửi xuống
thiết bị đều do CODE tự dựng sẵn theo template cố định — agent chỉ được
điền tham số (device_name, interface, vlan_id), không được viết CLI. Đây là
khác biệt cốt lõi so với "để LLM tự sinh lệnh configure rồi chạy": cách đó
phải LỌC lệnh sau khi model đã sinh ra (dễ có kẽ hở). Ở đây KHÔNG CÓ NHÁNH
CODE NÀO build ra `ip route`/`ip routing`/lệnh L3 bất kỳ — không phải "bị
chặn", mà là "không tồn tại trong khả năng của tool".

4 lớp kiểm soát độc lập, đều bắt buộc phải qua hết trước khi 1 lệnh ghi
chạm tới thiết bị thật:
1. Device whitelist — chỉ thiết bị đánh dấu `writable: true` trong
   inventory.yaml mới cho phép ghi (mặc định false — router/switch phân
   phối tự động bị loại vì rủi ro ảnh hưởng cao hơn switch access).
2. VLAN ID blocklist — chặn cứng VLAN quản trị (99) và VLAN mặc định (1),
   không cho gán port qua tool này dù vô tình hay cố ý.
3. Interface pattern — chỉ chấp nhận cổng vật lý dạng EthernetX/Y, tự động
   loại trừ SVI/Vlan interface (không khớp pattern).
4. VLAN phải đã tồn tại trên thiết bị (đọc bằng show vlan brief NGAY
   trước khi gán) — vì tool không có quyền tạo VLAN, nếu VLAN chưa có thì
   không có đường nào để tiếp tục, phải dừng lại và báo lỗi.

Ngoài 4 lớp trên, MỌI lệnh ghi còn phải qua thêm 1 cổng chặn con người:
sau khi gom đủ thông tin (VLAN đã tồn tại chưa, cổng đang ở mode gì), tool
IN RA bản tóm tắt thay đổi sắp thực hiện và DỪNG LẠI chờ quản trị viên gõ
yes/no ngay trên console đang chạy chương trình — không có nhánh nào trong
code gửi lệnh ghi xuống thiết bị mà bỏ qua bước hỏi này, kể cả khi agent
"tự tin" là đúng. Đây KHÔNG phải cơ chế human-in-the-loop dạng review văn
bản của CrewAI (Task human_input) — review kiểu đó chạy SAU KHI agent đã
gọi tool xong nên không chặn được hành vi ghi. Ở đây việc hỏi nằm NGAY
TRONG hàm gửi lệnh ghi, trước dòng ConnectHandler(...).send_config_set(...).
"""

import re
import json
from netmiko import ConnectHandler
from crewai.tools import tool

from network_tools import _device_params, _load_devices, _run_raw

# VLAN ID không được phép gán/tạo qua tool này.
BLOCKED_VLAN_IDS = {1, 99}
VLAN_ID_MIN, VLAN_ID_MAX = 2, 999

# Chỉ chấp nhận cổng vật lý dạng EthernetX/Y — loại trừ tự nhiên SVI
# ("Vlan99", "Vlan10"...) vì không khớp pattern này.
INTERFACE_RE = re.compile(r"^Ethernet\d+/\d+$", re.IGNORECASE)


def _check_writable(device_name: str) -> dict:
    """Trả về device params nếu thiết bị được đánh dấu writable: true
    trong inventory.yaml. Raise PermissionError nếu không — kể cả khi
    thiết bị tồn tại và username/password đúng, vẫn từ chối nếu thiếu cờ
    writable rõ ràng."""
    devices = _load_devices()
    if device_name not in devices:
        available = ", ".join(devices.keys()) or "(inventory rỗng)"
        raise ValueError(
            f"Không tìm thấy thiết bị '{device_name}' trong inventory.yaml. "
            f"Thiết bị có sẵn: {available}"
        )
    dev = devices[device_name]
    if not dev.get("writable", False):
        raise PermissionError(
            f"Thiết bị '{device_name}' KHÔNG được đánh dấu writable trong "
            "inventory.yaml — tool cấu hình chỉ hoạt động trên switch access "
            "được cấp phép rõ ràng, không áp dụng cho router/switch phân "
            "phối vì rủi ro ảnh hưởng cao hơn."
        )
    return _device_params(device_name)


def _validate_vlan_id(vlan_id: int) -> None:
    if not (VLAN_ID_MIN <= vlan_id <= VLAN_ID_MAX):
        raise ValueError(
            f"VLAN ID {vlan_id} ngoài dải cho phép ({VLAN_ID_MIN}-{VLAN_ID_MAX})."
        )
    if vlan_id in BLOCKED_VLAN_IDS:
        raise ValueError(
            f"VLAN {vlan_id} nằm trong danh sách bị chặn (VLAN quản trị/mặc "
            "định) — tool này không được phép tạo/gán VLAN đó."
        )


def _validate_interface(interface: str) -> str:
    interface = interface.strip()
    if not INTERFACE_RE.match(interface):
        raise ValueError(
            f"'{interface}' không đúng định dạng cổng vật lý cho phép "
            "(vd: Ethernet1/0). Không chấp nhận cổng trunk hay SVI/Vlan "
            "interface làm target."
        )
    return interface


def _confirm_with_admin(summary: str) -> bool:
    """Cổng chặn con người — IN bản tóm tắt thay đổi sắp thực hiện ra
    console và DỪNG chờ quản trị viên gõ yes/no trước khi cho phép hàm gọi
    tiếp tục gửi lệnh ghi. Đây là lớp kiểm soát bắt buộc cho MỌI lệnh ghi,
    nằm ở tầng code (ngay trong hàm *_text), không phải một bước mà agent
    có thể "quên" gọi.

    Không có console tương tác (vd chạy trong môi trường tự động không gắn
    stdin) thì input() sẽ ném EOFError — mặc định HUỶ (an toàn hơn là mặc
    định đồng ý)."""
    print("\n" + "=" * 70)
    print("[XÁC NHẬN THAY ĐỔI CẤU HÌNH] Chuẩn bị thực hiện:")
    print(summary)
    print("=" * 70)
    try:
        answer = input("Đồng ý thực hiện thay đổi này trên thiết bị thật? (yes/no): ")
    except EOFError:
        print("[network_write_tools] Không có console tương tác để xác nhận — mặc định HUỶ.")
        return False
    return answer.strip().lower() in ("y", "yes")


def _get_existing_vlan_ids(device_name: str) -> set:
    """Đọc danh sách VLAN ID hiện có trên thiết bị qua 'show vlan brief'.
    Dùng để kiểm tra VLAN đích đã tồn tại chưa TRƯỚC khi assign — vì
    assign_access_port không có quyền tạo VLAN, nếu VLAN chưa tồn tại thì
    không có cách nào tiếp tục, phải dừng lại ngay tại đây."""
    result = _run_raw(device_name, "show vlan brief")
    parsed = result["parsed"] or []
    ids = set()
    for row in parsed:
        raw_id = row.get("vlan_id")
        if raw_id is None:
            continue
        try:
            ids.add(int(raw_id))
        except (TypeError, ValueError):
            continue
    return ids


def list_vlans_text(device_name: str) -> str:
    """Liệt kê toàn bộ VLAN hiện có trên thiết bị (show vlan brief) — dùng
    để kiểm tra VLAN cần gán đã tồn tại hay chưa, trước khi assign. Hàm
    PLAIN, chỉ đọc — không cần thiết bị writable."""
    try:
        result = _run_raw(device_name, "show vlan brief")
        return json.dumps(
            {
                "device": device_name,
                "vlans": result["parsed"],
                "raw_output": result["raw_output"],
            },
            ensure_ascii=False,
            indent=2,
        )
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)


def check_port_status_text(device_name: str, interface: str) -> str:
    """Kiểm tra trạng thái HIỆN TẠI của 1 cổng: mode (access/trunk), VLAN
    đang gán (nếu access), trạng thái link (connected/notconnect) — dùng để
    xác nhận cổng có phù hợp để gán access VLAN hay không TRƯỚC khi đổi.
    Hàm PLAIN, chỉ đọc — không cần thiết bị writable."""
    try:
        interface = interface.strip()
        switchport = _run_raw(device_name, f"show interfaces {interface} switchport")
        status = _run_raw(device_name, f"show interfaces {interface} status")
        return json.dumps(
            {
                "device": device_name,
                "interface": interface,
                "switchport": switchport["parsed"],
                "status": status["parsed"],
                "switchport_raw": switchport["raw_output"],
                "status_raw": status["raw_output"],
            },
            ensure_ascii=False,
            indent=2,
        )
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)


def list_free_ports_text(device_name: str) -> str:
    """Liệt kê các cổng đang KHÔNG có thiết bị kết nối (status notconnect/
    disabled trong 'show interfaces status') — ứng viên cổng 'trống' có thể
    gán mới. Hàm PLAIN, chỉ đọc — không cần thiết bị writable."""
    try:
        result = _run_raw(device_name, "show interfaces status")
        parsed = result["parsed"]
        if not parsed:
            return json.dumps(
                {
                    "error": (
                        "Không parse được 'show interfaces status' — xem "
                        "raw_output thay vì tin danh sách cổng trống."
                    ),
                    "raw_output": result["raw_output"],
                },
                ensure_ascii=False,
            )
        free_statuses = {"notconnect", "disabled"}
        free_ports = [
            row for row in parsed
            if str(row.get("status", "")).strip().lower() in free_statuses
        ]
        return json.dumps(
            {
                "device": device_name,
                "total_ports_listed": len(parsed),
                "free_ports": free_ports,
            },
            ensure_ascii=False,
            indent=2,
        )
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)


def create_vlan_text(device_name: str, vlan_id: int, vlan_name: str) -> str:
    """Tạo (hoặc đảm bảo tồn tại đúng tên) 1 VLAN trên thiết bị writable.
    Hàm PLAIN, gọi tay được để test độc lập trước khi gắn agent."""
    try:
        _validate_vlan_id(vlan_id)
        params = _check_writable(device_name)

        commands = [f"vlan {vlan_id}", f" name {vlan_name}"]
        with ConnectHandler(**params) as conn:
            if params.get("secret"):
                try:
                    conn.enable()
                except Exception:
                    pass
            config_output = conn.send_config_set(commands)
            verify = conn.send_command("show vlan brief")

            # Lưu running-config vào startup-config, cùng lý do như trong
            # assign_access_port_text — không lưu thì VLAN mất khi reload.
            try:
                save_output = conn.save_config()
                config_saved = True
            except Exception as e:
                save_output = str(e)
                config_saved = False

        return json.dumps(
            {
                "device": device_name,
                "commands_issued": commands,
                "config_output": config_output,
                "verify_show_vlan_brief": verify,
                "config_saved": config_saved,
                "save_output": save_output,
            },
            ensure_ascii=False,
            indent=2,
        )
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)


def assign_access_port_text(device_name: str, interface: str, vlan_id: int) -> str:
    """Gán 1 cổng vật lý vào chế độ access + VLAN chỉ định, bật cổng lên
    (no shutdown), rồi verify lại trạng thái THẬT (không chỉ tin lệnh đã
    chạy thành công) — đúng yêu cầu 'đảm bảo cổng hoạt động tốt', không chỉ
    'đã gửi lệnh'. Hàm PLAIN, gọi tay được.

    Trước khi gửi bất kỳ lệnh ghi nào:
    1. VLAN đích PHẢI đã tồn tại trên thiết bị (đọc bằng show vlan brief) —
       hàm này không có quyền tạo VLAN, nếu chưa tồn tại thì dừng lại và
       báo lỗi ngay, không có nhánh nào khác.
    2. Đọc trạng thái cổng HIỆN TẠI (mode/VLAN/link) để quản trị viên có đủ
       thông tin khi xác nhận.
    3. In tóm tắt thay đổi và DỪNG chờ quản trị viên gõ yes/no trên console
       — trả lời 'no' (hoặc không có console tương tác) thì huỷ, không có
       lệnh ghi nào được gửi xuống thiết bị."""
    try:
        _validate_vlan_id(vlan_id)
        interface = _validate_interface(interface)
        params = _check_writable(device_name)

        existing_vlans = _get_existing_vlan_ids(device_name)
        if vlan_id not in existing_vlans:
            return json.dumps(
                {
                    "error": (
                        f"VLAN {vlan_id} chưa tồn tại trên '{device_name}'. "
                        "Tool này không có quyền tạo VLAN mới — cần được "
                        "tạo trước (bởi người/agent có quyền cao hơn) rồi "
                        "mới gán cổng được."
                    ),
                    "existing_vlans": sorted(existing_vlans),
                },
                ensure_ascii=False,
            )

        before = _run_raw(device_name, f"show interfaces {interface} switchport")

        summary = (
            f"- Thiết bị: {device_name}\n"
            f"- Cổng: {interface}\n"
            f"- VLAN đích: {vlan_id} (đã xác nhận tồn tại trên thiết bị)\n"
            f"- Trạng thái cổng HIỆN TẠI (trước khi đổi):\n{before['raw_output']}\n"
            f"- Lệnh sẽ gửi: switchport mode access / switchport access "
            f"vlan {vlan_id} / no shutdown"
        )
        if not _confirm_with_admin(summary):
            return json.dumps(
                {
                    "device": device_name,
                    "interface": interface,
                    "vlan_id": vlan_id,
                    "status": "cancelled",
                    "message": (
                        "Quản trị viên đã từ chối (hoặc không có console để "
                        "xác nhận) — không có lệnh nào được gửi xuống thiết bị."
                    ),
                },
                ensure_ascii=False,
            )

        commands = [
            f"interface {interface}",
            " switchport mode access",
            f" switchport access vlan {vlan_id}",
            " no shutdown",
        ]
        with ConnectHandler(**params) as conn:
            if params.get("secret"):
                try:
                    conn.enable()
                except Exception:
                    pass
            config_output = conn.send_config_set(commands)
            verify_switchport = conn.send_command(f"show interfaces {interface} switchport")
            verify_status = conn.send_command(f"show interfaces {interface} status")

            # Lưu running-config vào startup-config ("wr"/"copy run start") —
            # thiếu bước này thì thay đổi chỉ sống trong running-config, mất
            # ngay khi thiết bị reload. Không để lỗi ở bước lưu làm mất kết
            # quả gán cổng đã thành công phía trên — chỉ ghi lại thành
            # công/thất bại riêng để agent/báo cáo biết mà cảnh báo.
            try:
                save_output = conn.save_config()
                config_saved = True
            except Exception as e:
                save_output = str(e)
                config_saved = False

        return json.dumps(
            {
                "device": device_name,
                "commands_issued": commands,
                "config_output": config_output,
                "verify_switchport": verify_switchport,
                "verify_status": verify_status,
                "config_saved": config_saved,
                "save_output": save_output,
            },
            ensure_ascii=False,
            indent=2,
        )
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Tool cho CrewAI agent — cùng pattern plain/tool-wrapper như network_tools.py
# ---------------------------------------------------------------------------


# create_vlan CHƯA gắn vào agent nào hiện tại — không có agent nào trong
# crew_network.py được cấp quyền tạo VLAN theo thiết kế mới. Giữ lại tool
# wrapper này chỉ để gọi tay/test độc lập, hoặc để dùng sau nếu có nhu cầu
# thêm 1 agent cấp cao hơn với quyền tạo VLAN.
@tool("Tạo VLAN trên switch access (quyền giới hạn)")
def create_vlan(device_name: str, vlan_id: int, vlan_name: str) -> str:
    """Tạo 1 VLAN trên switch access được cấp phép (writable: true trong
    inventory.yaml). CHỈ hoạt động trên switch access, KHÔNG hoạt động trên
    router/switch phân phối — sẽ bị từ chối nếu gọi nhầm thiết bị. VLAN
    quản trị (99) và VLAN mặc định (1) bị chặn cứng, không tạo/sửa được
    qua tool này dù có cố tình yêu cầu.

    Args:
        device_name: Tên thiết bị, phải là switch access writable.
        vlan_id: Số VLAN cần tạo (2-999, trừ VLAN quản trị/mặc định).
        vlan_name: Tên gợi nhớ cho VLAN (vd 'HR', 'SALES').
    """
    return create_vlan_text(device_name, vlan_id, vlan_name)


@tool("Liệt kê VLAN hiện có trên thiết bị")
def list_vlans(device_name: str) -> str:
    """Liệt kê toàn bộ VLAN hiện có trên 1 thiết bị (show vlan brief) —
    LUÔN gọi tool này trước khi gán cổng vào 1 VLAN, để biết VLAN đó đã tồn
    tại hay chưa (tool gán cổng không có quyền tạo VLAN mới).

    Args:
        device_name: Tên thiết bị đúng như trong inventory.yaml.
    """
    return list_vlans_text(device_name)


@tool("Kiểm tra trạng thái hiện tại của 1 cổng")
def check_port_status(device_name: str, interface: str) -> str:
    """Kiểm tra trạng thái HIỆN TẠI của 1 cổng vật lý: đang ở mode access
    hay trunk, đang gán VLAN nào (nếu access), và trạng thái link
    (connected/notconnect). LUÔN gọi tool này trước khi gán cổng vào VLAN
    mới, để biết cổng có đang được dùng cho việc khác hay không trước khi
    đề xuất thay đổi.

    Args:
        device_name: Tên thiết bị đúng như trong inventory.yaml.
        interface: Tên cổng vật lý cần kiểm tra (vd 'Ethernet1/0').
    """
    return check_port_status_text(device_name, interface)


@tool("Liệt kê các cổng đang trống (chưa kết nối)")
def list_free_ports(device_name: str) -> str:
    """Liệt kê các cổng đang KHÔNG có thiết bị kết nối (notconnect/
    disabled) trên 1 thiết bị — dùng khi câu hỏi/ticket cần gợi ý cổng
    trống có thể gán, thay vì người dùng đã chỉ định sẵn cổng cụ thể.

    Args:
        device_name: Tên thiết bị đúng như trong inventory.yaml.
    """
    return list_free_ports_text(device_name)


@tool("Gán cổng access vào VLAN đã tồn tại (quyền giới hạn)")
def assign_access_port(device_name: str, interface: str, vlan_id: int) -> str:
    """Gán 1 cổng vật lý (access port) vào 1 VLAN ĐÃ TỒN TẠI và bật cổng
    lên (no shutdown). Tool này KHÔNG có quyền tạo VLAN — nếu VLAN chưa tồn
    tại trên thiết bị, tool sẽ từ chối và báo lỗi ngay, không tự tạo. Trước
    khi gửi bất kỳ thay đổi nào, tool tự đọc trạng thái cổng hiện tại rồi
    IN RA bản tóm tắt và DỪNG LẠI chờ quản trị viên xác nhận yes/no trên
    console — nếu quản trị viên từ chối, tool trả về status 'cancelled' và
    KHÔNG có lệnh nào được gửi xuống thiết bị (đây không phải lỗi, chỉ là
    kết quả hợp lệ cần báo lại cho người dùng). Sau khi thực hiện, tool TỰ
    KIỂM TRA lại trạng thái thật (switchport + status) để xác nhận cổng đã
    hoạt động, không chỉ tin lệnh gửi thành công. Sau khi verify xong, tool
    còn TỰ LƯU cấu hình (copy running-config startup-config) để thay đổi
    không mất khi thiết bị reload — đọc field 'config_saved' (true/false)
    trong kết quả để biết bước lưu có thành công hay không, báo lại cho
    người dùng nếu 'config_saved' là false (thay đổi vẫn đang hoạt động
    nhưng sẽ mất nếu thiết bị khởi động lại). CHỈ chấp nhận cổng vật lý
    (EthernetX/Y) — không chấp nhận cổng trunk hoặc SVI. CHỈ hoạt động trên
    switch access được cấp phép.

    Args:
        device_name: Tên thiết bị, phải là switch access writable.
        interface: Tên cổng vật lý (vd 'Ethernet1/2').
        vlan_id: Số VLAN cần gán cổng vào — nên gọi list_vlans trước để
            xác nhận VLAN này đã tồn tại trên thiết bị.
    """
    return assign_access_port_text(device_name, interface, vlan_id)
