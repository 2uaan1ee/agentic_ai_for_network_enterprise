"""
network_write_tools.py — Tool CÓ QUYỀN GHI, giới hạn nghiêm ngặt ở tầng
code: chỉ cho phép đúng 2 hành động ghi trên 1 cổng vật lý, và VLAN đích
luôn phải ĐÃ TỒN TẠI:
  - access: gán cổng vào 1 VLAN (switchport mode access + access vlan X).
  - tag   : cho VLAN đi qua cổng dạng tagged. Trunk trong lab được để allowed
            vlan ALL, nên nếu cổng đã là trunk thì VLAN đã được tag sẵn (không
            làm gì cả). Nếu cổng đang là access thì chuyển nó sang trunk.
            Tool KHÔNG BAO GIỜ sửa "switchport trunk allowed vlan".
KHÔNG có tool nào tạo VLAN mới (create_vlan_text vẫn
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
5. Đọc và PHÂN LOẠI trạng thái cổng hiện tại trong code (không để agent
   tự đánh giá): đã đúng cấu hình thì không gửi lệnh gì; cổng trống thì
   hỏi yes/no bình thường; đang thuộc VLAN khác / đang có thiết bị kết nối
   thì in CẢNH BÁO riêng rồi mới hỏi; đổi mode access <-> trunk thì bắt
   gõ lại tên cổng thay vì chỉ "yes".

Ngoài 5 lớp trên, MỌI lệnh ghi còn phải qua thêm 1 cổng chặn con người:
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

from network_tools import _device_params, _extract_status_rows, _load_devices, _run_raw

# VLAN ID không được phép gán/tạo qua tool này.
BLOCKED_VLAN_IDS = {1, 99}
VLAN_ID_MIN, VLAN_ID_MAX = 2, 999

# Chỉ chấp nhận cổng vật lý dạng EthernetX/Y — loại trừ tự nhiên SVI
# ("Vlan99", "Vlan10"...) vì không khớp pattern này.
INTERFACE_RE = re.compile(r"^Ethernet\d+/\d+$", re.IGNORECASE)

# Tên viết tắt người dùng hay gõ: e1/0, et1/0, eth1/0, ether1/0, Ethernet1/0.
_INTERFACE_SHORT_RE = re.compile(r"^(?:e|et|eth|ether|ethernet)\s*(\d+/\d+)$", re.IGNORECASE)

# Cổng coi là "chưa dùng" nếu access VLAN là 1 (mặc định) hoặc không đọc được.
_UNUSED_ACCESS_VLANS = {None, 1}


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


def _normalize_interface(interface: str) -> str:
    """Đổi tên viết tắt (e1/0, eth1/0, Et1/0...) thành dạng đầy đủ
    Ethernet1/0. Tên không nhận ra thì trả nguyên văn để bước validate
    báo lỗi."""
    interface = interface.strip()
    m = _INTERFACE_SHORT_RE.match(interface)
    if m:
        return f"Ethernet{m.group(1)}"
    return interface


def _validate_interface(interface: str) -> str:
    interface = _normalize_interface(interface)
    if not INTERFACE_RE.match(interface):
        raise ValueError(
            f"'{interface}' không đúng định dạng cổng vật lý cho phép "
            "(vd: Ethernet1/0 hoặc e1/0). Không chấp nhận SVI/Vlan "
            "interface hay loại cổng khác làm target."
        )
    return interface


def _confirm_with_admin(summary: str, warnings: list = None, require_token: str = "") -> bool:
    """Cổng chặn con người — IN bản tóm tắt thay đổi sắp thực hiện ra
    console và DỪNG chờ quản trị viên xác nhận trước khi cho phép hàm gọi
    tiếp tục gửi lệnh ghi. Đây là lớp kiểm soát bắt buộc cho MỌI lệnh ghi,
    nằm ở tầng code (ngay trong hàm *_text), không phải một bước mà agent
    có thể "quên" gọi.

    warnings: các cảnh báo riêng (cổng đang thuộc VLAN khác, đang có thiết
    bị kết nối...) in nổi bật trước câu hỏi.
    require_token: nếu có (thay đổi rủi ro cao như đổi mode access <->
    trunk), quản trị viên phải gõ lại CHÍNH XÁC chuỗi này thay vì chỉ "yes",
    để tránh gõ "y" theo quán tính.

    Không có console tương tác (vd chạy trong môi trường tự động không gắn
    stdin) thì input() sẽ ném EOFError — mặc định HUỶ (an toàn hơn là mặc
    định đồng ý)."""
    print("\n" + "=" * 70)
    print("[XÁC NHẬN THAY ĐỔI CẤU HÌNH] Chuẩn bị thực hiện:")
    print(summary)
    if warnings:
        print("\n!!! CẢNH BÁO:")
        for w in warnings:
            print(f"  - {w}")
    print("=" * 70)
    try:
        if require_token:
            answer = input(
                f"Thay đổi RỦI RO CAO — gõ lại chính xác '{require_token}' để "
                "xác nhận (gõ bất kỳ thứ gì khác = huỷ): "
            )
            return answer.strip() == require_token
        question = (
            "Cổng này đang được sử dụng — bạn có muốn THAY ĐỔI không? (yes/no): "
            if warnings
            else "Đồng ý thực hiện thay đổi này trên thiết bị thật? (yes/no): "
        )
        answer = input(question)
    except EOFError:
        print("[network_write_tools] Không có console tương tác để xác nhận — mặc định HUỶ.")
        return False
    return answer.strip().lower() in ("y", "yes")


def _vlan_in_list(vlan_id: int, vlan_spec: str) -> bool:
    """Kiểm tra vlan_id có nằm trong chuỗi danh sách VLAN kiểu IOS không
    (vd 'ALL', 'NONE', '1-10,30,40-50')."""
    if not vlan_spec:
        return False
    spec = vlan_spec.strip().upper()
    if spec == "ALL":
        return True
    if spec == "NONE":
        return False
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        try:
            if "-" in part:
                lo, hi = part.split("-", 1)
                if int(lo) <= vlan_id <= int(hi):
                    return True
            elif int(part) == vlan_id:
                return True
        except ValueError:
            continue
    return False


def _parse_switchport(raw: str) -> dict:
    """Parse 'show interfaces X switchport' từ raw text. Tự parse bằng regex
    thay vì dùng ntc-templates vì tên field của template đổi theo version,
    còn nhãn trong output IOS thì ổn định."""

    def field(label: str):
        m = re.search(rf"^\s*{label}:\s*(.*?)\s*$", raw, re.IGNORECASE | re.MULTILINE)
        return m.group(1) if m else None

    switchport = field("Switchport")
    admin_mode = (field("Administrative Mode") or "").lower() or None
    oper_mode = (field("Operational Mode") or "").lower() or None

    access_vlan = None
    access_raw = field("Access Mode VLAN")
    if access_raw:
        m = re.match(r"(\d+)", access_raw)
        if m:
            access_vlan = int(m.group(1))

    # "Trunking VLANs Enabled" có thể xuống dòng khi danh sách dài — gom
    # thêm các dòng tiếp theo chỉ chứa số/dấu phẩy/gạch ngang.
    trunk_vlans = None
    m = re.search(r"^\s*Trunking VLANs Enabled:\s*(.*?)\s*$", raw, re.IGNORECASE | re.MULTILINE)
    if m:
        parts = [m.group(1)]
        for line in raw[m.end():].splitlines()[1:]:
            if re.match(r"^\s*[\d,\-]+\s*$", line):
                parts.append(line.strip())
            else:
                break
        trunk_vlans = "".join(parts)

    is_trunk = "trunk" in (admin_mode or "") or "trunk" in (oper_mode or "")
    return {
        "switchport_enabled": None if switchport is None else switchport.lower().startswith("enabled"),
        "admin_mode": admin_mode,
        "oper_mode": oper_mode,
        "access_vlan": access_vlan,
        "trunk_vlans": trunk_vlans,
        "is_trunk": is_trunk,
    }


def _parse_link_status(status_result: dict) -> str:
    """Lấy trạng thái link (connected/notconnect/disabled/err-disabled) từ
    'show interfaces X status'. Ưu tiên dữ liệu parsed, fallback regex."""
    if status_result.get("parsed"):
        rows = _extract_status_rows(status_result["parsed"])
        if rows and rows[0]["status"]:
            return rows[0]["status"]
    m = re.search(r"\b(err-disabled|notconnect|connected|disabled)\b", status_result.get("raw_output") or "")
    return m.group(1).lower() if m else "unknown"


def _inspect_port(device_name: str, interface: str) -> dict:
    """Đọc trạng thái HIỆN TẠI của cổng (mode, VLAN, link) và kết luận cổng
    có đang được sử dụng hay không. Đây là phần kiểm tra "cổng có trống
    không / có đang thuộc VLAN khác không" — làm trong code để kết luận
    không phụ thuộc vào việc agent đọc raw output đúng hay sai."""
    switchport = _run_raw(device_name, f"show interfaces {interface} switchport")
    status = _run_raw(device_name, f"show interfaces {interface} status")
    info = _parse_switchport(switchport["raw_output"])
    info["link_status"] = _parse_link_status(status)

    in_use_reasons = []
    if info["is_trunk"]:
        in_use_reasons.append(f"đang là TRUNK (VLAN cho phép: {info['trunk_vlans'] or '?'})")
    elif info["access_vlan"] not in _UNUSED_ACCESS_VLANS:
        in_use_reasons.append(f"đang được gán access VLAN {info['access_vlan']}")
    if info["link_status"] == "connected":
        in_use_reasons.append("đang có thiết bị kết nối (connected)")
    info["in_use"] = bool(in_use_reasons)
    info["in_use_reasons"] = in_use_reasons

    info["interface"] = interface
    info["switchport_raw"] = switchport["raw_output"]
    info["status_raw"] = status["raw_output"]
    return info


def _port_summary_line(port: dict) -> str:
    mode = port["oper_mode"] or port["admin_mode"] or "?"
    vlan = (
        f"trunk VLAN {port['trunk_vlans'] or '?'}"
        if port["is_trunk"]
        else f"access VLAN {port['access_vlan'] if port['access_vlan'] is not None else '?'}"
    )
    state = "ĐANG SỬ DỤNG" if port["in_use"] else "TRỐNG"
    return f"mode={mode}, {vlan}, link={port['link_status']} -> {state}"


def _require_existing_vlan(device_name: str, vlan_id: int):
    """Trả về chuỗi JSON lỗi nếu VLAN chưa tồn tại, None nếu đã tồn tại."""
    existing_vlans = _get_existing_vlan_ids(device_name)
    if vlan_id in existing_vlans:
        return None
    return json.dumps(
        {
            "status": "error",
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


def _port_result(device_name: str, interface: str, vlan_id: int, mode: str,
                 status: str, message: str, port: dict) -> str:
    """JSON kết quả cho các trường hợp KHÔNG gửi lệnh ghi (đã đúng cấu
    hình / bị chặn / quản trị viên huỷ)."""
    return json.dumps(
        {
            "device": device_name,
            "interface": interface,
            "vlan_id": vlan_id,
            "requested_mode": mode,
            "status": status,
            "message": message,
            "port_before": _public_port_info(port),
        },
        ensure_ascii=False,
        indent=2,
    )


def _public_port_info(port: dict) -> dict:
    # Bỏ status_raw cho gọn — link_status đã parse sẵn, còn switchport_raw
    # vẫn giữ để báo cáo trích dẫn đối chiếu.
    return {k: v for k, v in port.items() if k != "status_raw"}


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
        interface = _validate_interface(interface)
        port = _inspect_port(device_name, interface)
        return json.dumps(
            {"device": device_name, "summary": _port_summary_line(port), **port},
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


def _apply_port_change(params: dict, device_name: str, interface: str,
                       vlan_id: int, mode: str, port: dict, commands: list,
                       warnings: list, require_token: str = "") -> str:
    """Bước chung cho mọi lệnh ghi lên cổng: in tóm tắt + cảnh báo, chờ
    quản trị viên xác nhận, gửi lệnh, verify lại trạng thái THẬT bằng cách
    parse output sau khi đổi, rồi lưu cấu hình."""
    summary = (
        f"- Thiết bị: {device_name}\n"
        f"- Cổng: {interface}\n"
        f"- Yêu cầu: {mode.upper()} VLAN {vlan_id} (VLAN đã xác nhận tồn tại trên thiết bị)\n"
        f"- Trạng thái cổng HIỆN TẠI: {_port_summary_line(port)}\n"
        f"{port['switchport_raw']}\n"
        f"- Lệnh sẽ gửi: {' / '.join(c.strip() for c in commands)}"
    )
    if not _confirm_with_admin(summary, warnings, require_token):
        return _port_result(
            device_name, interface, vlan_id, mode, "cancelled",
            "Quản trị viên đã từ chối (hoặc không có console để xác nhận) — "
            "không có lệnh nào được gửi xuống thiết bị.",
            port,
        )

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

    after = _parse_switchport(verify_switchport)
    after["link_status"] = _parse_link_status({"raw_output": verify_status})
    if mode == "access":
        verified = (not after["is_trunk"]) and after["access_vlan"] == vlan_id
    else:
        verified = after["is_trunk"] and _vlan_in_list(vlan_id, after["trunk_vlans"])

    return json.dumps(
        {
            "device": device_name,
            "interface": interface,
            "vlan_id": vlan_id,
            "requested_mode": mode,
            "status": "applied" if verified else "applied_but_not_verified",
            "warnings_acknowledged": warnings,
            "port_before": _public_port_info(port),
            "port_after": after,
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


def assign_access_port_text(device_name: str, interface: str, vlan_id: int) -> str:
    """Gán 1 cổng vật lý vào chế độ access + VLAN chỉ định, bật cổng lên
    (no shutdown), rồi verify lại trạng thái THẬT. Hàm PLAIN, gọi tay được.

    Thứ tự kiểm tra trước khi gửi bất kỳ lệnh ghi nào:
    1. VLAN đích PHẢI đã tồn tại (show vlan brief) — không có thì dừng.
    2. Đọc + phân loại trạng thái cổng hiện tại:
       - Không phải switchport (cổng routed) -> chặn.
       - Đã là access VLAN đích và không bị shutdown -> 'already_configured',
         không gửi lệnh gì.
       - Đang là trunk -> cảnh báo + bắt gõ lại tên cổng.
       - Đang thuộc VLAN khác / đang có thiết bị kết nối -> cảnh báo + hỏi
         có muốn thay đổi không.
       - Trống -> hỏi yes/no bình thường.
    3. Quản trị viên từ chối (hoặc không có console) -> 'cancelled'."""
    try:
        _validate_vlan_id(vlan_id)
        interface = _validate_interface(interface)
        params = _check_writable(device_name)

        vlan_error = _require_existing_vlan(device_name, vlan_id)
        if vlan_error:
            return vlan_error

        port = _inspect_port(device_name, interface)
        if port["switchport_enabled"] is False:
            return _port_result(
                device_name, interface, vlan_id, "access", "blocked",
                f"{interface} không phải switchport (cổng routed/L3) — tool "
                "không đổi cổng L3 thành L2.",
                port,
            )

        if (
            not port["is_trunk"]
            and port["admin_mode"] == "static access"
            and port["access_vlan"] == vlan_id
            and port["link_status"] != "disabled"
        ):
            return _port_result(
                device_name, interface, vlan_id, "access", "already_configured",
                f"{interface} đã là access VLAN {vlan_id} từ trước — không cần "
                "thay đổi, không có lệnh nào được gửi.",
                port,
            )

        warnings = []
        require_token = ""
        if port["is_trunk"]:
            warnings.append(
                f"{interface} đang là TRUNK (VLAN cho phép: {port['trunk_vlans'] or '?'}). "
                "Đổi sang access sẽ CẮT toàn bộ VLAN khác đang đi qua cổng này "
                "— nếu đây là uplink thì switch có thể mất kết nối."
            )
            require_token = interface
        elif port["access_vlan"] not in _UNUSED_ACCESS_VLANS and port["access_vlan"] != vlan_id:
            warnings.append(
                f"{interface} đang được gán access VLAN {port['access_vlan']} — "
                f"sẽ bị ĐỔI sang VLAN {vlan_id}."
            )
        if port["link_status"] == "connected":
            warnings.append(
                f"{interface} đang có thiết bị kết nối (connected) — thiết bị "
                "đó sẽ chuyển sang VLAN mới và mất kết nối mạng hiện tại."
            )
        elif port["link_status"] == "err-disabled":
            warnings.append(
                f"{interface} đang ở trạng thái err-disabled — 'no shutdown' "
                "có thể không đủ để cổng lên lại, cần kiểm tra nguyên nhân."
            )

        commands = [
            f"interface {interface}",
            " switchport mode access",
            f" switchport access vlan {vlan_id}",
            " no shutdown",
        ]
        return _apply_port_change(
            params, device_name, interface, vlan_id, "access", port,
            commands, warnings, require_token,
        )
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, ensure_ascii=False)


def tag_vlan_on_port_text(device_name: str, interface: str, vlan_id: int) -> str:
    """Cho VLAN đi qua cổng dạng tagged (802.1Q). Hàm PLAIN, gọi tay được.

    Trunk trong hệ thống được cấu hình allowed vlan ALL, nên tool KHÔNG BAO
    GIỜ đụng tới 'switchport trunk allowed vlan':
    - Cổng đã là trunk và cho phép VLAN đích -> 'already_configured', không
      gửi lệnh gì.
    - Cổng đã là trunk nhưng allowed list bị giới hạn, không có VLAN đích ->
      chặn, báo lại để người quản trị tự xử lý.
    - Cổng đang access/dynamic -> chuyển sang trunk (allowed mặc định ALL),
      luôn bắt gõ lại tên cổng vì đây là thay đổi mode."""
    try:
        _validate_vlan_id(vlan_id)
        interface = _validate_interface(interface)
        params = _check_writable(device_name)

        vlan_error = _require_existing_vlan(device_name, vlan_id)
        if vlan_error:
            return vlan_error

        port = _inspect_port(device_name, interface)
        if port["switchport_enabled"] is False:
            return _port_result(
                device_name, interface, vlan_id, "tag", "blocked",
                f"{interface} không phải switchport (cổng routed/L3) — tool "
                "không đổi cổng L3 thành L2.",
                port,
            )

        if port["is_trunk"]:
            if _vlan_in_list(vlan_id, port["trunk_vlans"]):
                return _port_result(
                    device_name, interface, vlan_id, "tag", "already_configured",
                    f"{interface} đã là trunk và cho phép VLAN {vlan_id} "
                    f"(allowed: {port['trunk_vlans']}) — VLAN {vlan_id} đã được "
                    "tag trên cổng này, không cần thay đổi.",
                    port,
                )
            return _port_result(
                device_name, interface, vlan_id, "tag", "blocked",
                f"{interface} là trunk nhưng allowed vlan đang bị giới hạn "
                f"({port['trunk_vlans'] or '?'}) và không có VLAN {vlan_id}. "
                "Tool không sửa allowed vlan list — cần quản trị viên tự kiểm "
                "tra vì sao trunk này không để ALL.",
                port,
            )

        warnings = [
            f"{interface} sẽ được CHUYỂN từ {port['admin_mode'] or 'access'} sang "
            "TRUNK (cho phép tất cả VLAN). Thiết bị đầu cuối thường (PC, máy in) "
            "cắm vào cổng trunk sẽ không còn chạy đúng."
        ]
        if port["access_vlan"] not in _UNUSED_ACCESS_VLANS:
            warnings.append(
                f"{interface} đang được gán access VLAN {port['access_vlan']} — "
                "cấu hình access đó sẽ không còn hiệu lực khi cổng là trunk."
            )
        if port["link_status"] == "connected":
            warnings.append(
                f"{interface} đang có thiết bị kết nối (connected) — kết nối "
                "hiện tại sẽ bị gián đoạn."
            )

        # 'switchport trunk encapsulation dot1q' bắt buộc trên IOL/switch hỗ
        # trợ cả ISL; trên switch chỉ có dot1q thì IOS báo '% Invalid input'
        # cho dòng này và bỏ qua, không ảnh hưởng các lệnh sau.
        commands = [
            f"interface {interface}",
            " switchport trunk encapsulation dot1q",
            " switchport mode trunk",
            " no shutdown",
        ]
        return _apply_port_change(
            params, device_name, interface, vlan_id, "tag", port,
            commands, warnings, require_token=interface,
        )
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, ensure_ascii=False)


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
    """Kiểm tra trạng thái HIỆN TẠI của 1 cổng vật lý (chỉ đọc): mode
    access/trunk, access VLAN, VLAN cho phép trên trunk, trạng thái link
    (connected/notconnect/disabled), và kết luận 'in_use' (cổng có đang được
    sử dụng không, kèm lý do). Chấp nhận tên viết tắt như 'e1/0'. Dùng khi
    người dùng chỉ HỎI về cổng. Khi cần GÁN/TAG VLAN thì không bắt buộc gọi
    tool này trước — tool ghi đã tự kiểm tra lại toàn bộ.

    Args:
        device_name: Tên thiết bị đúng như trong inventory.yaml.
        interface: Tên cổng vật lý cần kiểm tra (vd 'Ethernet1/0' hoặc 'e1/0').
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


@tool("Gán cổng vào VLAN dạng access (quyền giới hạn)")
def assign_access_port(device_name: str, interface: str, vlan_id: int) -> str:
    """Gán 1 cổng vật lý vào 1 VLAN ĐÃ TỒN TẠI ở chế độ ACCESS (untagged)
    và bật cổng lên. Dùng khi người dùng nói 'access', 'gán', 'cho cổng vào
    VLAN' mà không nói 'tag'/'trunk'.
    Tool TỰ làm toàn bộ bước kiểm tra trong code, theo thứ tự: VLAN đích đã
    tồn tại chưa (chưa có thì dừng, tool không có quyền tạo VLAN) -> cổng
    hiện đang ở trạng thái nào (trống / đang thuộc VLAN khác / đang có thiết
    bị kết nối / đang là trunk) -> in tóm tắt + cảnh báo và DỪNG chờ quản trị
    viên xác nhận trên console. Agent KHÔNG tự từ chối vì cổng đang được sử
    dụng — việc quyết định có thay đổi hay không là của quản trị viên, tool
    sẽ hỏi họ. Đọc field 'status' trong kết quả:
      - 'applied': đã đổi và verify trạng thái thật khớp yêu cầu.
      - 'applied_but_not_verified': đã gửi lệnh nhưng trạng thái sau khi đổi
        không khớp — phải báo rõ cho người dùng, kèm verify_switchport.
      - 'already_configured': cổng đã đúng cấu hình từ trước, không gửi gì.
      - 'cancelled': quản trị viên từ chối — kết quả hợp lệ, không phải lỗi.
      - 'blocked' / 'error': không thực hiện được, đọc 'message'/'error'.
    Khi đã ghi, tool tự lưu cấu hình (copy run start) — nếu 'config_saved'
    là false thì phải cảnh báo thay đổi sẽ mất khi thiết bị reload. CHỈ chấp
    nhận cổng vật lý EthernetX/Y (tên viết tắt như 'e1/0' tự được chuẩn
    hoá), CHỈ hoạt động trên switch access được cấp phép (writable).

    Args:
        device_name: Tên thiết bị, phải là switch access writable.
        interface: Tên cổng vật lý (vd 'Ethernet1/0' hoặc 'e1/0').
        vlan_id: Số VLAN cần gán.
    """
    return assign_access_port_text(device_name, interface, vlan_id)


@tool("Tag VLAN lên cổng dạng trunk (quyền giới hạn)")
def tag_vlan_on_port(device_name: str, interface: str, vlan_id: int) -> str:
    """Cho 1 VLAN ĐÃ TỒN TẠI đi qua cổng dạng TAGGED (802.1Q trunk). Dùng
    khi người dùng nói 'tag', 'tagged' hoặc 'trunk'. Trunk được để allowed
    vlan ALL, nên nếu cổng đã là trunk thì tool trả 'already_configured';
    nếu cổng đang là access thì tool chuyển cổng sang trunk (quản trị viên
    phải gõ lại tên cổng để xác nhận). Tool không bao giờ sửa allowed vlan.
    Tool TỰ làm toàn bộ bước kiểm tra trong code, theo thứ tự: VLAN đích đã
    tồn tại chưa (chưa có thì dừng, tool không có quyền tạo VLAN) -> cổng
    hiện đang ở trạng thái nào (trống / đang thuộc VLAN khác / đang có thiết
    bị kết nối / đang là trunk) -> in tóm tắt + cảnh báo và DỪNG chờ quản trị
    viên xác nhận trên console. Agent KHÔNG tự từ chối vì cổng đang được sử
    dụng — việc quyết định có thay đổi hay không là của quản trị viên, tool
    sẽ hỏi họ. Đọc field 'status' trong kết quả:
      - 'applied': đã đổi và verify trạng thái thật khớp yêu cầu.
      - 'applied_but_not_verified': đã gửi lệnh nhưng trạng thái sau khi đổi
        không khớp — phải báo rõ cho người dùng, kèm verify_switchport.
      - 'already_configured': cổng đã đúng cấu hình từ trước, không gửi gì.
      - 'cancelled': quản trị viên từ chối — kết quả hợp lệ, không phải lỗi.
      - 'blocked' / 'error': không thực hiện được, đọc 'message'/'error'.
    Khi đã ghi, tool tự lưu cấu hình (copy run start) — nếu 'config_saved'
    là false thì phải cảnh báo thay đổi sẽ mất khi thiết bị reload. CHỈ chấp
    nhận cổng vật lý EthernetX/Y (tên viết tắt như 'e1/0' tự được chuẩn
    hoá), CHỈ hoạt động trên switch access được cấp phép (writable).

    Args:
        device_name: Tên thiết bị, phải là switch access writable.
        interface: Tên cổng vật lý (vd 'Ethernet1/0' hoặc 'e1/0').
        vlan_id: Số VLAN cần tag.
    """
    return tag_vlan_on_port_text(device_name, interface, vlan_id)

