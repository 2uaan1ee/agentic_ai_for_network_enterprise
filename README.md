# Agent Operation Network

Multi-agent (CrewAI) hỗ trợ chẩn đoán, giám sát và vận hành mạng Cisco IOS qua SSH — LLM chỉ ra quyết định "gọi tool nào, với thiết bị/lệnh gì", còn số liệu, ngưỡng cảnh báo, và mọi lệnh ghi cấu hình đều do **code** tính/dựng sẵn, không để LLM tự sinh lệnh CLI hay tự phán đoán số liệu.

## Kiến trúc agent

4 agent, chia rõ 2 tầng quyền:

| Agent | Quyền | Vai trò |
|---|---|---|
| `engineer_agent` | READ | Chọn thiết bị + lệnh `show` phù hợp với câu hỏi, thu thập dữ liệu chẩn đoán |
| `monitor_agent` | READ | Đọc CPU/RAM/lỗi interface, đối chiếu ngưỡng cảnh báo đã tính sẵn trong code |
| `technical_agent` | WRITE (giới hạn) | Gán 1 cổng access vào 1 VLAN **đã tồn tại** — không có quyền tạo VLAN |
| `report_agent` | Không có tool | Tổng hợp dữ liệu từ agent khác thành câu trả lời tiếng Anh cho người dùng |

3 chế độ chạy tương ứng trong `main_network.py`: hỏi thông tin (read-only), xử lý ticket cấp phát VLAN/port (có ghi), giám sát sức khoẻ thiết bị.

## Các lớp an toàn (tầng code, không phụ thuộc LLM "cư xử đúng")

- **Whitelist lệnh** — `network_tools.py` chỉ cho phép lệnh bắt đầu bằng `show`; mọi lệnh khác bị từ chối trước khi chạm SSH.
- **Redact credential** — mọi `raw_output` (kể cả `show running-config`) được lọc bỏ enable secret / password / SNMP community trước khi đưa vào prompt gửi ra LLM cloud.
- **Whitelist thiết bị ghi** — chỉ thiết bị đánh dấu `writable: true` trong `inventory.yaml` mới cho phép `technical_agent` ghi cấu hình.
- **Blocklist VLAN** — VLAN quản trị (99) và mặc định (1) bị chặn cứng, không gán/tạo được qua tool.
- **VLAN phải tồn tại sẵn** — `assign_access_port` không có quyền tạo VLAN; nếu VLAN đích chưa có trên thiết bị, tool dừng và báo lỗi ngay.
- **Cổng xác nhận con người** — trước khi gửi bất kỳ lệnh ghi nào, tool in tóm tắt thay đổi và chờ quản trị viên gõ `yes`/`no` ngay trên console. Từ chối (hoặc không có console tương tác) → huỷ, không có lệnh nào được gửi xuống thiết bị. Cổng này nằm trong code của tool, không phải cơ chế review văn bản sau khi agent đã hành động.
- **Lưu cấu hình sau khi ghi** — `assign_access_port`/`create_vlan` tự chạy `copy running-config startup-config` sau khi verify, tránh mất cấu hình khi thiết bị reload.
- **Verify trạng thái thật** — mọi lệnh ghi đều đọc lại trạng thái thiết bị sau khi đổi, không chỉ tin lệnh đã chạy không lỗi.

## Cài đặt

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
```

Copy 2 file mẫu rồi điền giá trị thật (cả hai đã nằm trong `.gitignore`, không commit):

```bash
cp .env.example .env
cp inventory.example.yaml inventory.yaml
```

- `.env` — chọn `LLM_PROVIDER` (`anthropic` hoặc `openai`), điền API key tương ứng, và tài khoản SSH (`NETWORK_USERNAME`/`NETWORK_PASSWORD`/`NETWORK_ENABLE_SECRET`) dùng chung cho các thiết bị trong inventory. Khuyến nghị dùng tài khoản SSH riêng, giới hạn privilege thấp (chỉ đủ chạy `show`).
- `inventory.yaml` — khai báo thiết bị thật: tên, `host`, `device_type` (mặc định `cisco_ios`), và `writable: true` chỉ cho các switch access được phép cấu hình qua `technical_agent`.

## Chạy

```bash
python main_network.py
```

Chọn 1 trong 3 chế độ (hỏi thông tin / ticket cấp phát VLAN-port / giám sát). Mọi tương tác — kể cả khi gặp lỗi giữa chừng (API rate limit, SSH timeout...) — đều được ghi lại vào `qa_log.md` (local, không commit).

## Lưu ý riêng tư

Khi dùng API cloud, nội dung câu hỏi và raw config thiết bị (đã redact credential) sẽ được gửi ra ngoài LAN tới nhà cung cấp LLM. Với lab cá nhân thường không vấn đề gì, nhưng nếu áp dụng vào mạng thật có dữ liệu nhạy cảm thì cần cân nhắc lại — xem thêm phần đầu `crew_network.py`.

## Giới hạn hiện tại

- Giám sát (`monitor_agent`) chỉ đọc **snapshot tại thời điểm hỏi**, chưa lưu lịch sử theo thời gian — chưa hỗ trợ chọn khoảng thời gian (5 phút .. 90 ngày) hay xuất biểu đồ Excel.
