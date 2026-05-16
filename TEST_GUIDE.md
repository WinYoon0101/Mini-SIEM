# 🛡️ Mini SIEM - Hướng dẫn Kiểm thử (Test Guide)

Tài liệu này hướng dẫn cách kiểm thử hệ thống Mini SIEM bằng cách tương tác trực tiếp với website mô phỏng và theo dõi kết quả trên Dashboard.

---

## 1. Khởi chạy hệ thống

Chạy lệnh duy nhất để khởi động toàn bộ các thành phần (API, Dashboard, Database, Web Target):

```bash
docker-compose up -d --build
```

---

## 2. Nova Store - Nguồn Log Tương Tác & Thực Tế (Port 8080) 🚀

Đây là website bán hàng nơi bạn đóng vai trò là cả người dùng bình thường và hacker.

- **Địa chỉ:** [http://localhost:8080](http://localhost:8080)
- **Cơ chế thu thập log kép (Dual Logging):**
    1.  **Log Tương Tác:** Các hành động click nút được JavaScript gửi trực tiếp về SIEM (giúp log có thông tin chi tiết như tên User, tên sản phẩm).
    2.  **Log Nginx Thực:** Mọi lượt truy cập/refresh trang đều được Nginx ghi vào file log, sau đó được `log-collector` tự động thu thập.

### Kịch bản Người dùng (Bình thường):

| Hành động | Loại Log sinh ra | Mức độ |
|-----------|------------------|---------|
| **Tải trang / Refresh** | `web_access` (từ Nginx) | Info (1) |
| **Tìm kiếm sản phẩm** | `web_access` | Info (1) |
| **Thêm vào giỏ hàng** | `web_access` | Info (1) |
| **Đăng nhập sai mật khẩu** | `login_failure` | Medium (3) |
| **Đăng nhập đúng (admin/admin123)** | `login_success` | Info (1) |

### Kịch bản Hacker (Mô phỏng):
Nhấn vào **"Chế độ kiểm thử"** ở Footer hoặc dùng phím tắt `Ctrl + Shift + D` để mở bảng điều khiển bí mật:
- **Simulate SQL Injection:** Tạo log tấn công cơ sở dữ liệu.
- **Simulate XSS:** Tạo log tấn công script.
- **Simulate Port Scan:** Giả lập hành vi quét cổng (tạo chuỗi log liên tục).
- **Simulate DoS:** Giả lập tấn công từ chối dịch vụ.
- **Simulate Malware:** Giả lập phát hiện mã độc khi upload file.

---

## 3. ModSecurity WAF - Tường lửa thực (Port 8443) 🛡️

Đây là hệ thống bảo vệ thực tế. WAF sẽ thực sự phân tích và chặn các payload nguy hiểm trước khi chúng tới được web server.

- **Cách test:** Sử dụng `curl` để gửi các payload tấn công thực tế vào cổng `8443`.

| Loại tấn công | Tên kỹ thuật | Lệnh thực thi (Payload thực) |
|---------------|--------------|-----------------------------|
| **SQL Injection** | Tấn công DB | `curl "http://localhost:8443/?id=1' UNION SELECT 1,2,3--"` |
| **Cross-Site Scripting** | Chèn Script độc | `curl "http://localhost:8443/?q=<script>alert('XSS')</script>"` |
| **Path Traversal** | Truy cập file hệ thống | `curl "http://localhost:8443/?file=../../etc/passwd"` |
| **Remote Code Execution** | Chạy lệnh hệ thống | `curl "http://localhost:8443/?exec=/bin/bash"` |
| **Scanner Detection** | Phát hiện tool quét | `curl -A "Nikto" http://localhost:8443/` |

- **Kết quả mong đợi:** Nhận về lỗi **403 Forbidden**. Trên Dashboard xuất hiện log `firewall_block` hoặc `ids_alert` với mức độ **High/Critical**.

---

## 4. Windows Event Agent - Log từ Máy tính (Host) 💻

Agent này thu thập các sự kiện bảo mật thực tế đang diễn ra trên chính máy tính Windows của bạn.

- **Cài đặt thư viện:** `pip install pywin32 requests`
- **Cách chạy:** Mở Terminal bằng quyền **Administrator** và chạy:
  ```bash
  python scripts/win_event_agent.py
  ```

### Kịch bản Test thực tế:
1.  **Đăng nhập sai:** Thử nhấn `Win + L` để khóa máy, sau đó nhập sai mật khẩu Windows 1-2 lần.
2.  **Mở công cụ nhạy cảm:** Thử mở **PowerShell** hoặc **Command Prompt**.
3.  **Kết quả:** Dashboard sẽ nhận được log với nguồn là `endpoint`, loại `login_failure` (Event ID 4625) hoặc `ids_alert` (nếu mở PowerShell).

---

## 5. Kiểm thử Hiệu năng (Ingestion Throughput) ⚡

Kiểm tra khả năng chịu tải của hệ thống (≥ 1 triệu logs).

```bash
# Gửi 1 triệu logs với 8 luồng xử lý
python scripts/stress_test.py 1000000 5000 8
```
- **Chỉ số đạt:** EPS ≥ 1,000 logs/giây. Kiểm tra Dashboard thấy tổng log tăng thêm 1 triệu.

---

## 6. Kiểm thử Độ trễ Truy vấn (Query Latency) ⏱️

Đảm bảo Dashboard phản hồi nhanh (< 200ms) ngay cả khi database đầy tải.

```bash
# Chạy script benchmark để đo p50, p95, p99
python scripts/benchmark_query_latency.py -n 100 -w 5
```

---

## 7. Theo dõi Dashboard Mini SIEM 📊

- **Địa chỉ:** [http://localhost:3000](http://localhost:3000)

### Các khu vực cần kiểm tra:
1. **Live Feed:** Xem log đổ về thời gian thực (màu đỏ là tấn công, xanh là bình thường).
2. **Cảnh báo (Alerts):** Chờ 15s sau khi bấm "Simulate Port Scan" để xem Correlation Engine tự động tạo Cảnh báo đỏ.
3. **Thống kê (Stats):** Xem biểu đồ phân bổ loại tấn công và top IP vi phạm.

---

## 8. Checklist Đánh giá Nhanh

| Tính năng | Trạng thái |
|-----------|------------|
| Thu thập log từ Nova Store / Nginx | ✅ Đạt |
| Chặn & thu thập log từ WAF thực (ModSec) | ✅ Đạt |
| Thu thập log thực từ Windows Event Log | ✅ Đạt |
| Tự động phân loại mức độ nghiêm trọng | ✅ Đạt |
| Dashboard biểu đồ thời gian thực | ✅ Đạt |
| Correlation Engine (Phát hiện tấn công chuỗi) | ✅ Đạt |
| Xử lý dữ liệu lớn (1M+ logs) | ✅ Đạt |

---
**Lưu ý:** Nếu bạn cần kiểm tra chi tiết API, hãy truy cập [http://localhost:8000/docs](http://localhost:8000/docs).
