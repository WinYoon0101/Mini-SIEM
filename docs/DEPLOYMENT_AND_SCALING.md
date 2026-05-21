# 🚀 Hướng dẫn Mở rộng & Triển khai Hệ thống (Scaling & Deployment)

Tài liệu này dành cho nhà phát triển muốn mở rộng Mini SIEM, thêm nguồn log mới hoặc đóng gói hệ thống để chuyển giao/kinh doanh.

---

## 1. Cách thêm Nguồn Log mới (Log Sources) - Ví dụ Thực Tế

Hệ thống Mini SIEM được thiết kế rất linh hoạt. Giả sử bạn đã có một **Web App đang chạy thực tế** (ví dụ: một trang web bán hàng, một API server), dưới đây là 2 cách thực tiễn để nối Web App đó vào Mini SIEM để theo dõi:

### Cách A: Gửi trực tiếp qua API từ Code Web App (Khuyên dùng)
Nếu bạn có quyền sửa code của ứng dụng (ví dụ Node.js, Python, PHP), bạn có thể gọi thẳng API của Mini SIEM. Cách này cho phép bạn tùy chỉnh chính xác khi nào thì tạo log bảo mật.

**💡 Ví dụ thực tế: Tích hợp vào Web App Node.js (Express)**
Giả sử bạn muốn giám sát tất cả các request bị lỗi (4xx, 5xx) hoặc người dùng đăng nhập sai vào web của bạn. Thêm một middleware đơn giản:

```javascript
const express = require('express');
const axios = require('axios');
const app = express();

// Middleware tự động đẩy log bảo mật về Mini-SIEM
const siemLogger = async (req, res, next) => {
    res.on('finish', async () => {
        // Chỉ giám sát các request lỗi hoặc nghi ngờ tấn công (Status >= 400)
        if (res.statusCode >= 400) {
            const logData = {
                event_type: "web_access_error",
                src_ip: req.ip || req.connection.remoteAddress,
                severity: res.statusCode >= 500 ? 4 : 3, // 5xx là Critical, 4xx là Warning
                message: `Phát hiện lỗi: ${req.method} ${req.originalUrl} - Trạng thái: ${res.statusCode}`,
                source: "my_production_web"
            };
            
            try {
                // Thay <siem-ip> bằng IP thật của máy chủ cài đặt Mini SIEM
                // Đảm bảo máy chủ Web của bạn có thể kết nối mạng (Ping) tới IP này.
                await axios.post('http://<siem-ip>:8000/ingest', logData);
            } catch (error) {
                console.error("Lỗi khi gửi log về SIEM:", error.message);
            }
        }
    });
    next();
};

// Gắn middleware vào ứng dụng
app.use(siemLogger);

app.get('/login', (req, res) => {
    // Logic kiểm tra đăng nhập...
    res.status(401).send("Sai mật khẩu"); // Request này sẽ tự động bị middleware bắt và bắn log về SIEM!
});

app.listen(3000, () => console.log("Web App đang chạy..."));
```

### Cách B: Thu thập qua File Log (Không cần can thiệp code Web App)
Nếu web của bạn dùng Nginx/Apache hoặc một database sinh ra file log sẵn, và bạn không muốn đụng vào source code, hãy đọc trực tiếp file log đó.

**💡 Ví dụ thực tế: Thu thập log Nginx bằng Python Collector**
Thay vì sửa code web, bạn viết một đoạn script nhỏ chạy ngầm trên máy chủ web thực tế để đọc đuôi file (tail) `/var/log/nginx/access.log`:

```python
import time
import requests
import re

def tail_nginx_and_send_to_siem(filepath, siem_url):
    # Regex cơ bản bóc tách IP, Trạng thái từ Nginx log
    log_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*\] "(?P<method>[A-Z]+) (?P<url>.*?) HTTP/.*" (?P<status>\d+)')
    
    with open(filepath, 'r') as f:
        f.seek(0, 2) # Nhảy đến cuối file, chỉ đọc log mới
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            
            match = log_pattern.search(line)
            if match:
                log_data = {
                    "event_type": "nginx_access",
                    "src_ip": match.group("ip"),
                    "severity": 3 if int(match.group("status")) >= 400 else 1,
                    "message": f"Truy cập: {match.group('method')} {match.group('url')} - Status: {match.group('status')}",
                    "source": "production_nginx"
                }
                # Bắn log về Mini SIEM qua mạng
                requests.post(siem_url, json=log_data)

# Chạy ngầm hàm này trên server chứa Nginx
# tail_nginx_and_send_to_siem('/var/log/nginx/access.log', 'http://<siem-ip>:8000/ingest')
```
*(**Ghi chú cho môi trường Production thực thụ:** Trong các dự án lớn, người ta thường dùng các phần mềm chuẩn công nghiệp như **Elastic Filebeat**, **Fluentd** hoặc **Logstash** cài lên máy chủ Web để làm nhiệm vụ đọc file và tự động gửi sang Elasticsearch của hệ thống SIEM, thay vì viết script Python thủ công).*

### 💡 Tại sao Mini SIEM không dùng Filebeat/Logstash mà lại tự viết Collector bằng Python?

Mặc dù trong hệ thống Mini SIEM này bạn **vẫn đang thu thập log từ Nginx** một cách thực tế, nhưng chúng ta đang dùng một script Python tự viết (`log_sources/collector.py`) thay vì bộ đôi Filebeat/Logstash chuẩn của Elastic Stack. 

Dưới đây là bảng so sánh giúp bạn hiểu rõ lý do thiết kế này:

| Tiêu chí | Python Collector (Hiện tại của Mini SIEM) | Filebeat & Logstash (Chuẩn công nghiệp) |
| :--- | :--- | :--- |
| **Tiêu hao Tài nguyên** | **Siêu nhẹ (~15MB RAM)**. Rất thích hợp chạy thử nghiệm trên máy cá nhân mà không sợ đơ/giật lag máy. | **Rất nặng**. Logstash chạy trên máy ảo Java (JVM), yêu cầu tối thiểu **512MB - 1GB RAM** riêng cho nó để chạy ổn định. |
| **Độ phức tạp Cài đặt** | **Cực kỳ đơn giản**. Chỉ cần một file script Python nhỏ, dễ đọc, dễ chỉnh sửa logic regex theo ý mình. | **Khá phức tạp**. Phải học cách viết file cấu hình YAML của Filebeat và cú pháp lọc log (Grok Filter) phức tạp của Logstash. |
| **Phân tích Real-time & Cảnh báo** | Log sau khi parse sẽ đi qua API (FastAPI) để đối chiếu luật tấn công và **bắn cảnh báo Telegram** ngay tức khắc. | Log đi thẳng vào Elasticsearch. Để cảnh báo, phải cấu hình thêm Elasticsearch Alerting (thường yêu cầu bản quyền trả phí) hoặc các tool ngoài. |
| **Độ bền bỉ & Chống mất log** | Cơ bản. Nếu API SIEM chết tạm thời, log nằm trong queue bộ nhớ đệm sẽ bị mất nếu container restart. | Cực cao. Filebeat có tính năng "Registry" lưu lại vị trí đã đọc, nếu mạng lỗi hoặc Logstash sập, nó sẽ tự động gửi bù khi hệ thống online lại. |
| **Mục đích phù hợp** | Học tập, nghiên cứu (Lab), hệ thống SIEM siêu nhẹ chạy local để test nhanh. | Hệ thống doanh nghiệp lớn, hàng ngàn server web cần gom log tập trung về một chỗ (Centralized Logging). |

#### 🛠️ Nguyên lý hoạt động hiện tại của Nginx Log trong Mini SIEM:
Thực chất, Mini SIEM của bạn **đang thu thập log Nginx cực kỳ hiệu quả** theo mô hình File-based thông qua cơ chế mount volume của Docker:
1. File cấu hình `docker-compose.yml` sẽ chia sẻ chung thư mục chứa log của Nginx với container `log-collector`.
2. Script `collector.py` đóng vai trò như một **Filebeat thu nhỏ**: nó dùng hàm `tail_file()` đọc đuôi file log Nginx (`/var/log/nginx/access_json.log`) liên tục.
3. Khi phát hiện dòng log mới, nó lập tức parse dữ liệu JSON, phân loại mức độ nghiêm trọng (Severity) và đẩy lên SIEM API.

Do đó, với quy mô lab hoặc dự án vừa và nhỏ, việc tự viết Python Collector là phương án **tối ưu nhất về RAM, tốc độ phản hồi và độ dễ hiểu**!

---

## 1.5. Triển khai WAF (Web Application Firewall) trong Thực Tế

Trong hệ thống Mini SIEM hiện tại, bạn đang dùng **ModSecurity WAF** chạy bằng Docker (`modsecurity-waf`) hoạt động theo cơ chế **Reverse Proxy**. Tất cả request từ bên ngoài vào port `8443` sẽ được WAF lọc qua bộ luật **OWASP Core Rule Set (CRS)**, nếu an toàn thì forward về cho `nginx-target:80`, nếu nguy hiểm thì chặn (trả về 403 Forbidden) và ghi log chi tiết vào `/var/log/modsec/audit.log` trước khi được Python Collector thu thập.

Vậy trong môi trường **Production thực tế**, các doanh nghiệp triển khai WAF như thế nào? Dưới đây là 3 mô hình triển khai phổ biến nhất:

### Mô hình 1: WAF làm Reverse Proxy độc lập (Giống thiết kế hiện tại)
*   **Cách hoạt động:** Dựng riêng một cụm máy chủ WAF (ví dụ dùng Nginx + ModSecurity, HAProxy hoặc F5 BIG-IP) đứng trước toàn bộ hệ thống Web App.
*   **Luồng đi của request:** `Client` ➔ `WAF Server` (Phân tích & Chặn nếu có mã độc) ➔ `Web App Servers` (Backend).
*   **Cách kết nối SIEM:** Cài đặt log agent (ví dụ **Filebeat**) trên chính cụm máy chủ WAF này để theo dõi file log `/var/log/modsec/audit.log` và bắn trực tiếp về Elasticsearch của SIEM.
*   **Đặc điểm:** Tự chủ công nghệ 100%, bảo mật cao nhưng tốn tài nguyên quản lý rule và vận hành server proxy.

### Mô hình 2: Cloud WAF / SaaS WAF (Xu hướng hiện đại - Khuyên dùng)
*   **Dịch vụ tiêu biểu:** **Cloudflare WAF**, **AWS WAF**, **Azure WAF**, **Imperva**.
*   **Cách hoạt động:** Không cần dựng bất kỳ server WAF nào cả. Bạn chỉ cần cấu hình DNS (ví dụ trên Cloudflare) để toàn bộ request đi qua hạ tầng Cloud WAF của họ trước khi trỏ về IP của server bạn.
*   **Ưu điểm:** Kháng DDoS cực mạnh, tự động cập nhật các lỗi bảo mật mới nhất (Zero-day) mà bạn không cần phải làm gì, giảm tải RAM/CPU cho server của bạn.
*   **Cách kết nối SIEM:** Do Cloud WAF không lưu file trên server của bạn, bạn phải kết nối bằng cách:
    *   **Cloudflare Logpush:** Đẩy log tự động về Amazon S3 hoặc gửi trực tiếp qua một **Webhook API** (chính là endpoint `POST http://<siem-ip>:8000/ingest` của Mini SIEM).
    *   **AWS Kinesis Firehose:** Gom log từ AWS WAF và stream thẳng về Elasticsearch.

### Mô hình 3: Kubernetes Ingress Controller WAF (Hệ thống Container/Microservices)
*   **Cách hoạt động:** Nếu ứng dụng của bạn chạy trên Kubernetes (K8s), WAF sẽ được tích hợp trực tiếp dưới dạng một Module (ví dụ ModSecurity) nằm ngay trong **NGINX Ingress Controller** (cửa ngõ ra vào của cả cụm K8s).
*   **Cách kết nối SIEM:** Sử dụng một DaemonSet (chạy ngầm trên mọi Node của K8s) như **Fluent-Bit** để tự động đọc log của container Ingress Controller, lọc ra các log bị WAF block và đẩy về Elasticsearch trung tâm.

---

## 1.6. Triển khai IDS/IPS (Hệ thống Phát hiện & Ngăn ngừa Xâm nhập) trong Thực Tế

Trong hệ thống Mini SIEM hiện tại, bạn thấy có các cảnh báo loại **`ids_alert`**. Chúng đang được sinh ra dựa trên cơ chế kết hợp:
1.  **IDS giả lập ở mức ứng dụng (Host-based / App-based):** Script Python `collector.py` tự động quét dòng log Nginx bằng các mẫu biểu thức chính quy (Regex) để phát hiện hành vi chèn mã độc (SQLi, XSS, Path Traversal, Web Scanner).
2.  **IPS ở mức cổng vào (Network/Proxy-based):** ModSecurity WAF đóng vai trò ngăn chặn (Prevention) và ghi nhận các cuộc tấn công nghiêm trọng (`severity >= 4`).

Còn trong môi trường **Doanh nghiệp Thực tế**, người ta không viết script Python thủ công để bắt tấn công như vậy. Thay vào đó, họ triển khai các hệ thống **IDS (Intrusion Detection System)** và **IPS (Intrusion Prevention System)** chuyên dụng, chia làm 2 nhóm lớn:

### Nhóm 1: NIDS (Network Intrusion Detection System) - Giám sát Lưu lượng Mạng
*   **Công cụ tiêu chuẩn:** **Suricata**, **Snort**, **Zeek (Bro)**.
*   **Cách hoạt động thực tế:**
    *   Hệ thống NIDS thường chạy trên một máy chủ độc lập. Người quản trị sẽ cấu hình thiết bị mạng (Switch/Router) để sao chép (Mirror) toàn bộ luồng traffic đi qua hệ thống sang cổng của máy chủ NIDS (gọi là cổng **SPAN Port** hoặc dùng thiết bị phần cứng **Network TAP**).
    *   NIDS sẽ "ngửi" (inspect) sâu vào từng gói tin mạng (TCP/IP packet) theo thời gian thực để đối chiếu với hàng chục ngàn mẫu chữ ký tấn công (Signature) được cập nhật liên tục (quét cổng, khai thác lỗi phần mềm, hành vi tải mã độc, mã hóa ransomware...).
*   **Cách kết nối SIEM:** Khi Suricata phát hiện dấu hiệu xâm nhập, nó lập tức ghi log ra một file JSON chuẩn hóa cực kỳ chi tiết tên là `eve.json`. Một agent (như Filebeat) sẽ đọc file này và bắn trực tiếp về Elasticsearch của SIEM để hiển thị lên Dashboard.

### Nhóm 2: HIDS (Host-based Intrusion Detection System) - Giám sát ngay trên Máy chủ
*   **Công cụ tiêu chuẩn:** **Wazuh** (Phổ biến nhất thế giới mã nguồn mở), **OSSEC**, **Tripwire**.
*   **Cách hoạt động thực tế:**
    *   Doanh nghiệp sẽ cài một phần mềm Agent siêu nhẹ của Wazuh lên **tất cả các máy chủ** chạy dịch vụ (Linux, Windows Server, Database).
    *   Agent này sẽ chạy ngầm và thực hiện giám sát sâu trong hệ điều hành:
        *   **File Integrity Monitoring (FIM):** Kiểm tra xem có ai chỉnh sửa trái phép các file cấu hình hệ thống (như `/etc/passwd` trên Linux hoặc registry trên Windows).
        *   **Syslog & Event Log Analysis:** Phân tích log đăng nhập SSH, RDP để phát hiện dò mật khẩu (Brute force).
        *   **Rootkit & Malware Detection:** Quét các tiến trình chạy ngầm lạ, phát hiện các mã độc đã vượt qua được tường lửa ngoài.
*   **Cách kết nối SIEM:** Các Agent HIDS mã hóa và gửi dữ liệu cảnh báo về một cụm máy chủ quản trị trung tâm (**Wazuh Manager**). Từ đây, Wazuh Manager sẽ đồng bộ trực tiếp hoặc đẩy các cảnh báo chuẩn hóa sang Elasticsearch của SIEM.

---

## 2. Tùy chỉnh cho máy người dùng khác (Customization)

Khi đưa hệ thống cho người khác, bạn cần lưu ý các cấu hình "cứng" (Hardcoded) sau:

### 2.1. Địa chỉ IP & Port
- **Dashboard:** Hiện đang trỏ đến `localhost:8000`. Nếu người dùng cài trên server, bạn cần sửa `API_URL` trong `dashboard/app.js` thành IP của server đó.
- **Port Mapping:** Nếu port `8000`, `9200`, `3000` trên máy họ đã bị chiếm, hãy đổi cổng ở cột bên trái trong `docker-compose.yml` (ví dụ: `"8081:8000"`).

### 2.2. Tài nguyên hệ thống (RAM/CPU)
- **Elasticsearch:** Cần tối thiểu 2GB RAM để chạy ổn định. Trong `docker-compose.yml`, tôi đang giới hạn `ES_JAVA_OPTS=-Xms512m -Xmx512m` để chạy được trên máy yếu. Với máy mạnh, nên nâng lên `1g` hoặc `2g`.

---

## 3. Lộ trình biến Mini SIEM thành Web App kinh doanh (SaaS)

Nếu bạn muốn đóng gói hệ thống này để bán như một giải pháp phần mềm, bạn cần thực hiện các bước sau:

### 3.1. Phân tách dữ liệu (Multi-tenancy)
- **Vấn đề:** Hiện tại mọi khách hàng dùng chung 1 database.
- **Giải pháp:** Thêm trường `customer_id` vào mỗi log. Khi tìm kiếm (`/search`), API phải luôn filter theo `customer_id` của khách hàng đó.

### 3.2. Bảo mật Dashboard
- **Vấn đề:** Dashboard hiện tại ai cũng vào xem được.
- **Giải pháp:** Thêm hệ thống Login (JWT/OAuth2) cho Dashboard và API. Chỉ người dùng có token mới được xem log của mình.

### 3.3. Đóng gói & Triển khai Cloud
- **Docker Image:** Build và đẩy các image lên Docker Hub (Private).
- **Cloud:** Triển khai trên AWS/GCP/Azure. Sử dụng **Managed Service** cho Elasticsearch (như Elastic Cloud) và Redis (như AWS ElastiCache) để giảm tải việc quản trị server.

### 3.4. Hệ thống Cảnh báo (Alerting)
- Tích hợp thêm các kênh thông báo chuyên nghiệp: **Slack, Email, PagerDuty** thay vì chỉ có Telegram như hiện tại.

---

## 4. Checklist khi chuyển giao hệ thống

- [ ] Thay đổi các chuỗi bí mật (Secret Keys) trong `.env`.
- [ ] Cập nhật file `TEST_GUIDE.md` phù hợp với môi trường mới.
- [ ] Kiểm tra dung lượng đĩa cứng (Elasticsearch có thể ngốn rất nhiều ổ cứng sau thời gian dài).
- [ ] Cài đặt chế độ tự động dọn dẹp log cũ (Retention Policy) trong Elasticsearch.
