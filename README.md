# 🛡️ Mini SIEM - Security Information and Event Management

Hệ thống thu thập, phân tích và trực quan hóa log bảo mật từ nhiều nguồn **thực tế**.

**Tài liệu thiết kế:** [docs/THIET_KE_HE_THONG.md](docs/THIET_KE_HE_THONG.md) | 

## 🏗️ Kiến trúc

```
 NGUỒN LOG THỰC TẾ                 PIPELINE XỬ LÝ              LƯU TRỮ & HIỂN THỊ
 ─────────────────                 ───────────────              ──────────────────
 [Nginx :8080]  ──┐                                            ┌─ Elasticsearch
 [ModSec WAF]   ──┤──► [log-collector] ──► POST /ingest ──────►│   (Port 9200)
 (Port :8443)   ──┘                              │             └──► Dashboard :3000
                                         [API Collector]
 [Windows Host]                           (FastAPI :8000)
 win_event_agent ────────────────────────────────┘
                                                 │
                                          [Redis Queue]
                                                 │
                                          [Logstash]
                                       (Enrich & Index)
                                                 │
                                          Elasticsearch
```

## 🚀 Khởi chạy

```bash
# 1. Khởi động toàn bộ stack (bao gồm cả nguồn log thực)
docker-compose up -d --build

# 2. Mở Dashboard
http://localhost:3000

# 3. Tạo traffic thực vào Nginx (Web Server log)
curl http://localhost:8080/

curl "http://localhost:8080/search?q=laptop"

# 4. Thử tấn công qua WAF để sinh IDS/Firewall alert (audit log tự khởi tạo qua modsec-log-init)
curl "http://localhost:8443/?id=1%20UNION%20SELECT%20*"
curl "http://localhost:8443/?search=<script>alert(1)</script>"

# 5. Chạy Windows Event Log agent (trên máy host, quyền Admin)
pip install pywin32 requests
python scripts/win_event_agent.py
```

## 📡 Nguồn Log Thu Thập

| Service | Port | Mô tả | Log gửi về SIEM |
|---------|------|--------|-----------------|
| `nginx-target` | 8080 | Web Server thực (Nginx) | `web_access`, `ids_alert` |
| `modsecurity-waf` | 8443 | WAF/IDS thực (OWASP CRS) | `firewall_block`, `ids_alert` |
| `win_event_agent.py` | host | Endpoint Security (Windows) | `login_success`, `login_failure` |

## 📡 API Endpoints

| Method | Endpoint | Mô tả |
|--------|----------|--------|
| `POST` | `/ingest` | Nhận single log entry |
| `POST` | `/ingest/batch` | Nhận batch log entries (max 10,000) |
| `GET` | `/search` | Tìm kiếm log với filters |
| `GET` | `/stats` | Thống kê attack |
| `GET` | `/recent` | Log gần nhất (live feed) |
| `GET` | `/alerts` | Danh sách cảnh báo |
| `PATCH` | `/alerts/{id}` | Cập nhật trạng thái cảnh báo |
| `GET` | `/health` | Health check |
| `GET` | `/metrics` | Performance metrics |
| `GET` | `/docs` | Swagger API documentation |

## 📊 Dashboard Features

- **Stat Cards**: Tổng log, Attacks, Unique IPs, Avg Severity
- **Attack Timeline**: Line chart theo thời gian
- **Event Types**: Doughnut chart phân loại sự kiện
- **Top Attacking IPs**: Bar chart top 10 IP tấn công
- **Severity Distribution**: Polar area chart mức độ nghiêm trọng
- **Log Sources**: Phân bố nguồn log (web/firewall/ids/endpoint)
- **Attack Patterns**: Phân loại kiểu tấn công
- **Alerts Management**: Bảng theo dõi Cảnh báo từ Correlation Engine
- **Search**: Tìm kiếm với nhiều bộ lọc + pagination
- **Live Feed**: Real-time log stream (5s polling)

## 🧪 Testing

Xem chi tiết tại [TEST_GUIDE.md](TEST_GUIDE.md)

```bash
# Stress test (1M logs)
python scripts/stress_test.py 1000000 5000 8

# Benchmark query latency (p50/p95/p99)
python scripts/benchmark_query_latency.py -n 100 -w 5
```

## 📁 Cấu trúc dự án

```
mini-siem/
├── docs/
│   ├── THIET_KE_HE_THONG.md
│   └── CHIEN_LUOC_INDEXING.md
├── elasticsearch/
│   └── index-templates/
│       └── siem-logs-template.json
├── api/
│   ├── main.py
│   ├── requirements.txt
│   └── Dockerfile
├── dashboard/
│   ├── index.html
│   ├── style.css
│   ├── app.js
│   ├── nginx.conf
│   └── Dockerfile
├── logstash/
│   └── pipeline/logstash.conf
├── log_sources/                   #  Agent thu thập log thực
│   ├── collector.py               # Parse Nginx + ModSecurity log
│   ├── nginx.conf                 # Nginx JSON log format
│   ├── Dockerfile
│   └── requirements.txt
├── scripts/
│   ├── win_event_agent.py         #  Windows Event Log agent
│   ├── seed_data.py
│   ├── stress_test.py
│   └── benchmark_query_latency.py
├── docker-compose.yml
├── TEST_GUIDE.md
└── README.md
```

## 🔧 Tech Stack

- **API**: Python FastAPI + Uvicorn (4 workers)
- **Queue**: Redis (message broker)
- **Pipeline**: Logstash (log processing + enrichment)
- **Storage**: Elasticsearch 7.17 + Composable Index Template
- **Dashboard**: HTML/CSS/JS + Chart.js + Nginx
- **Web Server**: Nginx Alpine (nguồn log thực — port 8080)
- **WAF/IDS**: OWASP ModSecurity CRS (nguồn log thực — port 8443)
- **Endpoint**: Windows Event Log via pywin32 (nguồn log thực — host)
