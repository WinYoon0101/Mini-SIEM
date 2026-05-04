# 🛡️ Mini SIEM - Security Information and Event Management

Hệ thống thu thập, phân tích và trực quan hóa log bảo mật từ nhiều nguồn.

**Tài liệu thiết kế (báo cáo / hội đồng):** [docs/THIET_KE_HE_THONG.md](docs/THIET_KE_HE_THONG.md) — kiến trúc, luồng dữ liệu, lược đồ & **chiến lược chỉ mục**, scale-out.

## 🏗️ Kiến trúc

```
                    ┌─────────────────┐
                    │   Dashboard     │  ← Port 3000
                    │   (Nginx)       │
                    └────────┬────────┘
                             │ HTTP
                    ┌────────▼────────┐
  Log Sources ───►  │   API Collector  │  ← Port 8000
  (Web, FW, IDS)    │   (FastAPI)      │
                    └────────┬────────┘
                             │ LPUSH
                    ┌────────▼────────┐
                    │     Redis       │  ← Message Queue
                    │   (Port 6379)   │
                    └────────┬────────┘
                             │ BLPOP
                    ┌────────▼────────┐
                    │    Logstash     │  ← Processing Pipeline
                    │   (Enrichment)  │
                    └────────┬────────┘
                             │ Index
                    ┌────────▼────────┐
                    │ Elasticsearch   │  ← Port 9200
                    │   (Storage)     │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │     Kibana      │  ← Port 5601 (optional)
                    └─────────────────┘
```

## 🚀 Khởi chạy nhanh

```bash
# 1. Build và start (es-bootstrap nạp Index Template siem-logs trước khi Logstash/API tạo index)
docker-compose up -d --build

# 2. Đợi ES sẵn sàng (30-60 giây)
curl http://localhost:9200/_cluster/health

# (Tuỳ chọn) Xác nhận template đã áp dụng
curl -s "http://localhost:9200/_index_template/siem-logs?pretty"

# 3. Seed dữ liệu test
pip install requests
python scripts/seed_data.py 100

# 4. Mở Dashboard
# http://localhost:3000
```

## 📡 API Endpoints

| Method | Endpoint | Mô tả |
|--------|----------|--------|
| `POST` | `/ingest` | Nhận single log entry |
| `POST` | `/ingest/batch` | Nhận batch log entries (max 10,000) |
| `GET` | `/search` | Tìm kiếm log với filters |
| `GET` | `/stats` | Thống kê attack |
| `GET` | `/recent` | Log gần nhất (live feed) |
| `GET` | `/alerts` | Lấy danh sách cảnh báo (Alerts) |
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
- **Log Sources**: Phân bố nguồn log (web/firewall/ids)
- **Attack Patterns**: Phân loại kiểu tấn công
- **Alerts Management**: Bảng theo dõi và xử lý Cảnh báo tự động sinh bởi Correlation Engine
- **Search**: Tìm kiếm với nhiều bộ lọc + pagination
- **Live Feed**: Real-time log stream (5s polling)
- **System**: Health check + performance metrics

## 🧪 Testing

Xem chi tiết tại [TEST_GUIDE.md](TEST_GUIDE.md)

### Stress Test (1M logs)
```bash
python scripts/stress_test.py 1000000 5000 8
# Params: [total_entries] [batch_size] [workers]
```

### Benchmark độ trễ truy vấn (p50 / p95 / p99)
```bash
python scripts/benchmark_query_latency.py -n 100 -w 5
# Sau khi đã có nhiều log index, tùy chọn: --min-docs 1000000
```

## 📁 Cấu trúc dự án

```
mini-siem/
├── docs/
│   └── THIET_KE_HE_THONG.md      # Thiết kế hệ thống + indexing + scale-out
├── elasticsearch/
│   └── index-templates/
│       └── siem-logs-template.json  # Mapping & settings cho siem-logs-*
├── api/
│   ├── main.py                    # FastAPI application
│   ├── requirements.txt           # Python dependencies
│   └── Dockerfile
├── dashboard/
│   ├── index.html                 # Dashboard UI
│   ├── style.css                  # Dark theme styling
│   ├── app.js                     # Chart.js + API integration
│   ├── nginx.conf                 # Nginx config
│   └── Dockerfile
├── logstash/
│   └── pipeline/
│       └── logstash.conf          # Log processing pipeline
├── scripts/
│   ├── seed_data.py               # Tạo dữ liệu mẫu
│   ├── stress_test.py             # Benchmark throughput ingest (≥1M logs)
│   └── benchmark_query_latency.py # p50/p95/p99 cho /search, /stats, …
├── docker-compose.yml             # Tất cả services
├── .gitignore
├── TEST_GUIDE.md                  # Testing guide
└── README.md
```

## 🔧 Tech Stack

- **API**: Python FastAPI + Uvicorn (4 workers)
- **Queue**: Redis (message broker)
- **Pipeline**: Logstash (log processing + enrichment)
- **Storage**: Elasticsearch 7.17 + **Composable Index Template** `siem-logs` (`elasticsearch/index-templates/siem-logs-template.json`, nạp bởi `es-bootstrap` trong Docker Compose)
- **Dashboard**: HTML/CSS/JS + Chart.js + Nginx
- **Monitoring**: Kibana (optional)
