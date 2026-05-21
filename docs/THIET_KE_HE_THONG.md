# Tài liệu thiết kế hệ thống — Mini SIEM

Tài liệu này bổ sung các phần thiết kế dùng cho báo cáo đồ án, hội đồng hoặc bàn giao kỹ thuật: kiến trúc, luồng dữ liệu, mô hình lưu trữ, **chiến lược chỉ mục (indexing)** và hướng mở rộng.

---

## 1. Tổng quan

**Mini SIEM** là hệ thống gom log bảo mật từ nhiều nguồn (Web Server, Firewall, IDS), xử lý theo pipeline bất đồng bộ, lưu trữ trên Elasticsearch và trực quan hóa qua Dashboard HTTP.

Mục tiêu vận hành tham chiếu:

- Truy vấn/lọc theo thời gian, IP, loại sự kiện trên tập lớn (≥ 1M bản ghi trong kịch bản kiểm thử).
- Giảm nghẽn cổ chai khi bùng nổ lưu lượng ingest nhờ hàng đợi và bộ xử lý nền.

---

## 1B. Đối chiếu đặc tả yêu cầu & nghiệm thu (bắt buộc)

Bảng dưới đây map trực tiếp **Đặc tả yêu cầu & đánh giá bắt buộc** của đề tài với triển khai hiện tại và tài liệu/chứng cứ trong repo. Mục đích: hội đồng có thể đối chiếu nhanh từng dòng yêu cầu.

### 1B.1. Yêu cầu chức năng (Functional)

| Yêu cầu | Đáp ứng? | Cách triển khai / chứng cứ |
|--------|----------|----------------------------|
| **Thu thập đa nguồn:** ít nhất **Web Server**, **Firewall**, **IDS** | **Có** | **(1) Web Server:** service `nginx-target` + access log JSON → `log_sources/collector.py` → `POST /ingest/batch` (`event_type` thường là `web_access` / nâng cấp `ids_alert` khi phát hiện pattern). **(2) Firewall / chặn:** log ModSecurity OWASP CRS (chặn, tường lửa ứng dụng) → cùng collector → `firewall_block` / tương đương. **(3) IDS:** cùng luồng ModSecurity (phát hiện xâm nhập) + phân loại `ids_alert`; bổ sung **endpoint** qua `scripts/win_event_agent.py` (login, v.v.). Bảng nguồn vận hành: `README.md`. |
| **Truy vấn & phân tích:** lọc theo **thời gian**, **IP**, **loại sự kiện** | **Có** | `GET /search` với `time_from`, `time_to`, `src_ip`, `dest_ip`, `event_type` (+ mở rộng: `severity_*`, `source`, `is_attack`, full-text `q`). Mô tả đầy đủ: mục **6.3** dưới đây. |
| **Dashboard:** tổng quan + **thống kê tấn công theo thời gian** | **Có** | Dashboard HTTP (Nginx phục vụ static tại cổng **3000**, `dashboard/`): gọi `GET /stats` (timeline + `attacks` trong từng bucket), biểu đồ attack / severity / top IP; Live Feed `GET /recent`; tab Alerts. |

### 1B.2. Hạn chế kỹ thuật & phi chức năng (NFR)

| Yêu cầu | Đáp ứng? | Cách triển khai / chứng cứ |
|--------|----------|----------------------------|
| **Quy mô ≥ 1.000.000 log**, truy vấn ổn định | **Có (theo kịch bản kiểm thử)** | Elasticsearch lưu `siem-logs-*`; index template cố định mapping; tách index theo ngày. **Chứng minh số lượng:** `GET /health` → `total_indexed_logs`; script `scripts/stress_test.py` (mục tiêu ≥ 1M). Hướng dẫn: `TEST_GUIDE.md`. |
| **Pipeline bất đồng bộ + queue/buffer**, tránh nghẽn cổ chai ingest | **Có** | **API** nhận log → **Redis** `log_queue` (LPUSH) → **Logstash** tiêu thụ list (BRPOP) → bulk **Elasticsearch**. Kiến trúc: mục **2**, luồng: mục **3**. |

### 1B.3. Triển khai & tài liệu (Implementation & Documentation)

| Thành phần tài liệu | Đáp ứng? | Vị trí trong repo / ghi chú |
|---------------------|----------|------------------------------|
| **Thiết kế hệ thống:** sơ đồ kiến trúc | **Có** | Mục **2** (ASCII), `docker-compose.yml` (stack thực tế). |
| **Luồng tương tác** sinh log → nạp → lưu trữ → hiển thị | **Có** | Mục **3.1**. |
| **Scale-out** khi log tăng đột biến | **Có** | Mục **7**. |
| **Thiết kế CSDL:** schema log thô / log phân tích | **Một phần (đủ cho báo cáo có lập luận)** | **Một document** gộp `message` (gần thô) + trường đã chuẩn hóa/enrich (phân tích): mục **3.2**, bảng trường mục **4.2**. Phương án tách index `siem-raw-*` / `siem-logs-*` ghi trong **3.2** nếu hội đồng yêu cầu tách vật lý. |
| **Chiến lược indexing** (bắt buộc cho tìm kiếm trên triệu dòng) | **Có** | Mục **5** + file `elasticsearch/index-templates/siem-logs-template.json`; tài liệu bổ sung `docs/CHIEN_LUOC_INDEXING.md`. |
| **Đặc tả API** REST (ingest + JSON) | **Có** | Mục **6**; OpenAPI tương tác: `http://localhost:8000/docs`. |
| **Backend:** Log Collector API + Indexing Service | **Có** | **API:** `api/main.py` (FastAPI). **Indexing:** Logstash (`logstash/pipeline/logstash.conf`) + bootstrap template (`es-bootstrap` trong `docker-compose.yml`) + Elasticsearch — không tách microservice riêng nhưng đúng vai trò “dịch vụ chỉ mục” trong pipeline. |
| **Frontend:** Dashboard visualization | **Có** | `dashboard/` (HTML/CSS/JS), cổng 3000. |

### 1B.4. Tiêu chí đánh giá hiệu năng (Performance Evaluation)

| Tiêu chí | Đáp ứng? | Cách đo / artifact |
|-----------|----------|-------------------|
| **Load testing** (lượng lớn log đồng thời) | **Có** | `scripts/stress_test.py` — concurrent workers + batch; hướng dẫn `TEST_GUIDE.md` §4 / checklist. |
| **Ingestion throughput (EPS)** | **Có** | Phản hồi `POST /ingest/batch`: `rate_per_second`, `elapsed_seconds`; `GET /metrics` → `last_batch_ingest_rate`, `avg_ingest_rate_per_second`. |
| **Query latency** (tìm kiếm/lọc phức tạp trên ≥ 1M bản ghi, mức chấp nhận được) | **Có (định lượng theo kịch bản)** | `GET /search`, `GET /stats` trả `query_latency_ms`; script `scripts/benchmark_query_latency.py` (p50 / p95 / p99). Ngưỡng tham chiếu gợi ý trong `TEST_GUIDE.md` (ví dụ &lt; 500ms simple, &lt; 1s aggregation — tùy phần cứng lab). |

**Kết luận ngắn:** Hệ thống hiện tại **đáp ứng đủ các nhóm yêu cầu bắt buộc** trong đặc tả (chức năng, pipeline + scale 1M, tài liệu thiết kế + API, công cụ đo throughput/latency). Điểm cần **trình bày rõ khi bảo vệ:** “log thô vs log phân tích” đang là **một lớp document** có cả hai khía cạnh; nếu giảng viên bắt **hai index tách biệt**, có thể triển khai theo phương án B tại mục 3.2 (roadmap).

---

## 2. Kiến trúc tổng thể

```
  Nguồn log          Collector API          Hàng đợi           Pipeline           Lưu trữ
 (Web / FW / IDS)   (FastAPI :8000)        (Redis)            (Logstash)         (Elasticsearch)
        │                   │                  │                    │                  │
        │    POST /ingest    │    LPUSH         │    BRPOP + filter  │    bulk index    │
        └──────────────────►│─────────────────►│───────────────────►│─────────────────►│
                              │                  │                    │                  │
 Dashboard (Nginx :3000) ◄───┴── GET /search, /stats, /recent ──────┴──────────────────┘

```

**Các thành phần:**

| Thành phần | Vai trò |
|------------|---------|
| **API Collector** | Nhận log, enrich metadata (`is_attack`, pattern), đẩy vào Redis. Chạy **Correlation Engine** ngầm để phát hiện và sinh Cảnh báo (Alerts). |
| **Redis** | Hàng đợi danh sách (`log_queue`), tách tốc độ ghi API khỏi tốc độ index ES. |
| **Logstash** | Chuẩn hóa thời gian (`@timestamp`), kiểu dữ liệu, ghi vào ES theo index theo ngày. |
| **Elasticsearch** | Lưu trữ và tìm kiếm log (`siem-logs-*`) và cảnh báo (`siem-alerts`). |
| **Dashboard** | Giao diện thống kê, tìm kiếm, xem Live Feed và Quản lý Cảnh báo (Alerts). |

---

## 3. Luồng tương tác chi tiết

### 3.1. Từ sinh log đến hiển thị

1. **Sinh log:** Agent hoặc script mô phỏng gửi HTTP `POST /ingest` hoặc `POST /ingest/batch` (JSON theo schema `LogEntry` trong OpenAPI `/docs`).
2. **Enrich (API):** Bổ sung `timestamp` nếu thiếu; `severity_label`; `attack_patterns` (heuristic từ `message`); `is_attack`; `source` mặc định theo `event_type` nếu chưa có.
3. **Nạp (queue):** Mỗi bản ghi được `LPUSH` vào Redis key `log_queue` (chuỗi JSON).
4. **Tiêu thụ:** Logstash đọc từ Redis (`data_type => list`), áp dụng filter (parse `date`, ép kiểu `severity`, v.v.).
5. **Lưu trữ:** Output Elasticsearch, index `siem-logs-YYYY.MM.DD` (một index mỗi ngày, thuận rollover và dọn dẹp).
6. **Tương quan (Correlation):** API chạy Background Task mỗi 15s để gom nhóm log nguy hiểm, sinh ra cảnh báo lưu vào index `siem-alerts`.
7. **Hiển thị:** Dashboard gọi `GET /stats`, `GET /search`, `GET /alerts`; API dựng truy vấn DSL và trả JSON.

### 3.2. Log “thô” và log “đã phân tích” (quan điểm thiết kế)

Trong triển khai hiện tại, **một document Elasticsearch** mang cả nội dung gần với bản gốc (`message`) và các trường **đã chuẩn hóa/enrich** (`event_type`, `severity`, `is_attack`, `attack_patterns`, `@timestamp`, …). Điều này đơn giản hóa vận hành và truy vấn.

Nếu cần tách rõ theo đặc tả “log thô / log phân tích”:

- **Lựa chọn A:** Thêm trường `raw_message` (hoặc `original_payload`) lưu chuỗi gốc trước parser; các trường còn lại là tầng phân tích.
- **Lựa chọn B:** Index riêng `siem-raw-*` (append-only) và `siem-logs-*` (canonical), đồng bộ bằng cùng một pipeline hoặc pipeline thứ hai.

Tài liệu này ghi nhận phương án mở rộng; code hiện tại tương ứng **một index family** `siem-logs-*`.

---

## 4. Thiết kế cơ sở dữ liệu (Elasticsearch)

### 4.1. Quy ước index

- **Log Pattern:** `siem-logs-*` (ví dụ `siem-logs-2026.04.11`). Rollover theo thời gian (Logstash tạo một index mỗi ngày).
- **Alert Index:** `siem-alerts` (Lưu trữ các cảnh báo được sinh ra bởi Correlation Engine).

### 4.2. Lược đồ logic (các trường chính)

| Trường | Kiểu logic | Mô tả |
|--------|------------|--------|
| `@timestamp` | `date` | Thời điểm sự kiện (chuẩn hóa từ `timestamp` trong Logstash). |
| `timestamp` | `date` | Bản gốc từ client (nếu có). |
| `ingested_at` | `date` | Thời điểm ghi nhận pipeline (metadata). |
| `event_type` | `keyword` | Loại sự kiện; filter/agg trực tiếp. |
| `src_ip`, `dest_ip` | `ip` | Địa chỉ IP (đã tối ưu kiểu `ip`). |
| `source` | `keyword` | Nguồn: `web_server`, `firewall`, `ids`. |
| `severity` | integer | Mức 1–5. |
| `severity_label` | `keyword` | Nhãn: info, low, medium, high, critical. |
| `message` | `text` | Nội dung log; hỗ trợ full-text (`query_string`). |
| `log_message` | `text` | (Luồng parse tùy chọn từ Logstash khi `message` là JSON lồng). |
| `is_attack` | boolean | Cờ sự kiện tấn công / đáng ngờ. |
| `attack_patterns` | `keyword` (mảng) | Các nhãn pattern (vd. `sql_injection`, `port_scan`). |
| `port` | integer | Cổng liên quan. |
| `protocol`, `action` | `keyword` | Giao thức, hành động. |
| `user`, `username` | `keyword` | User từ API / Logstash. |

File mapping máy đọc được nằm tại: `elasticsearch/index-templates/siem-logs-template.json`.

---

## 5. Chiến lược chỉ mục (Indexing Strategy)

### 5.1. Composable Index Template

Hệ thống dùng **Elasticsearch Composable Index Template** tên `siem-logs`, áp dụng cho mọi index khớp `siem-logs-*`, **trước** khi Logstash tạo index ngày mới.

- **Cách nạp:** Dịch vụ Docker `es-bootstrap` gọi `PUT /_index_template/siem-logs` khi cluster đã healthy (xem `docker-compose.yml`).
- **Ưu điểm:** Mapping cố định, tránh kiểu trường sai lệch do dynamic mapping; tối ưu filter/aggregation (`.keyword`, `integer`, `date`).

### 5.2. Tối ưu tìm kiếm và aggregation

- **Filter chính xác** (IP, loại sự kiện, nguồn): dùng subfield **`keyword`** (`term` trên `*.keyword`) — chi phí thấp, phù hợp facet trên triệu bản ghi.
- **Full-text** trên nội dung: trường `message` kiểu `text`; API dùng `query_string` khi có tham số `q`.
- **Khoảng thời gian:** `range` trên `@timestamp` / `timestamp` (kiểu `date`) — có thể kết hợp index sort hoặc ILM theo thời gian.
- **Thống kê dashboard:** `terms`, `date_histogram`, `cardinality`, `filter` sub-aggregation — các trường facet đều map rõ (keyword hoặc integer).

### 5.3. Tham số index

- `number_of_shards: 1`, `number_of_replicas: 0`: phù hợp **single-node** trong môi trường lab.
- `refresh_interval` (trong `elasticsearch/index-templates/siem-logs-template.json`): mặc định triển khai **lab / test nguồn thật** dùng **`1s`** để log vào ES nhanh có thể search trên Dashboard (đánh đổi một phần throughput bulk so với refresh rất chậm). Khi cần **tối đa hóa EPS** (stress 1M+), có thể tạm chỉnh lên **`30s`** trên template hoặc `PUT .../_settings` theo index đang thử — Correlation Engine lùi mốc `time_to` so với `now` tương ứng cấu hình refresh + batch collector (xem `api/main.py`).

### 5.4. Kiểm tra nhanh sau khi khởi động

```bash
curl -s "http://localhost:9200/_index_template/siem-logs?pretty"
curl -s "http://localhost:9200/siem-logs-*/_mapping?pretty"
```

---

## 6. Đặc tả API

Tài liệu tương tác đầy đủ (Swagger UI): `http://localhost:8000/docs`

Bên dưới là đặc tả inline cho các endpoint lõi.

---

### 6.1. `POST /ingest` — Nhận một log entry

**Request body** (`Content-Type: application/json`):

```json
{
  "event_type": "ids_alert",
  "src_ip": "10.0.0.55",
  "dest_ip": "192.168.1.100",
  "severity": 5,
  "message": "SQL Injection attempt detected: UNION SELECT * FROM users",
  "source": "ids",
  "timestamp": "2026-05-03T14:00:00Z",
  "port": 80,
  "protocol": "TCP",
  "action": "alert",
  "user": "anonymous"
}
```

> Trường bắt buộc: `event_type`, `src_ip`, `severity` (1–5), `message`.  
> Trường tùy chọn: `dest_ip`, `source`, `timestamp` (tự sinh nếu thiếu), `port`, `protocol`, `action`, `user`.

**Response 200:**

```json
{
  "status": "success",
  "message": "Log queued successfully"
}
```

**Response 503** (Redis không sẵn sàng):

```json
{
  "detail": "Không thể kết nối Redis"
}
```

---

### 6.2. `POST /ingest/batch` — Nhận nhiều log cùng lúc (tối đa 10,000)

**Request body:**

```json
{
  "logs": [
    {
      "event_type": "firewall_block",
      "src_ip": "203.0.113.42",
      "severity": 4,
      "message": "Inbound connection blocked on port 22 (SSH brute force)",
      "source": "firewall"
    },
    {
      "event_type": "web_access",
      "src_ip": "192.168.1.10",
      "severity": 1,
      "message": "GET /index.html HTTP/1.1 200 OK",
      "source": "web_server"
    }
  ]
}
```

**Response 200:**

```json
{
  "status": "success",
  "count": 2,
  "elapsed_seconds": 0.003,
  "rate_per_second": 666.7
}
```

---

### 6.3. `GET /search` — Tìm kiếm log với bộ lọc

**Query parameters:**

| Tham số | Kiểu | Mô tả |
|---------|------|-------|
| `q` | string | Full-text search trên `message` |
| `src_ip` | string | Lọc chính xác theo IP nguồn |
| `dest_ip` | string | Lọc chính xác theo IP đích |
| `event_type` | string | `web_access`, `firewall_block`, `ids_alert`, … |
| `severity_min` | int (1–5) | Severity tối thiểu |
| `severity_max` | int (1–5) | Severity tối đa |
| `source` | string | `web_server`, `firewall`, `ids` |
| `is_attack` | bool | `true` = chỉ lấy attack events |
| `time_from` | ISO 8601 | Thời điểm bắt đầu |
| `time_to` | ISO 8601 | Thời điểm kết thúc |
| `page` | int | Trang hiện tại (mặc định 1) |
| `size` | int | Số kết quả/trang (mặc định 50, tối đa 500) |
| `sort_by` | string | Trường sắp xếp (mặc định `timestamp`) |
| `sort_order` | string | `asc` hoặc `desc` (mặc định `desc`) |

**Ví dụ request:**
```
GET /search?event_type=ids_alert&severity_min=4&is_attack=true&size=20
```

**Response 200:**

```json
{
  "status": "success",
  "total": 1523,
  "page": 1,
  "size": 20,
  "total_pages": 77,
  "query_latency_ms": 12.45,
  "results": [
    {
      "_id": "abc123",
      "_index": "siem-logs-2026.05.03",
      "event_type": "ids_alert",
      "src_ip": "10.0.0.55",
      "dest_ip": "192.168.1.100",
      "severity": 5,
      "severity_label": "critical",
      "message": "SQL Injection attempt detected: UNION SELECT * FROM users",
      "source": "ids",
      "is_attack": true,
      "attack_patterns": ["sql_injection"],
      "timestamp": "2026-05-03T14:00:00Z",
      "@timestamp": "2026-05-03T14:00:00.000Z",
      "ingested_at": "2026-05-03T14:00:01Z",
      "port": 80,
      "protocol": "TCP",
      "action": "alert"
    }
  ]
}
```

---

### 6.4. `GET /stats` — Thống kê tổng hợp cho Dashboard

**Query parameters:** `time_from`, `time_to` (ISO 8601), `interval` (`5m`, `30m`, `1h`, `6h`, `1d`).

**Response 200 (rút gọn):**

```json
{
  "status": "success",
  "query_latency_ms": 38.2,
  "summary": {
    "total_logs": 1000000,
    "total_attacks": 347821,
    "unique_ips": 4312,
    "avg_severity": 2.87
  },
  "event_types": [
    { "name": "web_access", "count": 412000 },
    { "name": "firewall_block", "count": 198000 }
  ],
  "top_attackers": [
    { "ip": "203.0.113.42", "count": 8921 },
    { "ip": "198.51.100.15", "count": 7634 }
  ],
  "severity_breakdown": [
    { "level": 1, "count": 310000 },
    { "level": 5, "count": 89000 }
  ],
  "source_distribution": [
    { "source": "web_server", "count": 450000 },
    { "source": "firewall", "count": 320000 },
    { "source": "ids", "count": 230000 }
  ],
  "attack_patterns": [
    { "pattern": "sql_injection", "count": 42100 },
    { "pattern": "brute_force", "count": 38900 }
  ],
  "timeline": [
    { "time": "2026-05-03T13:00:00.000Z", "total": 12500, "attacks": 4300 },
    { "time": "2026-05-03T14:00:00.000Z", "total": 15800, "attacks": 5900 }
  ]
}
```

---

### 6.5. `GET /alerts` & `PATCH /alerts/{id}` — Quản lý cảnh báo

- **`GET /alerts`**: Trả về danh sách cảnh báo, hỗ trợ tham số `status` (pending, investigating, resolved) và `size`.
- **`PATCH /alerts/{alert_id}`**: Nhận JSON `{"status": "resolved"}` để đánh dấu hoàn tất.

---

### 6.6. `GET /health` — Kiểm tra trạng thái hệ thống

**Response 200:**

```json
{
  "api": "ok",
  "redis": "ok",
  "elasticsearch": "ok",
  "overall": "ok",
  "es_version": "7.17.10",
  "total_indexed_logs": 1000000,
  "index_size_bytes": 524288000,
  "index_size_mb": 500.0,
  "redis_queue_length": 0
}
```

---

### 6.7. `GET /metrics` — Số liệu hiệu năng API

**Response 200:**

```json
{
  "status": "success",
  "uptime_seconds": 3721.5,
  "total_ingested": 1000000,
  "total_queries": 854,
  "avg_ingest_rate_per_second": 268.7,
  "last_batch_ingest_rate": 15420.3,
  "last_query_latency_ms": 12.45
}
```

---

## 7. Chiến lược mở rộng (Scale-out)

Khi khối lượng log tăng đột biến, có thể mở rộng theo từng lớp (mô tả cho báo cáo / roadmap):

| Lớp | Hướng xử lý |
|-----|-------------|
| **Collector API** | Nhiều replica (load balancer); giới hạn rate; xác thực API key/JWT cho `/ingest`. |
| **Hàng đợi** | Redis Cluster hoặc chuyển sang Kafka cho buffer lớn, consumer group, replay. |
| **Logstash** | Nhiều instance cùng consume một queue (cấu hình consumer phù hợp với broker). |
| **Elasticsearch** | Cluster nhiều node, tăng shard/replica, ILM rollover + shrink, warm/frozen tier (tuỳ phiên bản). |
| **Đọc (Dashboard/API)** | Tách node chỉ đọc, cache thống kê ngắn hạn (Redis) cho một số widget nặng. |

---

## 8. Tham chiếu file trong repository

| Nội dung | Đường dẫn |
|----------|-----------|
| Index template (JSON) | `elasticsearch/index-templates/siem-logs-template.json` |
| Nạp template khi `docker compose up` | `docker-compose.yml` → service `es-bootstrap` |
| Pipeline Logstash | `logstash/pipeline/logstash.conf` |
| API & truy vấn ES | `api/main.py` |
| Kiểm thử throughput / latency | `scripts/stress_test.py`, `scripts/benchmark_query_latency.py` (p50/p95/p99), `TEST_GUIDE.md` |

---


