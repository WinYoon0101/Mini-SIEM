# Tài liệu thiết kế hệ thống — Mini SIEM

Tài liệu này bổ sung các phần thiết kế dùng cho báo cáo đồ án, hội đồng hoặc bàn giao kỹ thuật: kiến trúc, luồng dữ liệu, mô hình lưu trữ, **chiến lược chỉ mục (indexing)** và hướng mở rộng.

---

## 1. Tổng quan

**Mini SIEM** là hệ thống gom log bảo mật từ nhiều nguồn (Web Server, Firewall, IDS), xử lý theo pipeline bất đồng bộ, lưu trữ trên Elasticsearch và trực quan hóa qua Dashboard HTTP.

Mục tiêu vận hành tham chiếu:

- Truy vấn/lọc theo thời gian, IP, loại sự kiện trên tập lớn (≥ 1M bản ghi trong kịch bản kiểm thử).
- Giảm nghẽn cổ chai khi bùng nổ lưu lượng ingest nhờ hàng đợi và bộ xử lý nền.

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
        │
        └── (tùy chọn) Kibana :5601 — truy vấn trực tiếp index `siem-logs-*`
```

**Các thành phần:**

| Thành phần | Vai trò |
|------------|---------|
| **API Collector** | Nhận log (đơn/lô), enrich siêu dữ liệu (mức độ, `is_attack`, pattern), đẩy JSON vào Redis. |
| **Redis** | Hàng đợi danh sách (`log_queue`), tách tốc độ ghi API khỏi tốc độ index ES. |
| **Logstash** | Chuẩn hóa thời gian (`@timestamp`), kiểu dữ liệu, ghi vào ES theo index theo ngày. |
| **Elasticsearch** | Lưu trữ và tìm kiếm; truy vấn từ API qua HTTP. |
| **Dashboard** | Giao diện thống kê và tìm kiếm, gọi REST API. |

---

## 3. Luồng tương tác chi tiết

### 3.1. Từ sinh log đến hiển thị

1. **Sinh log:** Agent hoặc script mô phỏng gửi HTTP `POST /ingest` hoặc `POST /ingest/batch` (JSON theo schema `LogEntry` trong OpenAPI `/docs`).
2. **Enrich (API):** Bổ sung `timestamp` nếu thiếu; `severity_label`; `attack_patterns` (heuristic từ `message`); `is_attack`; `source` mặc định theo `event_type` nếu chưa có.
3. **Nạp (queue):** Mỗi bản ghi được `LPUSH` vào Redis key `log_queue` (chuỗi JSON).
4. **Tiêu thụ:** Logstash đọc từ Redis (`data_type => list`), áp dụng filter (parse `date`, ép kiểu `severity`, v.v.).
5. **Lưu trữ:** Output Elasticsearch, index `siem-logs-YYYY.MM.DD` (một index mỗi ngày, thuận rollover và dọn dẹp).
6. **Hiển thị:** Dashboard gọi `GET /stats`, `GET /search`, `GET /recent`; API dựng truy vấn DSL và trả JSON + `query_latency_ms`.

### 3.2. Log “thô” và log “đã phân tích” (quan điểm thiết kế)

Trong triển khai hiện tại, **một document Elasticsearch** mang cả nội dung gần với bản gốc (`message`) và các trường **đã chuẩn hóa/enrich** (`event_type`, `severity`, `is_attack`, `attack_patterns`, `@timestamp`, …). Điều này đơn giản hóa vận hành và truy vấn.

Nếu cần tách rõ theo đặc tả “log thô / log phân tích”:

- **Lựa chọn A:** Thêm trường `raw_message` (hoặc `original_payload`) lưu chuỗi gốc trước parser; các trường còn lại là tầng phân tích.
- **Lựa chọn B:** Index riêng `siem-raw-*` (append-only) và `siem-logs-*` (canonical), đồng bộ bằng cùng một pipeline hoặc pipeline thứ hai.

Tài liệu này ghi nhận phương án mở rộng; code hiện tại tương ứng **một index family** `siem-logs-*`.

---

## 4. Thiết kế cơ sở dữ liệu (Elasticsearch)

### 4.1. Quy ước index

- **Pattern:** `siem-logs-*` (ví dụ `siem-logs-2026.04.11`).
- **Rollover theo thời gian:** Do Logstash gắn `%{+YYYY.MM.dd}`, mỗi ngày một index mới — hỗ trợ ILM (xóa index cũ) khi triển khai production.

### 4.2. Lược đồ logic (các trường chính)

| Trường | Kiểu logic | Mô tả |
|--------|------------|--------|
| `@timestamp` | `date` | Thời điểm sự kiện (chuẩn hóa từ `timestamp` trong Logstash). |
| `timestamp` | `date` | Bản gốc từ client (nếu có). |
| `ingested_at` | `date` | Thời điểm ghi nhận pipeline (metadata). |
| `event_type` | text + `.keyword` | Loại sự kiện; filter/agg dùng `.keyword`. |
| `src_ip`, `dest_ip` | text + `.keyword` | Địa chỉ IP (term filter trên `.keyword`). |
| `source` | text + `.keyword` | Nguồn: `web_server`, `firewall`, `ids`. |
| `severity` | integer | Mức 1–5. |
| `severity_label` | text + `.keyword` | Nhãn: info, low, medium, high, critical. |
| `message` | `text` | Nội dung log; hỗ trợ full-text (`query_string`). |
| `log_message` | `text` | (Luồng parse tùy chọn từ Logstash khi `message` là JSON lồng). |
| `is_attack` | boolean | Cờ sự kiện tấn công / đáng ngờ. |
| `attack_patterns` | `keyword` (mảng) | Các nhãn pattern (vd. `sql_injection`, `port_scan`). |
| `port` | integer | Cổng liên quan. |
| `protocol`, `action` | keyword | Giao thức, hành động. |
| `user`, `username` | keyword | User từ API / Logstash. |

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

- `number_of_shards: 1`, `number_of_replicas: 0`: phù hợp **single-node** trong môi trường lab; khi cluster nhiều node, tăng replica và shard theo khối lượng.
- `refresh_interval: 5s`: cân bằng độ “near real-time” và tải ghi; có thể tăng tạm (vd. `30s`) khi bulk ingest lớn.

### 5.4. Lưu ý khi đổi template sau khi đã có dữ liệu

Elasticsearch **không** tự sửa mapping mạnh trên index cũ. Sau khi chỉnh template:

- Xóa index thử nghiệm: `DELETE siem-logs-*` (mất dữ liệu local), hoặc
- **Reindex** sang index mới với mapping đã cập nhật.

### 5.5. Kiểm tra nhanh sau khi khởi động

```bash
curl -s "http://localhost:9200/_index_template/siem-logs?pretty"
curl -s "http://localhost:9200/siem-logs-*/_mapping?pretty"
```

---

## 6. Đặc tả API (tham chiếu)

Danh sách endpoint và schema JSON được mô tả đầy đủ tại:

- **OpenAPI tương tác:** `http://localhost:8000/docs`
- **Bảng tóm tắt:** `README.md`

Các endpoint lõi: `POST /ingest`, `POST /ingest/batch`, `GET /search`, `GET /stats`, `GET /recent`, `GET /health`, `GET /metrics`.

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
| Kiểm thử throughput / latency | `stress_test.py`, `benchmark_query_latency.py` (p50/p95/p99), `TEST_GUIDE.md` |

---


