# 🛡️ Mini SIEM - Hướng dẫn Test & Kiểm tra

## Mục lục
1. [Khởi chạy hệ thống](#1-khởi-chạy-hệ-thống)
2. [Test API Endpoints](#2-test-api-endpoints)
3. [Test Dashboard](#3-test-dashboard)
4. [Test Ingestion Throughput (≥ 1M logs)](#4-test-ingestion-throughput)
5. [Test Query Latency](#5-test-query-latency)
6. [Test Pipeline (Redis → Logstash → ES)](#6-test-pipeline)
7. [Checklist đánh giá](#7-checklist-đánh-giá)

---

## 1. Khởi chạy hệ thống

### Bước 1: Build và Start Docker
```bash
cd g:\mini-siem
docker-compose up -d --build
```

### Bước 2: Kiểm tra containers đã chạy
```bash
docker-compose ps
```
**Expected**: Các service chạy ổn định; trong đó có `elasticsearch`, `kibana`, `redis`, `logstash`, `api-collector`, `dashboard`. Service **`es-bootstrap`** chạy một lần rồi **thoát** (exit 0) sau khi `PUT /_index_template/siem-logs` thành công — trạng thái `Exited (0)` là bình thường.

```bash
docker-compose ps -a
```

### Bước 2b: Xác nhận Index Template (khuyến nghị)

```bash
curl -s "http://localhost:9200/_index_template/siem-logs?pretty"
```

**Expected**: Trong JSON có `"index_patterns": ["siem-logs-*"]` và phần `template.mappings.properties` chứa các trường như `event_type`, `src_ip`, `message`, `attack_patterns`, …

### Bước 3: Đợi Elasticsearch sẵn sàng (30-60 giây)
```bash
curl http://localhost:9200/_cluster/health
```
**Expected**: `"status":"green"` hoặc `"status":"yellow"`

### Bước 4: Seed dữ liệu test
```bash
pip install requests
python scripts/seed_data.py 100
```
**Expected**: `✅ Đã gửi 100 logs`

---

## 2. Test API Endpoints

### 2.1. Health Check
```bash
curl http://localhost:8000/health
```
**Expected response**:
```json
{
  "api": "ok",
  "redis": "ok",
  "elasticsearch": "ok",
  "overall": "ok",
  "total_indexed_logs": 100,
  "index_size_mb": ...
}
```

### 2.2. Single Log Ingestion
```bash
curl -X POST http://localhost:8000/ingest -H "Content-Type: application/json" -d "{\"event_type\":\"ids_alert\",\"src_ip\":\"10.0.0.55\",\"severity\":5,\"message\":\"SQL Injection attempt detected\"}"
```
**Expected**: `{"status":"success","message":"Log queued successfully"}`

### 2.3. Batch Log Ingestion
```bash

  curl -X POST http://localhost:8000/ingest/batch -H "Content-Type: application/json" -d "{\"logs\":[{\"event_type\":\"firewall_block\",\"src_ip\":\"203.0.113.42\",\"severity\":4,\"message\":\"Port scan blocked\"},{\"event_type\":\"web_access\",\"src_ip\":\"192.168.1.10\",\"severity\":1,\"message\":\"GET /index.html 200\"}]}"
```
**Expected**: `{"status":"success","count":2,"elapsed_seconds":...,"rate_per_second":...}`

### 2.4. Search Logs
```bash
# Tìm tất cả log
curl "http://localhost:8000/search?size=10"

# Tìm theo IP
curl "http://localhost:8000/search?src_ip=10.0.0.55"

# Tìm theo event type
curl "http://localhost:8000/search?event_type=ids_alert"

# Tìm theo severity
curl "http://localhost:8000/search?severity_min=4"

# Tìm theo thời gian
curl "http://localhost:8000/search?time_from=2026-04-10T00:00:00Z&time_to=2026-04-11T00:00:00Z"

# Tìm chỉ attacks
curl "http://localhost:8000/search?is_attack=true"

# Full-text search
curl "http://localhost:8000/search?q=SQL+Injection"

# Kết hợp nhiều filter
curl "http://localhost:8000/search?event_type=ids_alert&severity_min=4&is_attack=true&size=20"
```
**Expected**: Response có `status`, `total`, `results`, `query_latency_ms`

### 2.5. Statistics
```bash
curl "http://localhost:8000/stats?interval=1h"
```
**Expected**: Response có `summary`, `event_types`, `top_attackers`, `severity_breakdown`, `timeline`

### 2.6. Recent Logs (Live Feed)
```bash
curl "http://localhost:8000/recent?limit=10"
```

### 2.7. Metrics
```bash
curl http://localhost:8000/metrics
```
**Expected**: `total_ingested`, `avg_ingest_rate_per_second`, `last_query_latency_ms`

### 2.8. Alerts
```bash
# Lấy danh sách cảnh báo (pending)
curl "http://localhost:8000/alerts?status=pending"
```
**Expected**: Response có `status`, `total`, `results` chứa thông tin cảnh báo từ index `siem-alerts`.

### 2.9. API Documentation (Swagger)
Mở trình duyệt: **http://localhost:8000/docs**

---

## 3. Test Dashboard

### 3.1. Mở Dashboard
Trình duyệt: **http://localhost:3000**

### 3.2. Kiểm tra Dashboard Tab
- [ ] 4 stat cards hiển thị (Tổng Log, Attacks, Unique IPs, Avg Severity)
- [ ] Attack Timeline chart hiển thị line chart
- [ ] Event Types chart hiển thị doughnut chart
- [ ] Top 10 Attacking IPs chart hiển thị bar chart
- [ ] Severity Distribution chart hiển thị polar area chart
- [ ] Log Sources chart hiển thị doughnut chart
- [ ] Attack Patterns chart hiển thị bar chart
- [ ] Time range selector (1H, 6H, 24H, 7D, 30D) hoạt động

### 3.3. Kiểm tra Search Tab
- [ ] Click "Tìm kiếm Log" trên sidebar
- [ ] Nhập IP vào ô filter, nhấn "Tìm kiếm" → kết quả hiện đúng
- [ ] Chọn Event Type dropdown → filter đúng
- [ ] Chọn "Chỉ Attacks" → chỉ hiện attack logs
- [ ] Chọn Severity Min = 4 → chỉ hiện high/critical logs
- [ ] Pagination hoạt động (nếu > 50 results)
- [ ] Query latency hiển thị ở góc phải

### 3.4. Kiểm tra Live Feed Tab
- [ ] Click "Live Feed" trên sidebar
- [ ] Log entries hiển thị với màu đỏ (attack) và xanh (normal)
- [ ] Nút Live/Pause hoạt động
- [ ] Dropdown 20/50/100 log hoạt động
- [ ] Auto-refresh mỗi 5 giây

### 3.5. Kiểm tra System Tab
- [ ] Click "Hệ thống" trên sidebar
- [ ] Trạng thái API, Redis, ES hiển thị "ok" (badge xanh)
- [ ] Tổng log indexed hiển thị số đúng
- [ ] Performance metrics hiển thị

### 3.6. Kiểm tra Alerts Tab (Cảnh báo)
- [ ] Bơm thử dữ liệu có attack logs (`event_type=ids_alert` hoặc `severity=5` với cùng 1 IP nhiều lần).
- [ ] Chờ khoảng 15 giây.
- [ ] Badge "Cảnh báo" màu đỏ hiện số lượng trên menu sidebar.
- [ ] Click "Cảnh báo", bảng hiển thị log đang `pending`.
- [ ] Click "Đánh dấu đã xử lý" trên UI, trạng thái trong danh sách thay đổi và số trên badge giảm.

---

## 4. Test Ingestion Throughput

### 4.1. Test nhỏ (10,000 logs)
```bash
python scripts/stress_test.py 10000 1000 4
```
Tham số: `[tổng_entries] [batch_size] [workers]`

### 4.2. Test vừa (100,000 logs)
```bash
python scripts/stress_test.py 100000 5000 8
```

### 4.3. Test lớn (1,000,000 logs) ⭐
```bash
python scripts/stress_test.py 1000000 5000 8
```

**Kết quả mong đợi**:
- ✅ Gửi thành công 1,000,000 logs
- ✅ Throughput ≥ 1,000 logs/giây
- ✅ Không có batch thất bại
- ✅ Elasticsearch indexed được logs (kiểm tra sau 1-2 phút)

### 4.4. Kiểm tra sau khi chạy stress test
```bash
# Kiểm tra tổng log đã index
curl http://localhost:8000/health

# Kiểm tra trên ES trực tiếp
curl "http://localhost:9200/siem-logs-*/_count"
```

---

## 5. Test Query Latency

### 5.1. Simple query
```bash
# Đo thời gian query đơn giản
curl -w "\nTotal time: %{time_total}s\n" "http://localhost:8000/search?size=10"
```

### 5.2. Filtered query
```bash
curl -w "\nTotal time: %{time_total}s\n" "http://localhost:8000/search?event_type=ids_alert&severity_min=4&size=50"
```

### 5.3. Full-text search
```bash
curl -w "\nTotal time: %{time_total}s\n" "http://localhost:8000/search?q=SQL+Injection&size=50"
```

### 5.4. Stats aggregation
```bash
curl -w "\nTotal time: %{time_total}s\n" "http://localhost:8000/stats?interval=1h"
```

**Kết quả mong đợi**:
- ✅ Query latency < 500ms cho simple queries
- ✅ Query latency < 1s cho aggregation queries
- ✅ `query_latency_ms` trong response cho thấy ES query time

### 5.5. Benchmark phân vị (p50 / p95 / p99)

Script `benchmark_query_latency.py` lặp lại nhiều kịch bản (`/search` đơn giản, có lọc, full-text, khoảng thời gian + IP, `/stats`, `/recent`) và in **p50, p95, p99** cho:

- **client_ms**: thời gian vòng đời HTTP (gần trải nghiệm người dùng).
- **server_ms**: `query_latency_ms` từ API (phần truy vấn ES trong backend), với các endpoint có trường này.

```bash
pip install requests
# Khuyến nghị chạy sau khi đã index đủ lớn (vd. sau stress 1M):
python scripts/benchmark_query_latency.py --url http://localhost:8000 -n 100 -w 5

# Cảnh báo nếu chưa đủ bản ghi (ví dụ mong đợi ≥ 1M):
python scripts/benchmark_query_latency.py -n 200 --min-docs 1000000
```

Tham số: `-n` số lần đo mỗi kịch bản, `-w` warmup (bỏ qua khi tính thống kê), `--min-docs` chỉ in cảnh báo.

---

## 6. Test Pipeline (Redis → Logstash → ES)

### 6.1. Gửi 1 log và theo dõi pipeline
```bash
# Bước 1: Gửi log
curl -X POST http://localhost:8000/ingest -H "Content-Type: application/json" -d "{\"event_type\":\"ids_alert\",\"src_ip\":\"10.0.0.99\",\"severity\":5,\"message\":\"TEST PIPELINE - SQL Injection attack\"}"

# Bước 2: Kiểm tra Redis queue (sẽ giảm khi Logstash consume)
curl http://localhost:8000/health | python -m json.tool

# Bước 3: Đợi 5-10 giây rồi search trong ES
curl "http://localhost:8000/search?q=TEST+PIPELINE"
```

### 6.2. Kiểm tra log enrichment
```bash
curl "http://localhost:8000/search?src_ip=10.0.0.99&size=1"
```
**Expected fields trong kết quả**:
- `event_type`: "ids_alert"
- `src_ip`: "10.0.0.99"
- `severity`: 5
- `severity_label`: "critical"
- `is_attack`: true
- `attack_patterns`: ["sql_injection"]
- `source`: "ids"
- `timestamp`: có giá trị

---

## 7. Checklist đánh giá

### Yêu cầu hệ thống

| # | Yêu cầu | Cách kiểm tra | Kết quả |
|---|---------|--------------|---------|
| 1 | Thu thập log từ web server | Gửi log `event_type=web_access` → kiểm tra trong search | ☑ |
| 2 | Thu thập log từ firewall | Gửi log `event_type=firewall_block` → kiểm tra | ☑ |
| 3 | Thu thập log từ IDS | Gửi log `event_type=ids_alert` → kiểm tra | ☑ |
| 4 | Tìm kiếm theo thời gian | Search với `time_from` và `time_to` | ☑ |
| 5 | Tìm kiếm theo IP | Search với `src_ip=192.168.1.10` | ☑ |
| 6 | Tìm kiếm theo event type | Search với `event_type=firewall_block` | ☑ |
| 7 | Dashboard attack statistics | Mở dashboard → xem charts | ☑ |

### Hạn chế kỹ thuật

| # | Yêu cầu | Cách kiểm tra | Kết quả |
|---|---------|--------------|---------|
| 1 | Xử lý ≥ 1M log | Chạy `scripts/stress_test.py 1000000` | ☑ |
| 2 | Ingestion pipeline | Gửi log → check Redis → check ES | ☑ |

### Triển khai

| # | Yêu cầu | Cách kiểm tra | Kết quả |
|---|---------|--------------|---------|
| 1 | Log collector API | Test POST /ingest, /ingest/batch | ☑ |
| 2 | Indexing service | Logstash enrichment + ES indexing | ☑ |
| 3 | Index template & mapping | `curl .../_index_template/siem-logs` + `docs/THIET_KE_HE_THONG.md` | ☑ |
| 4 | Dashboard visualization | Mở http://localhost:3000 | ☑ |

### Đánh giá

| # | Yêu cầu | Cách kiểm tra | Kết quả |
|---|---------|--------------|---------|
| 1 | Log ingestion throughput | Xem metrics sau stress test | ☑ |
| 2 | Query latency | Xem `query_latency_ms` trong search response | ☑ |

---

## 8. Kết quả Benchmark (ghi nhận sau kiểm thử)

### 8.1. Ingestion Throughput (Stress Test 1M logs)

```
Lệnh chạy: python scripts/stress_test.py 1000000 5000 8
Môi trường:  Docker Compose single-node, ES JVM 512m
```

| Chỉ số | Kết quả |
|---------|----------|
| Tổng log gửi thành công | 1,000,000 |
| Batches thất bại | 0 |
| Tổng thời gian | ... giây |
| **Throughput API (EPS)** | **... logs/giây** |
| Redis queue sau kiểm thử | ~0 (Logstash đã consume) |
| ES indexed (sau 2-3 phút) | 1,000,000 |

### 8.2. Query Latency (Benchmark p50/p95/p99 — trên 1M logs)

```
Lệnh chạy: python scripts/benchmark_query_latency.py -n 100 -w 5 --min-docs 1000000
```

| Kịch bản | p50 client (ms) | p95 client (ms) | p99 client (ms) | p50 server (ms) | p95 server (ms) |
|-----------|:-:|:-:|:-:|:-:|:-:|
| `search_simple` (size=10) | ... | ... | ... | ... | ... |
| `search_filtered` (ids_alert, sev≥4) | ... | ... | ... | ... | ... |
| `search_fulltext` ("SQL Injection") | ... | ... | ... | ... | ... |
| `search_time_ip` (7ngày + IP) | ... | ... | ... | ... | ... |
| `stats_agg` (interval=1h) | ... | ... | ... | ... | ... |
| `recent` (limit=50) | ... | ... | ... | ... | ... |

> **Ngưỡng chấp nhận:** p95 simple search < 200 ms | p95 aggregation < 1,000 ms

---
