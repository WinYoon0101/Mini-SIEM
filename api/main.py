"""
Mini SIEM - Log Collector API
Thu thập, tìm kiếm và thống kê log bảo mật từ nhiều nguồn.
"""

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum
from datetime import datetime
from elasticsearch import Elasticsearch
import redis
import json
import time
import logging
import asyncio
import uuid
from datetime import datetime, timedelta

# ──────────────────────────── Config ────────────────────────────

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mini-siem")

app = FastAPI(
    title="Mini SIEM API",
    description="Security Log Aggregation System",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Redis connection
redis_client = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)

# Elasticsearch connection
es_client = Elasticsearch(["http://elasticsearch:9200"])

# Index patterns
ES_INDEX_PATTERN = "siem-logs-*"
ES_ALERT_INDEX = "siem-alerts"

# Metrics tracking (in-memory) — reset khi API restart; chỉ phục vụ monitoring nội bộ
_metrics = {
    "total_ingested": 0,
    "total_queries": 0,
    "start_time": time.time(),
    "last_ingest_rate": 0.0,
    "last_query_latency_ms": 0.0,
}

# ──────────────────────────── Models ────────────────────────────

class EventType(str, Enum):
    WEB_ACCESS = "web_access"
    FIREWALL_BLOCK = "firewall_block"
    IDS_ALERT = "ids_alert"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    PORT_SCAN = "port_scan"
    MALWARE_DETECTED = "malware_detected"
    DOS_ATTACK = "dos_attack"


class LogEntry(BaseModel):
    """Schema cho một log entry"""
    event_type: str = Field(..., description="Loại sự kiện: web_access, firewall_block, ids_alert, ...")
    src_ip: str = Field(..., description="Địa chỉ IP nguồn")
    dest_ip: Optional[str] = Field(None, description="Địa chỉ IP đích")
    severity: int = Field(..., ge=1, le=5, description="Mức độ nghiêm trọng (1-5)")
    message: str = Field(..., description="Nội dung log")
    source: Optional[str] = Field(None, description="Nguồn log: web_server, firewall, ids")
    timestamp: Optional[str] = Field(None, description="Thời gian (ISO 8601)")
    port: Optional[int] = Field(None, description="Port liên quan")
    protocol: Optional[str] = Field(None, description="Giao thức: TCP, UDP, ICMP")
    action: Optional[str] = Field(None, description="Hành động: allow, block, alert")
    user: Optional[str] = Field(None, description="Tên user liên quan")


class BatchLogRequest(BaseModel):
    """Schema cho batch log ingestion"""
    logs: List[LogEntry] = Field(..., max_length=10000, description="Danh sách log entries (tối đa 10,000)")


class AlertUpdate(BaseModel):
    """Schema cập nhật trạng thái cảnh báo"""
    status: str = Field(..., description="Trạng thái: pending, investigating, resolved")


# ──────────────────────────── Helpers ────────────────────────────

def _enrich_log(data: dict) -> dict:
    """Thêm metadata vào log entry trước khi đẩy vào queue"""
    if not data.get("timestamp"):
        data["timestamp"] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

    # Classify severity level
    severity = data.get("severity", 1)
    if severity >= 5:
        data["severity_label"] = "critical"
    elif severity >= 4:
        data["severity_label"] = "high"
    elif severity >= 3:
        data["severity_label"] = "medium"
    elif severity >= 2:
        data["severity_label"] = "low"
    else:
        data["severity_label"] = "info"

    # Detect attack patterns from message
    msg = (data.get("message") or "").lower()
    attack_patterns = []
    if any(kw in msg for kw in ["sql injection", "sqli", "union select", "or 1=1"]):
        attack_patterns.append("sql_injection")
    if any(kw in msg for kw in ["xss", "cross-site", "<script"]):
        attack_patterns.append("xss")
    if any(kw in msg for kw in ["brute force", "failed login", "multiple failed"]):
        attack_patterns.append("brute_force")
    if any(kw in msg for kw in ["port scan", "nmap", "syn scan"]):
        attack_patterns.append("port_scan")
    if any(kw in msg for kw in ["dos", "ddos", "flood"]):
        attack_patterns.append("dos_attack")
    if any(kw in msg for kw in ["malware", "trojan", "ransomware", "virus"]):
        attack_patterns.append("malware")

    # Sự kiện tấn công theo loại nhưng message không khớp từ khóa heuristic ở trên
    # (vd. DNS tunneling, chặn C2 không chứa "malware"...) — vẫn cần nhãn cho thống kê/dashboard.
    if not attack_patterns and data.get("event_type") in (
        "firewall_block",
        "ids_alert",
        "login_failure",
        "port_scan",
        "malware_detected",
        "dos_attack",
    ):
        attack_patterns.append(data["event_type"])

    data["attack_patterns"] = attack_patterns
    data["is_attack"] = len(attack_patterns) > 0 or data.get("event_type") in [
        "firewall_block", "ids_alert", "login_failure", "port_scan",
        "malware_detected", "dos_attack"
    ]

    # Gán source nếu chưa có dựa trên event_type
    if not data.get("source"):
        event_source_map = {
            "web_access": "web_server",
            "firewall_block": "firewall",
            "ids_alert": "ids",
            "login_success": "web_server",
            "login_failure": "web_server",
            "port_scan": "ids",
            "malware_detected": "ids",
            "dos_attack": "firewall",
        }
        data["source"] = event_source_map.get(data.get("event_type"), "unknown")

    return data


def _push_to_queue(log_data: dict):
    """Đẩy log đã enrich vào Redis queue"""
    redis_client.lpush("log_queue", json.dumps(log_data))


# ES_INDEX_PATTERN được định nghĩa ở phần Config phía trên


# ──────────────────────────── Correlation Engine ────────────────────────────

async def correlation_engine():
    """
    Background task phân tích log liên tục để phát hiện tấn công và sinh Cảnh báo (Alerts).
    """
    logger.info("Correlation Engine started.")
    # Khởi tạo index alerts nếu chưa có
    try:
        if not es_client.indices.exists(index=ES_ALERT_INDEX):
            es_client.indices.create(index=ES_ALERT_INDEX, body={
                "mappings": {
                    "properties": {
                        "timestamp": {"type": "date"},
                        "src_ip": {"type": "keyword"},
                        "event_type": {"type": "keyword"},
                        "status": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "message": {"type": "text"}
                    }
                }
            })
    except Exception as e:
        logger.warning(f"Could not create alert index: {e}")

    while True:
        await asyncio.sleep(15)  # Chạy mỗi 15 giây
        try:
            now = datetime.utcnow()
            time_from = (now - timedelta(seconds=15)).strftime('%Y-%m-%dT%H:%M:%SZ')
            
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"timestamp": {"gte": time_from}}},
                            {"bool": {
                                "should": [
                                    {"term": {"is_attack": True}},
                                    {"range": {"severity": {"gte": 4}}}
                                ]
                            }}
                        ]
                    }
                },
                "aggs": {
                    "by_ip": {
                        "terms": {"field": "src_ip.keyword", "size": 100},
                        "aggs": {
                            "by_event": {
                                "terms": {"field": "event_type.keyword", "size": 10}
                            }
                        }
                    }
                },
                "size": 0
            }
            
            # Sử dụng asyncio.to_thread để không block event loop của FastAPI
            result = await asyncio.to_thread(es_client.search, index=ES_INDEX_PATTERN, body=query, ignore_unavailable=True)
            aggs = result.get("aggregations", {}).get("by_ip", {}).get("buckets", [])
            
            for ip_bucket in aggs:
                src_ip = ip_bucket["key"]
                for event_bucket in ip_bucket.get("by_event", {}).get("buckets", []):
                    event_type = event_bucket["key"]
                    count = event_bucket["doc_count"]
                    
                    # Rule: Nếu có >= 3 logs hoặc là loại sự kiện nguy hiểm
                    if count >= 3 or event_type in ["ids_alert", "malware_detected", "dos_attack"]:
                        # Kiểm tra xem có cảnh báo đang pending không
                        pending_query = {
                            "query": {
                                "bool": {
                                    "must": [
                                        {"term": {"src_ip": src_ip}},
                                        {"term": {"event_type": event_type}},
                                        {"term": {"status": "pending"}}
                                    ]
                                }
                            }
                        }
                        existing = await asyncio.to_thread(es_client.search, index=ES_ALERT_INDEX, body=pending_query, ignore_unavailable=True)
                        if existing.get("hits", {}).get("total", {}).get("value", 0) > 0:
                            # Cập nhật số lượng log liên quan
                            alert_id = existing["hits"]["hits"][0]["_id"]
                            await asyncio.to_thread(
                                es_client.update,
                                index=ES_ALERT_INDEX, 
                                id=alert_id, 
                                body={"script": {"source": "ctx._source.related_logs += params.count", "params": {"count": count}}}
                            )
                        else:
                            # Tạo cảnh báo mới
                            alert_doc = {
                                "timestamp": now.strftime('%Y-%m-%dT%H:%M:%SZ'),
                                "src_ip": src_ip,
                                "event_type": event_type,
                                "related_logs": count,
                                "status": "pending",
                                "severity": "high" if count > 10 else "medium",
                                "message": f"Phát hiện {count} sự kiện {event_type} từ {src_ip}"
                            }
                            await asyncio.to_thread(es_client.index, index=ES_ALERT_INDEX, body=alert_doc)
        except Exception as e:
            logger.error(f"Correlation engine error: {e}")


@app.on_event("startup")
async def startup_event():
    asyncio.create_task(correlation_engine())


# ──────────────────────────── API Endpoints ────────────────────────────

# ─── 1. Ingestion ───

@app.post("/ingest", tags=["Ingestion"])
async def ingest_single_log(log: LogEntry):
    """
    Nhận và xử lý một log entry đơn lẻ.
    Log được enrich metadata rồi đẩy vào Redis queue → Logstash → Elasticsearch.
    """
    try:
        data = _enrich_log(log.dict())
        _push_to_queue(data)
        _metrics["total_ingested"] += 1
        return {"status": "success", "message": "Log queued successfully"}
    except redis.ConnectionError:
        raise HTTPException(status_code=503, detail="Không thể kết nối Redis")
    except Exception as e:
        logger.error(f"Ingestion error: {e}")
        raise HTTPException(status_code=500, detail=f"Lỗi xử lý log: {str(e)}")


@app.post("/ingest/batch", tags=["Ingestion"])
async def ingest_batch_logs(batch: BatchLogRequest):
    """
    Nhận batch log entries (tối đa 10,000 logs/request).
    Tối ưu cho throughput cao khi cần ingest lượng lớn log.
    """
    try:
        start = time.time()
        count = len(batch.logs)

        # Pipeline Redis để push nhanh hơn
        pipe = redis_client.pipeline()
        for log in batch.logs:
            data = _enrich_log(log.dict())
            pipe.lpush("log_queue", json.dumps(data))
        pipe.execute()

        elapsed = time.time() - start
        rate = count / elapsed if elapsed > 0 else 0

        _metrics["total_ingested"] += count
        _metrics["last_ingest_rate"] = rate

        return {
            "status": "success",
            "count": count,
            "elapsed_seconds": round(elapsed, 3),
            "rate_per_second": round(rate, 1),
        }
    except redis.ConnectionError:
        raise HTTPException(status_code=503, detail="Không thể kết nối Redis")
    except Exception as e:
        logger.error(f"Batch ingestion error: {e}")
        raise HTTPException(status_code=500, detail=f"Lỗi batch ingestion: {str(e)}")


# ─── 2. Search ───

@app.get("/search", tags=["Search"])
async def search_logs(
    q: Optional[str] = Query(None, description="Full-text search query"),
    src_ip: Optional[str] = Query(None, description="Filter theo IP nguồn"),
    dest_ip: Optional[str] = Query(None, description="Filter theo IP đích"),
    event_type: Optional[str] = Query(None, description="Filter theo event type"),
    severity_min: Optional[int] = Query(None, ge=1, le=5, description="Severity tối thiểu"),
    severity_max: Optional[int] = Query(None, ge=1, le=5, description="Severity tối đa"),
    source: Optional[str] = Query(None, description="Filter theo nguồn (web_server, firewall, ids)"),
    is_attack: Optional[bool] = Query(None, description="Chỉ hiển thị attack events"),
    time_from: Optional[str] = Query(None, description="Thời gian bắt đầu (ISO 8601)"),
    time_to: Optional[str] = Query(None, description="Thời gian kết thúc (ISO 8601)"),
    page: int = Query(1, ge=1, description="Trang hiện tại"),
    size: int = Query(50, ge=1, le=500, description="Số kết quả mỗi trang"),
    sort_by: str = Query("timestamp", description="Trường sắp xếp"),
    sort_order: str = Query("desc", description="Thứ tự: asc hoặc desc"),
):
    """
    Tìm kiếm log với nhiều bộ lọc: thời gian, IP, event type, severity, nguồn.
    Hỗ trợ pagination và sắp xếp.
    """
    try:
        start = time.time()

        # Build Elasticsearch query
        must_clauses = []
        filter_clauses = []

        if q:
            must_clauses.append({"query_string": {"query": q}})

        if src_ip:
            filter_clauses.append({"term": {"src_ip.keyword": src_ip}})
        if dest_ip:
            filter_clauses.append({"term": {"dest_ip.keyword": dest_ip}})
        if event_type:
            filter_clauses.append({"term": {"event_type.keyword": event_type}})
        if source:
            filter_clauses.append({"term": {"source.keyword": source}})
        if is_attack is not None:
            filter_clauses.append({"term": {"is_attack": is_attack}})

        # Severity range
        severity_range = {}
        if severity_min is not None:
            severity_range["gte"] = severity_min
        if severity_max is not None:
            severity_range["lte"] = severity_max
        if severity_range:
            filter_clauses.append({"range": {"severity": severity_range}})

        # Time range
        time_range = {}
        if time_from:
            time_range["gte"] = time_from
        if time_to:
            time_range["lte"] = time_to
        if time_range:
            filter_clauses.append({"range": {"timestamp": time_range}})

        query_body = {
            "bool": {
                "must": must_clauses if must_clauses else [{"match_all": {}}],
                "filter": filter_clauses,
            }
        }

        offset = (page - 1) * size

        result = es_client.search(
            index=ES_INDEX_PATTERN,
            body={
                "query": query_body,
                "sort": [{sort_by: {"order": sort_order, "unmapped_type": "date"}}],
                "from": offset,
                "size": size,
            },
            ignore_unavailable=True,
        )

        elapsed_ms = round((time.time() - start) * 1000, 2)
        _metrics["total_queries"] += 1
        _metrics["last_query_latency_ms"] = elapsed_ms

        hits = result.get("hits", {})
        total = hits.get("total", {}).get("value", 0)
        logs = []
        for hit in hits.get("hits", []):
            log_item = hit["_source"]
            log_item["_id"] = hit["_id"]
            log_item["_index"] = hit["_index"]
            logs.append(log_item)

        return {
            "status": "success",
            "total": total,
            "page": page,
            "size": size,
            "total_pages": (total + size - 1) // size if total > 0 else 0,
            "query_latency_ms": elapsed_ms,
            "results": logs,
        }
    except Exception as e:
        logger.error(f"Search error: {e}")
        raise HTTPException(status_code=500, detail=f"Lỗi tìm kiếm: {str(e)}")


# ─── 3. Statistics ───

@app.get("/stats", tags=["Statistics"])
async def get_attack_statistics(
    time_from: Optional[str] = Query(None, description="Thời gian bắt đầu"),
    time_to: Optional[str] = Query(None, description="Thời gian kết thúc"),
    interval: str = Query("1h", description="Khoảng thời gian group (1h, 1d, 1w)"),
):
    """
    Thống kê attack: top IPs, event type distribution, severity breakdown, timeline.
    Phục vụ cho Dashboard visualization.
    """
    try:
        start = time.time()

        # Time filter
        time_filter = []
        time_range = {}
        if time_from:
            time_range["gte"] = time_from
        if time_to:
            time_range["lte"] = time_to
        if time_range:
            time_filter.append({"range": {"timestamp": time_range}})

        base_query = {"bool": {"filter": time_filter}} if time_filter else {"match_all": {}}

        body = {
            "size": 0,
            "query": base_query,
            "aggs": {
                # Tổng số log
                "total_logs": {"value_count": {"field": "event_type.keyword"}},

                # Tổng attacks
                "total_attacks": {
                    "filter": {"term": {"is_attack": True}},
                },

                # Unique IPs
                "unique_ips": {"cardinality": {"field": "src_ip.keyword"}},

                # Average severity
                "avg_severity": {"avg": {"field": "severity"}},

                # Event type distribution
                "event_types": {
                    "terms": {"field": "event_type.keyword", "size": 20}
                },

                # Top attacking IPs
                "top_attackers": {
                    "filter": {"term": {"is_attack": True}},
                    "aggs": {
                        "ips": {
                            "terms": {"field": "src_ip.keyword", "size": 10}
                        }
                    }
                },

                # Severity breakdown
                "severity_breakdown": {
                    "terms": {"field": "severity", "size": 5}
                },

                # Severity label breakdown
                "severity_labels": {
                    "terms": {"field": "severity_label.keyword", "size": 5}
                },

                # Source distribution
                "source_distribution": {
                    "terms": {"field": "source.keyword", "size": 10}
                },

                # Attack patterns
                "attack_patterns": {
                    "terms": {"field": "attack_patterns", "size": 10}
                },

                # Timeline (histogram)
                "timeline": {
                    "date_histogram": {
                        "field": "timestamp",
                        "fixed_interval": interval,
                        "min_doc_count": 0,
                    },
                    "aggs": {
                        "attacks": {
                            "filter": {"term": {"is_attack": True}}
                        }
                    }
                },

                # Attacks timeline
                "attack_timeline": {
                    "filter": {"term": {"is_attack": True}},
                    "aggs": {
                        "over_time": {
                            "date_histogram": {
                                "field": "timestamp",
                                "fixed_interval": interval,
                                "min_doc_count": 0,
                            }
                        }
                    }
                },
            },
        }

        result = es_client.search(
            index=ES_INDEX_PATTERN,
            body=body,
            ignore_unavailable=True,
        )

        elapsed_ms = round((time.time() - start) * 1000, 2)
        aggs = result.get("aggregations", {})

        return {
            "status": "success",
            "query_latency_ms": elapsed_ms,
            "summary": {
                "total_logs": aggs.get("total_logs", {}).get("value", 0),
                "total_attacks": aggs.get("total_attacks", {}).get("doc_count", 0),
                "unique_ips": aggs.get("unique_ips", {}).get("value", 0),
                "avg_severity": round(aggs.get("avg_severity", {}).get("value", 0) or 0, 2),
            },
            "event_types": [
                {"name": b["key"], "count": b["doc_count"]}
                for b in aggs.get("event_types", {}).get("buckets", [])
            ],
            "top_attackers": [
                {"ip": b["key"], "count": b["doc_count"]}
                for b in aggs.get("top_attackers", {}).get("ips", {}).get("buckets", [])
            ],
            "severity_breakdown": [
                {"level": b["key"], "count": b["doc_count"]}
                for b in aggs.get("severity_breakdown", {}).get("buckets", [])
            ],
            "severity_labels": [
                {"label": b["key"], "count": b["doc_count"]}
                for b in aggs.get("severity_labels", {}).get("buckets", [])
            ],
            "source_distribution": [
                {"source": b["key"], "count": b["doc_count"]}
                for b in aggs.get("source_distribution", {}).get("buckets", [])
            ],
            "attack_patterns": [
                {"pattern": b["key"], "count": b["doc_count"]}
                for b in aggs.get("attack_patterns", {}).get("buckets", [])
            ],
            "timeline": [
                {
                    "time": b["key_as_string"],
                    "total": b["doc_count"],
                    "attacks": b.get("attacks", {}).get("doc_count", 0),
                }
                for b in aggs.get("timeline", {}).get("buckets", [])
            ],
        }
    except Exception as e:
        logger.error(f"Stats error: {e}")
        raise HTTPException(status_code=500, detail=f"Lỗi thống kê: {str(e)}")


# ─── 4. Recent Logs (for live feed) ───

@app.get("/recent", tags=["Search"])
async def get_recent_logs(
    limit: int = Query(20, ge=1, le=100, description="Số log gần nhất"),
):
    """Lấy log gần nhất cho live feed trên dashboard."""
    try:
        result = es_client.search(
            index=ES_INDEX_PATTERN,
            body={
                "query": {"match_all": {}},
                "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
                "size": limit,
            },
            ignore_unavailable=True,
        )

        logs = []
        for hit in result.get("hits", {}).get("hits", []):
            log_item = hit["_source"]
            log_item["_id"] = hit["_id"]
            logs.append(log_item)

        return {"status": "success", "count": len(logs), "results": logs}
    except Exception as e:
        logger.error(f"Recent logs error: {e}")
        raise HTTPException(status_code=500, detail=f"Lỗi lấy log gần nhất: {str(e)}")


# ─── 4.5. Alerts ───

@app.get("/alerts", tags=["Alerts"])
async def get_alerts(
    status: Optional[str] = Query(None, description="Lọc theo trạng thái: pending, investigating, resolved"),
    size: int = Query(50, ge=1, le=500, description="Số kết quả"),
):
    """Lấy danh sách các cảnh báo (Alerts) từ Correlation Engine."""
    try:
        query_body = {"match_all": {}}
        if status:
            query_body = {"term": {"status": status}}

        result = es_client.search(
            index=ES_ALERT_INDEX,
            body={
                "query": query_body,
                "sort": [{"timestamp": {"order": "desc"}}],
                "size": size,
            },
            ignore_unavailable=True,
        )

        alerts = []
        for hit in result.get("hits", {}).get("hits", []):
            alert = hit["_source"]
            alert["_id"] = hit["_id"]
            alerts.append(alert)

        return {"status": "success", "total": len(alerts), "results": alerts}
    except Exception as e:
        logger.error(f"Alerts retrieval error: {e}")
        raise HTTPException(status_code=500, detail=f"Lỗi lấy danh sách cảnh báo: {str(e)}")


@app.patch("/alerts/{alert_id}", tags=["Alerts"])
async def update_alert_status(alert_id: str, update: AlertUpdate):
    """Cập nhật trạng thái của một cảnh báo."""
    try:
        es_client.update(
            index=ES_ALERT_INDEX,
            id=alert_id,
            body={"doc": {"status": update.status}}
        )
        return {"status": "success", "message": f"Đã cập nhật trạng thái thành {update.status}"}
    except Exception as e:
        logger.error(f"Alert update error: {e}")
        raise HTTPException(status_code=500, detail=f"Lỗi cập nhật cảnh báo: {str(e)}")


# ─── 5. Health Check ───

@app.get("/health", tags=["System"])
async def health_check():
    """Kiểm tra tình trạng hoạt động của Redis và Elasticsearch."""
    health = {"api": "ok", "redis": "unknown", "elasticsearch": "unknown"}

    # Check Redis
    try:
        redis_client.ping()
        health["redis"] = "ok"
    except Exception:
        health["redis"] = "error"

    # Check Elasticsearch
    try:
        es_info = es_client.info()
        health["elasticsearch"] = "ok"
        health["es_version"] = es_info.get("version", {}).get("number", "unknown")

        # Check index stats
        try:
            stats = es_client.indices.stats(index=ES_INDEX_PATTERN)
            total_docs = stats.get("_all", {}).get("primaries", {}).get("docs", {}).get("count", 0)
            total_size = stats.get("_all", {}).get("primaries", {}).get("store", {}).get("size_in_bytes", 0)
            health["total_indexed_logs"] = total_docs
            health["index_size_bytes"] = total_size
            health["index_size_mb"] = round(total_size / (1024 * 1024), 2)
        except Exception:
            health["total_indexed_logs"] = 0
    except Exception:
        health["elasticsearch"] = "error"

    # Check Redis queue length
    try:
        health["redis_queue_length"] = redis_client.llen("log_queue")
    except Exception:
        health["redis_queue_length"] = -1

    overall = "ok" if health["redis"] == "ok" and health["elasticsearch"] == "ok" else "degraded"
    health["overall"] = overall

    return health


# ─── 6. Metrics ───

@app.get("/metrics", tags=["System"])
async def get_metrics():
    """
    Thông số hiệu suất: throughput ingestion, query latency, uptime.
    """
    uptime = time.time() - _metrics["start_time"]
    avg_ingest_rate = _metrics["total_ingested"] / uptime if uptime > 0 else 0

    return {
        "status": "success",
        "uptime_seconds": round(uptime, 1),
        "total_ingested": _metrics["total_ingested"],
        "total_queries": _metrics["total_queries"],
        "avg_ingest_rate_per_second": round(avg_ingest_rate, 2),
        "last_batch_ingest_rate": round(_metrics["last_ingest_rate"], 2),
        "last_query_latency_ms": round(_metrics["last_query_latency_ms"], 2),
    }


# ─── 7. Root ───

@app.get("/", tags=["System"])
async def root():
    return {
        "name": "Mini SIEM API",
        "version": "1.0.0",
        "description": "Security Log Aggregation System",
        "endpoints": {
            "POST /ingest": "Nhận single log entry",
            "POST /ingest/batch": "Nhận batch log entries (max 10,000)",
            "GET /search": "Tìm kiếm log với filters",
            "GET /stats": "Thống kê attack",
            "GET /recent": "Log gần nhất (live feed)",
            "GET /alerts": "Lấy danh sách cảnh báo (Alerts)",
            "PATCH /alerts/{id}": "Cập nhật trạng thái cảnh báo",
            "GET /health": "Health check",
            "GET /metrics": "Performance metrics",
            "GET /docs": "API documentation (Swagger)",
        }
    }