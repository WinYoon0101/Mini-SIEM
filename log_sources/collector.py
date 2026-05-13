"""
Mini SIEM - Log Collector (Docker Container)
Thu thập log thực từ:
  1. Nginx access log → source=web_server
  2. ModSecurity WAF audit log → source=firewall / ids

Gửi batch về SIEM API mỗi BATCH_INTERVAL giây.
"""

import os
import re
import json
import time
import queue
import threading
import logging
from datetime import datetime
from pathlib import Path

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s"
)
logger = logging.getLogger("log-collector")

API_URL        = os.getenv("API_URL", "http://api-collector:8000")
BATCH_INTERVAL = int(os.getenv("BATCH_INTERVAL", "5"))
NGINX_LOG      = "/var/log/nginx/access_json.log"
MODSEC_LOG     = "/var/log/modsec/audit.log"

log_queue: queue.Queue = queue.Queue()

# ─────────────────────────── Batch Sender ───────────────────────────

def send_batches():
    """Gom log từ queue và gửi batch định kỳ."""
    while True:
        time.sleep(BATCH_INTERVAL)
        batch = []
        try:
            while True:
                batch.append(log_queue.get_nowait())
        except queue.Empty:
            pass

        if not batch:
            continue

        try:
            r = requests.post(
                f"{API_URL}/ingest/batch",
                json={"logs": batch},
                timeout=10,
            )
            if r.status_code == 200:
                rate = r.json().get("rate_per_second", 0)
                logger.info(f"Sent {len(batch)} logs → SIEM ({rate:.1f} logs/s)")
            else:
                logger.warning(f"API returned {r.status_code}: {r.text[:150]}")
        except requests.ConnectionError:
            logger.error("Cannot reach SIEM API — will retry next interval")
        except Exception as e:
            logger.error(f"Batch send failed: {e}")

# ─────────────────────────── File Tailer ────────────────────────────

def tail_file(filepath: str, callback):
    """Đọc liên tục cuối file, gọi callback cho mỗi dòng mới."""
    path = Path(filepath)
    while not path.exists():
        logger.info(f"Waiting for {filepath} to appear...")
        time.sleep(5)

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        try:
            f.seek(0, 2)          # Bắt đầu từ cuối file (bỏ qua log cũ)
        except Exception:
            pass
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            line = line.strip()
            if line:
                callback(line)

# ─────────────────────────── Nginx Parser ───────────────────────────

ATTACK_PATTERNS_REGEX = {
    r"union\s+select":              "sql_injection",
    r"'\s*or\s+'?1'?\s*=\s*'?1":   "sql_injection",
    r"<script[\s>]":                "xss",
    r"javascript\s*:":              "xss",
    r"\.\./\.\./":                  "path_traversal",
    r"etc/passwd":                  "path_traversal",
    r"cmd\.exe|/bin/bash|/bin/sh":  "command_injection",
}

SCANNER_UAS = ["nikto", "nmap", "sqlmap", "masscan", "zgrab",
               "gobuster", "dirbuster", "wfuzz", "nuclei"]


def classify_nginx(entry: dict) -> dict:
    status  = int(entry.get("status", 200))
    uri     = entry.get("uri", "/")
    method  = entry.get("method", "GET")
    ua      = entry.get("http_user_agent", "")

    text = (uri + " " + ua).lower()
    attack_patterns = []
    for pattern, name in ATTACK_PATTERNS_REGEX.items():
        if re.search(pattern, text, re.IGNORECASE) and name not in attack_patterns:
            attack_patterns.append(name)

    if any(s in ua.lower() for s in SCANNER_UAS) and "scanner" not in attack_patterns:
        attack_patterns.append("scanner")

    if attack_patterns:
        severity   = 5 if status < 400 else 4   # Tấn công thành công = critical
        event_type = "ids_alert"
        action     = "alert"
    elif status >= 500:
        severity, event_type, action = 3, "web_access", "allow"
    elif status >= 400:
        severity, event_type, action = 2, "web_access", "allow"
    else:
        severity, event_type, action = 1, "web_access", "allow"

    return {
        "event_type": event_type,
        "src_ip":     entry.get("remote_addr", "0.0.0.0"),
        "severity":   severity,
        "message":    f"{method} {uri[:120]} → HTTP {status}",
        "source":     "web_server",
        "timestamp":  entry.get("time", datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')),
        "port":       80,
        "protocol":   "TCP",
        "action":     action,
    }


def tail_nginx():
    logger.info(f"Nginx tailer started → {NGINX_LOG}")

    def on_line(line):
        try:
            entry = json.loads(line)
            log_queue.put(classify_nginx(entry))
        except Exception:
            pass

    tail_file(NGINX_LOG, on_line)

# ─────────────────────────── ModSecurity Parser ─────────────────────

MODSEC_SEV_MAP = {
    "CRITICAL": 5, "ERROR": 4, "WARNING": 3, "NOTICE": 2, "INFO": 1, "DEBUG": 1,
}

# OWASP CRS rule ID ranges → attack type
CRS_RULE_MAP = [
    (910000, 910999, "scanner"),
    (913000, 913999, "scanner"),
    (920000, 920999, "protocol_violation"),
    (930000, 930999, "path_traversal"),
    (931000, 931999, "path_traversal"),
    (932000, 932999, "command_injection"),
    (941000, 941999, "xss"),
    (942000, 942999, "sql_injection"),
    (943000, 943999, "session_fixation"),
    (944000, 944999, "java_attack"),
]


def rule_id_to_pattern(rule_id_str: str) -> str | None:
    if not rule_id_str.isdigit():
        return None
    rid = int(rule_id_str)
    for lo, hi, name in CRS_RULE_MAP:
        if lo <= rid <= hi:
            return name
    return None


def parse_modsec_line(line: str) -> dict | None:
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    try:
        txn      = data.get("transaction", {})
        client   = txn.get("client_ip", "0.0.0.0")
        req      = txn.get("request", {})
        uri      = req.get("uri", "/")
        method   = req.get("method", "GET")
        messages = txn.get("messages", [])

        if not messages:
            return None

        max_sev    = 1
        patterns   = []
        first_msg  = ""

        for msg in messages:
            details = msg.get("details", {})
            sev_str = details.get("severity", "NOTICE").upper()
            max_sev = max(max_sev, MODSEC_SEV_MAP.get(sev_str, 2))
            rid     = details.get("ruleId", "")
            p       = rule_id_to_pattern(rid)
            if p and p not in patterns:
                patterns.append(p)
            if not first_msg:
                first_msg = msg.get("message", "")[:100]

        event_type = "ids_alert" if max_sev >= 4 else "firewall_block"
        source     = "ids"       if max_sev >= 4 else "firewall"

        return {
            "event_type": event_type,
            "src_ip":     client,
            "severity":   max_sev,
            "message":    f"WAF [{','.join(patterns) or 'generic'}] {method} {uri[:80]} — {first_msg}",
            "source":     source,
            "timestamp":  datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            "port":       80,
            "protocol":   "TCP",
            "action":     "block",
        }
    except Exception as e:
        logger.debug(f"ModSec parse error: {e}")
        return None


def tail_modsecurity():
    logger.info(f"ModSecurity tailer started → {MODSEC_LOG}")

    def on_line(line):
        entry = parse_modsec_line(line)
        if entry:
            log_queue.put(entry)

    tail_file(MODSEC_LOG, on_line)

# ─────────────────────────── Main ───────────────────────────────────

if __name__ == "__main__":
    logger.info(f"Log Collector | API={API_URL} | interval={BATCH_INTERVAL}s")

    # Kiểm tra API trước khi bắt đầu
    for _ in range(10):
        try:
            r = requests.get(f"{API_URL}/health", timeout=3)
            logger.info(f"SIEM API health: {r.json().get('overall')}")
            break
        except Exception:
            logger.info("Waiting for SIEM API...")
            time.sleep(5)

    threads = [
        threading.Thread(target=tail_nginx,        daemon=True, name="nginx-tailer"),
        threading.Thread(target=tail_modsecurity,  daemon=True, name="modsec-tailer"),
        threading.Thread(target=send_batches,      daemon=False, name="batch-sender"),
    ]

    for t in threads:
        t.start()

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("Collector shutting down...")
