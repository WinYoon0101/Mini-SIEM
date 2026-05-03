"""
Mini SIEM - Seed Data Generator
Tạo dữ liệu mẫu (20-100 log) để test dashboard nhanh.
Sử dụng: python seed_data.py [số_lượng]
"""

import requests
import random
import time
from datetime import datetime, timedelta

API_URL = "http://localhost:8000"

# Dữ liệu mẫu thực tế
SAMPLE_LOGS = [
    # Web Server Logs
    {"event_type": "web_access", "src_ip": "192.168.1.10", "severity": 1, "message": "GET /index.html HTTP/1.1 200 OK", "source": "web_server"},
    {"event_type": "web_access", "src_ip": "10.0.0.5", "severity": 3, "message": "GET /admin HTTP/1.1 403 Forbidden", "source": "web_server"},
    {"event_type": "web_access", "src_ip": "172.16.0.100", "severity": 2, "message": "POST /api/data HTTP/1.1 201 Created", "source": "web_server"},

    # Firewall Logs
    {"event_type": "firewall_block", "src_ip": "203.0.113.42", "severity": 4, "message": "Inbound connection blocked on port 22 (SSH brute force)", "source": "firewall"},
    {"event_type": "firewall_block", "src_ip": "198.51.100.15", "severity": 5, "message": "DDoS flood attack blocked - 50,000 SYN packets/sec", "source": "firewall"},
    {"event_type": "firewall_block", "src_ip": "203.0.113.88", "severity": 3, "message": "Outbound connection to known C2 server blocked", "source": "firewall"},

    # IDS Logs
    {"event_type": "ids_alert", "src_ip": "10.0.0.55", "severity": 5, "message": "SQL Injection attempt detected: UNION SELECT * FROM users WHERE 1=1", "source": "ids"},
    {"event_type": "ids_alert", "src_ip": "172.16.5.23", "severity": 4, "message": "XSS cross-site scripting payload detected in POST /comment", "source": "ids"},
    {"event_type": "ids_alert", "src_ip": "192.168.2.200", "severity": 3, "message": "Suspicious DNS tunneling activity - encoded data in DNS queries", "source": "ids"},

    # Login Logs
    {"event_type": "login_success", "src_ip": "192.168.1.50", "severity": 1, "message": "User admin login successful from internal network", "source": "web_server"},
    {"event_type": "login_failure", "src_ip": "203.0.113.99", "severity": 4, "message": "Multiple failed login attempts for user root (brute force suspected)", "source": "web_server"},
    {"event_type": "login_failure", "src_ip": "198.51.100.44", "severity": 3, "message": "Failed login for unknown user admin123", "source": "web_server"},

    # Port Scan
    {"event_type": "port_scan", "src_ip": "10.0.0.77", "severity": 4, "message": "Nmap SYN scan detected targeting ports 1-65535", "source": "ids"},

    # Malware
    {"event_type": "malware_detected", "src_ip": "192.168.3.15", "severity": 5, "message": "Ransomware signature matched in email attachment - blocked", "source": "ids"},

    # DoS
    {"event_type": "dos_attack", "src_ip": "203.0.113.200", "severity": 5, "message": "HTTP flood attack detected - 10,000+ requests/sec targeting /api/search", "source": "firewall"},
]


def seed(count=50):
    """Gửi seed data log entries"""
    print(f"🌱 Đang tạo {count} log entries mẫu...")

    # Check health first
    try:
        health = requests.get(f"{API_URL}/health", timeout=5).json()
        print(f"✅ API: {health.get('overall', 'unknown')}")
    except Exception as e:
        print(f"❌ Không thể kết nối API: {e}")
        return

    logs = []
    for i in range(count):
        template = random.choice(SAMPLE_LOGS).copy()
        # Random timestamp trong 24h gần đây
        offset = random.randint(0, 86400)
        template["timestamp"] = (datetime.utcnow() - timedelta(seconds=offset)).strftime('%Y-%m-%dT%H:%M:%SZ')
        # Random severity variation
        template["severity"] = max(1, min(5, template["severity"] + random.randint(-1, 1)))
        logs.append(template)

    # Gửi batch
    try:
        response = requests.post(f"{API_URL}/ingest/batch", json={"logs": logs}, timeout=30)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Đã gửi {data['count']} logs ({data['rate_per_second']} logs/s)")
        else:
            print(f"❌ Lỗi: HTTP {response.status_code}")
    except Exception as e:
        print(f"❌ Lỗi batch: {e}")
        # Fallback: gửi từng log
        print("🔄 Chuyển sang gửi từng log...")
        sent = 0
        for log in logs:
            try:
                r = requests.post(f"{API_URL}/ingest", json=log, timeout=5)
                if r.status_code == 200:
                    sent += 1
            except:
                pass
        print(f"✅ Đã gửi {sent}/{count} logs (single mode)")

    print("\n⏳ Đợi 5 giây cho Logstash xử lý...")
    time.sleep(5)

    # Verify
    try:
        health = requests.get(f"{API_URL}/health", timeout=5).json()
        print(f"📊 Logs indexed: {health.get('total_indexed_logs', 0)}")
        print(f"📬 Queue remaining: {health.get('redis_queue_length', 0)}")
    except:
        pass

    print("✅ Seed data hoàn tất! Mở dashboard tại http://localhost:3000")


if __name__ == "__main__":
    import sys
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    seed(count)
