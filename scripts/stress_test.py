"""
Mini SIEM - Stress Test
Kiểm tra throughput ingestion với batch API và concurrent requests.
Mục tiêu: ≥ 1M log entries
"""

import requests
import json
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

API_URL = "http://localhost:8000"

# ──────────────────────────── Log Templates ────────────────────────────

EVENT_TYPES = [
    "web_access", "firewall_block", "ids_alert",
    "login_success", "login_failure", "port_scan",
    "malware_detected", "dos_attack"
]

SOURCES = ["web_server", "firewall", "ids"]

IPS = [f"192.168.1.{i}" for i in range(1, 255)] + \
      [f"10.0.0.{i}" for i in range(1, 100)] + \
      [f"172.16.{j}.{i}" for j in range(0, 5) for i in range(1, 50)]

MESSAGES = {
    "web_access": [
        "GET /admin HTTP/1.1 403 Forbidden",
        "POST /api/login HTTP/1.1 200 OK",
        "GET /dashboard HTTP/1.1 200 OK",
        "GET /index.html HTTP/1.1 200 OK",
        "PUT /api/users/5 HTTP/1.1 401 Unauthorized",
    ],
    "firewall_block": [
        "Inbound connection blocked on port 22 (SSH brute force)",
        "Outbound connection blocked to known malware C2 server",
        "Inbound SYN flood detected and blocked from external IP",
        "Blocked port scan attempt on ports 1-1024",
        "DDoS attack traffic blocked - rate limit exceeded",
    ],
    "ids_alert": [
        "SQL Injection attempt detected: UNION SELECT * FROM users",
        "XSS cross-site scripting payload detected in form input",
        "Nmap port scan detected from external network",
        "Suspicious DNS tunneling activity detected",
        "Buffer overflow attempt on web application endpoint",
    ],
    "login_success": [
        "User admin login successful from internal network",
        "User john.doe logged in via SSO",
        "Service account api-svc authenticated",
    ],
    "login_failure": [
        "Multiple failed login attempts for user admin (brute force suspected)",
        "Login failed for unknown user 'root'",
        "Failed login: invalid password for user operator",
    ],
    "port_scan": [
        "Nmap SYN scan detected targeting ports 1-65535",
        "Slow port scan detected from external IP (stealth mode)",
        "UDP port scan detected on DNS and SNMP ports",
    ],
    "malware_detected": [
        "Trojan.GenericKD detected in downloaded file",
        "Ransomware signature matched in email attachment",
        "Cryptominer malware detected running on server",
    ],
    "dos_attack": [
        "HTTP flood attack detected - 10,000+ requests/sec",
        "SYN flood DDoS attack from botnet detected",
        "Application-layer DoS targeting /api/search endpoint",
    ],
}

PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS"]
ACTIONS = ["allow", "block", "alert", "drop"]


def generate_log():
    """Tạo một log entry random với dữ liệu thực tế"""
    event_type = random.choice(EVENT_TYPES)
    messages = MESSAGES.get(event_type, ["Generic log entry"])

    offset = random.randint(0, 86400)
    ts = (datetime.utcnow() - timedelta(seconds=offset)).strftime('%Y-%m-%dT%H:%M:%SZ')

    # ts = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

    return {
        "event_type": event_type,
        "src_ip": random.choice(IPS),
        "dest_ip": random.choice(IPS),
        "severity": random.randint(1, 5),
        "message": random.choice(messages),
        "source": random.choice(SOURCES),
        "timestamp": ts,
        "port": random.choice([22, 80, 443, 8080, 3306, 5432, 25, 53, 8443]),
        "protocol": random.choice(PROTOCOLS),
        "action": random.choice(ACTIONS),
    }


def send_batch(batch_size=1000):
    """Gửi một batch log entries"""
    logs = [generate_log() for _ in range(batch_size)]
    try:
        response = requests.post(
            f"{API_URL}/ingest/batch",
            json={"logs": logs},
            timeout=60
        )
        if response.status_code == 200:
            data = response.json()
            return {
                "success": True,
                "count": data.get("count", batch_size),
                "rate": data.get("rate_per_second", 0),
            }
        else:
            return {"success": False, "error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def run_stress_test(total_entries=1000000, batch_size=5000, max_workers=8):
    """
    Chạy stress test với concurrent batch requests.
    """
    print("=" * 60)
    print("  MINI SIEM - STRESS TEST")
    print("=" * 60)
    print(f"  Tổng entries:     {total_entries:,}")
    print(f"  Batch size:       {batch_size:,}")
    print(f"  Concurrent:       {max_workers} workers")
    print(f"  API endpoint:     {API_URL}/ingest/batch")
    print("=" * 60)

    try:
        health = requests.get(f"{API_URL}/health", timeout=5).json()
        initial_logs = health.get('total_indexed_logs', 0)
        print(f"\n✅ API Status:   {health.get('overall', 'unknown')}")
        print(f"   Redis:        {health.get('redis', 'unknown')}")
        print(f"   ES:           {health.get('elasticsearch', 'unknown')} (Current logs: {initial_logs:,})")
    except Exception as e:
        print(f"\n❌ Không thể kết nối API: {e}")
        print("   Hãy chắc chắn docker-compose đã chạy!")
        return

    num_batches = (total_entries + batch_size - 1) // batch_size
    print(f"\n📦 Tổng batches:  {num_batches}")
    print(f"🚀 Bắt đầu gửi...\n")

    start_time = time.time()
    total_sent = 0
    total_failed = 0
    batch_rates = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for i in range(num_batches):
            remaining = total_entries - (i * batch_size)
            current_batch = min(batch_size, remaining)
            futures.append(executor.submit(send_batch, current_batch))

        for i, future in enumerate(as_completed(futures)):
            result = future.result()
            if result["success"]:
                total_sent += result["count"]
                batch_rates.append(result["rate"])
            else:
                total_failed += 1

            progress = ((i + 1) / num_batches) * 100
            elapsed = time.time() - start_time
            rate = total_sent / elapsed if elapsed > 0 else 0

            if (i + 1) % 10 == 0 or (i + 1) == num_batches:
                print(f"  [{progress:5.1f}%] Sent: {total_sent:>10,} | "
                      f"Failed batches: {total_failed} | "
                      f"Rate: {rate:,.0f} logs/s | "
                      f"Elapsed: {elapsed:.1f}s")

    end_send_time = time.time()
    send_duration = end_send_time - start_time
    avg_send_rate = total_sent / send_duration if send_duration > 0 else 0
    avg_batch_rate = sum(batch_rates) / len(batch_rates) if batch_rates else 0

    print("\n⏳ Đang chờ Elasticsearch index toàn bộ dữ liệu...")
    
    target_logs = initial_logs + total_sent
    current_logs = initial_logs
    
    while current_logs < target_logs:
        try:
            health = requests.get(f"{API_URL}/health", timeout=5).json()
            current_logs = health.get('total_indexed_logs', 0)
            queued = health.get('redis_queue_length', 0)
            indexed_so_far = current_logs - initial_logs
            
            print(f"  [ES Indexing] Đã vào ES: {indexed_so_far:,}/{total_sent:,} | Redis Queue: {queued:,}", end="\r")
            
            if current_logs >= target_logs:
                print(f"  [ES Indexing] Đã vào ES: {total_sent:,}/{total_sent:,} | Redis Queue: 0{' ' * 20}")
                break
        except Exception:
            pass
        time.sleep(2)

    e2e_end_time = time.time()
    e2e_duration = e2e_end_time - start_time
    e2e_rate = total_sent / e2e_duration if e2e_duration > 0 else 0

    print("\n" + "=" * 60)
    print("  KẾT QUẢ STRESS TEST")
    print("=" * 60)
    print(f"  ✅ Tổng log đã gửi:         {total_sent:,}")
    print(f"  ❌ Batches thất bại:         {total_failed}")
    print(f"  ⏱  Thời gian gửi (API):      {send_duration:.2f} giây")
    print(f"  🚀 Tốc độ gửi (API):         {avg_send_rate:,.0f} logs/giây")
    print(f"  ⏱  Thời gian E2E (Tới ES):   {e2e_duration:.2f} giây")
    print(f"  🚀 Throughput E2E (Thực tế): {e2e_rate:,.0f} logs/giây")
    print("=" * 60)
    print("  ✅ STRESS TEST HOÀN TẤT!")
    print("=" * 60)


if __name__ == "__main__":
    import sys

    total = int(sys.argv[1]) if len(sys.argv) > 1 else 1000000
    batch = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else 8

    run_stress_test(total_entries=total, batch_size=batch, max_workers=workers)