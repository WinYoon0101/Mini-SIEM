import requests
import time
import random

# Địa chỉ API của bạn
url = "http://localhost:8000/ingest"

# Danh sách dữ liệu mẫu để giả lập các nguồn khác nhau
event_types = ["web_access", "firewall_block", "ids_alert"]
ips = ["192.168.1.10", "10.0.0.5", "172.16.0.100", "8.8.8.8"]
messages = [
    "GET /admin HTTP/1.1 403",
    "Inbound connection blocked on port 22",
    "SQL Injection attempt detected",
    "User login successful",
    "Multiple failed login attempts"
]

print("--- Đang bắt đầu gửi 20 logs thử nghiệm ---")

for i in range(20):
    payload = {
        "event_type": random.choice(event_types),
        "src_ip": random.choice(ips),
        "severity": random.randint(1, 5),
        "message": f"Log thu {i+1}: {random.choice(messages)}"
    }
    
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print(f"✅ Đã gửi log {i+1}: {payload['event_type']} từ {payload['src_ip']}")
    except Exception as e:
        print(f"❌ Lỗi: {e}")
    
    # Nghỉ 0.5 giây giữa mỗi lần gửi để bạn kịp quan sát
    time.sleep(0.5)

print("--- Hoàn tất! Hãy mở Kibana để kiểm tra ---")