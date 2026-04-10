import requests
import json
import random
import time

API_URL = "http://localhost:8000/ingest"
EVENT_TYPES = ["web_access", "firewall_block", "ids_alert", "login_success"]
IPS = ["192.168.1." + str(i) for i in range(1, 255)]

def send_logs(total_entries=1000000):
    start_time = time.time()
    print(f"Đang bắt đầu gửi {total_entries} logs...")
    
    for i in range(total_entries):
        payload = {
            "event_type": random.choice(EVENT_TYPES),
            "src_ip": random.choice(IPS),
            "severity": random.randint(1, 5),
            "message": f"Log entry number {i}"
        }
        try:
            # Gửi log dạng async thông qua API
            requests.post(API_URL, json=payload)
        except:
            pass
        
        if i % 10000 == 0:
            print(f"Đã gửi: {i} logs...")

    end_time = time.time()
    duration = end_time - start_time
    print(f"Hoàn thành! Tổng thời gian: {duration:.2f} giây")
    print(f"Tốc độ trung bình: {total_entries/duration:.2f} logs/giây")

if __name__ == "__main__":
    send_logs(1000000) # Thử nghiệm với 1 triệu bản ghi