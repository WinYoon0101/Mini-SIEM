# python scripts/test_alerts.py

import requests
import time
from datetime import datetime

API_URL = "http://localhost:8000"

def send_log(event_type, src_ip, severity=3, message="Test log"):
    """Gửi một log entry giả lập qua API"""
    log = {
        "event_type": event_type,
        "src_ip": src_ip,
        "severity": severity,
        "message": message,
        "timestamp": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    }
    try:
        res = requests.post(f"{API_URL}/ingest", json=log, timeout=5)
        if res.status_code == 200:
            return True
        else:
            print(f"   [!] Lỗi API khi gửi log: {res.text}")
    except Exception as e:
        print(f"   [!] Lỗi kết nối khi gửi log: {e}")
    return False

def check_alerts(src_ip, event_type):
    """Kiểm tra API /alerts xem có alert tương ứng không"""
    try:
        res = requests.get(f"{API_URL}/alerts", params={"size": 100}, timeout=5)
        if res.status_code == 200:
            alerts = res.json().get("results", [])
            for alert in alerts:
                if alert["src_ip"] == src_ip and alert["event_type"] == event_type:
                    return alert
    except Exception:
        pass
    return None

def run_test():
    print("=" * 60)
    print("   KIỂM THỬ CORRELATION ENGINE (ALERTS)")
    print("=" * 60)
    
    # Kịch bản 1: Cảnh báo do số lượng (>= 3 log cùng loại)
    ip_1 = "10.99.99.1"
    event_1 = "login_failure"
    print(f"\n[Kịch bản 1] Gửi 4 logs '{event_1}' từ IP {ip_1}")
    print("  -> Kỳ vọng: Triggers 1 alert vì số lượng >= 3")
    for i in range(4):
        send_log(event_1, ip_1, 3, f"Failed login attempt {i+1}")
        time.sleep(0.1)
        
    # Kịch bản 2: Cảnh báo do tính chất sự kiện nguy hiểm (dù chỉ 1 log)
    ip_2 = "10.99.99.2"
    event_2 = "ids_alert"
    print(f"\n[Kịch bản 2] Gửi 1 log '{event_2}' từ IP {ip_2}")
    print("  -> Kỳ vọng: Triggers 1 alert ngay lập tức vì đây là sự kiện nghiêm trọng")
    send_log(event_2, ip_2, 5, "SQL Injection payload detected in URI")
    
    print("\n⏳ Đã gửi xong log. Đang chờ xử lý...")
    print("   - Pipeline cần thời gian: Redis -> Logstash -> Elasticsearch (Refresh 30s)")
    print("   - Correlation Engine có cửa sổ quét lùi 45s để đảm bảo không sót log.")
    print("   => Vui lòng đợi từ 60-80 giây...\n")
    
    wait_time = 0
    max_wait = 90
    found_1 = False
    found_2 = False
    
    while wait_time <= max_wait:
        print(f"   Đang quét API Alerts... ({wait_time}s / {max_wait}s)", end="\r")
        
        if not found_1:
            alert1 = check_alerts(ip_1, event_1)
            if alert1:
                print(f"\n   ✅ [PASS] Kịch bản 1: Đã tạo Alert! Mức độ: {alert1['severity']} | Tin nhắn: {alert1['message']} | Logs liên quan: {alert1['related_logs']}")
                found_1 = True
                
        if not found_2:
            alert2 = check_alerts(ip_2, event_2)
            if alert2:
                print(f"\n   ✅ [PASS] Kịch bản 2: Đã tạo Alert! Mức độ: {alert2['severity']} | Tin nhắn: {alert2['message']} | Logs liên quan: {alert2['related_logs']}")
                found_2 = True
                
        if found_1 and found_2:
            break
            
        time.sleep(5)
        wait_time += 5
        
    print("\n" + "=" * 60)
    if found_1 and found_2:
        print("🎉 TỔNG KẾT: TẤT CẢ KỊCH BẢN ĐỀU PASS!")
        print("   Correlation Engine hoạt động chính xác 100%.")
    else:
        print("❌ TỔNG KẾT: TEST FAILED (Không tìm thấy đủ Alerts)")
        if not found_1: print(f"   - Thiếu alert cho Kịch bản 1 ({ip_1} - {event_1})")
        if not found_2: print(f"   - Thiếu alert cho Kịch bản 2 ({ip_2} - {event_2})")
    print("=" * 60)

if __name__ == "__main__":
    run_test()
