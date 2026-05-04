#  Kiểm tra trạng thái của pipeline bằng cách gọi API /health mỗi giây và hiển thị thông tin về trạng thái tổng thể, độ dài hàng đợi Redis, số lượng log đã được index vào Elasticsearch và dung lượng index hiện tại. Chạy script này trong terminal để theo dõi hoạt động của pipeline.
# Cách sử dụng: python scripts/monitor_pipeline.py
import time
import requests
import os

API_URL = "http://localhost:8000/health"

def monitor():
    print(f"{'Thời gian':<12} | {'Trạng thái':<10} | {'Redis Queue':<15} | {'ES Indexed':<15} | {'Dung lượng (MB)':<15}")
    print("-" * 78)
    
    start_time = time.time()
    
    while True:
        try:
            res = requests.get(API_URL, timeout=2)
            if res.status_code == 200:
                data = res.json()
                
                # Lấy các thông số từ API /health
                overall = data.get("overall", "unknown")
                queue_len = data.get("redis_queue_length", 0)
                total_indexed = data.get("total_indexed_logs", 0)
                index_size_mb = data.get("index_size_mb", 0)
                
                elapsed = round(time.time() - start_time, 1)
                
                print(f"{elapsed:<11}s | {overall:<10} | {queue_len:<15} | {total_indexed:<15} | {index_size_mb:<15}")
            else:
                print(f"[!] API trả về lỗi: {res.status_code}")
        except Exception as e:
            print(f"[-] Lỗi kết nối API: {e}")
            
        time.sleep(1)

if __name__ == "__main__":
    try:
        monitor()
    except KeyboardInterrupt:
        print("\n[*] Dừng giám sát.")