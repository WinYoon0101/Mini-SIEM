from fastapi import FastAPI, Request
import redis
import json
import time

app = FastAPI()
# Kết nối tới Redis container
r = redis.Redis(host='redis', port=6379, db=0)

@app.post("/ingest")
async def ingest_log(request: Request):
    data = await request.json()
    # Thêm timestamp nếu log chưa có
    if 'timestamp' not in data:
        data['timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    
    # Đẩy vào Redis List tên là 'log_queue'
    r.lpush("log_queue", json.dumps(data))
    return {"status": "success", "message": "Log queued"}