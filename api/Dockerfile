# api/Dockerfile
FROM python:3.9-slim

WORKDIR /app

# Copy file yêu cầu và cài đặt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy toàn bộ code vào container
COPY . .

# Expose port
EXPOSE 8000

# Chạy API với Uvicorn (4 workers cho throughput cao)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]