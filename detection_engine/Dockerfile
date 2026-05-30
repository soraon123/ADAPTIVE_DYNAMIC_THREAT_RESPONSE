# Detection Engine Service Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Store data files in a volume-mounted directory
ENV DATA_DIR=/app/data
RUN mkdir -p /app/data

EXPOSE 5001

CMD ["python", "app.py"]
