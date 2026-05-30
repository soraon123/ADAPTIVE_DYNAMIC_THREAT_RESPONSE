FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=5003
ENV DATA_DIR=/app/data

EXPOSE 5003

CMD ["python", "app.py"]
