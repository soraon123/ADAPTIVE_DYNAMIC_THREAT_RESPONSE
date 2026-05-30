FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=5004
ENV DATA_DIR=/app/data

EXPOSE 5004

CMD ["python", "app.py"]
