# Agent Service Dockerfile
# NOTE: For Docker deployments on Linux, use 'pid: host' in docker-compose
# to allow the container to see the host's running processes.
# winotify is Windows-only and is excluded from the Docker build.
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
# Exclude winotify (Windows-only) from the Docker build
RUN grep -v "winotify" requirements.txt > temp-req.txt && \
    pip install --no-cache-dir -r temp-req.txt && \
    rm temp-req.txt

COPY . .

CMD ["python", "agent.py"]
