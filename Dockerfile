# Use a lightweight python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements file
COPY requirements.txt .

# Install dependencies.
# Note: winotify is a Windows-specific library for local desktop notifications.
# It is excluded on Linux environments to prevent installation issues.
RUN grep -v "winotify" requirements.txt > temp-req.txt && \
    pip install --no-cache-dir -r temp-req.txt && \
    rm temp-req.txt

# Copy the rest of the application code
COPY . .

# Expose the Flask port
EXPOSE 5000

# Run the Flask application
CMD ["python", "app.py"]
