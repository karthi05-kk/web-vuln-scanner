################################################################################
# Web Vulnerability Scanner - Dockerfile
# 
# This Dockerfile creates a containerized environment for the scanner
# with all dependencies pre-installed.
#
# Usage:
#   docker build -t vuln-scanner .
#   docker run vuln-scanner "http://target.com/page?param=value" --pdf
#   docker run -v $(pwd)/reports:/app/reports vuln-scanner "http://target.com/page?param=value" --pdf
################################################################################

FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Copy project files
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Create reports directory
RUN mkdir -p /app/reports && \
    chmod 755 /app/reports

# Make script executable
RUN chmod +x /app/simple_main.py

# Set the entry point
ENTRYPOINT ["python3", "simple_main.py"]

# Default command (can be overridden)
CMD ["--help"]
