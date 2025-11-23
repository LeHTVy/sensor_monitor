FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tcpdump \
    net-tools \
    iputils-ping \
    netcat-openbsd \
    libpcap-dev \
    python3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY capture.py .
COPY receiver.py .
COPY analyzer.py .
COPY kafka_consumer.py .
COPY security_middleware.py .
COPY tool_detection.py .
COPY enrichment_engine.py .
COPY geoip_enricher.py .
COPY osint_enricher.py .

# Create directories
RUN mkdir -p /app/logs/packets /app/logs/analysis /app/logs/honeypot /app/logs/reports

# Create startup script
RUN echo '#!/bin/bash\n\
    echo "Starting Capture Server..."\n\
    \n\
    # Start packet capture in background\n\
    python capture.py &\n\
    CAPTURE_PID=$!\n\
    \n\
    # Start log receiver\n\
    python receiver.py &\n\
    RECEIVER_PID=$!\n\
    \n\
    # Function to handle shutdown\n\
    shutdown() {\n\
    echo "Shutting down..."\n\
    kill $CAPTURE_PID $RECEIVER_PID 2>/dev/null\n\
    exit 0\n\
    }\n\
    \n\
    # Set up signal handlers\n\
    trap shutdown SIGTERM SIGINT\n\
    \n\
    # Wait for processes\n\
    wait $CAPTURE_PID $RECEIVER_PID\n\
    ' > /start.sh && chmod +x /start.sh

# Expose receiver API port
EXPOSE 8080

# Run as root for packet capture capabilities
USER root

CMD ["/start.sh"]
