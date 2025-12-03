FROM python:3.11-slim

WORKDIR /app

# Install system dependencies and reconnaissance tools
RUN apt-get update && apt-get install -y \
    tcpdump \
    net-tools \
    iputils-ping \
    netcat-openbsd \
    libpcap-dev \
    python3-dev \
    build-essential \
    nmap \
    wget \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Amass (OWASP subdomain enumeration tool)
RUN wget https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip \
    && unzip amass_Linux_amd64.zip \
    && mv amass_Linux_amd64/amass /usr/local/bin/ \
    && chmod +x /usr/local/bin/amass \
    && rm -rf amass_Linux_amd64*

# Install Subfinder (ProjectDiscovery subdomain finder)
RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip \
    && unzip subfinder_2.6.3_linux_amd64.zip \
    && mv subfinder /usr/local/bin/ \
    && chmod +x /usr/local/bin/subfinder \
    && rm subfinder_2.6.3_linux_amd64.zip

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install BBOT (comprehensive OSINT/reconnaissance tool)
RUN pip install --no-cache-dir bbot

# Copy application code
COPY capture.py .
COPY receiver.py .
COPY analyzer.py .
COPY kafka_consumer.py .
COPY security_middleware.py .
COPY recon_service.py .
COPY report_generator.py .

# Create directories
RUN mkdir -p /app/logs/packets /app/logs/analysis /app/logs/honeypot /app/logs/reports /app/recon_reports \
    && chmod 777 /app/recon_reports

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
