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

# Create application directory structure
RUN mkdir -p /app/core /app/services /app/recon /app/malware /app/routes

# Copy main application
COPY receiver.py .

# Copy core modules
COPY core/__init__.py core/
COPY core/kafka_consumer.py core/
COPY core/security_middleware.py core/

# Copy service modules
COPY services/__init__.py services/
COPY services/analyzer.py services/
COPY services/api_keys_manager.py services/
COPY services/stix_formatter.py services/

# Copy recon modules
COPY recon/__init__.py recon/
COPY recon/recon_service.py recon/
COPY recon/report_generator.py recon/

# Copy malware modules
COPY malware/__init__.py malware/
COPY malware/malware_collector.py malware/
COPY malware/malware_kafka_consumer.py malware/

# Copy route modules
COPY routes/__init__.py routes/
COPY routes/auth.py routes/
COPY routes/stats.py routes/
COPY routes/logs.py routes/
COPY routes/attackers.py routes/
COPY routes/stix.py routes/

# Create log directories
RUN mkdir -p /app/logs/packets /app/logs/analysis /app/logs/honeypot /app/logs/reports /app/recon_reports \
    && chmod 777 /app/recon_reports /app/logs

# Create startup script
RUN echo '#!/bin/bash\n\
    echo "Starting Capture Server..."\n\
    \n\
    # Start log receiver (main service)\n\
    python receiver.py &\n\
    RECEIVER_PID=$!\n\
    \n\
    # Function to handle shutdown\n\
    shutdown() {\n\
    echo "Shutting down..."\n\
    kill $RECEIVER_PID 2>/dev/null\n\
    exit 0\n\
    }\n\
    \n\
    # Set up signal handlers\n\
    trap shutdown SIGTERM SIGINT\n\
    \n\
    # Wait for process\n\
    wait $RECEIVER_PID\n\
    ' > /start.sh && chmod +x /start.sh

# Expose receiver API port
EXPOSE 8080

# Run as root for packet capture capabilities
USER root

CMD ["/start.sh"]
