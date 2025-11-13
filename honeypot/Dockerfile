FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nginx \
    openssl \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY network_monitor/ ./network_monitor/
COPY nginx/nginx.conf /etc/nginx/nginx.conf

# Create directories
RUN mkdir -p /app/logs /etc/nginx/certs /etc/ssl/certs /etc/ssl/private

# Generate self-signed SSL certificate
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/certs/nginx.key \
    -out /etc/nginx/certs/nginx.crt \
    -subj "/C=VN/ST=HCM/L=HCM/O=Honeypot/OU=IT/CN=honeypot.local"

# Set permissions
RUN chmod 600 /etc/nginx/certs/nginx.key
RUN chmod 644 /etc/nginx/certs/nginx.crt

# Remove default nginx site that conflicts with our config
RUN rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default

# Set Python path
ENV PYTHONPATH=/app/app:$PYTHONPATH

# Create startup script with proper Gunicorn config and Network Monitor
RUN echo '#!/bin/bash\n\
set -e\n\
echo "🚀 Starting Honeypot Services..."\n\
# Start nginx in background\n\
echo "📡 Starting Nginx..."\n\
nginx &\n\
# Wait a moment for nginx to start\n\
sleep 2\n\
echo "✅ Nginx started"\n\
# Start Network Monitor in background\n\
echo "🌐 Starting Network Monitor..."\n\
cd /app/network_monitor && PYTHONPATH=/app:/app/app:$PYTHONPATH python3 packet_sniffer.py --interface auto --kafka 10.8.0.1:9093 &\n\
NETWORK_MONITOR_PID=$!\n\
echo "✅ Network Monitor started (PID: $NETWORK_MONITOR_PID)"\n\
sleep 2\n\
# Start Gunicorn with proper configuration (foreground)\n\
echo "🐍 Starting Gunicorn Flask App..."\n\
cd /app && exec python -m gunicorn \\\n\
    --bind 0.0.0.0:5000 \\\n\
    --workers 2 \\\n\
    --timeout 120 \\\n\
    --keep-alive 5 \\\n\
    --graceful-timeout 30 \\\n\
    --access-logfile - \\\n\
    --error-logfile - \\\n\
    --log-level info \\\n\
    --max-requests 1000 \\\n\
    --max-requests-jitter 100 \\\n\
    --worker-connections 1000 \\\n\
    --config /dev/null \\\n\
    app.app:app\n\
' > /start.sh && chmod +x /start.sh

EXPOSE 80 443

CMD ["/start.sh"]
