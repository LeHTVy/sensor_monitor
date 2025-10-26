FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nginx \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY nginx/ /etc/nginx/

# Create directories
RUN mkdir -p /app/logs /etc/ssl/certs /etc/ssl/private

# Generate self-signed SSL certificate
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/honeypot.key \
    -out /etc/ssl/certs/honeypot.crt \
    -subj "/C=VN/ST=HCM/L=HCM/O=Honeypot/OU=IT/CN=honeypot.local"

# Set permissions
RUN chmod 600 /etc/ssl/private/honeypot.key
RUN chmod 644 /etc/ssl/certs/honeypot.crt

# Create startup script
RUN echo '#!/bin/bash\n\
nginx &\n\
cd /app && python -m gunicorn --bind 0.0.0.0:5000 app.app:app\n\
' > /start.sh && chmod +x /start.sh

EXPOSE 80 443

CMD ["/start.sh"]
