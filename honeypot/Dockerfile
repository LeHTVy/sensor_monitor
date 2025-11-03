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

# Create startup script
RUN echo '#!/bin/bash\n\
nginx &\n\
cd /app && python -m gunicorn --bind 0.0.0.0:5000 app.app:app\n\
' > /start.sh && chmod +x /start.sh

EXPOSE 80 443

CMD ["/start.sh"]
