#!/bin/bash

# Honeypot Server Deployment Script
# Target: 172.235.245.60

set -e

echo "=========================================="
echo "Honeypot Server Deployment"
echo "Target: 172.235.245.60"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
HONEYPOT_IP="172.235.245.60"
CAPTURE_IP="172.232.246.68"
HONEYPOT_DIR="/opt/honeypot"
LOG_DIR="/var/log/honeypot"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "Please run as root (use sudo)"
    exit 1
fi

print_status "Starting honeypot deployment..."

# Update system
print_status "Updating system packages..."
apt-get update -y
apt-get upgrade -y

# Install Docker
print_status "Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    systemctl enable docker
    systemctl start docker
    rm get-docker.sh
    print_status "Docker installed successfully"
else
    print_status "Docker already installed"
fi

# Install Docker Compose
print_status "Installing Docker Compose..."
if ! command -v docker-compose &> /dev/null; then
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    print_status "Docker Compose installed successfully"
else
    print_status "Docker Compose already installed"
fi

# Create directories
print_status "Creating directories..."
mkdir -p $HONEYPOT_DIR
mkdir -p $LOG_DIR
mkdir -p $HONEYPOT_DIR/logs
mkdir -p $HONEYPOT_DIR/uploads

# Copy honeypot files
print_status "Copying honeypot files..."
if [ -d "honeypot" ]; then
    cp -r honeypot/* $HONEYPOT_DIR/
    print_status "Honeypot files copied successfully"
else
    print_error "Honeypot directory not found. Please run this script from the project root."
    exit 1
fi

# Set permissions
print_status "Setting permissions..."
chown -R root:root $HONEYPOT_DIR
chmod -R 755 $HONEYPOT_DIR
chown -R root:root $LOG_DIR
chmod -R 755 $LOG_DIR

# Configure environment
print_status "Configuring environment..."
cat > $HONEYPOT_DIR/.env << EOF
FLASK_ENV=production
CAPTURE_SERVER_URL=http://$CAPTURE_IP:8080
HONEYPOT_IP=$HONEYPOT_IP
LOG_LEVEL=INFO
EOF

# Update docker-compose.yml with correct IPs
print_status "Updating configuration..."
sed -i "s/172.232.246.68/$CAPTURE_IP/g" $HONEYPOT_DIR/docker-compose.yml

# Configure firewall
print_status "Configuring firewall..."
ufw --force enable
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow from $CAPTURE_IP to any port 80
ufw allow from $CAPTURE_IP to any port 443
print_status "Firewall configured"

# Start honeypot services
print_status "Starting honeypot services..."
cd $HONEYPOT_DIR
docker-compose down 2>/dev/null || true
docker-compose up -d

# Wait for services to start
print_status "Waiting for services to start..."
sleep 30

# Check if services are running
print_status "Checking service status..."
if docker-compose ps | grep -q "Up"; then
    print_status "Honeypot services started successfully"
else
    print_error "Failed to start honeypot services"
    docker-compose logs
    exit 1
fi

# Test honeypot
print_status "Testing honeypot..."
if curl -s -o /dev/null -w "%{http_code}" http://localhost | grep -q "200\|302"; then
    print_status "Honeypot is responding correctly"
else
    print_warning "Honeypot may not be responding correctly"
fi

# Create monitoring script
print_status "Creating monitoring script..."
cat > /usr/local/bin/honeypot-monitor.sh << 'EOF'
#!/bin/bash
# Honeypot monitoring script

HONEYPOT_DIR="/opt/honeypot"
LOG_DIR="/var/log/honeypot"

echo "=== Honeypot Status ==="
cd $HONEYPOT_DIR
docker-compose ps

echo ""
echo "=== Recent Logs ==="
tail -n 20 $LOG_DIR/honeypot/attacks.log 2>/dev/null || echo "No attack logs found"

echo ""
echo "=== Disk Usage ==="
df -h $LOG_DIR

echo ""
echo "=== Memory Usage ==="
free -h
EOF

chmod +x /usr/local/bin/honeypot-monitor.sh

# Create systemd service for auto-start
print_status "Creating systemd service..."
cat > /etc/systemd/system/honeypot.service << EOF
[Unit]
Description=Honeypot Service
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$HONEYPOT_DIR
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable honeypot.service

# Create log rotation
print_status "Configuring log rotation..."
cat > /etc/logrotate.d/honeypot << EOF
$LOG_DIR/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        docker-compose -f $HONEYPOT_DIR/docker-compose.yml restart honeypot
    endscript
}
EOF

# Final status
print_status "Deployment completed successfully!"
echo ""
echo "=========================================="
echo "Honeypot Server Information"
echo "=========================================="
echo "Server IP: $HONEYPOT_IP"
echo "HTTP Port: 80"
echo "HTTPS Port: 443"
echo "Log Directory: $LOG_DIR"
echo "Service Directory: $HONEYPOT_DIR"
echo ""
echo "Access URLs:"
echo "  HTTP:  http://$HONEYPOT_IP"
echo "  HTTPS: https://$HONEYPOT_IP"
echo ""
echo "Management Commands:"
echo "  Check Status:  honeypot-monitor.sh"
echo "  View Logs:     docker-compose -f $HONEYPOT_DIR/docker-compose.yml logs"
echo "  Restart:       systemctl restart honeypot"
echo "  Stop:          systemctl stop honeypot"
echo ""
echo "=========================================="

# Test connectivity to capture server
print_status "Testing connectivity to capture server..."
if ping -c 1 $CAPTURE_IP &> /dev/null; then
    print_status "Capture server is reachable"
else
    print_warning "Cannot reach capture server at $CAPTURE_IP"
    print_warning "Please ensure the capture server is running and accessible"
fi

print_status "Honeypot deployment completed!"
