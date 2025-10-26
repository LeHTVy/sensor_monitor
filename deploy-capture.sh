#!/bin/bash

# Capture Server Deployment Script
# Target: 172.232.246.68

set -e

echo "=========================================="
echo "Capture Server Deployment"
echo "Target: 172.232.246.68"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
CAPTURE_IP="172.232.246.68"
HONEYPOT_IP="172.235.245.60"
CAPTURE_DIR="/opt/capture"
LOG_DIR="/var/log/capture"

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

print_status "Starting capture server deployment..."

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

# Install additional tools for packet capture
print_status "Installing network tools..."
apt-get install -y \
    tcpdump \
    wireshark-common \
    net-tools \
    iputils-ping \
    netcat-openbsd \
    htop \
    iotop

# Create directories
print_status "Creating directories..."
mkdir -p $CAPTURE_DIR
mkdir -p $LOG_DIR
mkdir -p $LOG_DIR/packets
mkdir -p $LOG_DIR/analysis
mkdir -p $LOG_DIR/honeypot
mkdir -p $LOG_DIR/reports

# Copy capture files
print_status "Copying capture files..."
if [ -d "capture" ]; then
    cp -r capture/* $CAPTURE_DIR/
    print_status "Capture files copied successfully"
else
    print_error "Capture directory not found. Please run this script from the project root."
    exit 1
fi

# Set permissions
print_status "Setting permissions..."
chown -R root:root $CAPTURE_DIR
chmod -R 755 $CAPTURE_DIR
chown -R root:root $LOG_DIR
chmod -R 755 $LOG_DIR

# Configure environment
print_status "Configuring environment..."
cat > $CAPTURE_DIR/.env << EOF
TARGET_IP=$CAPTURE_IP
HONEYPOT_IP=$HONEYPOT_IP
LOG_DIR=/app/logs
LOG_LEVEL=INFO
EOF

# Update docker-compose.yml with correct IPs
print_status "Updating configuration..."
sed -i "s/172.232.246.68/$CAPTURE_IP/g" $CAPTURE_DIR/docker-compose.yml

# Configure firewall
print_status "Configuring firewall..."
ufw --force enable
ufw allow 22/tcp
ufw allow 8080/tcp
ufw allow from $HONEYPOT_IP to any port 8080
print_status "Firewall configured"

# Configure network interfaces for packet capture
print_status "Configuring network interfaces..."
# Enable promiscuous mode for packet capture
ip link set dev eth0 promisc on 2>/dev/null || true

# Start capture services
print_status "Starting capture services..."
cd $CAPTURE_DIR
docker-compose down 2>/dev/null || true
docker-compose up -d

# Wait for services to start
print_status "Waiting for services to start..."
sleep 30

# Check if services are running
print_status "Checking service status..."
if docker-compose ps | grep -q "Up"; then
    print_status "Capture services started successfully"
else
    print_error "Failed to start capture services"
    docker-compose logs
    exit 1
fi

# Test capture server
print_status "Testing capture server..."
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/health | grep -q "200"; then
    print_status "Capture server is responding correctly"
else
    print_warning "Capture server may not be responding correctly"
fi

# Create monitoring script
print_status "Creating monitoring script..."
cat > /usr/local/bin/capture-monitor.sh << 'EOF'
#!/bin/bash
# Capture server monitoring script

CAPTURE_DIR="/opt/capture"
LOG_DIR="/var/log/capture"

echo "=== Capture Server Status ==="
cd $CAPTURE_DIR
docker-compose ps

echo ""
echo "=== Recent Packet Captures ==="
tail -n 10 $LOG_DIR/packets/captured_packets.log 2>/dev/null || echo "No packet logs found"

echo ""
echo "=== Recent Attacks ==="
tail -n 10 $LOG_DIR/analysis/attack_analysis.log 2>/dev/null || echo "No attack logs found"

echo ""
echo "=== Honeypot Logs ==="
tail -n 10 $LOG_DIR/honeypot/honeypot_logs.log 2>/dev/null || echo "No honeypot logs found"

echo ""
echo "=== Disk Usage ==="
df -h $LOG_DIR

echo ""
echo "=== Memory Usage ==="
free -h

echo ""
echo "=== Network Interfaces ==="
ip addr show

echo ""
echo "=== Active Connections ==="
netstat -tuln | grep -E ":(80|443|8080|22)"
EOF

chmod +x /usr/local/bin/capture-monitor.sh

# Create analysis script
print_status "Creating analysis script..."
cat > /usr/local/bin/run-analysis.sh << 'EOF'
#!/bin/bash
# Run attack analysis

CAPTURE_DIR="/opt/capture"

echo "Running attack analysis..."
cd $CAPTURE_DIR
docker-compose exec capture-server python analyzer.py

echo "Analysis completed. Check reports in /var/log/capture/reports/"
EOF

chmod +x /usr/local/bin/run-analysis.sh

# Create systemd service for auto-start
print_status "Creating systemd service..."
cat > /etc/systemd/system/capture.service << EOF
[Unit]
Description=Capture Server Service
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$CAPTURE_DIR
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable capture.service

# Create log rotation
print_status "Configuring log rotation..."
cat > /etc/logrotate.d/capture << EOF
$LOG_DIR/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        docker-compose -f $CAPTURE_DIR/docker-compose.yml restart capture-server
    endscript
}
EOF

# Create cron job for regular analysis
print_status "Setting up automated analysis..."
cat > /etc/cron.d/capture-analysis << EOF
# Run attack analysis every hour
0 * * * * root /usr/local/bin/run-analysis.sh >> /var/log/capture/analysis.log 2>&1
EOF

# Final status
print_status "Deployment completed successfully!"
echo ""
echo "=========================================="
echo "Capture Server Information"
echo "=========================================="
echo "Server IP: $CAPTURE_IP"
echo "API Port: 8080"
echo "Log Directory: $LOG_DIR"
echo "Service Directory: $CAPTURE_DIR"
echo ""
echo "API Endpoints:"
echo "  Health Check: http://$CAPTURE_IP:8080/api/health"
echo "  Statistics:   http://$CAPTURE_IP:8080/api/stats"
echo "  Recent Logs:  http://$CAPTURE_IP:8080/api/logs/recent"
echo "  Attacks:      http://$CAPTURE_IP:8080/api/attacks"
echo ""
echo "Management Commands:"
echo "  Check Status:  capture-monitor.sh"
echo "  Run Analysis:  run-analysis.sh"
echo "  View Logs:     docker-compose -f $CAPTURE_DIR/docker-compose.yml logs"
echo "  Restart:       systemctl restart capture"
echo "  Stop:          systemctl stop capture"
echo ""
echo "=========================================="

# Test connectivity to honeypot server
print_status "Testing connectivity to honeypot server..."
if ping -c 1 $HONEYPOT_IP &> /dev/null; then
    print_status "Honeypot server is reachable"
else
    print_warning "Cannot reach honeypot server at $HONEYPOT_IP"
    print_warning "Please ensure the honeypot server is running and accessible"
fi

# Test packet capture
print_status "Testing packet capture capabilities..."
if timeout 5 tcpdump -i any -c 1 &> /dev/null; then
    print_status "Packet capture is working"
else
    print_warning "Packet capture may not be working properly"
    print_warning "Please check network interface permissions"
fi

print_status "Capture server deployment completed!"
