#!/bin/bash

# Deploy to both servers script
# Usage: ./deploy-all.sh <GIT_REPO_URL>

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
HONEYPOT_IP="172.235.245.60"
CAPTURE_IP="172.232.246.68"
GIT_REPO_URL="$1"

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

print_header() {
    echo -e "${BLUE}==========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==========================================${NC}"
}

# Check if Git repo URL is provided
if [ -z "$GIT_REPO_URL" ]; then
    print_error "Please provide Git repository URL"
    echo "Usage: $0 <GIT_REPO_URL>"
    echo "Example: $0 https://github.com/username/sensor-monitor.git"
    exit 1
fi

print_header "Honeypot System Deployment"
print_status "Git Repository: $GIT_REPO_URL"
print_status "Honeypot Server: $HONEYPOT_IP"
print_status "Capture Server: $CAPTURE_IP"

# Function to deploy to server
deploy_to_server() {
    local server_ip=$1
    local server_name=$2
    local deploy_script=$3
    
    print_header "Deploying to $server_name ($server_ip)"
    
    print_status "Connecting to $server_ip..."
    
    # Create deployment script for remote execution
    cat > /tmp/deploy_remote.sh << EOF
#!/bin/bash
set -e

echo "=== Deploying on $server_ip ==="

# Update system
apt-get update -y

# Install Git if not present
if ! command -v git &> /dev/null; then
    apt-get install -y git
fi

# Clone or update repository
if [ -d "/opt/sensor-monitor" ]; then
    echo "Updating existing repository..."
    cd /opt/sensor-monitor
    git pull origin main
else
    echo "Cloning repository..."
    git clone $GIT_REPO_URL /opt/sensor-monitor
    cd /opt/sensor-monitor
fi

# Make scripts executable
chmod +x deploy-honeypot.sh deploy-capture.sh

# Run appropriate deployment script
echo "Running $deploy_script..."
./$deploy_script

echo "=== Deployment completed on $server_ip ==="
EOF

    # Copy and execute deployment script on remote server
    scp /tmp/deploy_remote.sh root@$server_ip:/tmp/
    ssh root@$server_ip "chmod +x /tmp/deploy_remote.sh && /tmp/deploy_remote.sh"
    
    # Clean up
    rm /tmp/deploy_remote.sh
    
    print_status "Deployment to $server_name completed!"
}

# Deploy to Honeypot Server
deploy_to_server $HONEYPOT_IP "Honeypot Server" "deploy-honeypot.sh"

# Deploy to Capture Server
deploy_to_server $CAPTURE_IP "Capture Server" "deploy-capture.sh"

# Final verification
print_header "Verification"

print_status "Testing Honeypot Server..."
if curl -s -o /dev/null -w "%{http_code}" http://$HONEYPOT_IP | grep -q "200\|302"; then
    print_status "✅ Honeypot Server is responding"
else
    print_warning "❌ Honeypot Server may not be responding"
fi

print_status "Testing Capture Server..."
if curl -s -o /dev/null -w "%{http_code}" http://$CAPTURE_IP:8080/api/health | grep -q "200"; then
    print_status "✅ Capture Server is responding"
else
    print_warning "❌ Capture Server may not be responding"
fi

print_header "Deployment Summary"
echo "Honeypot Server: http://$HONEYPOT_IP"
echo "Capture Server: http://$CAPTURE_IP:8080"
echo ""
echo "Management Commands:"
echo "  Honeypot:  ssh root@$HONEYPOT_IP 'honeypot-monitor.sh'"
echo "  Capture:   ssh root@$CAPTURE_IP 'capture-monitor.sh'"
echo ""
print_status "Deployment completed successfully!"
