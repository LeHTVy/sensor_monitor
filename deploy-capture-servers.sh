#!/bin/bash

# Deploy Capture Server to Multiple Servers
# This script deploys the capture server to two different servers

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Server configurations
SERVER1_IP="172.232.246.68"
SERVER1_USER="pandora"
SERVER1_PORT="22"

SERVER2_IP="172.235.245.60"
SERVER2_USER="pandora"
SERVER2_PORT="22"

# Project details
PROJECT_NAME="sensor-monitor"
GIT_REPO="https://github.com/LeHTVy/sensor_monitor.git"
CAPTURE_DIR="/opt/sensor-monitor/capture"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to deploy to a server
deploy_to_server() {
    local server_ip=$1
    local server_user=$2
    local server_port=$3
    local server_name=$4
    
    print_status "Deploying to $server_name ($server_ip)..."
    
    # Test SSH connection
    print_status "Testing SSH connection to $server_name..."
    if ! ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -p $server_port $server_user@$server_ip "echo 'SSH connection successful'" > /dev/null 2>&1; then
        print_error "Cannot connect to $server_name ($server_ip). Please check SSH configuration."
        return 1
    fi
    print_success "SSH connection to $server_name established"
    
    # Create project directory
    print_status "Creating project directory on $server_name..."
    ssh -p $server_port $server_user@$server_ip "sudo mkdir -p /opt/sensor-monitor && sudo chown $server_user:$server_user /opt/sensor-monitor"
    
    # Clone or update repository
    print_status "Cloning/updating repository on $server_name..."
    ssh -p $server_port $server_user@$server_ip "
        if [ -d '$CAPTURE_DIR' ]; then
            cd $CAPTURE_DIR
            git pull origin main
        else
            cd /opt/sensor-monitor
            git clone $GIT_REPO .
        fi
    "
    
    # Stop existing containers
    print_status "Stopping existing containers on $server_name..."
    ssh -p $server_port $server_user@$server_ip "
        cd $CAPTURE_DIR
        if [ -f docker-compose.yml ]; then
            docker-compose down || true
        fi
    "
    
    # Build and start new containers
    print_status "Building and starting containers on $server_name..."
    ssh -p $server_port $server_user@$server_ip "
        cd $CAPTURE_DIR
        docker-compose build --no-cache
        docker-compose up -d
    "
    
    # Wait for services to start
    print_status "Waiting for services to start on $server_name..."
    sleep 10
    
    # Test the deployment
    print_status "Testing deployment on $server_name..."
    if curl -s -f "http://$server_ip:8080/api/health" > /dev/null; then
        print_success "Capture server is running on $server_name at http://$server_ip:8080"
    else
        print_warning "Capture server health check failed on $server_name. Check logs with: ssh -p $server_port $server_user@$server_ip 'cd $CAPTURE_DIR && docker-compose logs'"
    fi
    
    print_success "Deployment to $server_name completed!"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -1, --server1    Deploy only to server 1 ($SERVER1_IP)"
    echo "  -2, --server2    Deploy only to server 2 ($SERVER2_IP)"
    echo "  -a, --all        Deploy to all servers (default)"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Deploy to all servers"
    echo "  $0 --server1          # Deploy only to server 1"
    echo "  $0 --server2          # Deploy only to server 2"
}

# Main deployment function
main() {
    local deploy_server1=false
    local deploy_server2=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -1|--server1)
                deploy_server1=true
                shift
                ;;
            -2|--server2)
                deploy_server2=true
                shift
                ;;
            -a|--all)
                deploy_server1=true
                deploy_server2=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # If no specific servers selected, deploy to all
    if [ "$deploy_server1" = false ] && [ "$deploy_server2" = false ]; then
        deploy_server1=true
        deploy_server2=true
    fi
    
    print_status "Starting deployment process..."
    print_status "Git repository: $GIT_REPO"
    print_status "Project directory: $CAPTURE_DIR"
    echo ""
    
    # Deploy to servers
    if [ "$deploy_server1" = true ]; then
        echo "=========================================="
        print_status "DEPLOYING TO SERVER 1"
        echo "=========================================="
        deploy_to_server $SERVER1_IP $SERVER1_USER $SERVER1_PORT "Server 1"
        echo ""
    fi
    
    if [ "$deploy_server2" = true ]; then
        echo "=========================================="
        print_status "DEPLOYING TO SERVER 2"
        echo "=========================================="
        deploy_to_server $SERVER2_IP $SERVER2_USER $SERVER2_PORT "Server 2"
        echo ""
    fi
    
    print_success "Deployment process completed!"
    echo ""
    print_status "Access URLs:"
    if [ "$deploy_server1" = true ]; then
        echo "  Server 1: http://$SERVER1_IP:8080"
    fi
    if [ "$deploy_server2" = true ]; then
        echo "  Server 2: http://$SERVER2_IP:8080"
    fi
    echo ""
    print_status "To check logs:"
    if [ "$deploy_server1" = true ]; then
        echo "  Server 1: ssh -p $SERVER1_PORT $SERVER1_USER@$SERVER1_IP 'cd $CAPTURE_DIR && docker-compose logs -f'"
    fi
    if [ "$deploy_server2" = true ]; then
        echo "  Server 2: ssh -p $SERVER2_PORT $SERVER2_USER@$SERVER2_IP 'cd $CAPTURE_DIR && docker-compose logs -f'"
    fi
}

# Run main function with all arguments
main "$@"
