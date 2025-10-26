# Deploy Capture Server to Multiple Servers
# PowerShell script for Windows deployment

param(
    [switch]$Server1,
    [switch]$Server2,
    [switch]$All,
    [switch]$Help
)

# Server configurations
$SERVER1_IP = "172.232.246.68"
$SERVER1_USER = "pandora"
$SERVER1_PORT = "22"

$SERVER2_IP = "172.235.245.60"
$SERVER2_USER = "pandora"
$SERVER2_PORT = "22"

# Project details
$PROJECT_NAME = "sensor-monitor"
$GIT_REPO = "https://github.com/LeHTVy/sensor_monitor.git"
$CAPTURE_DIR = "/opt/sensor-monitor/capture"

# Function to print colored output
function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Function to deploy to a server
function Deploy-ToServer {
    param(
        [string]$ServerIP,
        [string]$ServerUser,
        [string]$ServerPort,
        [string]$ServerName
    )
    
    Write-Status "Deploying to $ServerName ($ServerIP)..."
    
    # Test SSH connection
    Write-Status "Testing SSH connection to $ServerName..."
    $sshTest = ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -p $ServerPort $ServerUser@$ServerIP "echo 'SSH connection successful'" 2>$null
    if (-not $sshTest) {
        Write-Error "Cannot connect to $ServerName ($ServerIP). Please check SSH configuration."
        return $false
    }
    Write-Success "SSH connection to $ServerName established"
    
    # Create project directory
    Write-Status "Creating project directory on $ServerName..."
    ssh -p $ServerPort $ServerUser@$ServerIP "sudo mkdir -p /opt/sensor-monitor && sudo chown $ServerUser:$ServerUser /opt/sensor-monitor"
    
    # Clone or update repository
    Write-Status "Cloning/updating repository on $ServerName..."
    ssh -p $ServerPort $ServerUser@$ServerIP @"
        if [ -d '$CAPTURE_DIR' ]; then
            cd $CAPTURE_DIR
            git pull origin main
        else
            cd /opt/sensor-monitor
            git clone $GIT_REPO .
        fi
"@
    
    # Stop existing containers
    Write-Status "Stopping existing containers on $ServerName..."
    ssh -p $ServerPort $ServerUser@$ServerIP "cd $CAPTURE_DIR; if [ -f docker-compose.yml ]; then docker-compose down; fi"
    
    # Build and start new containers
    Write-Status "Building and starting containers on $ServerName..."
    ssh -p $ServerPort $ServerUser@$ServerIP "cd $CAPTURE_DIR; docker-compose build --no-cache; docker-compose up -d"
    
    # Wait for services to start
    Write-Status "Waiting for services to start on $ServerName..."
    Start-Sleep -Seconds 10
    
    # Test the deployment
    Write-Status "Testing deployment on $ServerName..."
    try {
        $response = Invoke-WebRequest -Uri "http://$ServerIP`:8080/api/health" -TimeoutSec 10 -UseBasicParsing
        if ($response.StatusCode -eq 200) {
            Write-Success "Capture server is running on $ServerName at http://$ServerIP`:8080"
        } else {
            Write-Warning "Capture server health check failed on $ServerName. Check logs with: ssh -p $ServerPort $ServerUser@$ServerIP 'cd $CAPTURE_DIR && docker-compose logs'"
        }
    } catch {
        Write-Warning "Capture server health check failed on $ServerName. Check logs with: ssh -p $ServerPort $ServerUser@$ServerIP 'cd $CAPTURE_DIR && docker-compose logs'"
    }
    
    Write-Success "Deployment to $ServerName completed!"
    return $true
}

# Function to show usage
function Show-Usage {
    Write-Host "Usage: .\deploy-capture-servers.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Server1    Deploy only to server 1 ($SERVER1_IP)"
    Write-Host "  -Server2    Deploy only to server 2 ($SERVER2_IP)"
    Write-Host "  -All        Deploy to all servers (default)"
    Write-Host "  -Help       Show this help message"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\deploy-capture-servers.ps1                    # Deploy to all servers"
    Write-Host "  .\deploy-capture-servers.ps1 -Server1           # Deploy only to server 1"
    Write-Host "  .\deploy-capture-servers.ps1 -Server2           # Deploy only to server 2"
}

# Main deployment function
function Main {
    $deployServer1 = $false
    $deployServer2 = $false
    
    # Parse command line arguments
    if ($Help) {
        Show-Usage
        return
    }
    
    if ($Server1) { $deployServer1 = $true }
    if ($Server2) { $deployServer2 = $true }
    if ($All) { 
        $deployServer1 = $true
        $deployServer2 = $true
    }
    
    # If no specific servers selected, deploy to all
    if (-not $deployServer1 -and -not $deployServer2) {
        $deployServer1 = $true
        $deployServer2 = $true
    }
    
    Write-Status "Starting deployment process..."
    Write-Status "Git repository: $GIT_REPO"
    Write-Status "Project directory: $CAPTURE_DIR"
    Write-Host ""
    
    # Deploy to servers
    if ($deployServer1) {
        Write-Host "=========================================="
        Write-Status "DEPLOYING TO SERVER 1"
        Write-Host "=========================================="
        Deploy-ToServer $SERVER1_IP $SERVER1_USER $SERVER1_PORT "Server 1"
        Write-Host ""
    }
    
    if ($deployServer2) {
        Write-Host "=========================================="
        Write-Status "DEPLOYING TO SERVER 2"
        Write-Host "=========================================="
        Deploy-ToServer $SERVER2_IP $SERVER2_USER $SERVER2_PORT "Server 2"
        Write-Host ""
    }
    
    Write-Success "Deployment process completed!"
    Write-Host ""
    Write-Status "Access URLs:"
    if ($deployServer1) {
        Write-Host "  Server 1: http://$SERVER1_IP`:8080"
    }
    if ($deployServer2) {
        Write-Host "  Server 2: http://$SERVER2_IP`:8080"
    }
    Write-Host ""
    Write-Status "To check logs:"
    if ($deployServer1) {
        Write-Host "  Server 1: ssh -p $SERVER1_PORT $SERVER1_USER@$SERVER1_IP 'cd $CAPTURE_DIR && docker-compose logs -f'"
    }
    if ($deployServer2) {
        Write-Host "  Server 2: ssh -p $SERVER2_PORT $SERVER2_USER@$SERVER2_IP 'cd $CAPTURE_DIR && docker-compose logs -f'"
    }
}

# Run main function
Main
