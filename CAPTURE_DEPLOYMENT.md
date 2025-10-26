# Capture Server Deployment Guide

## Tổng quan

Capture Server là một hệ thống giám sát mạng và honeypot với giao diện web hiện đại. Hệ thống bao gồm:

- **Packet Capture**: Thu thập và phân tích gói tin mạng
- **Log Receiver**: Nhận và xử lý logs từ honeypot servers
- **Web Dashboard**: Giao diện web real-time để giám sát
- **Database**: SQLite để lưu trữ logs và thống kê
- **API Endpoints**: RESTful API để tích hợp với các hệ thống khác

## Cấu trúc Project

```
capture/
├── capture.py              # Packet capture engine
├── receiver.py             # Log receiver và web API
├── analyzer.py             # Log analysis engine
├── templates/
│   └── index.html          # Web dashboard
├── static/
│   └── style.css           # CSS styles
├── docker-compose.yml      # Docker configuration
├── Dockerfile              # Container build file
├── requirements.txt        # Python dependencies
└── test_integration.py     # Test script
```

## Yêu cầu Hệ thống

- Docker và Docker Compose
- Git
- SSH access đến target servers
- Port 8080 mở cho web interface

## Deployment

### 1. Sử dụng Script Tự động

#### Trên Linux/macOS:
```bash
# Deploy to all servers
./deploy-capture-servers.sh

# Deploy to specific server
./deploy-capture-servers.sh --server1
./deploy-capture-servers.sh --server2
```

#### Trên Windows:
```powershell
# Deploy to all servers
.\deploy-capture-servers.ps1

# Deploy to specific server
.\deploy-capture-servers.ps1 -Server1
.\deploy-capture-servers.ps1 -Server2
```

### 2. Deploy Thủ công

#### Bước 1: Clone Repository
```bash
git clone https://github.com/LeHTVy/sensor_monitor.git
cd sensor-monitor/capture
```

#### Bước 2: Build và Chạy
```bash
# Build Docker image
docker-compose build

# Start services
docker-compose up -d

# Check logs
docker-compose logs -f
```

#### Bước 3: Kiểm tra Deployment
```bash
# Health check
curl http://localhost:8080/api/health

# Access web interface
open http://localhost:8080
```

## Cấu hình Server

### Server 1: 172.232.246.68
- User: pandora
- Port: 22
- Web Interface: http://172.232.246.68:8080

### Server 2: 172.235.245.60
- User: pandora
- Port: 22
- Web Interface: http://172.235.245.60:8080

## API Endpoints

### Health Check
```bash
GET /api/health
```

### Logs
```bash
# Get all logs
GET /api/logs

# Get logs by type
GET /api/logs?type=attack
GET /api/logs?type=honeypot
GET /api/logs?type=error

# Search logs
GET /api/logs/search?q=search_term

# Export logs
GET /api/logs/export?type=all&limit=1000
```

### Statistics
```bash
GET /api/stats
```

### Attack Patterns
```bash
GET /api/attack-patterns
```

### Receive Logs (for honeypot integration)
```bash
# Single log
POST /api/logs/receive
Content-Type: application/json

{
  "type": "attack",
  "timestamp": "2025-10-26T16:30:00",
  "src_ip": "192.168.1.100",
  "dst_ip": "172.232.246.68",
  "protocol": "TCP",
  "src_port": 12345,
  "dst_port": 22,
  "payload": "SSH brute force attempt"
}

# Bulk logs
POST /api/logs/bulk
Content-Type: application/json

{
  "logs": [
    {
      "type": "attack",
      "timestamp": "2025-10-26T16:30:00",
      "src_ip": "192.168.1.100",
      "dst_ip": "172.232.246.68",
      "protocol": "TCP",
      "src_port": 12345,
      "dst_port": 22,
      "payload": "Attack 1"
    },
    {
      "type": "honeypot",
      "timestamp": "2025-10-26T16:30:01",
      "src_ip": "192.168.1.101",
      "dst_ip": "172.232.246.68",
      "protocol": "TCP",
      "src_port": 12346,
      "dst_port": 80,
      "payload": "HTTP request"
    }
  ]
}
```

## Tích hợp với Honeypot

Để tích hợp với honeypot server, thêm code sau vào honeypot:

```python
import requests
import json
from datetime import datetime

def send_log_to_capture(log_data, capture_server_url="http://172.232.246.68:8080"):
    """Send log to capture server"""
    try:
        response = requests.post(
            f"{capture_server_url}/api/logs/receive",
            json=log_data,
            timeout=5
        )
        return response.status_code == 200
    except Exception as e:
        print(f"Error sending log to capture server: {e}")
        return False

# Example usage
log_entry = {
    "type": "attack",
    "timestamp": datetime.now().isoformat(),
    "src_ip": "192.168.1.100",
    "dst_ip": "172.232.246.68",
    "protocol": "TCP",
    "src_port": 12345,
    "dst_port": 22,
    "payload": "SSH brute force attempt"
}

send_log_to_capture(log_entry)
```

## Monitoring và Troubleshooting

### Kiểm tra Logs
```bash
# Docker logs
docker-compose logs -f

# Application logs
docker-compose exec capture-server tail -f /app/logs/capture.log
docker-compose exec capture-server tail -f /app/logs/receiver.log
```

### Kiểm tra Database
```bash
# Access database
docker-compose exec capture-server sqlite3 /app/logs/capture.db

# View tables
.tables

# View logs
SELECT * FROM logs ORDER BY timestamp DESC LIMIT 10;

# View attack patterns
SELECT * FROM attack_patterns ORDER BY count DESC LIMIT 10;
```

### Restart Services
```bash
# Restart all services
docker-compose restart

# Restart specific service
docker-compose restart capture-server
```

### Update Deployment
```bash
# Pull latest code
git pull origin main

# Rebuild and restart
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## Security Considerations

1. **Firewall**: Chỉ mở port 8080 cho web interface
2. **Authentication**: Thêm authentication cho production
3. **HTTPS**: Sử dụng SSL/TLS cho production
4. **Database**: Backup database thường xuyên
5. **Logs**: Rotate logs để tránh disk đầy

## Performance Tuning

1. **Database**: Tối ưu SQLite cho high-volume logs
2. **Memory**: Tăng memory limit cho container
3. **CPU**: Sử dụng multiple workers cho Flask
4. **Storage**: Sử dụng SSD cho database

## Backup và Recovery

### Backup Database
```bash
# Create backup
docker-compose exec capture-server sqlite3 /app/logs/capture.db ".backup /app/logs/capture_backup.db"

# Copy backup to host
docker cp capture-server:/app/logs/capture_backup.db ./capture_backup_$(date +%Y%m%d_%H%M%S).db
```

### Restore Database
```bash
# Copy backup to container
docker cp capture_backup.db capture-server:/app/logs/capture.db

# Restart services
docker-compose restart
```

## Support

Nếu gặp vấn đề, kiểm tra:

1. Docker logs: `docker-compose logs -f`
2. Health check: `curl http://server-ip:8080/api/health`
3. Network connectivity: `ping server-ip`
4. Port accessibility: `telnet server-ip 8080`

## Changelog

### v1.0.0 (2025-10-26)
- Initial release
- Web dashboard với real-time monitoring
- SQLite database integration
- RESTful API endpoints
- Docker containerization
- Multi-server deployment scripts
