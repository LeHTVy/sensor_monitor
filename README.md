# Hệ thống Honeypot với Packet Capture

Hệ thống honeypot hoàn chỉnh với 2 server: honeypot server giả mạo trang admin database và capture server để bắt và phân tích các gói tin tấn công.

## Tổng quan

### Server 1: Honeypot (172.235.245.60)
- **Chức năng**: Giả mạo trang admin database để dụ hacker tấn công
- **Ports**: 80 (HTTP), 443 (HTTPS)
- **Tính năng**: SQL injection, file upload, command injection vulnerabilities
- **Logging**: Ghi log tất cả requests và gửi về capture server

### Server 2: Capture (172.232.246.68)
- **Chức năng**: Bắt và phân tích các gói tin tấn công
- **Ports**: 8080 (API)
- **Tính năng**: Packet capture, attack detection, log analysis
- **Detection**: Nmap, telnet, metasploit, port scanning

## Cấu trúc thư mục

```
sensor-monitor/
├── honeypot/                    # Honeypot server
│   ├── app/
│   │   ├── app.py              # Flask application
│   │   ├── templates/          # HTML templates
│   │   └── utils/
│   │       ├── logger.py       # Logging system
│   │       └── sender.py       # Log sender
│   ├── nginx/
│   │   └── nginx.conf          # Nginx configuration
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── requirements.txt
├── capture/                     # Capture server
│   ├── capture.py              # Packet capture script
│   ├── receiver.py             # Log receiver API
│   ├── analyzer.py             # Attack analyzer
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── requirements.txt
├── deploy-honeypot.sh          # Honeypot deployment script
├── deploy-capture.sh           # Capture deployment script
└── README.md
```

## Tính năng chính

### Honeypot Server
- **Trang login admin** với SQL injection vulnerability
- **Dashboard database** giả mạo với các bảng dữ liệu
- **File upload** với arbitrary file upload vulnerability
- **Console terminal** với command injection vulnerability
- **API endpoints** vulnerable cho testing
- **Logging đầy đủ** tất cả requests và attacks

### Capture Server
- **Packet capture** sử dụng Scapy
- **Attack detection** cho nmap, telnet, metasploit
- **Log receiver** API nhận logs từ honeypot
- **Attack analyzer** phân tích patterns và classify threats
- **Real-time monitoring** và alerting

## Cài đặt và Deployment

### Yêu cầu hệ thống
- Ubuntu/Debian server
- Docker và Docker Compose
- Root access
- Network connectivity giữa 2 servers

### 1. Deploy Honeypot Server (172.235.245.60)

```bash
# Copy files lên server
scp -r honeypot/ root@172.235.245.60:/tmp/
scp deploy-honeypot.sh root@172.235.245.60:/tmp/

# SSH vào server và chạy deployment
ssh root@172.235.245.60
cd /tmp
chmod +x deploy-honeypot.sh
./deploy-honeypot.sh
```

### 2. Deploy Capture Server (172.232.246.68)

```bash
# Copy files lên server
scp -r capture/ root@172.232.246.68:/tmp/
scp deploy-capture.sh root@172.232.246.68:/tmp/

# SSH vào server và chạy deployment
ssh root@172.232.246.68
cd /tmp
chmod +x deploy-capture.sh
./deploy-capture.sh
```

### 3. Kiểm tra deployment

```bash
# Kiểm tra honeypot
curl http://172.235.245.60
curl https://172.235.245.60

# Kiểm tra capture server
curl http://172.232.246.68:8080/api/health
```

## Sử dụng

### Truy cập Honeypot
- **HTTP**: http://172.235.245.60
- **HTTPS**: https://172.235.245.60
- **Login**: Bất kỳ username/password nào (luôn "thành công")

### Monitoring

#### Honeypot Server
```bash
# Kiểm tra status
honeypot-monitor.sh

# Xem logs
docker-compose -f /opt/honeypot/docker-compose.yml logs

# Restart service
systemctl restart honeypot
```

#### Capture Server
```bash
# Kiểm tra status
capture-monitor.sh

# Chạy analysis
run-analysis.sh

# Xem logs
docker-compose -f /opt/capture/docker-compose.yml logs

# Restart service
systemctl restart capture
```

### API Endpoints

#### Capture Server API
- `GET /api/health` - Health check
- `GET /api/stats` - Statistics
- `GET /api/logs/recent` - Recent logs
- `GET /api/attacks` - Attack logs
- `POST /api/logs` - Receive logs from honeypot

## Cấu hình

### Environment Variables

#### Honeypot Server
```bash
FLASK_ENV=production
CAPTURE_SERVER_URL=http://172.232.246.68:8080
HONEYPOT_IP=172.235.245.60
LOG_LEVEL=INFO
```

#### Capture Server
```bash
TARGET_IP=172.232.246.68
HONEYPOT_IP=172.235.245.60
LOG_DIR=/app/logs
LOG_LEVEL=INFO
```

### Firewall Configuration

#### Honeypot Server
```bash
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow from 172.232.246.68 to any port 80
ufw allow from 172.232.246.68 to any port 443
```

#### Capture Server
```bash
ufw allow 22/tcp
ufw allow 8080/tcp
ufw allow from 172.235.245.60 to any port 8080
```

## Log Files

### Honeypot Logs
- `/var/log/honeypot/requests.log` - Tất cả requests
- `/var/log/honeypot/attacks.log` - Attack attempts
- `/var/log/honeypot/errors.log` - Error logs

### Capture Logs
- `/var/log/capture/packets/captured_packets.log` - Raw packets
- `/var/log/capture/analysis/attack_analysis.log` - Attack analysis
- `/var/log/capture/honeypot/honeypot_logs.log` - Logs from honeypot
- `/var/log/capture/reports/` - Analysis reports

## Security Notes

⚠️ **CẢNH BÁO QUAN TRỌNG**:
- Honeypot server **CÓ Ý** tạo lỗ hổng để dụ hacker
- **KHÔNG** deploy trên mạng nội bộ thực
- **ISOLATE** honeypot khỏi hệ thống production
- Capture server phải **SECURE** và không có lỗ hổng
- Logs chứa **SENSITIVE DATA**, cần bảo mật

## Troubleshooting

### Honeypot không hoạt động
```bash
# Kiểm tra Docker containers
docker ps

# Xem logs
docker-compose -f /opt/honeypot/docker-compose.yml logs

# Kiểm tra ports
netstat -tuln | grep -E ":(80|443)"
```

### Capture server không bắt được packets
```bash
# Kiểm tra permissions
ls -la /dev/net/tun

# Kiểm tra network interface
ip addr show

# Test packet capture
tcpdump -i any -c 5
```

### Không nhận được logs từ honeypot
```bash
# Kiểm tra connectivity
ping 172.235.245.60

# Test API
curl http://172.232.246.68:8080/api/health

# Xem logs
tail -f /var/log/capture/honeypot/honeypot_logs.log
```

## Maintenance

### Log Rotation
Logs được tự động rotate hàng ngày và giữ 30 ngày.

### Updates
```bash
# Update honeypot
cd /opt/honeypot
docker-compose pull
docker-compose up -d

# Update capture server
cd /opt/capture
docker-compose pull
docker-compose up -d
```

### Backup
```bash
# Backup logs
tar -czf honeypot-logs-$(date +%Y%m%d).tar.gz /var/log/honeypot/
tar -czf capture-logs-$(date +%Y%m%d).tar.gz /var/log/capture/
```

## Support

Nếu gặp vấn đề, vui lòng kiểm tra:
1. Log files trong `/var/log/`
2. Docker container status
3. Network connectivity giữa 2 servers
4. Firewall rules
5. System resources (CPU, memory, disk)

## License

Dự án này được tạo ra cho mục đích giáo dục và nghiên cứu bảo mật. Sử dụng có trách nhiệm.
# sensor_monitor
