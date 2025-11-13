# Honeypot Intelligence Detection System - Deployment Guide

## Tổng quan hệ thống

Hệ thống honeypot đã được nâng cấp với khả năng detect tools tấn công ở cả **Network Layer** và **Application Layer**:

### Kiến trúc mới:

```
┌─────────────────────────────────────────────────────────────┐
│                    HONEYPOT SERVER                          │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Network Layer (NEW)                                 │  │
│  │  - Packet Sniffer (Scapy)                           │  │
│  │  - Detectors: Nmap, Masscan, Generic Scanner        │  │
│  │  - Captures: SYN scans, port scans, ICMP, UDP       │  │
│  └──────────────────────────────────────────────────────┘  │
│                           ↓                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Application Layer (ENHANCED)                        │  │
│  │  - Flask App + Nginx                                 │  │
│  │  - 26 Tool Detectors (improved signatures)          │  │
│  │  - Behavioral Analysis                               │  │
│  └──────────────────────────────────────────────────────┘  │
│                           ↓                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Kafka Producer                                      │  │
│  │  - Background queue worker                           │  │
│  │  - Non-blocking log transmission                     │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            ↓
                     VPN Tunnel (WireGuard)
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    CAPTURE SERVER                           │
│  Kafka → Collector → Elasticsearch → Backend API → Frontend │
└─────────────────────────────────────────────────────────────┘
```

### Tính năng mới:

✅ **Network Layer Detection**:
- Detect **nmap SYN scan** (-sS) - FIXED!
- Detect các loại port scans khác
- Detect Masscan (ultra-fast scanner)
- Detect unknown scanners (heuristic)

✅ **Enhanced Application Layer Detection**:
- Improved Nmap NSE scripts detection
- Enhanced SQLMap patterns (2024-2025)
- Better behavioral analysis
- 26 tool detectors với signatures mới

✅ **Real-time Processing**:
- Network monitor chạy song song với Flask app
- Logs được gửi real-time qua VPN
- Non-blocking architecture

---

## Yêu cầu hệ thống

### Honeypot Server:
- OS: Linux (Ubuntu 20.04+)
- RAM: >= 2GB
- Docker & Docker Compose
- WireGuard (VPN client)
- Network: Public IP với ports 80, 443 mở

### Capture Server:
- OS: Linux (Ubuntu 20.04+)
- RAM: >= 4GB
- Docker & Docker Compose
- WireGuard (VPN server)
- Services: Kafka, Elasticsearch, Backend API, Frontend

---

## Bước 1: Chuẩn bị môi trường

### 1.1. Clone repository và update code

Trên Honeypot Server:

```bash
cd /opt/sensor-monitor/honeypot
git pull  # Hoặc download code mới
```

### 1.2. Cài đặt WireGuard (nếu chưa có)

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install wireguard

# Kiểm tra
sudo wg --version
```

### 1.3. Verify VPN đang chạy

```bash
# Check WireGuard interface
sudo wg show

# Ping capture server qua VPN
ping 10.8.0.1

# Test Kafka port
nc -zv 10.8.0.1 9093
```

---

## Bước 2: Build và Deploy Honeypot

### 2.1. Kiểm tra files mới

Đảm bảo các files sau đã có:

```bash
ls -la honeypot/network_monitor/
# Phải có:
# - packet_sniffer.py
# - detectors/nmap_network_detector.py
# - detectors/masscan_network_detector.py
# - detectors/generic_scan_detector.py
# - detectors/base_network_detector.py
# - detectors/__init__.py

ls -la honeypot/
# Phải có:
# - requirements.txt (đã có scapy==2.5.0)
# - Dockerfile (đã update)
# - docker-compose.yml (đã có cap_add)
# - test_vpn_kafka.py
```

### 2.2. Build Docker image mới

```bash
cd /opt/sensor-monitor/honeypot

# Stop container cũ
docker-compose down

# Build image mới (sẽ cài scapy và libpcap)
docker-compose build --no-cache

# Start container với capabilities mới
docker-compose up -d
```

### 2.3. Verify logs

```bash
# Xem logs để đảm bảo cả 3 services đã start:
docker logs -f honeypot-server

# Phải thấy:
# ✅ Nginx started
# ✅ Network Monitor started (PID: xxx)
# ✅ Gunicorn Flask App started
```

---

## Bước 3: Test hệ thống

### 3.1. Test VPN và Kafka connectivity

```bash
# Chạy test script trong container
docker exec -it honeypot-server python3 test_vpn_kafka.py

# Expected output:
# ✅ Kafka is reachable
# ✅ Backend API is reachable
# ✅ Kafka producer created successfully
# ✅ Test log sent successfully
# 🎉 All tests passed!
```

### 3.2. Test Network Layer Detection (SYN scan)

Từ máy khác, chạy nmap scan:

```bash
# Test SYN scan (vấn đề cũ)
nmap -sS -p 80,443,22,3306,5432 <HONEYPOT_IP>

# Test aggressive scan
nmap -T4 -p 1-1000 <HONEYPOT_IP>

# Test stealth scan
nmap -sS -T2 -p 80,443 <HONEYPOT_IP>
```

### 3.3. Test Application Layer Detection (HTTP requests)

```bash
# Test Nmap HTTP scan
nmap -p 80 --script http-enum <HONEYPOT_IP>

# Test với curl
curl -A "nmap/7.80" http://<HONEYPOT_IP>/

# Test SQLMap
sqlmap -u "http://<HONEYPOT_IP>/login?id=1"

# Test Gobuster
gobuster dir -u http://<HONEYPOT_IP>/ -w wordlist.txt
```

### 3.4. Verify logs trên Honeypot

```bash
# Xem logs của Network Monitor
docker logs honeypot-server | grep "Network Monitor"

# Xem attack detection logs
docker logs honeypot-server | grep "Attack detected"

# Xem Kafka logs
docker logs honeypot-server | grep "Kafka"

# Expected:
# 🚨 Attack detected: nmap from <IP> (85% confidence)
# ✅ Log sent to topic honeypot-attacks
```

---

## Bước 4: Verify logs trên Capture Server

### 4.1. Check Kafka topics

```bash
# SSH vào capture server
ssh user@10.8.0.1

# List Kafka topics
docker exec -it kafka kafka-topics --list --bootstrap-server localhost:9092

# Check honeypot-attacks topic
docker exec -it kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic honeypot-attacks \
  --from-beginning \
  --max-messages 10
```

### 4.2. Check Elasticsearch

```bash
# Query recent attack logs
curl -X GET "localhost:9200/sensor-logs-attacks/_search?size=10&sort=timestamp:desc&pretty"

# Search for nmap detections
curl -X GET "localhost:9200/sensor-logs-attacks/_search?q=attack_tool:nmap&pretty"

# Search for network scans
curl -X GET "localhost:9200/sensor-logs-attacks/_search?q=type:network_scan&pretty"
```

### 4.3. Check Frontend

Truy cập Frontend qua VPN:
```
http://10.8.0.1:3000
```

Kiểm tra:
- Dashboard có hiển thị attacks mới không
- Filter by tool: "nmap" có kết quả không
- Log details có đầy đủ thông tin không

---

## Bước 5: Monitoring và Troubleshooting

### 5.1. Monitor Network Monitor service

```bash
# Check if network monitor is running
docker exec -it honeypot-server ps aux | grep packet_sniffer

# View network monitor logs
docker logs honeypot-server 2>&1 | grep -A 5 "Network Monitor"

# Check packet capture stats
docker exec -it honeypot-server tcpdump -i any -c 10
```

### 5.2. Common issues và giải pháp

#### Issue 1: Network Monitor không start

**Triệu chứng:**
```
❌ Kafka connection attempt failed
```

**Giải pháp:**
```bash
# 1. Check VPN
ping 10.8.0.1

# 2. Check Kafka port
nc -zv 10.8.0.1 9093

# 3. Restart WireGuard
sudo wg-quick down wg0
sudo wg-quick up wg0

# 4. Rebuild container
docker-compose down
docker-compose up -d
```

#### Issue 2: Không capture được packets

**Triệu chứng:**
```
📊 Statistics:
   Packets captured: 0
```

**Giải pháp:**
```bash
# 1. Check container có NET_ADMIN capability
docker inspect honeypot-server | grep -A 10 CapAdd

# 2. Nếu không có, update docker-compose.yml:
cap_add:
  - NET_ADMIN
  - NET_RAW

# 3. Restart container
docker-compose down
docker-compose up -d

# 4. Hoặc dùng host network mode
# Uncomment trong docker-compose.yml:
# network_mode: host
```

#### Issue 3: Detection không chính xác

**Triệu chứng:**
```
Attack tool: unknown
Confidence: 0%
```

**Giải pháp:**
```bash
# 1. Check logs chi tiết
docker logs honeypot-server | grep "Enhanced Detection Debug"

# 2. Verify tool signatures
# Network layer: network_monitor/detectors/
# Application layer: app/utils/tools/

# 3. Adjust detection thresholds nếu cần
# Edit detectors và rebuild
```

#### Issue 4: Logs không đến Elasticsearch

**Triệu chứng:**
```
# Kafka có message nhưng Elasticsearch không có
```

**Giải pháp:**
```bash
# 1. Check collector logs trên capture server
docker logs collector

# 2. Check Kafka consumer group
docker exec -it kafka kafka-consumer-groups \
  --bootstrap-server localhost:9092 \
  --describe --group capture-es-collector

# 3. Check Elasticsearch status
curl localhost:9200/_cluster/health?pretty

# 4. Restart collector
docker restart collector
```

### 5.3. Performance tuning

Nếu honeypot server load cao:

```yaml
# Trong docker-compose.yml, điều chỉnh resources:
services:
  honeypot:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 1G
        reservations:
          memory: 512M
```

Điều chỉnh packet capture:

```python
# Trong network_monitor/packet_sniffer.py
# Giảm buffer size nếu cần
self.ip_contexts = defaultdict(lambda: {
    'syn_packets': deque(maxlen=500),  # Giảm từ 1000
    ...
})
```

---

## Bước 6: Advanced Features (Optional)

### 6.1. Machine Learning Detector (Future)

File: `honeypot/app/utils/ml_detector.py` (chưa implement)

Tính năng:
- Train model từ logs lịch sử
- Feature extraction từ requests
- Confidence boosting

### 6.2. Threat Intelligence Integration (Future)

File: `honeypot/app/utils/threat_intel.py` (chưa implement)

Tích hợp:
- AbuseIPDB API
- Shodan API
- GreyNoise API

### 6.3. Correlation Engine (Future)

File: `honeypot/app/utils/correlation_engine.py` (chưa implement)

Chức năng:
- Correlate network + application events
- Timeline reconstruction
- Attack chain analysis

---

## FAQ

### Q1: Tại sao nmap -sS không được detect trước đây?

**A:** Vì Flask app chỉ nhận HTTP/HTTPS requests (application layer). Nmap SYN scan gửi raw TCP packets (network layer) không đến được Flask.

**Giải pháp:** Network Monitor service capture packets ở network layer bằng Scapy.

### Q2: Network Monitor có ảnh hưởng performance không?

**A:** Có một chút, nhưng đã optimize:
- Chỉ capture TCP/UDP/ICMP
- Buffer giới hạn (1000 packets)
- Cleanup context cũ tự động
- Non-blocking Kafka transmission

### Q3: Làm sao biết detection chính xác?

**A:** Xem confidence score và method:
- Confidence >= 90%: Rất chắc chắn
- Confidence 70-89%: Chắc chắn
- Confidence 50-69%: Có thể
- Method: ua (User-Agent), payload, behavior, network_pattern

### Q4: Có thể detect tools mới không?

**A:** Có, qua:
1. Generic detector (heuristic scoring)
2. Behavioral analysis
3. Thêm detector mới (copy từ template)

### Q5: Logs có bị mất không?

**A:** Không, vì:
- Background queue (1000 capacity)
- Kafka retry logic (5 attempts)
- Persistent Kafka topics
- Elasticsearch backup

---

## Log Format mới

### Network Layer Log:

```json
{
  "type": "network_scan",
  "timestamp": "2025-11-12T10:30:45.123456",
  "source": "network_monitor",
  "src_ip": "203.0.113.45",
  "dst_ip": "172.235.245.60",
  "dst_port": 80,
  "protocol": "TCP",
  "attack_tool": "nmap",
  "attack_tool_info": {
    "tool": "nmap",
    "confidence": 85,
    "method": "syn_scan+timing_analysis",
    "details": {
      "syn_rate": 15.5,
      "ports_scanned": 150,
      "timing_template": "T4",
      "scan_speed": "aggressive"
    }
  },
  "attack_technique": ["reconnaissance", "port_scan", "aggressive_scan"],
  "log_category": "attack",
  "metrics": {
    "packet_rate": 15.5,
    "syn_rate": 15.5,
    "port_diversity": 150,
    "total_packets": 300
  },
  "ports_scanned": [21, 22, 23, 25, 80, 443, ...]
}
```

### Application Layer Log (đã có, không đổi):

```json
{
  "type": "request",
  "method": "GET",
  "url": "http://172.235.245.60/admin",
  "path": "/admin",
  "ip": "203.0.113.45",
  "user_agent": "nmap/7.80",
  "timestamp": "2025-11-12T10:30:45.123456",
  "attack_tool": "nmap",
  "attack_tool_info": {
    "tool": "nmap",
    "confidence": 80,
    "method": "ua",
    "details": {
      "user_agent": "nmap/7.80",
      "matched_pattern": "nmap/7."
    }
  },
  "attack_technique": ["reconnaissance"],
  "log_category": "attack",
  ...
}
```

---

## Summary Checklist

Sau khi deploy, verify:

- [ ] VPN tunnel hoạt động (ping 10.8.0.1)
- [ ] Kafka reachable (nc -zv 10.8.0.1 9093)
- [ ] Container có NET_ADMIN capability
- [ ] Network Monitor started trong logs
- [ ] Test script passed (test_vpn_kafka.py)
- [ ] Nmap SYN scan được detect
- [ ] Logs xuất hiện trong Elasticsearch
- [ ] Frontend hiển thị attacks mới
- [ ] Confidence scores hợp lý (>50%)
- [ ] No errors trong container logs

---

## Liên hệ hỗ trợ

Nếu gặp vấn đề:

1. Check logs: `docker logs -f honeypot-server`
2. Run test: `docker exec -it honeypot-server python3 test_vpn_kafka.py`
3. Review troubleshooting section phía trên
4. Gửi logs và error messages để được hỗ trợ

---

**Chúc bạn deploy thành công! 🎉**
