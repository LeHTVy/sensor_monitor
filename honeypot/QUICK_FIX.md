# 🔧 Quick Fix - Network Monitor Not Working

## Vấn đề

1. **Network Monitor crash**: `[Errno 19] No such device`
2. **Chỉ log được browsing traffic**: Không detect được nmap/port scans

## Nguyên nhân

- Docker bridge network không hỗ trợ interface `any`
- Scapy không capture được packets trong bridge mode

## Giải pháp đã apply

### 1. Thay đổi sang Host Network Mode

**File**: `docker-compose.yml`

```yaml
honeypot:
  network_mode: host  # Dùng host network thay vì bridge
  cap_add:
    - NET_ADMIN
    - NET_RAW
```

**Lợi ích**:
- ✅ Network Monitor capture được packets trực tiếp
- ✅ Detect được nmap SYN scans
- ✅ Không cần port mapping (container dùng host network)

### 2. Auto-detect Network Interface

**File**: `packet_sniffer.py`

- Thêm method `_detect_interface()` để tự động detect interface
- Priority: eth0 → ens33 → ens18 → wlan0 → etc.
- Fallback: first non-loopback interface

**File**: `Dockerfile`

```bash
python3 packet_sniffer.py --interface auto  # Thay vì 'any'
```

---

## 🚀 Rebuild và Test

### Step 1: Rebuild Docker

```bash
cd /opt/sensor-monitor/honeypot

# Stop container cũ
docker-compose down

# Rebuild image
docker-compose build --no-cache

# Start với host network mode
docker-compose up -d
```

### Step 2: Check Logs

```bash
docker logs -f honeypot-server
```

**Expected logs (SUCCESS)**:

```
🚀 Starting Honeypot Services...
📡 Starting Nginx...
✅ Nginx started
🌐 Starting Network Monitor...
📡 Available interfaces: ['lo', 'eth0', 'wg0']  # <-- Phải show interfaces
🔍 Auto-detected interface: eth0                # <-- Phải detect được
✅ Network Monitor started (PID: 11)

============================================================
🚀 Starting Network Monitor Service
============================================================
📡 Interface: eth0                              # <-- Không phải 'any'
🔌 Kafka: 10.8.0.1:9093
🔍 Detectors loaded: 3
🔌 Connecting to Kafka...
✅ Kafka producer connected successfully!
✅ Network monitor is running...                # <-- SUCCESS!
🎯 Monitoring for port scans, SYN scans...

🐍 Starting Gunicorn Flask App...
[INFO] Starting gunicorn
```

**KHÔNG được thấy**:
```
❌ Fatal error: [Errno 19] No such device  # <-- KHÔNG ĐƯỢC CÓ!
```

### Step 3: Test Detection

#### Test 1: Nmap SYN Scan (từ máy khác)

```bash
# Từ máy remote
nmap -sS -p 80,443,22,3306 172.235.245.60
```

**Expected logs trên honeypot**:

```
🚨 Attack detected: nmap from <IP> (85% confidence)
✅ Log sent to topic honeypot-attacks
```

#### Test 2: Check Elasticsearch

```bash
# SSH vào capture server
curl "localhost:9200/sensor-logs-attacks/_search?q=attack_tool:nmap&size=5&pretty"
```

**Expected**: Phải có logs với `type: "network_scan"`

### Step 4: Verify Network Monitor hoạt động

```bash
# Check process
docker exec -it honeypot-server ps aux | grep packet_sniffer

# Expected:
root   11  python3 packet_sniffer.py --interface auto
```

---

## 📊 So sánh Before/After

### BEFORE (Bridge Network):

```
❌ Network Monitor: CRASH (No such device)
❌ Nmap SYN scan: NO LOGS
✅ Browser access: Có logs (Flask app)
```

### AFTER (Host Network):

```
✅ Network Monitor: RUNNING (eth0)
✅ Nmap SYN scan: DETECT được + có logs
✅ Browser access: Có logs (Flask app)
✅ All packets captured at network layer
```

---

## ⚠️ Lưu ý với Host Network Mode

### Pros:
- ✅ Packet capture hoạt động hoàn hảo
- ✅ Detect được network layer attacks
- ✅ Performance tốt hơn (no NAT overhead)

### Cons:
- ⚠️ Container share network với host
  - Port 80/443 trên host bị chiếm bởi honeypot
  - Nếu host đã có service chạy port 80/443 → conflict
- ⚠️ Không isolate network như bridge mode

### Nếu gặp port conflict:

```bash
# Check port đang dùng
sudo netstat -tulpn | grep ':80\|:443'

# Stop service conflicts (nếu cần)
sudo systemctl stop nginx  # If host Nginx running
sudo systemctl stop apache2
```

---

## 🧪 Troubleshooting

### Issue 1: Network Monitor vẫn crash

**Giải pháp**:
```bash
# Check interfaces available
docker exec -it honeypot-server ip addr show

# Check logs
docker logs honeypot-server 2>&1 | grep "Available interfaces"
```

### Issue 2: Không capture được packets

**Check**:
```bash
# Verify capabilities
docker inspect honeypot-server | grep -A 10 CapAdd
# Phải có: NET_ADMIN, NET_RAW

# Check network mode
docker inspect honeypot-server | grep -A 5 NetworkMode
# Phải là: "host"
```

### Issue 3: Kafka vẫn không connect được

**Giải pháp**:
```bash
# Test VPN
ping 10.8.0.1

# Test Kafka
nc -zv 10.8.0.1 9093

# Check WireGuard
sudo wg show
```

---

## ✅ Success Criteria

Sau khi rebuild, verify:

- [ ] Network Monitor started (không crash)
- [ ] Interface detected (eth0 hoặc tương tự)
- [ ] Kafka connected
- [ ] Nmap SYN scan được detect
- [ ] Logs xuất hiện trong Elasticsearch
- [ ] Frontend hiển thị attacks

---

## 🔄 Rollback (nếu cần)

Nếu host network mode gây vấn đề, rollback về bridge mode:

```yaml
# docker-compose.yml
honeypot:
  ports:
    - "80:80"
    - "443:443"
  networks:
    - honeypot-network
  # Comment out network_mode: host
```

**Note**: Bridge mode sẽ KHÔNG detect được nmap SYN scans.

---

**Status**: ✅ Ready to deploy

**Next**: Rebuild → Test → Verify logs
