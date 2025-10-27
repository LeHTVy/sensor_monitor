# Kafka Integration Deployment Guide

## 🚀 Kafka Integration cho Sensor Monitor

### **Kiến trúc mới:**
```
Honeypot → Kafka Producer → Kafka Topics → Kafka Consumer → Capture Server Dashboard
```

### **Kafka Topics:**
- `honeypot-browser` - Logs từ browser (hiển thị trong Recent Logs)
- `honeypot-attacks` - Logs từ security tools (hiển thị trong Attack Patterns)
- `honeypot-errors` - Error logs

## **📋 Deployment Steps:**

### **1. Start Kafka Infrastructure:**
```bash
# Start Kafka và Zookeeper
cd kafka
docker-compose up -d

# Check status
docker-compose ps
```

### **2. Update Honeypot:**
```bash
cd honeypot
docker-compose down
docker-compose up -d --build
```

### **3. Update Capture Server:**
```bash
cd capture
docker-compose down
docker-compose up -d --build
```

### **4. Test Integration:**
```bash
# Test Kafka
python test-kafka.py

# Check logs
docker logs honeypot-server
docker logs capture-server
```

## **🔧 Configuration:**

### **Environment Variables:**
- `KAFKA_BOOTSTRAP_SERVERS=172.232.246.68:9092`
- `CAPTURE_SERVER_URL=http://172.232.246.68:8080`

### **Kafka UI:**
- URL: http://172.232.246.68:8080
- Monitor topics và messages

## **✨ Features:**

### **1. Phân loại Logs:**
- **Browser logs** → `honeypot-browser` topic → Recent Logs
- **Attack logs** → `honeypot-attacks` topic → Attack Patterns
- **Error logs** → `honeypot-errors` topic

### **2. Thời gian Vietnam:**
- Tự động convert UTC → Asia/Ho_Chi_Minh
- Hiển thị đúng timezone local

### **3. Real-time Processing:**
- Kafka consumer chạy background thread
- Logs được xử lý ngay lập tức
- Auto-refresh dashboard mỗi 2 giây

### **4. Detailed Attack Detection:**
- Detect tools: Nmap, SQLMap, Nikto, Dirb, Gobuster, Metasploit, Telnet
- Detect techniques: Port Scanning, SQL Injection, Directory Traversal
- GeoIP: Country, City, ISP
- OS Detection: Windows, Linux, macOS, Android, iOS

## **🎯 Benefits:**

✅ **Phân loại chính xác** - Browser vs Security Tools  
✅ **Thời gian đúng** - Vietnam timezone  
✅ **Real-time** - Xử lý logs ngay lập tức  
✅ **Scalable** - Có thể mở rộng nhiều honeypot  
✅ **Reliable** - Kafka đảm bảo message delivery  
✅ **Monitor** - Kafka UI để theo dõi  

## **🔍 Troubleshooting:**

### **Kafka không kết nối:**
```bash
# Check Kafka status
docker logs kafka
docker logs zookeeper

# Check network
docker network ls
```

### **Honeypot không gửi logs:**
```bash
# Check environment variables
docker exec honeypot-server env | grep KAFKA

# Check logs
docker logs honeypot-server
```

### **Capture Server không nhận logs:**
```bash
# Check Kafka consumer
docker logs capture-server

# Check topics
# Access Kafka UI: http://172.232.246.68:8080
```

## **📊 Monitoring:**

### **Kafka UI Dashboard:**
- Topics: Xem các topics và messages
- Consumers: Monitor consumer groups
- Brokers: Check broker status

### **Dashboard Features:**
- Recent Logs: Browser interactions
- Attack Patterns: Security tool activities
- Real-time updates: Auto-refresh
- Vietnam timezone: Correct local time
