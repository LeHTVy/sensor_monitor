# Sensor Monitor - Advanced Honeypot & Malware Analysis Platform

Comprehensive honeypot system with integrated malware analysis, OSINT enrichment, and AI-powered attack intelligence.

## 🎯 Overview

This is a production-ready honeypot platform that captures, analyzes, and provides intelligence on cyber attacks in real-time.

### Key Capabilities

- 🕸️ **Honeypot Server** - Vulnerable web application to attract attackers
- 📊 **Real-time Analytics** - Live attack monitoring and visualization
- 🦠 **Malware Analysis** - Automated file capture and analysis
- 🤖 **AI Intelligence** - LLM-powered attack attribution and recommendations
- 🌍 **OSINT Enrichment** - GeoIP, Shodan, AbuseIPDB, VirusTotal integration
- 🔍 **Attack Detection** - Identifies tools (Nmap, SQLmap, Metasploit, etc.)
- 📈 **Data Explorer** - Advanced filtering and historical analysis
- 🎨 **Modern Dashboard** - Vue.js frontend with beautiful visualizations

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        HONEYPOT SERVER                           │
│  - Vulnerable web app with file upload, SQL injection, etc.    │
│  - Captures all attack traffic                                  │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         │ Sends logs via Kafka
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                      CAPTURE & ANALYSIS SERVER                   │
│                                                                  │
│  ┌──────────────┐  ┌─────────────┐  ┌────────────────────────┐ │
│  │   Kafka      │  │ Elasticsearch│  │    Kibana              │ │
│  │ Message Queue│  │ Log Storage  │  │   Analytics            │ │
│  └──────┬───────┘  └──────┬──────┘  └────────────────────────┘ │
│         │                 │                                     │
│         ▼                 ▼                                     │
│  ┌─────────────────────────────────────────────────────┐       │
│  │              ENRICHMENT & ANALYSIS PIPELINE          │       │
│  │                                                      │       │
│  │  ┌─────────────┐  ┌──────────────┐  ┌────────────┐ │       │
│  │  │  Collector  │  │   Malware    │  │    LLM     │ │       │
│  │  │   - OSINT   │  │   Analyzer   │  │  Analyzer  │ │       │
│  │  │   - GeoIP   │  │ - File Hash  │  │ - AI Intel │ │       │
│  │  │   - Shodan  │  │ - Type Detect│  │ - MITRE    │ │       │
│  │  │   - Abuse   │  │ - Quarantine │  │   ATT&CK   │ │       │
│  │  └─────────────┘  └──────────────┘  └────────────┘ │       │
│  └─────────────────────────────────────────────────────┘       │
│         │                                                       │
│         ▼                                                       │
│  ┌─────────────────────────────────────────────────────┐       │
│  │              VUE.JS FRONTEND DASHBOARD              │       │
│  │  - Real-time attack visualization                   │       │
│  │  - Malware sample browser                           │       │
│  │  - IOC management                                   │       │
│  │  - Threat intelligence reports                      │       │
│  └─────────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

## 📁 Directory Structure

```
sensor-monitor/
├── honeypot/                        # Honeypot server
│   ├── app/
│   │   ├── app.py                  # Flask application
│   │   ├── honeypot_file_handler.py # Malware file capture
│   │   ├── templates/              # HTML templates
│   │   └── utils/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── requirements.txt
│
├── capture/                         # Analysis & intelligence server
│   ├── collector/                  # OSINT enrichment
│   │   ├── collector.py
│   │   ├── osint/                  # Shodan, GeoIP, AbuseIPDB
│   │   └── requirements.txt
│   ├── frontend/                   # Vue.js dashboard
│   │   ├── src/
│   │   │   ├── views/
│   │   │   │   ├── DashboardView.vue
│   │   │   │   ├── DataExplorerView.vue
│   │   │   │   └── MalwareView.vue (coming in Phase 2)
│   │   │   └── components/
│   │   └── package.json
│   ├── malware_collector.py        # 🆕 Malware file analysis
│   ├── malware_kafka_consumer.py   # 🆕 Malware processing
│   ├── llm_analyzer.py             # AI-powered analysis
│   ├── receiver.py                 # API backend
│   ├── docker-compose.yml          # All services
│   ├── requirements.txt
│   └── MALWARE_QUICK_START.md      # 🆕 Malware setup guide
│
├── casestudy/
│   └── awesome-malware-analysis-main/ # Reference resources
│
└── README.md                        # This file
```

## ✨ Key Features

### 🕸️ Honeypot Capabilities

- **SQL Injection** - Fake admin login vulnerable to SQLi
- **File Upload** - Arbitrary file upload endpoint
- **Command Injection** - Terminal console with RCE
- **Path Traversal** - Vulnerable file access
- **XSS & CSRF** - Client-side vulnerabilities
- **Full Request Logging** - Every attack captured

### 🦠 Malware Analysis (NEW! - Stage 1)

- **Automatic File Capture** - Intercepts all file uploads
- **Hash Calculation** - MD5, SHA1, SHA256, SHA512
- **File Type Detection** - Magic byte analysis
- **Organized Quarantine** - Categorized storage (executables, scripts, documents, webshells)
- **Encrypted Backups** - Password-protected ZIPs (password: `infected`)
- **Metadata Tracking** - Comprehensive JSON metadata
- **Kafka Integration** - Real-time processing pipeline

**Coming Soon** (Phase 2-5):
- YARA scanning for malware family detection
- Cuckoo Sandbox integration for behavioral analysis
- IOC extraction (IPs, domains, C2 infrastructure)
- LLM-powered malware attribution
- MITRE ATT&CK framework mapping

### 🤖 AI-Powered Intelligence

- **LLM Analysis** - Ollama integration for attack analysis
- **Attack Intent Prediction** - Understand attacker goals
- **Sophistication Assessment** - Script kiddie vs APT-level
- **Defense Recommendations** - Actionable mitigation steps
- **IOC Generation** - Automatic indicator extraction
- **Threat Attribution** - Link attacks to known campaigns

### 🌍 OSINT Enrichment

- **GeoIP** - Location, ISP, organization, timezone
- **Shodan** - Open ports, services, vulnerabilities, CVEs
- **AbuseIPDB** - Abuse reports, confidence scores
- **VirusTotal** - (Optional) File/URL reputation

### 📊 Visualization & Reporting

- **Real-time Dashboard** - Live attack statistics
- **Attack Timeline** - Temporal attack patterns
- **World Map** - Geographic attack origins
- **Tool Detection** - Identify attacking tools (Nmap, SQLmap, Hydra, etc.)
- **Endpoint Heatmap** - Most targeted paths
- **Data Explorer** - Advanced filtering and search

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Ubuntu/Debian server (recommended)
- 4GB+ RAM
- 20GB+ disk space

### 1. Clone Repository

```bash
git clone <repository-url>
cd sensor-monitor
```

### 2. Configure Environment

```bash
cd capture
cp .env.example .env

# Edit .env with your API keys (optional)
nano .env
```

**API Keys** (Optional - system works without them):
- `GEOIP_API_KEY` - MaxMind GeoIP
- `SHODAN_API_KEY` - Shodan.io
- `ABUSEIPDB_API_KEY` - AbuseIPDB
- `VIRUSTOTAL_API_KEY` - VirusTotal

### 3. Start All Services

```bash
cd capture
docker-compose up -d
```

This starts:
- ✅ Kafka & Zookeeper (message queue)
- ✅ Elasticsearch (log storage)
- ✅ Kibana (analytics)
- ✅ Backend API (Flask)
- ✅ Frontend (Vue.js)
- ✅ Collector (OSINT enrichment)
- ✅ Malware Analyzer (NEW!)

### 4. Access Dashboard

- **Frontend**: http://localhost:3000 (or http://10.8.0.1:3000)
- **Kibana**: http://localhost:5601 (or http://10.8.0.1:5601)
- **Kafka UI**: http://localhost:8081 (or http://10.8.0.1:8081)
- **Backend API**: http://localhost:8082 (or http://10.8.0.1:8082)

**Default Login**:
- Username: `admin`
- Password: `admin123`

### 5. Deploy Honeypot (Optional)

```bash
cd ../honeypot
docker-compose up -d
```

Or deploy to remote server - see deployment section below.

## 🔧 Configuration

### Environment Variables

#### Capture Server (`capture/.env`)

```bash
# Kafka
KAFKA_BOOTSTRAP_SERVERS=kafka:9092

# Elasticsearch
ELASTICSEARCH_URL=http://elasticsearch:9200
ES_INDEX_PREFIX=sensor-logs

# API Keys (optional)
GEOIP_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here

# LLM (if using Ollama)
OLLAMA_URL=http://ollama:11434
OLLAMA_MODEL=llama3.2

# Malware Analysis
QUARANTINE_PATH=/data/malware_quarantine
```

#### Honeypot Server

```bash
FLASK_ENV=production
CAPTURE_SERVER_URL=http://capture-server:8080
KAFKA_SERVERS=kafka:9092
```

## 🦠 Malware Analysis Usage

### Enable File Capture on Honeypot

Add to your honeypot Flask app:

```python
from honeypot_file_handler import HoneypotFileHandler

file_handler = HoneypotFileHandler(
    upload_dir='/app/uploads',
    kafka_servers=['kafka:9092']
)

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' in request.files:
        request_info = {
            'source_ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent')
        }
        file_handler.handle_file_upload(request.files['file'], request_info)
        return jsonify({'status': 'success'})
```

### View Captured Malware

```bash
# Check malware analyzer logs
docker logs malware-analyzer -f

# View statistics
docker exec malware-analyzer python -c "
from malware_collector import MalwareCollector
stats = MalwareCollector(quarantine_path='/data/malware_quarantine').get_statistics()
print(f'Total samples: {stats[\"total_samples\"]}')
print(f'Categories: {stats[\"by_category\"]}')
"
```

### Access Quarantine

Malware samples stored in: `capture/malware_quarantine/`

```
malware_quarantine/
├── samples/
│   ├── executables/      # .exe, .dll, .sys
│   ├── scripts/          # .ps1, .py, .js
│   ├── webshells/        # .php, .jsp
│   └── documents/        # .doc, .pdf
├── metadata/             # JSON metadata
└── encrypted_storage/    # Encrypted backups
```

**⚠️ Security**: Encrypted ZIPs use password: `infected` (industry standard)

## 📊 API Endpoints

### Backend API (Port 8082)

#### Authentication
```bash
POST /api/auth/login
Body: {"username": "admin", "password": "admin123"}
Response: {"api_key": "...", "jwt_token": "..."}
```

#### Logs & Statistics
```bash
GET /api/logs?type=attack&limit=100
GET /api/stats
GET /api/logs/timeline?hours=24
GET /api/logs/heatmap
GET /api/attack-patterns
```

#### Health Check
```bash
GET /api/health
```

## 📚 Documentation

- **Malware Analysis Quick Start**: `capture/MALWARE_QUICK_START.md`
- **Malware Analysis Full Guide**: `capture/MALWARE_ANALYSIS_README.md`
- **Tool Detection**: `TOOL_DETECTION.md`
- **Implementation Plan**: See artifacts (7-phase roadmap)

## 🔐 Security Considerations

### ⚠️ CRITICAL WARNINGS

1. **Honeypot is INTENTIONALLY vulnerable** - Never deploy on production network
2. **Isolate from real systems** - Use separate VLAN or air-gapped network
3. **Malware quarantine** - Contains REAL malware samples
4. **Logs contain sensitive data** - Encrypt backups, restrict access
5. **Never execute malware** - Files stored, never run
6. **API authentication** - Change default passwords immediately

### Best Practices

- ✅ Deploy honeypot on isolated VPS/cloud instance
- ✅ Use firewall rules to restrict access
- ✅ Rotate logs regularly (30-day retention)
- ✅ Monitor disk space (Elasticsearch can grow large)
- ✅ Backup quarantine with encrypted archives
- ✅ Review malware samples in isolated VM only

## 🛠️ Deployment

### Production Deployment (Capture Server)

```bash
# On capture server
git clone <repo>
cd sensor-monitor/capture

# Configure environment
cp .env.example .env
nano .env  # Add API keys

# Start services
docker-compose up -d

# Verify services
docker ps
docker logs collector -f
docker logs malware-analyzer -f
```

### Production Deployment (Honeypot)

```bash
# On honeypot server (separate machine!)
cd sensor-monitor/honeypot

# Configure Kafka connection
nano .env
# Set KAFKA_SERVERS=capture-server-ip:9092

# Start honeypot
docker-compose up -d

# Verify
curl http://localhost:80
```

### Firewall Configuration

#### Honeypot Server
```bash
ufw allow 22/tcp                    # SSH
ufw allow 80/tcp                    # HTTP
ufw allow 443/tcp                   # HTTPS
ufw allow from <capture-ip> to any port 9092  # Kafka
```

#### Capture Server
```bash
ufw allow 22/tcp                    # SSH
ufw allow from <your-ip> to any port 3000    # Frontend
ufw allow from <your-ip> to any port 5601    # Kibana
ufw allow from <honeypot-ip> to any port 9092  # Kafka
```

## 📈 Monitoring & Maintenance

### Check Service Status

```bash
# All containers
docker-compose ps

# Specific services
docker logs backend -f
docker logs collector -f
docker logs malware-analyzer -f
docker logs elasticsearch -f
```

### Disk Usage

```bash
# Elasticsearch indices
docker exec elasticsearch du -sh /usr/share/elasticsearch/data

# Malware quarantine
du -sh capture/malware_quarantine/

# Logs
du -sh capture/logs/
```

### Performance Tuning

```bash
# Elasticsearch memory (in docker-compose.yml)
ES_JAVA_OPTS=-Xms2g -Xmx2g  # Increase for large deployments

# Kafka retention
KAFKA_LOG_RETENTION_HOURS=168  # 7 days (default)
```

## 🐛 Troubleshooting

### Service Won't Start

```bash
# Check logs
docker-compose logs <service-name>

# Check resource usage
docker stats

# Restart specific service
docker-compose restart <service-name>
```

### Elasticsearch Issues

```bash
# Check cluster health
curl http://localhost:9200/_cluster/health?pretty

# Check indices
curl http://localhost:9200/_cat/indices?v

# Delete old indices (if disk full)
curl -X DELETE http://localhost:9200/sensor-logs-2024.11.01
```

### Kafka Connection Failed

```bash
# Check Kafka is running
docker ps | grep kafka

# Test connectivity
docker exec kafka kafka-topics.sh --list --bootstrap-server localhost:9092

# Check topics
docker exec kafka kafka-topics.sh --describe --topic malware-samples --bootstrap-server localhost:9092
```

### Malware Analyzer Not Working

```bash
# Check logs
docker logs malware-analyzer -f

# Verify Kafka topic exists
docker exec kafka kafka-topics.sh --list --bootstrap-server localhost:9092 | grep malware

# Test file detection
docker exec malware-analyzer python -c "import magic; print('OK')"
```

### Frontend Can't Connect to Backend

```bash
# Check backend API
curl http://localhost:8082/api/health

# Check CORS settings in receiver.py
# Verify API_URL in frontend/.env
```

## 🔄 Updates & Backups

### Update System

```bash
cd capture
git pull
docker-compose pull
docker-compose up -d
```

### Backup Data

```bash
# Backup Elasticsearch
docker exec elasticsearch \
  curl -X POST "http://localhost:9200/_snapshot/backup_repo/snapshot_1?wait_for_completion=true"

# Backup malware quarantine
tar -czf malware-backup-$(date +%Y%m%d).tar.gz \
  --exclude='*/temp/*' \
  capture/malware_quarantine/

# Encrypt backup
gpg -c malware-backup-$(date +%Y%m%d).tar.gz
```

## 🎓 Learning Resources

### Malware Analysis

- Awesome Malware Analysis: `casestudy/awesome-malware-analysis-main/`
- YARA Rules: https://github.com/Yara-Rules/rules
- Malware Samples: https://github.com/ytisf/theZoo (⚠️ Use with caution!)

### Threat Intelligence

- MITRE ATT&CK: https://attack.mitre.org/
- OSINT Framework: https://osintframework.com/
- Threat Intelligence Platforms: MISP, OpenCTI

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test thoroughly
4. Submit pull request

## 📜 License

This project is for educational and security research purposes only. Use responsibly and ethically.

**⚠️ DISCLAIMER**: The honeypot contains intentional vulnerabilities. Never use in production environments. The authors are not responsible for any misuse.

## 🆘 Support

For issues or questions:
1. Check documentation in `capture/` directory
2. Review logs: `docker-compose logs`
3. Check GitHub Issues
4. Consult awesome-malware-analysis resources

---

## 📊 System Status

- ✅ **Honeypot** - Production ready
- ✅ **Log Collection** - Kafka + Elasticsearch
- ✅ **OSINT Enrichment** - GeoIP, Shodan, AbuseIPDB
- ✅ **AI Analysis** - LLM integration (optional)
- ✅ **Frontend Dashboard** - Vue.js with visualizations
- ✅ **Malware Analysis Stage 1** - File capture & storage
- 🚧 **Malware Analysis Stage 2** - YARA scanning (coming soon)
- 🚧 **Malware Analysis Stage 3** - Sandbox integration (planned)

**Current Version**: 2.0 (with Malware Analysis Stage 1)

---

**Built with ❤️ for cybersecurity research and education**
