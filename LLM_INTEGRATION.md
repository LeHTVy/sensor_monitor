# 🤖 LLM-Enhanced Threat Intelligence System

## 📋 Overview

This system uses **Local LLM (Ollama)** to automatically analyze attacker behavior, predict intent, and provide intelligent defense recommendations.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         HONEYPOT SERVER                              │
│  ┌──────────────┐   ┌─────────────────┐   ┌────────────────────┐  │
│  │   Request    │──▶│ IDS Engine      │──▶│ Tool Detector      │  │
│  │              │   │ - Rate Limiting │   │ - 25 Detectors     │  │
│  └──────────────┘   │ - Anomaly Det.  │   └────────────────────┘  │
│                     └─────────────────┘             │              │
│                             │                        │              │
│                             ▼                        ▼              │
│                     ┌─────────────────────────────────────┐        │
│                     │  Threat Intel Enricher              │        │
│                     │  ┌────────────┐  ┌──────────────┐  │        │
│                     │  │   Shodan   │  │  AbuseIPDB   │  │        │
│                     │  │  IP Intel  │  │  Reputation  │  │        │
│                     │  └────────────┘  └──────────────┘  │        │
│                     │  ┌────────────────────────────────┐ │        │
│                     │  │  LLM Context Builder           │ │        │
│                     │  │  - Attacker Profile            │ │        │
│                     │  │  - Attack Details              │ │        │
│                     │  │  - Technical Intelligence      │ │        │
│                     │  │  - Behavioral Indicators       │ │        │
│                     │  └────────────────────────────────┘ │        │
│                     └─────────────────────────────────────┘        │
│                                     │                               │
│                                     ▼                               │
│                            ┌──────────────────┐                    │
│                            │  Kafka Producer  │                    │
│                            └──────────────────┘                    │
└─────────────────────────────────────│──────────────────────────────┘
                                      │
                              VPN Tunnel (WireGuard)
                                      │
┌─────────────────────────────────────▼──────────────────────────────┐
│                         CAPTURE SERVER                              │
│                     ┌──────────────────┐                           │
│                     │  Kafka Broker    │                           │
│                     └────────┬─────────┘                           │
│                              │                                      │
│          ┌───────────────────┼───────────────────┐                 │
│          │                   │                   │                 │
│    ┌─────▼──────┐    ┌──────▼────────┐   ┌─────▼───────────┐     │
│    │ Collector  │    │ LLM Consumer  │   │  Elasticsearch  │     │
│    │  (ES)      │    │  (Analysis)   │   │                 │     │
│    └────────────┘    └───────┬───────┘   └─────────────────┘     │
│                              │                                      │
│                    ┌─────────▼──────────┐                          │
│                    │  Ollama LLM        │                          │
│                    │  (llama3.2)        │                          │
│                    │  ┌──────────────┐  │                          │
│                    │  │ Behavioral   │  │                          │
│                    │  │ Analysis     │  │                          │
│                    │  └──────────────┘  │                          │
│                    │  ┌──────────────┐  │                          │
│                    │  │ Intent       │  │                          │
│                    │  │ Prediction   │  │                          │
│                    │  └──────────────┘  │                          │
│                    │  ┌──────────────┐  │                          │
│                    │  │ Defense      │  │                          │
│                    │  │ Playbook     │  │                          │
│                    │  └──────────────┘  │                          │
│                    └────────────────────┘                          │
│                              │                                      │
│                    ┌─────────▼──────────┐                          │
│                    │  Elasticsearch     │                          │
│                    │  (llm-analysis-*)  │                          │
│                    └────────────────────┘                          │
│                              │                                      │
│                    ┌─────────▼──────────┐                          │
│                    │  Kibana Dashboard  │                          │
│                    │  - Attack Intent   │                          │
│                    │  - Recommendations │                          │
│                    │  - Defense Actions │                          │
│                    └────────────────────┘                          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Deployment

### Prerequisites

1. **Honeypot Server**:
   - Docker & Docker Compose installed
   - WireGuard VPN connected to Capture Server
   - Shodan API key configured

2. **Capture Server**:
   - Docker & Docker Compose installed
   - At least 8GB RAM (4GB for Ollama + 4GB for other services)
   - (Optional) NVIDIA GPU for faster LLM inference

### Step 1: Setup Honeypot Server

```bash
cd sensor-monitor/honeypot

# Add Shodan API key to .env
echo "SHODAN_API_KEY=7ROdb5EjnZ5kO71MJNgC9mQURAcmS3pz" >> .env

# Rebuild and restart
docker-compose down
docker-compose build --no-cache
docker-compose up -d

# Check logs
docker-compose logs -f honeypot
```

### Step 2: Setup Capture Server

```bash
cd sensor-monitor/capture

# Start all services (including Ollama)
docker-compose up -d

# Wait for Ollama to start (30-60 seconds)
sleep 60

# Pull LLM model (first time only, ~2GB download)
bash init_ollama.sh

# Check LLM analyzer logs
docker-compose logs -f llm-analyzer
```

### Step 3: Verify Pipeline

```bash
# 1. Check Kafka topics
docker exec -it kafka kafka-topics --bootstrap-server localhost:9092 --list

# Should show: honeypot-attacks, honeypot-traffic, honeypot-browser

# 2. Check Ollama models
curl http://localhost:11434/api/tags

# 3. Check Elasticsearch indices
curl http://localhost:9200/_cat/indices?v

# Should show: llm-analysis-*, sensor-logs-*

# 4. Generate test attack
# From another machine:
nmap -sS YOUR_HONEYPOT_IP

# 5. Watch LLM analysis in real-time
docker-compose logs -f llm-analyzer
```

---

## 📊 Data Flow

### 1. Attack Detection (Honeypot)

```python
# Request arrives
→ IDS checks (rate limiting, anomalies)
→ Tool detection (25 detectors)
→ Threat scoring (0-100)
→ Log categorization (attack/traffic/honeypot)
```

### 2. Data Enrichment (Honeypot)

```python
# If attack detected:
→ Query Shodan for IP intelligence
  - Open ports
  - Services
  - Vulnerabilities (CVEs)
  - Tags (scanner, malware, etc.)
  - Organization/ISP
  - ASN

→ Query AbuseIPDB (if API key available)
  - Abuse confidence score
  - Total reports
  - Last reported date

→ Build LLM context
  - Attacker profile
  - Attack details
  - Technical intelligence
  - Behavioral indicators
```

### 3. Kafka Transmission (VPN Encrypted)

```python
→ Package enriched log
→ Send to Kafka topic: "honeypot-attacks"
→ Encrypted via WireGuard VPN
```

### 4. LLM Analysis (Capture Server)

```python
→ LLM Consumer receives from Kafka
→ Extract llm_context
→ Query Ollama LLM with detailed prompt
→ LLM analyzes:
  - Attacker intent ("What are they trying to do?")
  - Attack stage (Recon, Initial Access, Persistence, etc.)
  - Sophistication level (Script Kiddie, APT, etc.)
  - Threat assessment ("How dangerous is this?")
  - Likely next steps ("What will they try next?")
  - Defense recommendations (Actionable steps)
  - IOCs (Indicators to monitor/block)

→ Generate defense playbook
  - Immediate actions (block IP, enable logging, etc.)
  - Short-term mitigation (WAF rules, rate limiting, etc.)
  - Long-term prevention (architecture changes, etc.)
  - Monitoring requirements (what to watch)
```

### 5. Storage & Visualization

```python
→ Store in Elasticsearch
  - Index: llm-analysis-YYYY-MM-DD
  - Includes: original log + LLM analysis + defense playbook

→ Visualize in Kibana
  - Attack timeline
  - Intent distribution
  - Sophistication levels
  - Top recommendations
  - Defense playbooks
```

---

## 🔍 LLM Analysis Example

### Input (llm_context):

```json
{
  "attacker_profile": {
    "ip_address": "45.67.89.10",
    "reputation_score": 85,
    "threat_level": "high",
    "location": {
      "country": "Russia",
      "city": "Moscow",
      "isp": "Digital Ocean"
    },
    "infrastructure": {
      "is_known_scanner": true,
      "is_cloud": true,
      "open_ports": [22, 80, 443, 3306, 8080]
    },
    "attack_history": {
      "abuse_reports": 47,
      "confidence_score": 90
    }
  },
  "attack_details": {
    "attack_tool": "sqlmap",
    "attack_technique": ["sql_injection", "database_enumeration"],
    "target_path": "/api/users",
    "payload": {
      "query_string": {"search": "admin' OR 1=1--"}
    }
  },
  "technical_intelligence": {
    "vulnerabilities": ["CVE-2023-12345"],
    "tags": ["scanner", "malicious"]
  }
}
```

### Output (LLM Analysis):

```json
{
  "intent": "Attacker is attempting SQL injection to bypass authentication and enumerate database structure, likely seeking to dump user credentials or escalate privileges.",

  "attack_stage": "Initial Access",

  "sophistication": "Intermediate",

  "threat_assessment": "HIGH RISK. This is an active exploitation attempt using automated tools (SQLMap). The attacker's IP has significant abuse history and is operating from cloud infrastructure, indicating potential for persistent attack campaigns.",

  "next_steps": [
    "If successful, attacker will enumerate database tables and columns",
    "Likely to attempt credential dumping from users table",
    "May try to escalate to OS command execution via SQL functions",
    "Could establish backdoor for persistent access"
  ],

  "recommendations": [
    "IMMEDIATE: Block source IP 45.67.89.10 at firewall level",
    "Deploy Web Application Firewall (WAF) with SQLi rules",
    "Implement parameterized queries for all database operations",
    "Enable database query logging and monitoring",
    "Conduct urgent security audit of /api/users endpoint",
    "Implement rate limiting: 10 req/min per IP",
    "Review all recent database queries for signs of successful exploitation"
  ],

  "iocs": [
    "IP: 45.67.89.10 (AS14061 - Digital Ocean)",
    "User-Agent: sqlmap/1.8#stable",
    "Payload pattern: ' OR 1=1--",
    "Target endpoint: /api/users",
    "Attack timing: Rapid sequential requests (15.5 req/sec)"
  ]
}
```

### Defense Playbook:

```json
{
  "immediate_actions": [
    "🚨 BLOCK IP: 45.67.89.10 immediately",
    "🔒 Enable rate limiting on /api/users endpoint",
    "📊 Review all logs from this IP for compromise indicators",
    "🔍 Check for successful SQL injection attempts",
    "📧 Alert security team - HIGH priority"
  ],

  "short_term_mitigation": [
    "Deploy WAF with SQL injection rules",
    "Implement parameterized queries",
    "Enable database query logging",
    "Conduct security audit of API endpoints"
  ],

  "long_term_prevention": [
    "Implement zero-trust architecture",
    "Deploy SIEM for advanced threat detection",
    "Regular penetration testing",
    "Security awareness training for developers"
  ],

  "monitoring_requirements": [
    "Monitor all traffic from AS14061 (Digital Ocean)",
    "Alert on User-Agent: sqlmap",
    "Watch for SQL injection patterns in logs",
    "Track similar behavior from other IPs"
  ]
}
```

---

## 🎯 Use Cases

### 1. Real-Time Attack Response

**Scenario**: SQLMap attack detected

**System Response**:
1. ✅ IDS detects SQL injection payload
2. ✅ Enriches with Shodan data (IP is known scanner)
3. ✅ Sends to Kafka → LLM analyzes
4. ✅ LLM: "Automated database enumeration, HIGH risk"
5. ✅ Generates defense playbook
6. ✅ Admin receives actionable recommendations
7. ✅ IP auto-blocked if threat level = critical

### 2. Attack Campaign Analysis

**Scenario**: Multiple IPs targeting same endpoint

**System Response**:
1. ✅ LLM analyzes each attack
2. ✅ Identifies common patterns (same ASN, similar tools)
3. ✅ Concludes: "Coordinated attack campaign"
4. ✅ Recommends: "Block entire ASN, deploy WAF rules"

### 3. Sophisticated Threat Detection

**Scenario**: Slow, stealthy reconnaissance

**System Response**:
1. ✅ IDS detects low-rate scanning
2. ✅ Enriches: Tor exit node, known APT infrastructure
3. ✅ LLM analyzes: "APT-level threat, reconnaissance phase"
4. ✅ Recommends: "Heightened monitoring, threat hunting"

---

## 📈 Benefits

### Traditional IDS vs LLM-Enhanced IDS

| Feature | Traditional IDS | LLM-Enhanced IDS |
|---------|----------------|------------------|
| **Detection** | Pattern matching | Pattern + Behavioral analysis |
| **Context** | Limited | Rich (Shodan, AbuseIPDB, history) |
| **Intent** | ❌ Cannot predict | ✅ Predicts attacker goals |
| **Sophistication** | ❌ No assessment | ✅ Script Kiddie to APT level |
| **Recommendations** | Generic | ✅ Specific, actionable |
| **Playbooks** | Manual | ✅ Auto-generated |
| **Next Steps** | ❌ Unknown | ✅ Predicts attacker's next move |
| **Learning** | Static rules | ✅ Adapts with LLM updates |

---

## ⚙️ Configuration

### Ollama Models

**Recommended models** (by resource):

```bash
# Lightweight (4GB RAM) - Good for most attacks
llama3.2        # Default, balanced

# Medium (8GB RAM) - Better analysis
mistral         # Excellent for security analysis

# Advanced (16GB RAM) - Best quality
llama3:70b      # Most sophisticated analysis
codellama:34b   # Best for code/exploit analysis
```

Change model in `docker-compose.yml`:

```yaml
llm-analyzer:
  environment:
    - OLLAMA_MODEL=mistral  # Change here
```

### API Keys

**Honeypot** (`.env`):
```bash
SHODAN_API_KEY=7ROdb5EjnZ5kO71MJNgC9mQURAcmS3pz
ABUSEIPDB_API_KEY=your_key_here  # Optional
```

**Shodan API Limits** (Free tier):
- 1 request/second
- 100 requests/month

**Tip**: System caches Shodan results for 1 hour to save API quota.

### Rate Limiting

Edit `honeypot/app/utils/ids_engine.py`:

```python
self.rate_limits = {
    'requests_per_second': 10,      # Adjust as needed
    'requests_per_minute': 100,
    'requests_per_hour': 1000,
}
```

---

## 🐛 Troubleshooting

### Ollama Not Starting

```bash
# Check Ollama logs
docker-compose logs ollama

# Common issue: Not enough memory
# Solution: Stop other services or upgrade RAM

# Test connection
curl http://localhost:11434/api/tags
```

### LLM Consumer Not Processing

```bash
# Check if Ollama model is pulled
docker exec -it ollama-llm ollama list

# Pull model manually if needed
docker exec -it ollama-llm ollama pull llama3.2

# Check consumer logs
docker-compose logs -f llm-analyzer
```

### No Shodan Data

```bash
# Check API key in .env
cat .env | grep SHODAN

# Test Shodan API
curl "https://api.shodan.io/shodan/host/8.8.8.8?key=YOUR_KEY"

# Check cache
# Shodan results cached for 1 hour
```

### High Memory Usage

```bash
# Check Ollama memory
docker stats ollama-llm

# Reduce memory if needed
docker exec -it ollama-llm ollama run llama3.2 --num-gpu 0

# Or use smaller model
# Change OLLAMA_MODEL to "tinyllama" (1GB RAM)
```

---

## 📚 API Reference

### LLM Analysis Response

```typescript
interface LLMAnalysis {
  timestamp: string;              // ISO 8601
  llm_model: string;              // "llama3.2"
  attacker_ip: string;            // "1.2.3.4"
  intent: string;                 // Attacker's goal
  attack_stage: string;           // Recon, Initial Access, etc.
  sophistication: string;         // Script Kiddie, Intermediate, Advanced, APT
  threat_assessment: string;      // Detailed threat analysis
  next_steps: string[];           // Predicted attacker actions
  recommendations: string[];      // Defense recommendations
  iocs: string[];                 // Indicators of Compromise
}
```

### Defense Playbook

```typescript
interface DefensePlaybook {
  timestamp: string;
  attacker_ip: string;
  threat_level: string;           // low, medium, high, critical
  immediate_actions: string[];    // Block IP, enable logging, etc.
  short_term_mitigation: string[]; // WAF rules, patches, etc.
  long_term_prevention: string[]; // Architecture changes, etc.
  monitoring_requirements: string[]; // What to watch
  iocs: string[];                 // Indicators to block
}
```

---

## 🔒 Security Considerations

1. **Ollama runs locally** - No data sent to external LLM APIs
2. **VPN encrypted** - All honeypot → capture traffic via WireGuard
3. **API keys secured** - Stored in `.env`, not in code
4. **Shodan caching** - Reduces external API calls
5. **Rate limiting** - Prevents API quota exhaustion

---

## 📞 Support

**Issues?**
- Check logs: `docker-compose logs -f llm-analyzer`
- Test Ollama: `curl http://localhost:11434/api/tags`
- Verify Shodan: Check `.env` file

**Performance?**
- Use smaller model (tinyllama) for low-resource systems
- Adjust cache TTL (default: 1 hour)
- Reduce concurrent LLM requests

---

**Deployed**: 2025-11-19
**Version**: 2.0.0 - LLM Enhanced
**Author**: Claude Code Assistant
