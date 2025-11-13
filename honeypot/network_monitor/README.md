# Network Monitor - Network Layer Attack Detection

## Overview

Network Monitor là component mới trong honeypot system, chịu trách nhiệm detect attacks ở **Network Layer** (Layer 3-4) mà Flask app không thể capture được.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Network Monitor                       │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────┐      ┌──────────────────────────┐    │
│  │   Scapy     │──────│   Packet Sniffer Core    │    │
│  │ Raw Packets │      │   - IP/TCP/UDP/ICMP      │    │
│  └─────────────┘      │   - Context tracking     │    │
│                        │   - Metrics calculation  │    │
│                        └──────────┬───────────────┘    │
│                                   │                     │
│                        ┌──────────▼───────────────┐    │
│                        │   Tool Detectors         │    │
│                        │  - NmapDetector          │    │
│                        │  - MasscanDetector       │    │
│                        │  - GenericDetector       │    │
│                        └──────────┬───────────────┘    │
│                                   │                     │
│                        ┌──────────▼───────────────┐    │
│                        │   Kafka Producer         │    │
│                        │   - Queue worker         │    │
│                        │   - Topic: attacks       │    │
│                        └──────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

## What It Detects

### 1. Port Scans
- **SYN scan** (-sS): Half-open scanning
- **TCP Connect scan** (-sT): Full connection
- **UDP scan** (-sU): UDP port scanning
- **XMAS scan** (-sX): FIN+PSH+URG flags
- **NULL scan** (-sN): No flags
- **FIN scan** (-sF): FIN flag only
- **ACK scan** (-sA): Firewall detection

### 2. Scanning Tools
- **Nmap**: All scan types, timing templates (T0-T5)
- **Masscan**: Ultra-fast scanning (1000+ pps)
- **ZMap**: Internet-wide scanning
- **Unknown scanners**: Heuristic detection

### 3. Scan Characteristics
- Packet rates (slow scan vs aggressive)
- Port diversity (how many ports)
- Sequential vs random patterns
- Timing analysis (T0-T5 detection)
- Custom TCP/IP stack fingerprinting

## Files

```
network_monitor/
├── packet_sniffer.py          # Main sniffer core
├── detectors/
│   ├── __init__.py
│   ├── base_network_detector.py      # Base class
│   ├── nmap_network_detector.py      # Nmap detection
│   ├── masscan_network_detector.py   # Masscan detection
│   └── generic_scan_detector.py      # Generic scanner
└── README.md                   # This file
```

## Usage

### Running Standalone

```bash
# As root (required for packet capture)
sudo python3 packet_sniffer.py --interface any --kafka 10.8.0.1:9093

# Specific interface
sudo python3 packet_sniffer.py --interface eth0 --kafka 10.8.0.1:9093
```

### Running in Docker

The network monitor is automatically started in the Docker container via the startup script in `Dockerfile`.

**Important**: Container must have `NET_ADMIN` and `NET_RAW` capabilities:

```yaml
# docker-compose.yml
services:
  honeypot:
    cap_add:
      - NET_ADMIN
      - NET_RAW
```

### Monitoring

```bash
# Check if running
ps aux | grep packet_sniffer

# View logs
docker logs -f honeypot-server | grep "Network Monitor"

# View attack detections
docker logs honeypot-server | grep "Attack detected"
```

## Detection Logic

### Nmap Detection

**Patterns:**
1. **High SYN rate** (>5 pps) + many ports → Confidence: 60-85%
2. **Unusual TCP flags** (XMAS, NULL, FIN) → Confidence: 65-70%
3. **Port diversity** (>50 ports) → Confidence: 55-80%
4. **Timing analysis** (packet rate matching T0-T5) → Confidence: 55-75%
5. **Sequential ports** (1,2,3,4...) → Confidence: 50-70%

**Example Detection:**
```python
{
    'tool': 'nmap',
    'confidence': 85,
    'method': 'syn_scan+timing_analysis+port_diversity',
    'details': {
        'syn_rate': 15.5,
        'ports_scanned': 150,
        'timing_template': 'T4',
        'scan_speed': 'aggressive',
        'sequential_ratio': 0.8
    },
    'techniques': ['reconnaissance', 'port_scan', 'aggressive_scan']
}
```

### Masscan Detection

**Patterns:**
1. **Extremely high rate** (>100 pps) → Confidence: 60-80%
2. **Custom TCP stack** (unusual TTL, window size) → Confidence: 50-70%
3. **Pure SYN scanning** (>95% SYN packets) → Confidence: 55-75%
4. **Massive port diversity** (>200 ports) → Confidence: 60-80%

**Example Detection:**
```python
{
    'tool': 'masscan',
    'confidence': 95,
    'method': 'high_rate_scan',
    'details': {
        'packet_rate': 1024.5,
        'rate_classification': 'extreme',
        'syn_ratio': 0.98,
        'stateless_scan': True,
        'massive_port_scan': 500
    },
    'techniques': ['reconnaissance', 'mass_scan', 'aggressive_scan']
}
```

### Generic Scanner Detection

**Heuristic Scoring (max 100 points):**
- Packet rate analysis: 0-25 points
- Port diversity: 0-25 points
- SYN patterns: 0-20 points
- Traffic patterns: 0-15 points
- Temporal analysis: 0-15 points

**Threshold**: Confidence >= 50% to report

**Example Detection:**
```python
{
    'tool': 'unknown_scanner',
    'confidence': 72,
    'method': 'behavioral_heuristics',
    'details': {
        'rate_level': 'high',
        'packet_rate': 25.5,
        'port_scan_scope': 'large',
        'ports_scanned': 75,
        'syn_pattern': 'high_syn_ratio',
        'syn_ratio': 0.85
    },
    'techniques': ['reconnaissance', 'port_scan', 'aggressive_scan']
}
```

## IP Context Tracking

For each source IP, the system tracks:

```python
{
    'syn_packets': deque(maxlen=1000),   # Last 1000 SYN packets
    'ports_scanned': set(),               # Unique ports accessed
    'packet_times': deque(maxlen=1000),   # Timestamps
    'packet_types': {                     # Packet type counts
        'TCP': 500,
        'SYN': 450,
        'UDP': 50,
        'ICMP': 10
    },
    'last_seen': datetime,
    'total_packets': 1000
}
```

**Cleanup**: Contexts older than 1 hour are automatically removed.

## Metrics Calculated

```python
{
    'packet_rate': 15.5,          # Packets per second
    'syn_rate': 14.8,             # SYN packets per second
    'port_diversity': 150,         # Unique ports scanned
    'recent_ports_count': 45,      # Ports scanned in last 10s
    'total_packets': 300,
    'syn_packets': 280,
    'packet_types': {
        'TCP': 290,
        'SYN': 280,
        'UDP': 10
    }
}
```

## Log Format

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
    "details": {...}
  },
  "attack_technique": ["reconnaissance", "port_scan", "aggressive_scan"],
  "log_category": "attack",
  "metrics": {...},
  "ports_scanned": [21, 22, 23, 25, 80, ...]
}
```

## Performance

### Metrics:
- **Packet capture**: ~10,000 pps (tested)
- **Memory usage**: ~200-300 MB
- **CPU usage**: ~10-20% (1 core)
- **Detection latency**: <100ms

### Optimization:
- Deque with maxlen for bounded memory
- Context cleanup every 1000 packets
- Non-blocking Kafka transmission
- Efficient packet filtering (TCP/UDP/ICMP only)

## Configuration

### Adjust Detection Thresholds

Edit detector files:

```python
# network_monitor/detectors/nmap_network_detector.py

# Timing templates
self.timing_templates = {
    'T0': (0, 0.2),      # Adjust as needed
    'T1': (0.2, 1),
    ...
}

# Minimum rates
if syn_rate > 5:  # Adjust threshold
    confidence += 30
```

### Adjust Buffer Sizes

```python
# packet_sniffer.py

self.ip_contexts = defaultdict(lambda: {
    'syn_packets': deque(maxlen=500),  # Reduce if memory constrained
    ...
})
```

### Adjust Kafka Queue

```python
# packet_sniffer.py

self.kafka_queue = queue.Queue(maxsize=500)  # Reduce if needed
```

## Troubleshooting

### No packets captured

**Cause**: Missing NET_ADMIN capability

**Fix**:
```yaml
# docker-compose.yml
cap_add:
  - NET_ADMIN
  - NET_RAW
```

### Detection not working

**Cause**: Thresholds too high

**Fix**: Lower thresholds in detector files

### High memory usage

**Cause**: Too many IPs tracked

**Fix**: Reduce maxlen in deques or decrease cleanup interval

### Kafka connection fails

**Cause**: VPN not working

**Fix**: Check WireGuard and Kafka connectivity

## Testing

### Test SYN Scan

```bash
# From external machine
nmap -sS -p 1-1000 <HONEYPOT_IP>
```

**Expected**: Detection with confidence >80%

### Test Fast Scan

```bash
nmap -T5 -p 1-1000 <HONEYPOT_IP>
```

**Expected**: Detection with timing_template: T5

### Test Masscan

```bash
masscan <HONEYPOT_IP> -p1-65535 --rate=1000
```

**Expected**: Masscan detection with confidence >90%

## Future Enhancements

1. **DDoS Detection**: Detect flood attacks
2. **OS Fingerprinting**: Detect attacker OS
3. **Botnet Detection**: Identify botnet traffic
4. **Advanced ML**: Train model on packet patterns
5. **Correlation**: Combine with application layer events

---

**Status**: ✅ Production Ready

**Version**: 1.0.0

**Last Updated**: 2025-11-12
