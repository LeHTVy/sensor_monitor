# Tool Detection System

Hệ thống nhận diện công cụ tấn công được cải thiện với các detector riêng biệt cho từng tool.

## Cấu trúc

```
tools/
├── __init__.py          # Module exports
├── base.py              # Base class ToolDetector và DetectionResult
├── processor.py         # ToolProcessor - kết hợp tất cả detectors
├── nmap_detector.py     # Nmap detection
├── sqlmap_detector.py   # SQLMap detection
├── nikto_detector.py    # Nikto detection
├── burp_detector.py     # Burp Suite detection
├── zap_detector.py      # OWASP ZAP detection
├── metasploit_detector.py  # Metasploit detection
├── dirb_detector.py     # DirB/Gobuster detection
├── hydra_detector.py    # Hydra/Medusa detection
├── wfuzz_detector.py    # Wfuzz/FFUF detection
└── cobalt_strike_detector.py  # Cobalt Strike detection
```

## Các phương pháp nhận diện

Mỗi detector sử dụng nhiều phương pháp:

1. **User-Agent Matching** (confidence: 80-95%)
   - Phân tích User-Agent header
   - So khớp với patterns từ scanner_user_agents database

2. **Payload Signatures** (confidence: 70-95%)
   - Phân tích query string, form data, request body
   - So khớp với payload signatures đặc trưng của từng tool

3. **Header Analysis** (confidence: 75-95%)
   - Phân tích HTTP headers
   - Phát hiện headers đặc trưng (ví dụ: X-Burp-Version)

4. **Behavioral Patterns** (confidence: 60-75%)
   - Phân tích request rate, response codes
   - Phát hiện patterns như nhiều 404s, sequential paths, etc.

5. **Path Patterns** (confidence: 65-70%)
   - Phân tích request paths
   - So khớp với common scanner paths

## ToolProcessor

`ToolProcessor` kết hợp tất cả detectors và:
- Chạy tất cả detectors song song
- Chọn detection có confidence cao nhất
- Tăng confidence nếu có nhiều detectors phát hiện cùng tool
- Duy trì context theo IP để behavioral detection

## Context Tracking

ToolProcessor theo dõi:
- Request times (để tính request rate)
- Request paths (để phát hiện scanning patterns)
- Response codes (để phát hiện nhiều 404s, failed auths)
- Failed authentication attempts

Context được reset mỗi giờ để tránh memory leak.

## Sử dụng

```python
from utils.tools import ToolProcessor

processor = ToolProcessor()
result = processor.process_request(request, ip_address)

# result = {
#     'tool': 'sqlmap',
#     'confidence': 95,
#     'method': 'payload',
#     'details': {...}
# }
```

## Tích hợp với Logger

`HoneypotLogger` tự động sử dụng `ToolProcessor`:
- Tool detection được cải thiện tự động
- Không cần thay đổi code hiện tại
- Logs bao gồm thông tin detection chi tiết

## Cải thiện so với trước

1. **Tách biệt logic**: Mỗi tool có detector riêng
2. **Dễ mở rộng**: Thêm tool mới chỉ cần tạo detector mới
3. **Confidence scoring**: Mỗi detection có confidence score
4. **Multiple methods**: Kết hợp nhiều phương pháp detection
5. **Behavioral analysis**: Phát hiện dựa trên patterns hành vi
6. **Context tracking**: Theo dõi lịch sử request theo IP

