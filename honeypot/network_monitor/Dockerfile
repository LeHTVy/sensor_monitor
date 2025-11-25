FROM python:3.11-slim

# Install system dependencies for Scapy (libpcap)
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Run as root (required for sniffing)
USER root

# Command to run the sniffer
CMD ["python", "-u", "packet_sniffer.py", "--interface", "auto"]
