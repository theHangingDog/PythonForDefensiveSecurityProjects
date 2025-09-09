# 🕵️ Python Network Traffic Analyzer

A Python-based tool to analyze PCAP files and detect suspicious or malicious network activity.
It parses raw packet captures into flows, enriches them with protocol-specific details, and runs a series of anomaly detectors.

Currently, it supports detection for:

🔎 Unusual Port Usage – traffic on non-standard ports

📡 Beaconing Activity – repetitive or timed connections that may indicate C2 traffic

🧩 DNS Exfiltration – suspiciously long or structured DNS queries

🌐 HTTP Anomalies – detection of suspicious User-Agents, base64/encoded URIs, and obfuscated paths

🚀 Features

- Parses PCAPs with pyshark
 (wrapper for Tshark/Wireshark)

- Stores traffic as flows (IP + port + protocol) for easier correlation

- Progress bars for parsing and analyzing flows

- Modular detection engine (add your own detectors easily)

- JSON reporting of all alerts
```
📂 Project Structure
network_analyzer/
├── main.py                  # Entry point
├── parsers/
│   └── pcap_parser.py       # Packet → flow parser
├── storage/
│   └── flow_store.py        # Flow storage & stats
├── detectors/
│   ├── unusual_port.py      # Detect non-standard ports
│   ├── beaconing.py         # Detect beaconing activity
│   ├── dns_exfil.py         # Detect suspicious DNS
│   └── http_anomalies.py    # Detect bad/malicious HTTP
├── reports/
│   └── reporter.py          # Save results (JSON, extendable)
└── requirements.txt         # Python dependencies
```
⚙️ Installation

Clone the repo:
```
git clone https://github.com/yourusername/network_analyzer.git
cd network_analyzer
```

Install dependencies:
```
pip install -r requirements.txt
```

Install Tshark (required for PyShark):
```
Linux (Debian/Kali/Ubuntu):

sudo apt update && sudo apt install tshark -y


Windows: Install Wireshark
 and ensure tshark is in PATH.
```
🖥️ Usage

Basic run:
```
python3 main.py --pcap traffic.pcap
```

Verbose mode (shows flow stats + detector errors if any):
```
python3 main.py --pcap traffic.pcap --verbose
```

Custom report directory:
```
python3 main.py --pcap traffic.pcap --outdir my_reports
```
📊 Example Output
```
Alerts are stored in reports/report_TIMESTAMP.json.

Example JSON structure:

{
  "pcap": "traffic.pcap",
  "summary": {
    "total_flows": 12,
    "total_packets": 350,
    "total_bytes": 45231
  },
  "alerts": [
    {
      "flow": {
        "flow_id": "abc123...",
        "src_ip": "192.168.1.5",
        "dst_ip": "8.8.8.8",
        "src_port": 53212,
        "dst_port": 53,
        "protocol": "UDP",
        "packets": 15,
        "bytes": 2048
      },
      "alerts": [
        "[DNS Exfil] Unusually long DNS label: 45 chars: ajdkslfjsldkjf.example.com"
      ]
    }
  ]
}
```
🛠️ Roadmap

Planned improvements:

- Add back TLS/SSL anomaly detection (JA3, SNI mismatch, self-signed certs)

- File extraction for HTTP/DNS payloads

- Visualization of flows (graph output)

- SIEM integration (e.g., Splunk, ELK)

🤝 Contributing

Fork this repo

Add new detection modules under detectors/

Update main.py to call your detector

Submit a PR 🚀
