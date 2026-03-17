🌐 Network Traffic Analyzer — Forensic Tool
A Python-based network packet analyzer for forensic investigation — detects suspicious connections, port scans, cleartext protocols, and known malware ports.
📌 Features
Live Packet Capture — raw socket sniffing (TCP, UDP, ICMP)
Protocol Detection — identifies HTTP, HTTPS, FTP, DNS, Telnet, SSH, and more
Threat Detection — flags suspicious ports (Metasploit 4444, Backdoors, Tor)
Port Scan Detection — identifies rapid multi-port scanning activity
Cleartext Alerts — warns on Telnet, FTP (unencrypted protocols)
Demo Mode — works without root/network access for testing
JSON Report — full forensic output for documentation
🛠️ Tools & Technologies
Tool
Purpose
Python 3
Core language
socket
Raw packet capture
struct
Binary protocol parsing
collections
Traffic statistics
✅ No external libraries needed — pure Python!
🚀 How to Run
# Clone the repo
git clone https://github.com/YOUR_USERNAME/network-traffic-analyzer.git
cd network-traffic-analyzer

# Run in demo mode (no root needed)
python network_analyzer.py

# Run live capture (Linux, requires root)
sudo python network_analyzer.py
📸 Sample Output
============================================================
         NETWORK TRAFFIC FORENSIC REPORT
============================================================
[+] Protocol Summary:
    TCP      : ██████ (6)
    UDP      : █ (1)
    ICMP     : █ (1)

[+] Security Alerts (4 found):
    🔴 [HIGH] Suspicious Port
       Detail: Port 4444 (Metasploit Default) detected from 10.0.0.55
    🟡 [MEDIUM] Cleartext Protocol
       Detail: Telnet detected: 192.168.1.105 -> 192.168.1.1
    🔴 [HIGH] Possible Port Scan
       Detail: 192.168.1.200 made multiple rapid connections
🎯 Forensic Use Cases
Detecting C2 (Command & Control) traffic
Identifying unauthorized remote access
Network intrusion post-incident analysis
Evidence collection for cybercrime investigation
📁 Project Structure
network-traffic-analyzer/
├── network_analyzer.py          # Main analysis script
├── README.md                    # Documentation
└── network_forensic_report.json # Sample output
📜 Disclaimer
For authorized forensic and educational use only. Do not capture traffic on networks you do not own or have permission to monitor.
👤 Author
Sivani Sri.N 
Btech CYBER Forensics and Information Security 
LinkedIn: https://www.linkedin.com/in/sivani-sri-n-b135bb303?utm_source=share_via&utm_content=profile&utm_medium=member_android
