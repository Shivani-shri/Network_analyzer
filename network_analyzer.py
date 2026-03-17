"""
Network Traffic Analyzer - Forensic Tool
Author: [Your Name]
Description: Captures and analyzes network packets to detect anomalies,
             suspicious connections, and potential intrusions.
"""

import socket
import struct
import json
import os
import sys
from datetime import datetime
from collections import defaultdict


# Known suspicious ports
SUSPICIOUS_PORTS = {
    4444: "Metasploit Default",
    1337: "Common Backdoor",
    31337: "Elite Backdoor",
    12345: "NetBus Trojan",
    27374: "SubSeven Trojan",
    6667: "IRC (Botnet)",
    6668: "IRC (Botnet)",
    9001: "Tor",
    9050: "Tor SOCKS",
    8080: "Proxy/C2 Common",
}

# Port to protocol map
KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
}


class PacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.connections = defaultdict(int)
        self.alerts = []
        self.protocol_counts = defaultdict(int)
        self.ip_activity = defaultdict(int)

    def parse_ethernet_frame(self, data):
        """Parse Ethernet frame."""
        dest_mac = ':'.join(f'{b:02x}' for b in data[:6])
        src_mac = ':'.join(f'{b:02x}' for b in data[6:12])
        proto = struct.unpack('!H', data[12:14])[0]
        return dest_mac, src_mac, proto, data[14:]

    def parse_ipv4_packet(self, data):
        """Parse IPv4 packet."""
        version_ihl = data[0]
        ihl = (version_ihl & 0xF) * 4
        ttl = data[8]
        proto = data[9]
        src_ip = socket.inet_ntoa(data[12:16])
        dest_ip = socket.inet_ntoa(data[16:20])
        return ihl, ttl, proto, src_ip, dest_ip, data[ihl:]

    def parse_tcp_segment(self, data):
        """Parse TCP segment."""
        src_port, dest_port, seq, ack = struct.unpack('!HHII', data[:12])
        offset = ((data[12] >> 4) * 4)
        flags = data[13]
        flag_str = ""
        if flags & 0x02: flag_str += "SYN "
        if flags & 0x10: flag_str += "ACK "
        if flags & 0x01: flag_str += "FIN "
        if flags & 0x04: flag_str += "RST "
        if flags & 0x08: flag_str += "PSH "
        return src_port, dest_port, flag_str.strip(), data[offset:]

    def parse_udp_segment(self, data):
        """Parse UDP segment."""
        src_port, dest_port, length = struct.unpack('!HHH', data[:6])
        return src_port, dest_port, data[8:]

    def check_suspicious(self, src_ip, dest_ip, src_port, dest_port, protocol):
        """Check for suspicious patterns."""
        alerts = []

        # Check suspicious ports
        for port in [src_port, dest_port]:
            if port in SUSPICIOUS_PORTS:
                alerts.append({
                    "severity": "HIGH",
                    "type": "Suspicious Port",
                    "detail": f"Port {port} ({SUSPICIOUS_PORTS[port]}) detected from {src_ip}"
                })

        # Check for Telnet (unencrypted)
        if dest_port == 23:
            alerts.append({
                "severity": "MEDIUM",
                "type": "Cleartext Protocol",
                "detail": f"Telnet detected: {src_ip} -> {dest_ip}"
            })

        # Check for FTP (unencrypted)
        if dest_port == 21:
            alerts.append({
                "severity": "LOW",
                "type": "Cleartext Protocol",
                "detail": f"FTP detected: {src_ip} -> {dest_ip}"
            })

        # Detect port scanning (high unique port activity)
        conn_key = f"{src_ip}->{dest_ip}"
        self.connections[conn_key] += 1
        if self.connections[conn_key] > 10:
            alerts.append({
                "severity": "HIGH",
                "type": "Possible Port Scan",
                "detail": f"{src_ip} made {self.connections[conn_key]} connections to {dest_ip}"
            })

        return alerts

    def capture_live(self, count=20):
        """Capture live packets using raw socket."""
        print(f"[*] Starting live capture ({count} packets)...")
        print("[*] Requires root/admin privileges\n")

        try:
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except PermissionError:
            print("[!] Permission denied. Run as root or use demo mode.")
            return False
        except AttributeError:
            print("[!] AF_PACKET not supported on this OS. Use demo mode.")
            return False

        for i in range(count):
            raw_data, addr = conn.recvfrom(65536)
            self.process_packet(raw_data)
            print(f"    [{i+1}/{count}] Packet processed")

        conn.close()
        return True

    def process_packet(self, raw_data):
        """Process a single raw packet."""
        packet_info = {"timestamp": datetime.now().strftime('%H:%M:%S.%f')}

        try:
            dest_mac, src_mac, eth_proto, data = self.parse_ethernet_frame(raw_data)

            if eth_proto == 0x0800:  # IPv4
                ihl, ttl, proto, src_ip, dest_ip, data = self.parse_ipv4_packet(data)
                packet_info.update({"src_ip": src_ip, "dest_ip": dest_ip, "ttl": ttl})
                self.ip_activity[src_ip] += 1

                if proto == 6:  # TCP
                    src_port, dest_port, flags, payload = self.parse_tcp_segment(data)
                    protocol = KNOWN_PORTS.get(dest_port, f"Port-{dest_port}")
                    packet_info.update({
                        "protocol": "TCP", "service": protocol,
                        "src_port": src_port, "dest_port": dest_port, "flags": flags
                    })
                    self.protocol_counts["TCP"] += 1
                    alerts = self.check_suspicious(src_ip, dest_ip, src_port, dest_port, "TCP")
                    self.alerts.extend(alerts)

                elif proto == 17:  # UDP
                    src_port, dest_port, payload = self.parse_udp_segment(data)
                    protocol = KNOWN_PORTS.get(dest_port, f"Port-{dest_port}")
                    packet_info.update({
                        "protocol": "UDP", "service": protocol,
                        "src_port": src_port, "dest_port": dest_port
                    })
                    self.protocol_counts["UDP"] += 1

                elif proto == 1:  # ICMP
                    packet_info["protocol"] = "ICMP"
                    self.protocol_counts["ICMP"] += 1

            self.packets.append(packet_info)

        except Exception as e:
            pass

    def load_demo_packets(self):
        """Load simulated packet data for demo."""
        demo_data = [
            {"timestamp": "10:22:01.001", "src_ip": "192.168.1.101", "dest_ip": "8.8.8.8", "protocol": "UDP", "service": "DNS", "src_port": 54322, "dest_port": 53},
            {"timestamp": "10:22:01.120", "src_ip": "192.168.1.101", "dest_ip": "142.250.80.46", "protocol": "TCP", "service": "HTTPS", "src_port": 49200, "dest_port": 443, "flags": "SYN"},
            {"timestamp": "10:22:02.005", "src_ip": "192.168.1.105", "dest_ip": "192.168.1.1", "protocol": "TCP", "service": "Telnet", "src_port": 56001, "dest_port": 23, "flags": "SYN ACK"},
            {"timestamp": "10:22:03.110", "src_ip": "10.0.0.55", "dest_ip": "192.168.1.101", "protocol": "TCP", "service": "Metasploit Default", "src_port": 4444, "dest_port": 4444, "flags": "SYN"},
            {"timestamp": "10:22:04.001", "src_ip": "192.168.1.200", "dest_ip": "192.168.1.101", "protocol": "TCP", "service": "HTTP", "src_port": 60001, "dest_port": 80, "flags": "SYN"},
            {"timestamp": "10:22:04.002", "src_ip": "192.168.1.200", "dest_ip": "192.168.1.101", "protocol": "TCP", "service": "SSH", "src_port": 60002, "dest_port": 22, "flags": "SYN"},
            {"timestamp": "10:22:04.003", "src_ip": "192.168.1.200", "dest_ip": "192.168.1.101", "protocol": "TCP", "service": "FTP", "src_port": 60003, "dest_port": 21, "flags": "SYN"},
            {"timestamp": "10:22:04.100", "src_ip": "192.168.1.101", "dest_ip": "192.168.1.50", "protocol": "ICMP", "service": "Ping"},
        ]
        self.packets = demo_data

        # Simulate alerts
        self.alerts = [
            {"severity": "HIGH", "type": "Suspicious Port", "detail": "Port 4444 (Metasploit Default) detected from 10.0.0.55"},
            {"severity": "MEDIUM", "type": "Cleartext Protocol", "detail": "Telnet detected: 192.168.1.105 -> 192.168.1.1"},
            {"severity": "LOW", "type": "Cleartext Protocol", "detail": "FTP detected: 192.168.1.200 -> 192.168.1.101"},
            {"severity": "HIGH", "type": "Possible Port Scan", "detail": "192.168.1.200 made multiple rapid connections"},
        ]
        self.protocol_counts = {"TCP": 6, "UDP": 1, "ICMP": 1}

    def generate_report(self):
        """Generate and print forensic report."""
        print("\n" + "=" * 60)
        print("         NETWORK TRAFFIC FORENSIC REPORT")
        print("=" * 60)
        print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Total Packets Analyzed: {len(self.packets)}")

        print("\n[+] Protocol Summary:")
        for proto, count in self.protocol_counts.items():
            bar = "█" * count
            print(f"    {proto:8} : {bar} ({count})")

        print("\n[+] Captured Packets:")
        print(f"    {'Time':<15} {'Source IP':<18} {'Dest IP':<18} {'Proto':<6} {'Service'}")
        print("    " + "-" * 65)
        for p in self.packets[:15]:
            src = p.get("src_ip", "N/A")
            dst = p.get("dest_ip", "N/A")
            proto = p.get("protocol", "?")
            svc = p.get("service", "Unknown")
            ts = p.get("timestamp", "")
            print(f"    {ts:<15} {src:<18} {dst:<18} {proto:<6} {svc}")

        print(f"\n[⚠] Security Alerts ({len(self.alerts)} found):")
        if self.alerts:
            for alert in self.alerts:
                icon = "🔴" if alert["severity"] == "HIGH" else "🟡" if alert["severity"] == "MEDIUM" else "🟢"
                print(f"    {icon} [{alert['severity']}] {alert['type']}")
                print(f"       Detail: {alert['detail']}")
        else:
            print("    ✅ No suspicious activity detected.")

        report = {
            "generated": datetime.now().isoformat(),
            "total_packets": len(self.packets),
            "protocols": dict(self.protocol_counts),
            "alerts": self.alerts,
            "packets": self.packets
        }
        with open("network_forensic_report.json", 'w') as f:
            json.dump(report, f, indent=4)

        print("\n[✓] Report saved: network_forensic_report.json")
        print("=" * 60)


def main():
    print("=" * 60)
    print("    NETWORK TRAFFIC ANALYZER - FORENSIC TOOL")
    print("=" * 60)
    print("\nModes:")
    print("  1. Live Capture (requires root)")
    print("  2. Demo Mode (simulated traffic)")

    mode = input("\nSelect mode (1 or 2): ").strip()
    analyzer = PacketAnalyzer()

    if mode == "1":
        count = int(input("How many packets to capture? (default 20): ") or "20")
        success = analyzer.capture_live(count)
        if not success:
            print("[*] Falling back to demo mode...")
            analyzer.load_demo_packets()
    else:
        print("\n[*] Loading demo network traffic data...")
        analyzer.load_demo_packets()

    analyzer.generate_report()


if __name__ == "__main__":
    main()
