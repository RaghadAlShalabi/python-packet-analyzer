from scapy.all import *
from dashboard import run_dashboard


class TrafficAnalyzer:

    def __init__(self):

        # Configuration
        self.MODE = "live"      # Change to "pcap" for PCAP analysis
        self.PCAP_FILE = "Traffic.pcap"

        # Counters
        self.total_packets = 0
        self.total_bytes = 0

        # Dictionaries
        self.protocol_count = {}
        self.connections = {}
        self.ip_counter = {}

        # Detection dictionaries
        self.port_tracker = {}
        self.icmp_counter = {}

    # Process Packet
    def process_packet(self, pkt):

        # Ignore packets without IP layer
        if not pkt.haslayer(IP):
            return

        # Update counters
        self.total_packets += 1
        self.total_bytes += len(pkt)

        # Extract source and destination IP
        src = pkt[IP].src
        dst = pkt[IP].dst

        # Detect protocol
        proto = pkt[IP].proto

        if proto == 6:
            protocol = "TCP"

        elif proto == 17:
            protocol = "UDP"

        elif proto == 1:
            protocol = "ICMP"

        else:
            protocol = "OTHER"

        # Count protocols
        if protocol in self.protocol_count:
            self.protocol_count[protocol] += 1
        else:
            self.protocol_count[protocol] = 1

        # Extract destination port
        dport = 0

        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport

        elif pkt.haslayer(UDP):
            dport = pkt[UDP].dport

        # Store connection
        conn = str(src) + " -> " + str(dst) + ":" + str(dport)

        if conn in self.connections:
            self.connections[conn] += 1
        else:
            self.connections[conn] = 1

        # Count packets per IP
        if src in self.ip_counter:
            self.ip_counter[src] += 1
        else:
            self.ip_counter[src] = 1

        # Simple Detection Section

        # 1. Possible DoS Detection
        if self.ip_counter[src] == 300:
            print("[ALERT] Possible DoS from:", src)

        # 2. Possible Port Scan Detection
        if dport != 0:

            if src not in self.port_tracker:
                self.port_tracker[src] = set()

            self.port_tracker[src].add(dport)

            if len(self.port_tracker[src]) == 40:
                print("[ALERT] Possible Port Scan from:", src)

        # 3. ICMP Flood Detection
        if protocol == "ICMP":

            if src in self.icmp_counter:
                self.icmp_counter[src] += 1
            else:
                self.icmp_counter[src] = 1

            if self.icmp_counter[src] == 50:
                print("[ALERT] High ICMP Traffic from:", src)

    # Run Analyzer
    def run(self):

        if self.MODE == "pcap":

            try:

                packets = rdpcap(self.PCAP_FILE)

                for pkt in packets:
                    self.process_packet(pkt)

            except Exception as e:

                print("Error reading PCAP file")
                print(e)

        elif self.MODE == "live":

            print("Starting live capture...")

            try:

                sniff(prn=self.process_packet, store=False)

            except Exception as e:

                print("Error during live capture")
                print(e)

        else:
            print("Invalid mode")

    # Find Top Talker
    def get_top_talker(self):

        top_ip = ""
        max_packets = 0

        for ip in self.ip_counter:

            if self.ip_counter[ip] > max_packets:
                max_packets = self.ip_counter[ip]
                top_ip = ip

        return top_ip, max_packets

    # Print Results
    def print_results(self):

        print("\n===== REPORT =====")

        print("Total Packets:", self.total_packets)
        print("Total Bytes:", self.total_bytes)

        print("\nProtocol Count:")

        for p in self.protocol_count:
            print(p, ":", self.protocol_count[p])

        top_ip, max_packets = self.get_top_talker()

        print("\nTop Talker:", top_ip)
        print("Packets:", max_packets)

    # Dashboard
    def generate_dashboard(self):

        top_ip, max_packets = self.get_top_talker()

        alerts = []

        # Possible DoS
        for ip in self.ip_counter:

            if self.ip_counter[ip] >= 300:

                alerts.append(
                    "Possible DoS Activity from IP: " + ip
                )

        # Possible Port Scan
        for ip in self.port_tracker:

            if len(self.port_tracker[ip]) >= 40:

                alerts.append(
                    "Possible Port Scanning from IP: " + ip
                )

        # ICMP Flood
        for ip in self.icmp_counter:

            if self.icmp_counter[ip] >= 50:

                alerts.append(
                    "High ICMP Traffic Detected from IP: " + ip
                )

        dashboard_data = {

            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "protocol_count": self.protocol_count,
            "connections": self.connections,
            "mode": self.MODE,
            "top_ip": top_ip,
            "max_packets": max_packets,
            "alerts": alerts
        }

        run_dashboard(dashboard_data)