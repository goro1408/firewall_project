import logging
from scapy.all import sniff, IP, TCP, UDP

# Define filtering rules (blocked IPs, ports, etc.)
BLOCKED_IPS = ["192.168.1.10"]
BLOCKED_PORTS = [80, 443]
BLOCKED_PROTOCOLS = ["UDP"]

# Set up logging configuration
logging.basicConfig(filename="blocked_packets.log", level=logging.INFO, format="%(asctime)s - %(message)s")

def log_blocked_packet(packet_info):
    """Log the blocked packet information to a file."""
    logging.info(packet_info)

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Check if packet matches any blocking rules
        if src_ip in BLOCKED_IPS or dst_ip in BLOCKED_IPS:
            info = f"Blocked packet from/to IP: {src_ip} -> {dst_ip}"
            print(info)
            log_blocked_packet(info)
            return

        if TCP in packet or UDP in packet:
            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            else:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            # Check protocol and ports
            if protocol in BLOCKED_PROTOCOLS:
                info = f"Blocked {protocol} packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                print(info)
                log_blocked_packet(info)
                return
            
            if src_port in BLOCKED_PORTS or dst_port in BLOCKED_PORTS:
                info = f"Blocked packet on port {src_port} or {dst_port}: {src_ip} -> {dst_ip}"
                print(info)
                log_blocked_packet(info)
                return

        # If packet passes all checks, it is allowed
        print(f"Allowed packet: {src_ip} -> {dst_ip}")

def start_firewall():
    print("Starting firewall simulation with logging... Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    start_firewall()
