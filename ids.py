import sys
try:
    from scapy.all import sniff, ICMP, IP
except ImportError:
    print("Scapy is not installed. Run: pip3 install scapy")
    sys.exit()
packet_counts = {}
def detect_attack(packet):
    if packet.haslayer(ICMP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        packet_counts[src_ip] = packet_counts.get(src_ip, 0) + 1
        if packet_counts[src_ip] > 10:
            print(f"[ALERT] Intrusion Detected! ICMP Flood from IP: {src_ip} (Packets: {packet_counts[src_ip]})")
if __name__ == "__main__":
    print("Intrusion Detection System (IDS) is active and monitoring traffic...")
    try:
        sniff(filter="icmp", prn=detect_attack, store=0)
    except KeyboardInterrupt:
        print("\nStopping IDS.")
        sys.exit()