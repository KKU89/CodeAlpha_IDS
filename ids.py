import sys
try:
    from scapy.all import sniff, ICMP, IP
except ImportError:
    print("Scapy is not installed.")
    sys.exit()
packet_counts = {}
def detect_attack(packet):
    if packet.haslayer(ICMP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        packet_counts[src_ip] = packet_counts.get(src_ip, 0) + 1
        print(f"Packet received from {src_ip} | Total: {packet_counts[src_ip]}")
        if packet_counts[src_ip] > 5:
            print(f"[ALERT] Intrusion Detected! ICMP Flood from IP: {src_ip} (Packets: {packet_counts[src_ip]})")
if __name__ == "__main__":
    print("IDS is active on local interface...")
    try:
        sniff(iface="lo", filter="icmp", prn=detect_attack, store=0)
    except KeyboardInterrupt:
        print("\nStopping IDS.")
        sys.exit()