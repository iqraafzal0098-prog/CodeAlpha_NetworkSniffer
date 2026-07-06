from scapy.all import sniff, IP, TCP, UDP, ICMP

def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        # Map protocol number to name
        proto_name = "OTHER"
        if TCP in packet:
            proto_name = "TCP"
        elif UDP in packet:
            proto_name = "UDP"
        elif ICMP in packet:
            proto_name = "ICMP"

        print(f"[+] Source IP: {src_ip} --> Destination IP: {dst_ip} | Protocol: {proto_name}")

        # Show ports if TCP/UDP
        if TCP in packet:
            print(f"    Source Port: {packet[TCP].sport} | Destination Port: {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    Source Port: {packet[UDP].sport} | Destination Port: {packet[UDP].dport}")

        # Show payload if present
        if packet.haslayer('Raw'):
            payload = packet['Raw'].load
            print(f"    Payload (first 50 bytes): {payload[:50]}")

        print("-" * 60)

def start_sniffer(count=20):
    print("Starting network sniffer... (Press Ctrl+C to stop)\n")
    sniff(prn=analyze_packet, count=count, store=False)

if __name__ == "__main__":
    start_sniffer(count=20)
