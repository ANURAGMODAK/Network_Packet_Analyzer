import sys
from scapy.all import *

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        print(f"Source IP: {src_ip} --> Destination IP: {dst_ip}  Protocol: {proto}")

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"TCP Source Port: {src_port} --> TCP Destination Port: {dst_port}")

        if UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"UDP Source Port: {src_port} --> UDP Destination Port: {dst_port}")

        if ICMP in packet:
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            print(f"ICMP Type: {icmp_type} Code: {icmp_code}")

        print("Packet Summary:")
        print(packet.summary())
        print("Packet Hexdump:")
        print(hexdump(packet))


def main():
    if len(sys.argv) != 2:
        print("Usage: python packet_sniffer.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]

    try:
        print(f"[*] Starting packet sniffer on interface {interface}")
        sniff(iface=interface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("[*] Stopping packet sniffer.")
        sys.exit(0)


if __name__ == "__main__":
    main()