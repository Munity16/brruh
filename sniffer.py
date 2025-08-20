# codealpha_network_sniffer
# A Python-based live network packet sniffer using Scapy

from scapy.all import sniff, IP, Raw
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
import csv
from datetime import datetime

# Open CSV file to store captured packet data
csv_file = open("packets.csv", "w", newline="")
csv_writer = csv.writer(csv_file)
csv_writer.writerow(["Timestamp", "SrcIP", "DstIP", "Protocol", "Length", "Payload"])

print("📡 Starting packet capture... Press Ctrl+C to stop.\n")


def process_packet(pkt):
    """Processes each captured packets and extracts key information."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = dst_ip = protocol = ""
    length = len(pkt)
    payload_data = b""

    if pkt.haslayer(IP):
        ip_layer = pkt.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_num = ip_layer.proto
        protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, str(proto_num))
    elif pkt.haslayer(IPv6):
        ip6 = pkt.getlayer(IPv6)
        src_ip = ip6.src
        dst_ip = ip6.dst
        proto_num = ip6.nh
        protocol = {6: "TCP", 17: "UDP", 58: "ICMPv6"}.get(proto_num, str(proto_num))
    elif pkt.haslayer(ARP):
        arp = pkt.getlayer(ARP)
        src_ip = arp.psrc
        dst_ip = arp.pdst
        protocol = "ARP"

    if pkt.haslayer(Raw):
        payload_data = pkt.getlayer(Raw).load

    payload_hex = payload_data.hex()

    csv_writer.writerow([timestamp, src_ip, dst_ip, protocol, length, payload_hex])

    print(f"{timestamp} | {src_ip} -> {dst_ip} | Proto: {protocol} | "
          f"Len: {length} | Payload: {payload_hex[:16]}{'...' if len(payload_hex) > 16 else ''}")


try:
    sniff(prn=process_packet, store=False)
except KeyboardInterrupt:
    print("\n📁 Capture stopped. Data saved to packets.csv")
    csv_file.close()
