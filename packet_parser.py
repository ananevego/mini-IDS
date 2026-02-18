from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
from scapy.packet import Raw

def parse_packet(packet):

    if not packet.haslayer(IP):
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # TCP
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": "TCP",
            "src_port": src_port,
            "dst_port": dst_port
        }

    # UDP
    if packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": "UDP",
            "src_port": src_port,
            "dst_port": dst_port
        }

    return None
