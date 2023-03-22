from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from rich import print

file_name = "package.txt"


def print_packet(packet):
    protocol = packet[IP].proto
    protocol_type = None
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if protocol == 6:
        protocol_type = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        seq = packet[TCP].seq
        ack = packet[TCP].ack
        flags = packet[TCP].flags
        window = packet[TCP].window
        tcp_size = len(packet[TCP])
        print(f"[blue]Protocol: {protocol_type}\t[/blue]Src IP: {src_ip}\tDst IP: {dst_ip}\tSrc Port: {src_port}\tDst Port: {dst_port}\tSeq: {seq}\tAck: {ack}\tFlags: {flags}\tWindow: {window}\tTCP Size: {tcp_size}")
        with open(file_name, "a") as f:
            f.write(f"{src_ip}\t{dst_ip}\t{src_port}\t{dst_port}\n")

    elif protocol == 17:
        protocol_type = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        length = packet[UDP].len
        checksum = packet[UDP].chksum
        print(f"[blue]Protocol: {protocol_type}\t[/blue]Src IP: {src_ip}\tDst IP: {dst_ip}\tSrc Port: {src_port}\tDst Port: {dst_port}\tLength: {length}\tChecksum: {checksum}")
        with open(file_name, "a") as f:
            f.write(f"{src_ip}\t{dst_ip}\t{src_port}\t{dst_port}\n") 

if __name__ == "__main__":
    try:
        sniff(filter="ip", prn=print_packet)
    except PermissionError:
        print("Please run this script with administrator privileges.")