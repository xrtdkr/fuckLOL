# coding = utf-8

from scapy.all import send




def packet_judge(packet):
    return None


def send_packet(packet):
    send(packet)
    return 'packet_send'