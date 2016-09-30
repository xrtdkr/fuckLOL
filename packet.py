# coding:utf-8


from scapy.all import send


class Packet_ez(object):
    def __init__(self, destination_ip, source_ip, packet_itself, protocol):
        self.destination_ip = destination_ip
        self.source_ip = source_ip
        self.packet_itself = packet_itself
        self.protocol = protocol

    def send_packet(self):
        send(self.packet_itself)
        return "send_success"
