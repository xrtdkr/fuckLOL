# coding:utf-8


from scapy.all import send
from configure import lol_ip_config
from tools import *


class Packet_ez(object):
    def __init__(self, destination_ip, source_ip, destination_mac, source_mac, packet_itself, protocol):
        self.destination_ip = destination_ip
        self.source_ip = source_ip
        self.packet_itself = packet_itself
        self.protocol = protocol
        self.destination_mac = destination_mac
        self.source_mac = source_mac

    def __send_packet(self):
        send(self.packet_itself)
        print 'packet send'
        return "send_success"

    def packet_judge(self):
        if self.destination_ip in lol_ip_config:
            pass
        elif self.source_mac == get_mac_address() or self.destination_mac == get_mac_address():
            pass
        elif self.destination_ip == get_broadcast():
            pass
        else:
            print 'packet judged'
            self.__send_packet()
            print '=========== divid line ==============='
        return "judge_success"
