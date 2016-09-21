# coding=utf-8


from scapy.all import ARP, send, IPField

def ARP_attack(local_address, my_mac):
    