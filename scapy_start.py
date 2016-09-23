# coding=utf-8

'''
思路:
第一步：实现断网：我需要不断的向公网广播自己的arp应答包,把应答包中的目的地址的Mac发过去.


'''

from scapy.all import send
from scapy.all import sniff


import socket


