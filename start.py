# coding=utf-8

'''
###########################################
思路:

第一步：实现数据报欺骗：我需要不断的向公网广播自己的arp应答包,把应答包中的目的地址的Mac发过去
       arp_attack.py 使用一个进程去完成 可以开一个进程去做

第二步：实现对欺骗过来的数据报文的处理：对于所有流入网卡的数据包，
       检查源地址和目的地址，不匹配ip则进行发送
#############################################
'''

import socket
import multiprocessing
from ARP_attack import *
from packet_investigate import *
import argparse


arp_attack()


main_start()
