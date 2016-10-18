# coding= utf-8
'''演进过程：'''

import os
from multiprocessing import Process

from scapy.all import *
from scapy.all import send
import binascii
from packet import Packet_ez

# 配置混杂
conf.sniff_promisc = True


def sniff_en():
    def prn(packet):
        raw = packet.__str__()
        etherheader = struct.unpack('!6s6s', raw[0:12])

        src_mac = packet[0][0].src
        dst_mac = packet[0][0].dst
        print src_mac
        print dst_mac

        src = packet[0][1].src
        dst = packet[0][1].dst

        print '============look here============='
        '''
        print binascii.hexlify(raw)
        print dst
        print src
        '''
        print src + ' ====> ' + dst
        print '=================================='
        # init the packet
        packet_ez = Packet_ez( destination_ip=dst,
                               source_ip=src,
                               packet_itself=packet,
                               protocol='ip',
                               destination_mac=dst_mac,
                               source_mac=src_mac,
                               )
        packet_ez.packet_judge()

    sniff(filter='ip', prn=prn)

if __name__ == '__main__':
    sniff_en()


'''
def child_process(name):
    print "i am a child process and pid is: " + str(os.getpid())

if __name__ == '__main__':
    print 'Parents process: '+str(os.getpid()) + ' now start'
    child_p = Process(target=child_process, args=('hahaha', ))
    child_p.start()
    child_p.join()
    print "child_p process is over"

'''

'''
from multiprocessing import Process
import os


# 子进程要执行的代码
def run_proc(name):
    print 'Run child process %s (%s)...' % (name, os.getpid())


if __name__ == '__main__':
    print 'Parent process %s.' % os.getpid()
    p = Process(target=run_proc, args=('test',))
    print 'Process will start.'
    p.start()
    p.join()
    print 'Process end.'
'''
