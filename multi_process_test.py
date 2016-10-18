# coding= utf-8


import os
from multiprocessing import Process

from scapy.all import *
from scapy.all import send
import binascii

'''
def child_process(name):
    print "i am a child process and pid is: " + str(os.getpid())
'''

conf.sniff_promisc = True


def sniff_en():
    def prn(packet):
        raw = packet.__str__()
        etherheader = struct.unpack('!6s6s', raw[0:12])
        dst = binascii.hexlify(etherheader[0])
        src = binascii.hexlify(etherheader[1])
        print '============look here============='
        print binascii.hexlify(raw)
        print dst
        print src
        print '=================================='

    sniff(iface='en0', filter='ip', prn=prn)


'''
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
