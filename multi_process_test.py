# coding= utf-8


import os
from multiprocessing import Process


def child_process(name):
    print "i am a child process and pid is: " + str(os.getpid())

if __name__ == '__main__':
    print 'Parents process: '+str(os.getpid()) + ' now start'
    child_p = Process(target=child_process, args=('hahaha', ))
    child_p.start()
    child_p.join()
    print "child_p process is over"

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