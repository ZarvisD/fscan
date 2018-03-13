#!/bin/python3

import socket
import threading
from queue import Queue
import time
import nmap


print """                                                                         

XXXXXXX  XXXXX   XXXXX     X    X     X
X       X     X X     X   X X   XX    X
X       X       X        X   X  X X   X
XXXXX    XXXXX  X       X     X X  X  X
X             X X       XXXXXXX X   X X
X       X     X X     X X     X X    XX
X        XXXXX   XXXXX  X     X X     X

"""


nm=nmap.PortScanner()
ports=[]

print_lock = threading.Lock()

ip = raw_input("Enter your ip address: \t")

def nmapscan(port):
    out=nm.scan(ip,str(port))
    state= out['scan'][ip]['tcp'][port]['state']
    product= out['scan'][ip]['tcp'][port]['product']
    version= out['scan'][ip]['tcp'][port]['version']
    extrainfo= out['scan'][ip]['tcp'][port]['extrainfo']
    cpe= out['scan'][ip]['tcp'][port]['cpe']
    if extrainfo=="":
        print '[+]' + '  ' +str(port)+'/tcp' + '  ' + state +'  '+product + '  ' +version
    else:
        print '[+]' + '  ' +str(port)+'/tcp' + '  ' + state +'  '+product + '  ' +version + '  ' +'('+extrainfo+')'


def portscan(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        con = s.connect((ip,port))
        with print_lock:
            ports.append(port)
            print "[+]  " + str(port) + " is open"
        con.close()
    except:
        pass

def threader():
    while True:
        worker = q.get()
        portscan(worker)
        q.task_done()

def threader1():
    while True:
        nn=r.get()
        nmapscan(nn)
        r.task_done()

q = Queue()
for x in range(30):
    t = threading.Thread(target=threader,name='child')
    t.daemon = True
    t.start()


for worker in range(1,65535):
    q.put(worker)



for port in ports:
    q.put(ports)

q.join() 
r=Queue()
count=len(ports)

if count >= 30:
    c=count-30
    for y in range(c):
        u=threading.Thread(target=threader1)
        u.daemon=True
        u.start()
else:
    for w in range(count):
        u=threading.Thread(target=threader1)
        u.daemon=True
        u.start()

for l in ports:
    r.put(l)

r.join()
