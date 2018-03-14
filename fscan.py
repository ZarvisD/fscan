import socket
import threading
from queue import Queue
import time
import nmap
from colorama import Fore

zarvis= Fore.RED + "By:- Zarvis"
print Fore.GREEN + """                                                                         

XXXXXXX  XXXXX   XXXXX     X    X     X
X       X     X X     X   X X   XX    X
X       X       X        X   X  X X   X
XXXXX    XXXXX  X       X     X X  X  X
X             X X       XXXXXXX X   X X
X       X     X X     X X     X X    XX
X        XXXXX   XXXXX  X     X X     X     (V1.0)""" + '\n\t\t\t\t\t'+zarvis

#Simple color Shitt
que =  '\033[1;34m[?]\033[1;m'
good = '\033[1;32m[+]\033[1;m'

nm=nmap.PortScanner()
ports=[]

print_lock = threading.Lock()

ip = raw_input(que + " Enter your ip address: ")

#Function that will scan the IP after given the list of open ports
def nmapscan(port):
    out=nm.scan(ip,str(port))
    state= out['scan'][ip]['tcp'][port]['state']
    product= out['scan'][ip]['tcp'][port]['product']
    version= out['scan'][ip]['tcp'][port]['version']
    extrainfo= out['scan'][ip]['tcp'][port]['extrainfo']
    cpe= out['scan'][ip]['tcp'][port]['cpe']
    try:
    	if extrainfo=="":
        	print good+ '  '  +str(port)+'/tcp' + '  ' + state +'  '+product + '  ' +version
    	else:
        	print good+ '  '  +str(port)+'/tcp' + '  ' + state +'  '+product + '  ' +version + '  ' +'('+extrainfo+')'
    except:
    	print good+ '  '  +str(port)+'/tcp' + '  ' + state +'  '+product + '  ' +version

#function to check the open ports ranging from 1-65535
def portscan(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        con = s.connect((ip,port))
        with print_lock:
            ports.append(port)
            print good+ '  ' + str(port) + " is open"
        con.close()
    except:
        pass

# Queue instance which will wait for items to arrive in the queue and upon arrival will call the function portscan    
def threader():
    while True:
        worker = q.get()
        portscan(worker)
        q.task_done()

# Queue instance which will wait for the final open ports to arrive in the Queue and upon arrival will call the nmapsca function.        
def threader1():
    while True:
        nn=r.get()
        nmapscan(nn)
        r.task_done()

        
q = Queue()   # Instantiating Queue
for x in range(30):   # Creating Threads 
    t = threading.Thread(target=threader,name='child')
    t.daemon = True
    t.start()

#Putting items(list of the ports to be checked on IP) in the queue
for worker in range(1,65535):
    q.put(worker)


# Putting the list of open ports in the queue to be further scanned for Service Version
for port in ports:
    q.put(ports)

q.join() 
r=Queue()
count=len(ports)

# Over here I have make sure to create maximum of 30 threads for the open ports
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

r.join() #Waiting for all the threads to exist
