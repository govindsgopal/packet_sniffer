#!/usr/bin/python3
import subprocess  # Create another processs
from datetime import datetime
from scapy.all import *
import sys

time = datetime.now()
print("Use Sudo")

def display_interface():
	interface = os.popen('ip l | cut -d":" -f2 | tr -d " "').read()
	interfaces = interface.split('\n')
	interfaces.remove('altnameenp2s1')
	interface_lst = interfaces[0:-2:2]
	print(interface_lst)

display_interface()	
net_iface = input("Enter the network interface :  ")


subprocess.call(["ifconfig", net_iface, "promisc"])

num_of_pkt = int(input("Enter the number of packets to capture :  "))

time_sec = int(input("Enter how long (in seconds) to run capture :  "))

protocol = input("Enter the protocol(arp | icmp |all) :  ")

def logs(packet):
	print(f'Time : {time}')
	source_mac = f'SRC_MAC: {str(packet[0].src)}'
	destination_mac = f'DEST_MAC : {str(packet[0].dst)}'
	print(source_mac, destination_mac)

if protocol == "all":
	sniff(iface=net_iface, count=num_of_pkt,timeout=time_sec, prn=logs)  # sniffing packet
elif protocol == "arp":
	sniff(iface=net_iface, count=num_of_pkt,timeout=time_sec, prn=logs)  # sniffing packet
elif protocol == "icmp":
	sniff(iface=net_iface, count=num_of_pkt,timeout=time_sec, prn=logs)  # sniffing packet
else:
	print("Wrong protocol")
