#! /usr/bin/env python

from scapy.all import *

ip = ["","1.2.3.4","7.8.9.0"]
mac = ["","1:2:3:4:5:6","7:8:9:A:B:C"]


arp1=Ether(src=mac[1],dst="FF:FF:FF:FF:FF:FF")/ARP(hwsrc=mac[1],hwdst="00:00:00:00:00:00",psrc=ip[1],pdst=ip[2],op=1)

arp2=Ether(src=mac[2],dst=mac[1])/ARP(hwsrc=mac[2],hwdst=mac[1],psrc=ip[2],pdst=ip[1],op=2)

arp3=Ether(src=mac[2],dst="FF:FF:FF:FF:FF:FF")/ARP(hwsrc=mac[2],hwdst="00:00:00:00:00:00",psrc=ip[2],pdst=ip[1],op=1)

arp4=Ether(src=mac[1],dst=mac[2])/ARP(hwsrc=mac[1],hwdst=mac[2],psrc=ip[1],pdst=ip[2],op=2)

pkt=[]
pkt.append(arp1);pkt.append(arp2);pkt.append(arp3);pkt.append(arp4)

wrpcap("1.pcap",pkt)

