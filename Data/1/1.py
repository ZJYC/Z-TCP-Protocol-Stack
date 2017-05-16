#! /usr/bin/env python
from scapy.all import *

ip = ["","1.2.3.4","7.8.9.0"]
mac = ["","1:2:3:4:5:6","7:8:9:A:B:C"]
port = [0,1234,7890]
winsize = [0,90,100]
mss = [0,10,10]

LLayer12=Ether(src=mac[1],dst=mac[2])/IP(src=ip[1],dst=ip[2])
LLayer21=Ether(src=mac[2],dst=mac[1])/IP(src=ip[2],dst=ip[1])

#Remote Active SYN Remote means 2,Local means 1
RA_1=LLayer21/TCP(sport=port[2],dport=port[1],flags="S",seq=100,ack=0,window=100,options=[("MSS",10)])
RA_2=LLayer12/TCP(sport=port[1],dport=port[2],flags="S"+"A",seq=10,ack=101,window=50,options=[("MSS",15)])
RA_3=LLayer21/TCP(sport=port[2],dport=port[1],flags="A",ack=11,seq=101,window=100,options=[("MSS",10)])
RA_4=LLayer21/TCP(sport=port[2],dport=port[1],flags="P"+"A",seq=101,ack=11,window=100)/("ABCDEFG")
RA_5=LLayer12/TCP(sport=port[1],dport=port[2],flags="A",seq=11,ack=108,window=50)
#Storage packets
pkt=[]
pkt.append(RA_1);pkt.append(RA_2);pkt.append(RA_3)
pkt.append(RA_4);pkt.append(RA_5);#pkt.append(RA_6)

wrpcap("1.pcap",pkt)


