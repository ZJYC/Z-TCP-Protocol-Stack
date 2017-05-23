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
RA_6=LLayer21/TCP(sport=port[2],dport=port[1],flags="P"+"A",seq=108,ack=11,window=100)/("123456789")
RA_7=LLayer12/TCP(sport=port[1],dport=port[2],flags="A",seq=11,ack=117,window=50)
RA_8=LLayer21/TCP(sport=port[2],dport=port[1],flags="P"+"A",seq=117,ack=11,window=100)/("ZJYC")
RA_9=LLayer12/TCP(sport=port[1],dport=port[2],flags="A",seq=11,ack=121,window=50)

RP_1=LLayer12/TCP(sport=port[1],dport=port[2],flags="S",seq=10,ack=0,window=50,options=[("MSS",15)])
RP_2=LLayer21/TCP(sport=port[2],dport=port[1],flags="S"+"A",seq=100,ack=11,window=100,options=[("MSS",10)])
RP_3=LLayer12/TCP(sport=port[1],dport=port[2],flags="A",seq=11,ack=101,window=50)
RP_4=LLayer12/TCP(sport=port[1],dport=port[2],flags="A"+"P",seq=11,ack=101,window=50)/("QWER")
RP_5=LLayer21/TCP(sport=port[2],dport=port[1],flags="A",seq=101,ack=15,window=100)
RP_6=LLayer12/TCP(sport=port[1],dport=port[2],flags="A"+"P",seq=15,ack=101,window=50)/("ZXCVBN")
RP_7=LLayer21/TCP(sport=port[2],dport=port[1],flags="A",seq=101,ack=21,window=100)
RP_8=LLayer12/TCP(sport=port[1],dport=port[2],flags="A"+"P",seq=21,ack=101,window=50)/("!@#$%^")
RP_9=LLayer21/TCP(sport=port[2],dport=port[1],flags="A",seq=101,ack=27,window=100)

#Storage packets
pkt=[]

#pkt.append(RA_1);pkt.append(RA_2);pkt.append(RA_3)
#pkt.append(RA_4);pkt.append(RA_5);pkt.append(RA_6)
#pkt.append(RA_7);pkt.append(RA_8);pkt.append(RA_9)

pkt.append(RP_1);pkt.append(RP_2);pkt.append(RP_3)
pkt.append(RP_4);pkt.append(RP_5);pkt.append(RP_6)
pkt.append(RP_7);pkt.append(RP_8);pkt.append(RP_9)

wrpcap("1.pcap",pkt)


