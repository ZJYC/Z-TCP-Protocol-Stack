#! /usr/bin/env python
from scapy.all import *

ip = ["","1.1.1.1","2.2.2.2"]
mac = ["","1:1:1:1:1:1","2:2:2:2:2:2"]

LLayer12=Ether(src=mac[1],dst=mac[2])/IP(src=ip[1],dst=ip[2])/UDP(sport=67,dport=68)
LLayer21=Ether(src=mac[2],dst=mac[1])/IP(src=ip[2],dst=ip[1])/UDP(sport=68,dport=67)
pkt=[]
pkt+=LLayer12/BOOTP(chaddr="123456",xid=0)/DHCP(options=[("message-type","discover"),\
                                    ("requested_addr","1.2.3.4"),\
                                    ("lease_time",100),\
                                    ("client_id","ZJYC"),"end"])
pkt+=LLayer21/BOOTP(yiaddr="1.2.3.4",xid=0,chaddr="123456",op="BOOTREPLY")/DHCP(options=[("message-type","offer"),\
				    ("server_id","192.168.120.1"),"end"])
pkt+=LLayer12/BOOTP(xid=0,chaddr="123456",op="BOOTREQUEST")/DHCP(options=[("message-type","request"),\
				    ("server_id","192.168.120.1"),("requested_addr","1.2.3.4"),\
                                    ("client_id","ZJYC_ZJYC"),("lease_time",100),"end"])
pkt+=LLayer21/BOOTP(yiaddr="1.2.3.4",xid=0,chaddr="123456",op="BOOTREPLY")/DHCP(options=[("message-type","ack"),\
				    ("lease_time",100),("server_id","192.168.120.1"),"end"])
wrpcap("DHCP.pcap",pkt)
