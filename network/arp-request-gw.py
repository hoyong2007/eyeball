import sys
from scapy.all import *

# get Gateway IP address on conf.route
def get_gw_addr():
	route = conf.route.routes
	for info in route:
		if info[2] != "0.0.0.0":
			print "gateway : " + info[2]
			return info[2]

# Send ARP Request to Gateway
def send_ARP():
	pkt = Ether()/ARP(pdst=get_gw_addr(), op=1)
	return srp(pkt)


ans,unans=send_ARP()
ans.summary(lambda (s,r): r.sprintf("MAC addr of %ARP.psrc% -> %ARP.hwsrc%"))
