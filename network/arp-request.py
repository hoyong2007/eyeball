import sys
from scapy.all import *

# ARP REQUEST to sys.argv[1]
pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=sys.argv[1],op=1)


print "+++++++++++++++++++++++++++ Sending Packets ++++++++++++++++++++++++++++++"
print pkt.summary()

# Send ARP REQUEST packet
ans = srp(pkt, timeout=1)

print "\n+++++++++++++++++++++++++++ Receive Packets ++++++++++++++++++++++++++++++"

for r in ans:
	print r.nsummary()
