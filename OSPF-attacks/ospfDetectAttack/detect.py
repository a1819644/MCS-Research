#! /usr/bin/env python


import sys
import argparse

"""
Import Scapy avoiding error printing on the console.
"""
sys.stderr = None
from scapy.all import *
sys.stderr = sys.__stderr__

#####################################################
# Utils functions		 							#
#####################################################

"""
Checks if the incoming packet is an OSFP LS Update packet
sent from the victim router.
"""
def check_incoming_packet(pkt, iface):
	
	if OSPF_Router_LSA in pkt:
		for lsa in pkt[OSPF_LSUpd].lsalist:
			if OSPF_Router_LSA in lsa:
				if len(lsa[OSPF_Router_LSA].linklist) > 0:
					going_in(lsa[OSPF_Router_LSA].linklist, iface)

	return False

"""
Returns the position of the victim router LSA taken from the originally captured packet
"""


# creating sets 
filter_sets = {1}
def going_in(getLinkList, iface):
	find_dis_router = []
	position = 0
	for lsa in getLinkList:
		if lsa.type != 3:
			filter_sets.add(lsa.id)
			find_dis_router.append(lsa.id)
	# for ip in filter_sets:
	# 	print("creating threads", ip)
	# 	ip_find_thread = threading.Thread(target=sniffing_for_hello_pkt, args=(ip,iface))
	# 	print(find_dis_router)
	# 	ip_find_thread.start()
	
	print(filter_sets)
	return position

# def sniffing_for_hello_pkt(ip_address, iface):
	x = sniff(filter="proto ospf", iface=iface, stop_filter=lambda x: check_incoming_hello_packt(x, ip_address))
	if x == True:
		return True
	return False

# def check_incoming_hello_packt(pkt, ip_address):
	print("inside check_incoming_hello_packt")
	if OSPF_Hello in pkt:
		if pkt[IP].src == ip_address:
			print("[+] legitimate router id :", ip_address)
			return True
		else: 
			print("[+] router id not found :", ip_address)
	return False

if __name__ == '__main__':

	"""
    Load the Scapy's OSPF module
    """
	load_contrib("ospf")

	n = len(sys.argv)
	print("please pass all the veth", n)

	def sniffing_ospf(iface):
		time.sleep(0.01)
		sniff(filter="proto ospf", iface=iface,stop_filter=lambda x: check_incoming_packet(x,iface))

	for i in range(1, n):
		pck = threading.Thread(target=sniffing_ospf, args=(sys.argv[i],))
		print("sniffing packets from ", sys.argv[i])
		pck.start()

	print("this is main ")


