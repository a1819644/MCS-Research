#! /usr/bin/env python

import sys
import time

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
class for checking the number of hello packets.
"""
start_time = time.perf_counter()

def sniffing_ospf_LSA(finish_time):
	print(interfaces)
	sniff(filter="proto ospf", iface=interfaces,stop_filter=lambda x: check_incoming_packet(x, finish_time))

"""
	Checks if the incoming packet is an OSFP LS Update packet
	sent from the victim router.
"""
def check_incoming_packet(pkt, finish_time):
	"""
	looking for the max sequence attack 
	"""
	if OSPF_Router_LSA in pkt:
		if pkt[OSPF_Router_LSA].seq == 2147483647 and round(start_time - finish_time) <= 3600:
			print("Max sequence attack detected from victim router", pkt[OSPF_Router_LSA].id)
			maxSequenceFound.append(pkt[OSPF_Router_LSA].id)
			print("max seq =>", )
	"""
	looking for the max sequence attack 
	"""
	if OSPF_Router_LSA in pkt:
		if pkt[OSPF_Router_LSA].age == 3600 and round(start_time - finish_time) <= 3600:
			print("Max age attack detected from victim router", pkt[OSPF_Router_LSA].id)
			maxAgeAttack.append(pkt[OSPF_Router_LSA].id)
			print("max seq =>", )   
	print("current list : " ,filter_setIp_addresss)
	"""
	looking for the the LSA update pcks
	"""
	if OSPF_Router_LSA in pkt:
		for lsa in pkt[OSPF_LSUpd].lsalist:
			if OSPF_Router_LSA in lsa:
				if len(lsa[OSPF_Router_LSA].linklist) > 0:
					going_in(lsa[OSPF_Router_LSA].linklist)
	
		return False

"""
capturing all the lsa router from the LSA update pkt
"""
def going_in(getLinkList):
	for lsa in getLinkList:
		if lsa.type != 3:
			filter_setIp_addresss.add(lsa.id)
	time.sleep(0.1)

"""
part of the hello packt 
"""
def sniffing_for_hello_pkt(ip_address):
	print("from the hello packet function")
	sniff(filter="proto ospf", iface=interfaces, stop_filter=lambda x: check_incoming_hello_packt(x,ip_address))
	
"""
capturing all the hello packet sent from the router 
"""

def check_incoming_hello_packt(pkt, ip_address):
	global count_for_already_seen
	print("check_incoming_hello_packt.....")
	if OSPF_Hello in pkt:
		if pkt[IP].src == ip_address:
				print("[+] legitimate router id :", ip_address)
				filter_setIp_addresss.remove(ip_address)
				count_for_already_seen = 0
				return True
		else: 
			if count_for_already_seen >= 10:
				list_already_seen_ip.add(ip_address)
				filter_setIp_addresss.remove(ip_address)
				count_for_already_seen = 0
			count_for_already_seen += 1
			print("[+] router id not found :", ip_address)
			return False


if __name__ == '__main__':
	interfaces = []
	# creating sets
	finish_time = time.perf_counter()
	maxSequenceFound = []
	maxAgeAttack =[]
	filter_setIp_addresss = {1}
	list_objects = []
	count_for_already_seen = 0
	list_already_seen_ip= {1}
	"""
    Load the Scapy's OSPF module
    """
	load_contrib("ospf")

	n = len(sys.argv)
	print("Pass the veths are", n)

	for i in range(1, n):
		interfaces.append(sys.argv[i])

	
	while(True):
		threads1 = threading.Thread(target=sniffing_ospf_LSA, args=(finish_time,))
		threads1.start()
		threads1.join(10)
		print(round(finish_time))
		if 1 in filter_setIp_addresss:
			filter_setIp_addresss.remove(1)
		for i in filter_setIp_addresss:
			threads = threading.Thread(target=sniffing_for_hello_pkt, args=(i,))
			threads.start()
		print("list of routers we haven't seen sending hello packets: ", list_already_seen_ip)
