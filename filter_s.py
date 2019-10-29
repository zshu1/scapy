import os
import sys
from scapy.all import *
from threading import Thread

def show_packet(pkt,message=None):
	if message:
		print 15 * '-',
		print message,
		print 15 * '-'
	pkt.show()

def send_packet(pkt,dev):
#	show_packet(pkt,'modified')
	sendp(pkt,iface = dev)

def craft_packet(pkt,direction):
	""" if the packet come from attacker, send to VM,
	if the packet come from VM , send to virb0 interface.
	
	if direction == 1 , it come from attacker
			0 , comes from VM 
	"""
	if direction == 1 : 
		pkt[Ether].dst = "52:54:00:8e:85:0d"
		del pkt[Ether].chksum
		del pkt[IP].chksum
		if UDP in pkt:
			del pkt[UDP].chksum
		if TCP in pkt:
			del pkt[TCP].chksum
	return pkt 

def forward_list():
	ip_list = [] 
	list_path = "/home/zhan/proftp_conf/list.txt"
	ip_list.append("149.125.84.151")
	return ip_list

def send_packet_forward(pkt):

	if not pkt:
#		print 'NONE packet catched'
		return 
	ip_list = forward_list()
	if IP not in pkt:
		return 
#	print "virb1 packet : ",
#	print pkt[IP].src 
	if pkt[IP].src in ip_list:
#		print "catch attacker packet"
#		show_packet(pkt)
		pkt1 = craft_packet(pkt,1)
#		show_packet(pkt1,"changed")
		send_packet(pkt1,"virbr0")

def send_sniff():
	print "sniff on virbr1 sending packet"
	sniff(iface='wlp6s0',prn=send_packet_forward)


def main():
	ip_list = forward_list()
	for e in ip_list:
		cmd = ['iptables','-A','INPUT','-s',e,'-j','DROP']
		p = subprocess.Popen(cmd)
		p.wait()
	send_sniff()

main()
	

	
	
