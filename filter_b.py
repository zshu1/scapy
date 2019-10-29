import os
import sys
from scapy.all import *
from threading import Thread
import subprocess


fake_ip_list = []
def show_packet(pkt,message=None):
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
		pkt[Ether].dst = "52:54:00:4c:33:f7"
		del pkt[IP].chksum
		if UDP in pkt:
			del pkt[UDP].chksum
		if TCP in pkt:
			del pkt[TCP].chksum
	if direction == 0 :
		del pkt[IP].chksum
#		pkt[Ether].src = "fe:54:00:4c:33:f7"
		if UDP in pkt:
			del pkt[UDP].chksum
			pkt = Ether()/pkt[IP]
		if TCP in pkt:
			del pkt[TCP].chksum
			pkt = Ether()/pkt[IP]
	return pkt 

def forward_list():
	ip_list = [] 
	list_path = "/home/zhan/bftpd/list.txt"
	ip_list.append("149.125.84.151")
	fake_ip_list = ip_list
	return ip_list

def send_packet_forward(pkt):
	if not pkt:
		#print 'NONE packet catched'
		return 
	ip_list = forward_list()
# need to drop all the packet from client
	for e in ip_list:
		cmd = ['iptables','-A','INPUT','-s',e,'-j','DROP']
		p = subprocess.Popen(cmd)	
	if IP not in pkt:
		return 
#	print "virb0 packet : ",
#	print pkt[IP].src 
	if pkt[IP].src in ip_list:
#		print "catch attacker packet"
		show_packet(pkt)
		pkt1 = craft_packet(pkt,1)
#		show_packet(pkt1,"changed")
#		send_packet(pkt1,"virbr0")	
def back_packet_forward(pkt):
	if IP not in pkt:
		return
	ip_list = forward_list()
	if pkt[IP].dst in ip_list:
#		print "catch VM back packet"
#		show_packet(pkt,'original')
		pkt1 = craft_packet(pkt,0)
#		show_packet(pkt1,'changed')
		send_packet(pkt1,'wlp6s0')


def back_sniff():
#	print "sniff on virbr0 replay packet"
	sniff(iface='virbr0',prn=back_packet_forward)
	

	
def main():
	cmd = ['iptables','-A','INPUT','-s','149.125.86.208','-j','DROP']
	back_sniff()	

main()
