from utils import *
from dpkt.ethernet import Ethernet
from dpkt.ip import IP
from dpkt import http 

from binascii import b2a_hex

if __name__ == '__main__':
	files = ["QQ_Music_2017_03_16_201434.pcap"]
	pcaps = read_pcaps(files)
	for pcap in pcaps:
		for ts, buf in pcap:
			eth = Ethernet(buf)
			if eth.type != 0x0800:
				exit()
			ip = eth.data
			try:
				udp = ip.udp
				print(udp)
			except:
				
			else:
				tcp = ip.data
			# print(ip)
			# print(tcp.sport)
			# print(eth.__repr__())
			# print(b2a_hex(eth.dst))
