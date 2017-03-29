from utils import *
from dpkt.ethernet import Ethernet
from dpkt.ip import IP
from dpkt import http 

from binascii import b2a_hex

if __name__ == '__main__':
	files = ["QQ_Music_2017_03_16_201434.pcap"]
	pcaps = read_pcaps(files)

	tcp_num = udp_num = http_request_num = http_response_num = 0
	http_data = b''

	for pcap in pcaps:
		for ts, buf in pcap:
			eth = Ethernet(buf)
			# if eth.type != 0x0800:
			# 	exit()
			ip = eth.data

			transport_layer_type = ''
			application_layer_type = ''

			try:
				ip.udp
				transport_layer_type = 'udp'
				udp_num = udp_num + 1
				# print(udp.__repr__())
			except AttributeError:
				transport_layer_type = 'tcp'
				tcp_num = tcp_num + 1

			if transport_layer_type == 'udp':
				udp = ip.udp
				# print(dir(udp))

			elif transport_layer_type == 'tcp':
				tcp = ip.data
				# print(dir(tcp))
				# print(tcp.__repr__())
				if tcp.dport == 80 and len(tcp.data) > 0:
					try:
						http_request = dpkt.http.Request(tcp.data)
						http_request_num = http_request_num + 1
						print(http_request.uri)
					except Exception as e:
						print('Error : %s' % e)

				if tcp.sport == 80 and len(tcp.data) > 0:
					http_data = tcp.data
					# f_headers = BytesIO(http_data)
					# headers = dpkt.http.parse_headers(f_headers)
					# print(headers)
					# print(dir(dpkt.http))
					# print(dir(http_data))
					try:
						http_response = dpkt.http.Response(tcp.data)
						if http_response.status == 206:
							print("206")
							http_data = http_response.body + http_data
							continue
						http_response_num = http_response_num + 1
						# print(dir(http_response))
						# print(http_response.data)
					except Exception as e:
						print('Error : %s' % e)

	print("TCP packets: %d\nUDP packets: %d\nHTTP request: %d\nHTTP response: %d\n" %
	 (tcp_num, udp_num, http_request_num, http_response_num))
			# print(ip)
			# print(tcp.sport)
			# print(eth.__repr__())
			# print(b2a_hex(eth.dst))
