import codecs
import dpkt

def read_pcaps(files=[]):
	pcaps = []
	try:
		for file in files:
			f = open(file, 'rb')
			# f.decode('gbk', 'ignore').encode('utf-8') 
			pcap = dpkt.pcap.Reader(f)
			pcaps.append(pcap)
	except NameError:
		print("%s 打开失败\n 失败原因为：" % file, NameError)
	return pcaps
