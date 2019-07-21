import socket
import struct
import binascii
from tabulate import tabulate

headers = ["Dest MAC", "Src MAC", "Src IP", "Dest IP", "Protocol", "SrcPort", "DestPort"]

def sniffer_fn(rawSocket):
	while True:
		pkt = rawSocket.recvfrom(2048)

		ethernetHdr = pkt[0][0:14]

		eth_hdr = struct.unpack("!6s6s2s",ethernetHdr)

		dest_mac = binascii.hexlify(eth_hdr[0])
		src_mac = binascii.hexlify(eth_hdr[1])
		length =  binascii.hexlify(eth_hdr[2])

		ipHeader = pkt[0][14:34]

		ip_hdr = struct.unpack("12s4s4s", ipHeader)

		ip_src = socket.inet_ntoa(ip_hdr[1])

		ip_dest = socket.inet_ntoa(ip_hdr[2])

		ip_proto = binascii.hexlify(pkt[0][23])

		if ip_proto == '06':
			ip_proto = 'TCP'
		elif ip_proto == '01':
			ip_proto = 'ICMP'
		
		if ip_proto == 'TCP':
			src_port = int(binascii.hexlify(pkt[0][34:36]),16)
			dest_port = int(binascii.hexlify(pkt[0][36:38]),16)
			mydata = [(dest_mac,src_mac,ip_src,ip_dest,ip_proto,src_port,dest_port)]
			print (tabulate(mydata, headers = headers))

