#!/usr/bin/python

import socket 
import struct
import binascii
from tabulate import tabulate
from sniffer import sniffer_fn
from injector import injector_fn



rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

rawSocket.bind(("eno1",0))

print "Choose one option"
menu = {"1" :"Sniffer","2": "Injector"}
for key in sorted(menu.keys()):
	print key + ":" + menu[key]

ans = raw_input("Enter the option:")
  
if ans == "1":
	sniffer_fn(rawSocket)
elif ans == "2":
	menu = {"1": "Send ARP Request"}
	for key in sorted(menu.keys()):
		print key + ":" + menu[key]
	ans = raw_input("Enter the option:")
	if ans == "1":
		injector_fn(rawSocket)
	
