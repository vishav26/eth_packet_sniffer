import struct
import socket

def injector_fn(rawSocket):
	packet = struct.pack("!6s6s2s2s2s1s1s2s6s4s6s4s", '\xff\xff\xff\xff\xff\xff', '\xd4\xbe\xd9\x0b\x2a\xa9','\x08\x06','\x00\x01','\x08\x00','\x06','\x04','\x00\x01','\xd4\xbe\xd9\x0b\x2a\xa9','\xa9\xfe\xd5\x0a','\xff\xff\xff\xff\xff\xff','\xa9\xfe\xd5\x3d')


	rawSocket.send(packet)
