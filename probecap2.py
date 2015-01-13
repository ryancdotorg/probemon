import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import impacket
import pcapy
import scapy_ex
import scapy
from scapy.all import *
import sys
import struct
import json
import time

MGMT_TYPE = 0x0
PROBE_SUBTYPE = 0x04
BEACON_SUBTYPE = 0x08

FMT_HEADER_80211 = "<HH6s6s6sH"
WLAN_MGMT_ELEMENT = "<BB"
BEACON_FIXED_PARAMETERS = "<xxxxxxxxHH"

TO_DS_BIT = 2**9
FROM_DS_BIT = 2**10

def encodeMac(s):
	return ':'.join(( '%.2x' % ord(i) for i in s ))

def handler(header, payload):
	try:
		radiotap = RadioTap(payload)
		dot11 = radiotap.payload
		if not dot11.haslayer(Dot11ProbeReq):
			return

		if dot11.proto != 0:
			return
		
		#Extract the payload from the packet
		payload = buffer(str(dot11))
		#Carve out just the header
		headerSize = struct.calcsize(FMT_HEADER_80211)
		header = payload[:headerSize]
		#unpack the header
		frameControl,dur,addr1,addr2,addr3,seq = struct.unpack(FMT_HEADER_80211,header)
		
		fromDs = (FROM_DS_BIT & frameControl) != 0
		toDs = (TO_DS_BIT & frameControl) != 0
		
		if fromDs and not toDs:
			srcAddr = addr3
		elif not  fromDs and not toDs:
			srcAddr = addr2
		elif not fromDs and toDs:
			srcAddr = addr2
		elif fromDs and toDs:
			return
		
		#Extract each tag from the payload
		tags = payload[headerSize:]
		
		ssid = None
		while len(tags) != 0:
			#Carve out and extract the id and length of the  tag
			tagHeader = tags[0:struct.calcsize(WLAN_MGMT_ELEMENT)]
			tagId,tagLength = struct.unpack(WLAN_MGMT_ELEMENT,tagHeader)
			tags = tags[struct.calcsize(WLAN_MGMT_ELEMENT):]

			#The tag id must be zero for SSID
			#The tag length must be greater than zero or it is a 
			#an anonymous probe
			#The tag length must be less than or equal to 32 or it is
			#not a valid SSID

			if tagId == 0 and tagLength <=32:
				
				if tagLength == 0:
					ssid = '<ANY>'
				else:
					ssid = tags[:tagLength]
			
				#Made sure what is extracted is valid ASCII
				#Psycopg2 pukes otherwise
				#try:
				#	ssid = ssid.decode('ascii')
				#except UnicodeDecodeError:
				#	ssid = None
				#	continue
				
				break 
				
			tags = tags[tagLength:]
			
		print "%s %4d %4d %s '%s'" % (
			time.strftime('[%Y-%m-%d %H:%M:%S]'),
			radiotap.Channel,
			radiotap.dBm_AntSignal,
			encodeMac(srcAddr),
			ssid
		)
	except e:
		print e

	#radiotap.show()


def handler2(header, payload):
	


if __name__ == "__main__":
	iface = sys.argv[1]
	
	cap = pcapy.open_live(iface, 4096, 1, 0)
	cap.setfilter('type mgt subtype probe-req')
	print "Listening on %s: linktype=%d" % (iface, cap.datalink())

	cap.loop(-1, handler)
