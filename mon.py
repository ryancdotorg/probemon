import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import pcapy
#import scapy_ex
#import scapy
#from scapy.all import *

import impacket
from impacket.ImpactDecoder import RadioTapDecoder

from binascii import hexlify

import sys
import struct
import json
import time

MGMT_TYPE = 0x00
PROBE_SUBTYPE = 0x04
BEACON_SUBTYPE = 0x08

FMT_HEADER_80211 = "<HH6s6s6sH"
WLAN_MGMT_ELEMENT = "<BB"
BEACON_FIXED_PARAMETERS = "<xxxxxxxxHH"

NO_DS = 0
TO_DS = 1<<8
FROM_DS = 1<<9
DS_TO_DS = TO_DS + FROM_DS
DS_MASK = TO_DS + FROM_DS

RTF_FLAGS = impacket.dot11.RadioTap.RTF_FLAGS
FLAG_BAD_FCS = RTF_FLAGS.PROPERTY_BAD_FCS

def encodeMac(s):
	return ':'.join(( '%.2x' % ord(i) for i in s ))

"""
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
"""

# implemented as a class mostly for scoping
class RadioTapParser(object):
	def __init__(self):
		self.present = None
		self.data = None
		self.pkt = None
		self.pos = None

	def _get_field(self, bit, align, name, fmt):
		if self.present & 1<<bit:
			size = struct.calcsize(fmt)
			pad = self.pos % align
			# do alignment
			if pad:
				self.pos += align - pad

			tmp = struct.unpack(fmt, self.pkt[self.pos:self.pos+size])
			if len(tmp) == 1:
				tmp = tmp[0]

			self.data[name] = tmp
			self.pos += size

	def __call__(self, pkt):
		self.pkt = pkt
		ver, pad, length, present = struct.unpack('<BBHL', pkt[0:8])
		tmp = self.present = present
		self.pos = 8

		# this sucks
		while tmp & 1<<31:
			tmp = struct.unpack('<L', pkt[self.pos:self.pos+4])[0]
			self.pos += 4
			self.present += tmp << ((self.pos - 8) * 8)

		self.data = {'len': length}

		self._get_field( 0, 8, 'tsft', '<Q')
		self._get_field( 1, 1, 'flags', '<B')
		self._get_field( 2, 1, 'rate', '<B')
		self._get_field( 3, 2, 'freq', '<HH')
		self._get_field( 4, 1, 'fhss', '<BB')
		self._get_field( 5, 1, 'signal', '<b')
		self._get_field( 6, 1, 'noise', '<b')
		# don't care about these for now
		#self._get_field( 7, 2, 'lockq', '<H')
		#self._get_field( 8, 2, 'txatten', '<H')
		#self._get_field( 9, 2, 'dbtxatten', '<H')
		#self._get_field(10, 1, 'txpower, '<b')
		#self._get_field(11, 1, 'ant, '<B')
		#self._get_field(12, 1, 'dbantsignal, '<B')
		#self._get_field(13, 1, 'dbantnoise, '<B')
		#self._get_field(14, 2, 'rxflags, '<H')

		ret = self.data

		self.present = None
		self.data = None
		self.pkt = None
		self.pos = None

		return ret

parse_radiotap = RadioTapParser()
decoder = RadioTapDecoder()
headerSize = struct.calcsize(FMT_HEADER_80211)
def handler2(hdr, pkt):
	#try:
		rtmeta = parse_radiotap(pkt)
		#print json.dumps(rtmeta)
		# Don't try to process packets with bad checksum
		if rtmeta['flags'] & FLAG_BAD_FCS:
			return

		rtap = pkt[:rtmeta['len']]
		frame = pkt[rtmeta['len']:]
		header = frame[:headerSize]
		body = frame[headerSize:] # FCS is last 4 bytes, but may be missing

		frameControl, dur, addr1, addr2, addr3, seq = struct.unpack(FMT_HEADER_80211, header)

		ftype = (frameControl >> 2) & 0x3
		stype = (frameControl >> 4) & 0xf
		
		#print '%02x %d %d' % (frameControl & 0xfc, ftype, stype)

		if ftype == 2 and frameControl & DS_MASK == TO_DS:
			#print '# data (%u) %s -> %s' % (stype, encodeMac(addr2), encodeMac(addr1))
			handle_data(rtmeta['freq'][0], rtmeta['signal'], encodeMac(addr2), encodeMac(addr1))
		elif ftype == 0 and stype == 4:
			#print '# probe request'
			handle_probe_req(rtmeta['freq'][0], rtmeta['signal'], encodeMac(addr2), body)
		elif ftype == 0 and stype == 5:
			#print '# probe response'
			handle_probe_resp(rtmeta['freq'][0], rtmeta['signal'], encodeMac(addr3), encodeMac(addr1), body)
		elif ftype == 0 and stype == 8:
			#print hexlify(body)
			handle_beacon(rtmeta['freq'][0], rtmeta['signal'], encodeMac(addr2), body)
			pass
		else:
			#print DS_MASK, ' ', TO_DS, ' ', FROM_DS, ' ', ftype, ' ', stype
			#print '%04x' % (frameControl & DS_MASK)
			#print '%s %s' % (bin(frameControl+65536)[-16:-8], bin(frameControl+65536)[-8:])
			return
	
		return

	#except:
	#	return

def get_tag(body, tag):
	pos = 0
	end = len(body) - 2

	while pos <= end:
		tagid, taglen = struct.unpack('<BB', body[pos:pos+2])
		pos += 2
		if tagid == tag:
			return body[pos:pos+taglen]
		else:
			pos += taglen

	return None

def handle_data(freq, signal, sa, bssid):
	print 'data %4uMHz %3ddBm %s -> %s' % (freq, signal, sa, bssid)
	

def handle_probe_resp(freq, signal, bssid, sa, body):
	pos = 12 # skip over fixed parameters (timestamp, beacon interval and capabilities)
	end = len(body) - 2

	# get the essid from the tag
	essid = get_tag(body[pos:], 0)
	
	#print 'probe response %4uMHz %3ddBm %s -> %s "%s"' % (freq, signal, bssid, sa, essid)
	handle_network(bssid, essid)

def handle_probe_req(freq, signal, sa, body):
	pos = 0
	end = len(body) - 2
	
	# get the essid from the tag
	essid = get_tag(body[pos:], 0)

	print 'probe request %4uMHz %3ddBm %s "%s"' % (freq, signal, sa, essid)
	

def handle_beacon(freq, signal, bssid, body):
	pos = 12 # skip over fixed parameters (timestamp, beacon interval and capabilities)
	end = len(body) - 2
	
	# get the essid from the tag
	essid = get_tag(body[pos:], 0)

	#print 'beacon %4uMHz %3ddBm %s "%s"' % (freq, signal, bssid, essid)
	handle_network(bssid, essid)

known_networks = {}
def handle_network(bssid, essid):
	if bssid in known_networks and (known_networks[bssid] == essid or essid == ''):
		return
	known_networks[bssid] = essid
	print 'new network %s "%s"' % (bssid, essid)

if __name__ == "__main__":
	iface = sys.argv[1]
	
	cap = pcapy.open_live(iface, 4096, 1, 0)
	cap.setfilter('(type data and dir tods) or (type mgt subtype probe-req) or (type mgt subtype probe-resp) or (type mgt subtype beacon)')
	#cap.setfilter('(type data and dir tods)')
	print "Listening on %s: linktype=%d" % (iface, cap.datalink())

	cap.loop(-1, handler2)
