#!/usr/bin/env python
import logging
#logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import pcapy
#import scapy_ex
#import scapy
#from scapy.all import *

import impacket
from impacket.ImpactDecoder import RadioTapDecoder

from radiotapparser import RadioTapParser

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

def timestamp():
	return time.strftime('%Y-%m-%d %H:%M:%S %z')

def encodeMac(s):
	return ':'.join(( '%.2x' % ord(i) for i in s ))

parse_radiotap = RadioTapParser()
#decoder = RadioTapDecoder()
headerSize = struct.calcsize(FMT_HEADER_80211)
def handler2(hdr, pkt):
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
	#print 'data %4uMHz %3ddBm %s -> %s' % (freq, signal, sa, bssid)
	handle_station(signal, sa, bssid=bssid)
	

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

	#print 'probe request %4uMHz %3ddBm %s "%s"' % (freq, signal, sa, essid)
	handle_station(signal, sa, essid=essid)
	

def handle_beacon(freq, signal, bssid, body):
	pos = 12 # skip over fixed parameters (timestamp, beacon interval and capabilities)
	end = len(body) - 2
	
	# get the essid from the tag
	essid = get_tag(body[pos:], 0)

	#print 'beacon %4uMHz %3ddBm %s "%s"' % (freq, signal, bssid, essid)
	handle_network(bssid, essid)

known_networks = {}
def handle_network(bssid, essid):
	#global known_networks
	if bssid in known_networks and (known_networks[bssid] == essid or essid == ''):
		return
	known_networks[bssid] = essid
	print '[%s] new network %s "%s"' % (timestamp(), bssid, essid)

known_stations = {}
def handle_station(signal, sa, essid=None, bssid=None):
	#global known_stations
	if sa not in known_stations:
		print '[%s] new station %s' % (timestamp(), sa)
		known_stations[sa] = {
			'essids': set(),
			'bssids': set(),
			'rstsig': None,
			'minsig':  200,
			'maxsig': -200		
		}

	if essid is not None and essid not in known_stations[sa]['essids']:
		known_stations[sa]['essids'].add(essid)
		print '[%s] new probe for station %s "%s"' % (timestamp(), sa, essid) 

	if bssid is not None and bssid not in known_stations[sa]['bssids']:
		known_stations[sa]['bssids'].add(bssid)
		print '[%s] new bssid for station %s %s' % (timestamp(), sa, bssid) 

	print_station(sa)
	if known_stations[sa]['rstsig'] is None:
		known_stations[sa]['rstsig'] = time.time()
	known_stations[sa]['minsig'] = min(known_stations[sa]['minsig'], signal)
	known_stations[sa]['maxsig'] = max(known_stations[sa]['maxsig'], signal)

def print_station(sa):
	#global known_stations
	if known_stations[sa]['rstsig'] is not None and known_stations[sa]['rstsig'] + 60 < time.time():
		print '[%s] station active %s %ddBm %ddBm' % (timestamp(), sa, known_stations[sa]['minsig'], known_stations[sa]['maxsig'])
		known_stations[sa]['rstsig'] = None
		known_stations[sa]['minsig'] =  200
		known_stations[sa]['maxsig'] = -200

if __name__ == "__main__":
	bpf = '(type data and dir tods) or (type mgt subtype probe-req) or (type mgt subtype probe-resp) or (type mgt subtype beacon)'

	caps = []
	for iface in sys.argv[1:]:
		cap = pcapy.open_live(iface, 4096, 1, 10)
		cap.setfilter(bpf)
		caps.append(cap)
		print "Listening on %s: linktype=%d" % (iface, cap.datalink())

	next_cleanup = time.time()
	#cap.loop(-1, handler2)
	while True:
		if next_cleanup < time.time():
			next_cleanup += 5
			#print "lol cleanup"
			for sa in known_stations:
				print_station(sa)
		for cap in caps:
			# process all the buffered packets
			cap.dispatch(-1, handler2)
