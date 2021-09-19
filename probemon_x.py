#!/usr/bin/python3

# CHANGELOG
# 19SEP2021 - successfully converted this to python3
#             ord() call removed on or near line 63; added "decode()" in some print statements that needed to print a byte datatype
#             adjusted other print statements by adding parentheses where needed
#             left in the filter for "DeprecationWarning" just in case it is needed
#
# 19SEP2021 - successfully added auto deletion of python 3 bytecode cache files and folders
#
# 19SEP2021 - fixed bug on or near line 134; packet gets skipped if 'signal' didn't make it into rtmeta; this was causing the script to crash
#
# Notes: the monitoring interface will be left in monitor mode when the script finishes

import logging

import pcapy

from radiotapparser import RadioTapParser

from binascii import hexlify

import os
import glob

import sys
sys.dont_write_bytecode = True
import struct
import json
import subprocess
import time
import traceback
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

sys.dont_write_bytecode = True

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

# frame types
T_MGMT = 0
T_CTRL = 1
T_DATA = 2

# Management frame subtypes
S_ASSOC_REQ = 0
S_ASSOC_RSP = 1
S_REASS_REQ = 2
S_REASS_RSP = 3
S_PROBE_REQ = 4
S_PROBE_RSP = 5
S_BEACON = 8
S_ATIM = 9
S_DISASSOC = 10
S_AUTHEN = 11
S_DEAUTH = 12

FLAG_BAD_FCS = 0x40

# relies on parsing output from iwconfig to make sure that the specified interface is in monitor mode
def interface_monitor_mode_check():
	# TODO switch from iwconfig to iw; iwconfig is deprecated
	check_for_monitor_mode_for_interface = subprocess.check_output(''.join(['iwconfig ',iface,' | grep \'Mode:\' | awk -F \':\' \'{print $2}\' | awk \'{print $1}\'']), shell=True)
	#strip the newline character from the end
	check_for_monitor_mode_for_interface = check_for_monitor_mode_for_interface.rstrip().decode()
	if check_for_monitor_mode_for_interface != 'Monitor':
		print("Monitor mode is not enabled.")
		print("Increase the DEVICE_STARTUP_MONITOR_MODE_DELAY value and check the installed driver.")
		sys.exit()
	else:
	    print("Monitor mode is enabled.  Check passed.")

def interface_existence_check():
		""" get the status code of "ip link show interface_name"
		 a status code of zero indicates that it found the interface in the OS and executed cleanly """
		current_retries = 0
		check_for_status_zero_for_interface = os.system(''.join(['ip link show ', iface]))
		#print (str(check_for_status_zero_for_interface))
		if check_for_status_zero_for_interface == 0:
			print (iface + " interface exists")
			print ("Entering monitor mode...")
			return True
		else:
			print (iface + " doesn't exist.")
			print ("Check your setting for the wireless interface.")
			print ("If you updated any OS packages, don't forget to reload any custom wireless drivers.")
			
			if current_retries < INTERFACE_RETRIES_BEFORE_QUIT:
				current_retries += 1
				interface_existence_check()
				return False
			sys.exit()

def kill_interfering_services():
	# these are services that are stopped in Ubuntu/Debian
	# they have traditionally caused problems for any wireless interface in monitor mode
	subprocess.call("sudo systemctl stop wpa_supplicant", shell=True)
	subprocess.call("sudo systemctl stop avahi-daemon", shell=True)

def restore_interfering_services():
	# restore wpa_supplicant upon exit
	subprocess.call("sudo systemctl start wpa_supplicant", shell=True)
	subprocess.call("sudo systemctl start avahi-daemon", shell=True)

def timestamp():
	return time.strftime('%Y-%m-%d %H:%M:%S %z')

def encodeMac(s):
	#return ':'.join(( '%.2x' % ord(i) for i in s ))
	return ':'.join(( '%.2x' % i for i in s ))

parse_radiotap = RadioTapParser()
headerSize = struct.calcsize(FMT_HEADER_80211)
def handler(hdr, pkt, iface=None):
	rtmeta = parse_radiotap(pkt)
	#print json.dumps(rtmeta)
	# Skip packet if rtmeta looks bad
	if 'flags' not in rtmeta:
		return
	# skip packet if 'signal' didn't make it into rtmeta
	if 'signal' not in rtmeta:
		return
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

	# dispatch packet data to appropriate handler
	if ftype == T_DATA and frameControl & DS_MASK == TO_DS:
		#print '# data (%u) %s -> %s' % (stype, encodeMac(addr2), encodeMac(addr1))
		#print('# data (%u) %s -> %s %s' % (stype, encodeMac(addr2), encodeMac(addr1), rtmeta['signal']))
		handle_data(iface, rtmeta['freq'][0], rtmeta['signal'], encodeMac(addr2), encodeMac(addr1))
	elif ftype == T_MGMT and stype == S_PROBE_REQ:
		handle_probe_req(iface, rtmeta['freq'][0], rtmeta['signal'], encodeMac(addr2), body)
	elif ftype == T_MGMT and stype == S_PROBE_RSP:
		handle_probe_resp(iface, rtmeta['freq'][0], rtmeta['signal'], encodeMac(addr3), encodeMac(addr1), body)
	elif ftype == T_MGMT and stype == S_BEACON:
		handle_beacon(iface, rtmeta['freq'][0], rtmeta['signal'], encodeMac(addr2), body)
		pass
	else:
		# the capture filter should prevent anything from reaching here
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

### PACKET INFORMATION HANDLERS

def handle_data(iface, freq, signal, sa, bssid):
	#print 'data %4uMHz %3ddBm %s -> %s' % (freq, signal, sa, bssid)
	handle_station(signal, sa, bssid=bssid)

def handle_probe_resp(iface, freq, signal, bssid, sa, body):
	pos = 12 # skip over fixed parameters (timestamp, beacon interval and capabilities)
	end = len(body) - 2

	# get the essid from the tag
	essid = get_tag(body[pos:], 0)
	
	#print 'probe response %4uMHz %3ddBm %s -> %s "%s"' % (freq, signal, bssid, sa, essid)
	handle_network(bssid, essid)
	handle_ap(signal, bssid)

def handle_probe_req(iface, freq, signal, sa, body):
	pos = 0
	end = len(body) - 2
	
	# get the essid from the tag
	essid = get_tag(body[pos:], 0)

	#print 'probe request %4uMHz %3ddBm %s "%s"' % (freq, signal, sa, essid)
	handle_station(signal, sa, essid=essid)
	
def handle_beacon(iface, freq, signal, bssid, body):
	pos = 12 # skip over fixed parameters (timestamp, beacon interval and capabilities)
	end = len(body) - 2
	
	# get the essid from the tag
	essid = get_tag(body[pos:], 0)

	#print 'beacon %4uMHz %3ddBm %s "%s"' % (freq, signal, bssid, essid)
	handle_network(bssid, essid)
	handle_ap(signal, bssid)

### AGGREGATE DATA TRACKERS

known_aps = {}
def handle_ap(signal, bssid):
	if bssid not in known_aps:
		known_aps[bssid] = {
			'rstsig': None,
			'minsig':  200,
			'maxsig': -200
		}

	if known_aps[bssid]['rstsig'] is None:
		known_aps[bssid]['rstsig'] = time.time()
	known_aps[bssid]['minsig'] = min(known_aps[bssid]['minsig'], signal)
	known_aps[bssid]['maxsig'] = max(known_aps[bssid]['maxsig'], signal)

known_stations = {}
def handle_station(signal, sa, essid=None, bssid=None):
	if sa not in known_stations:
		print('[%s] new station %s' % (timestamp(), sa))
		known_stations[sa] = {
			'essids': set(),
			'bssids': set(),
			'rstsig': None,
			'minsig':  200,
			'maxsig': -200		
		}

	if essid is not None and essid not in known_stations[sa]['essids']:
		known_stations[sa]['essids'].add(essid)
		print('[%s] new probe for station %s "%s"' % (timestamp(), sa, essid.decode()))

	if bssid is not None and bssid not in known_stations[sa]['bssids']:
		known_stations[sa]['bssids'].add(bssid)
		print('[%s] new bssid for station %s %s' % (timestamp(), sa, bssid)) 

	print_station(sa)
	if known_stations[sa]['rstsig'] is None:
		known_stations[sa]['rstsig'] = time.time()
	known_stations[sa]['minsig'] = min(known_stations[sa]['minsig'], signal)
	known_stations[sa]['maxsig'] = max(known_stations[sa]['maxsig'], signal)

known_networks = {}
def handle_network(bssid, essid):
	if bssid not in known_networks:
		known_networks[bssid] = set()
	if bssid in known_networks and essid in known_networks[bssid]:
		return
	known_networks[bssid].add(essid)
	print('[%s] new network %s "%s"' % (timestamp(), bssid, essid.decode()))

def print_station(sa):
	if known_stations[sa]['rstsig'] is not None and known_stations[sa]['rstsig'] + 60 < time.time():
		print('[%s] station active %s %ddBm %ddBm' % (timestamp(), sa, known_stations[sa]['minsig'], known_stations[sa]['maxsig']))
		known_stations[sa]['rstsig'] = None
		known_stations[sa]['minsig'] =  200
		known_stations[sa]['maxsig'] = -200

def print_ap(bssid):
	if known_aps[bssid]['rstsig'] is not None and known_aps[bssid]['rstsig'] + 60 < time.time():
		print('[%s] bssid active %s %ddBm %ddBm' % (timestamp(), bssid, known_aps[bssid]['minsig'], known_aps[bssid]['maxsig']))
		known_aps[bssid]['rstsig'] = None
		known_aps[bssid]['minsig'] =  200
		known_aps[bssid]['maxsig'] = -200

if __name__ == "__main__":
	# capture filter
	bpf = '(type data and dir tods) or (type mgt subtype probe-req) or (type mgt subtype probe-resp) or (type mgt subtype beacon)'

	caps = {}
	for iface in sys.argv[1:]:
		monitor_enable  = ''.join(['sudo ip link set ', iface, ' down;sudo iw ', iface, ' set monitor control;sudo ip link set ', iface, ' up'])
		iw_dev = 'sudo iw dev'
		INTERFACE_RETRIES_BEFORE_QUIT = 5
		DEVICE_STARTUP_MONITOR_MODE_DELAY = 3
		
		interface_existence_check()
		kill_interfering_services()
		os.system(monitor_enable)
		time.sleep(DEVICE_STARTUP_MONITOR_MODE_DELAY) # Delay to wait for monitor mode
		# insert check here for confirmation of monitor mode
		interface_monitor_mode_check()
		os.system(iw_dev)

		cap = pcapy.open_live(iface, 4096, 1, 10)
		cap.setfilter(bpf)
		caps[iface] = cap
		print("Listening on %s: linktype=%d" % (iface, cap.datalink()))

	next_cleanup = time.time()
	while True:
		try:
			if next_cleanup < time.time():
				next_cleanup += 5
				for sa in known_stations:
					print_station(sa)
				for bssid in known_aps:
					print_ap(bssid)
			for iface, cap in list(caps.items()):
			#for iface, cap in caps.items():
				# process all the buffered packets
				cap.dispatch(-1, lambda hdr, pkt: handler(hdr, pkt, iface))
		except KeyboardInterrupt:
			# delete python3 bytecode trash
			path_of_this_script = os.path.dirname(os.path.abspath(sys.argv[0]))
			print (path_of_this_script)
			pyCacheFiles = glob.glob(path_of_this_script + "/**/*.pyc", recursive = True)
			pyCacheFolders = glob.glob(path_of_this_script + "/**/__pycache__", recursive = True)

			for file in pyCacheFiles:
				try:
					print('Auto deleting cache file: ' + file)
					os.remove(file)
				except:
					print("Error removing .pyc files.")

			for dir in pyCacheFolders:
				try:
					print('Auto deleting cache dir: ' + dir)
					os.removedirs(dir)
				except:
					print("Error removing _pycache__ directories.")			
			os._exit(0)
