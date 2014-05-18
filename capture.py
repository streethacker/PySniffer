#!/usr/bin/env python
#-*- coding:utf-8 -*-

import dpkt, pcap
import re
import time

PATTERN_OF_FILTER = re.compile(r"""
		^	#beginning of string
		((ether|fddi|tr|ip|ip6|arp|rarp|decent|tcp|udp)?\s*	#proto(optional)
		 (src|dst)?\s*						#dir(optional)
		 (host|net|port)?\s*				#type(actually optional,but here we force it to be specified)
		 (\d|[a-zA-Z\._])*					#id(specified, could be a number or a string)
		)
		(\s*(and|or|not){1}\s+
		 (ether|fddi|tr|ip|ip6|arp|rarp|decent|tcp|udp)?\s*
		 (src|dst)?\s*
		 (host|net|port)?\s*
		 (\d|[a-zA-Z\._])*
		)*									#more groups of filter rules(concatenated by and, or, not)
		$	#end of string
		""", re.IGNORECASE | re.VERBOSE)

class DefaultError(Exception): 
	"""
	Unknown Error.
	"""
	pass

class QueueOverflowError(DefaultError):
	"""
	Error: Cannot enqueue to a full queue.
	+--------------------------------------------------------------------+
	Description:
		Shared queue is overloaded. This Exception is always
	raised when the thread of Packets Capture runs much faster
	then the thread of Packets Handler.
	+--------------------------------------------------------------------+
	"""
	pass

class BadFilterSyntaxError(DefaultError):
	"""
	Error: The syntax of filterString does not fit the PCAP Filter Expression.
	+---------------------------------------------------------------------------------------+
	Description:
		The filterString must follow the rules of the PCAP Filter Expression. That
	means an id(name or number) decorated by a type, dir, or proto word. Or a few
	of single expressions concatenated by 'and', 'or', or 'not'.
	+---------------------------------------------------------------------------------------+	
	"""
	pass

class PermissionError(DefaultError):
	"""
	Error: Permission denied.
	+---------------------------------------------------------------------------------------+
	Description:
		You don't have permission to capture on that specific network adapter. You
	would better to run this script as root or put yourself into the sudo group.
	+---------------------------------------------------------------------------------------+
	"""
	pass

class UnknownDeviceError(DefaultError):
	"""
	Error: No such device.
	+----------------------------------------------------------------------------------------+
	Description:
		No such device exists. That means the device name you have just specified,
	does not exists on this machine. You'd better run 'ifconfig' to make sure which
	network adapter really in use.
	+----------------------------------------------------------------------------------------+
	"""
	pass

class AllRejectsError(DefaultError):
	"""
	Error: Rejects all packets.
	+----------------------------------------------------------------------------------------+
	Description:
		Expression rejects all packets. That means the filter rule you have already
	set was conflicts with each other. You may use 'and' as a concatenated word. So
	check your expression again.
	+----------------------------------------------------------------------------------------+
	"""
	pass


class PacketCapture:
	def __init__(self, queue, filterString, name='eth0', snaplen=65535, promisc=True, immediate=False):
		self._queue = queue
		self._filterString = filterString
		self._pc = None
		self._name = name
		self._snaplen = snaplen
		self._promisc = promisc
		self._immediate = immediate
		self._create_pcap_object()
		self._setfilter()

	def _create_pcap_object(self):
		try:
			try:
				self._pc = pcap.pcap(name=self._name, snaplen=self._snaplen, promisc=self._promisc, \
						immediate=self._immediate)
			except OSError as err:
				if err.message.find("exists"):
					raise UnknownDeviceError
				elif err.message.find("permission"):
					raise PermissionError
				else:
					raise DefaultError
		except (PermissionError, UnknownDeviceError, DefaultError) as err:
			print err.__doc__

	def _check_filter_string(self):
		if not PATTERN_OF_FILTER.search(self._filterString):
			raise BadFilterSyntaxError
		else:
			return

	def _setfilter(self):
		try:
			try:
				self._check_filter_string()
				self._pc.setfilter(self._filterString)
			except (BadFilterSyntaxError, OSError) as err:
				if isinstance(err, OSError):
					raise AllRejectsError
				else:
					print err.__doc__
		except AllRejectsError as err:
			print err.__doc__
				
	def _enqueue(self, item):
		if self._queue.isFull():
			raise QueueOverflowError
		else:
			self._queue.enqueue(item)
			return True

	def pkt_capture(self):
		for ts, pkt in self._pc:
			_packet = {}
			try:
				_eth_object = dpkt.ethernet.Ethernet(pkt)
				_time_stamp = ts
				_packet[_time_stamp] = _eth_object
				self._enqueue(_packet)
			except QueueOverflowError as err:
				time.sleep(1)
			
if __name__ == "__main__":
	pass
