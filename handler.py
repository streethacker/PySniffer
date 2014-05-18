#!/usr/bin/env python
#-*- coding:utf-8 -*-

import dpkt, pcap
import os, sys, math
import time, binascii

class DefaultError(Exception):
	"Unknown Error"
	pass

class InvalidAccessError(DefaultError):
	"""
	Error: Cannot dequeue from an empty queue.
	+-----------------------------------------------------------------------+
	Description:
		Shared queue is empty. This exception is always raised
	when the thread of Packets Handler runs much faster then
	the thread of Packets Capture.
	+-----------------------------------------------------------------------+
	"""
	pass

class IncompatibleProtoError(DefaultError):
	"""
	Error: No compatible protocol to use.
	+------------------------------------------------------------------------+
	Description:
		An unsupported protocol handler is needed. You may write
	the handler by yourself, and copy the *.py file into the cur
	-rent working directory.
	+------------------------------------------------------------------------+
	"""
	pass


class PacketHandler:
	ALL_PROTOS = ['ethernet', 'arp', 'rarp','ip', 'ip6', 'icmp', 'tcp', 'udp', 'http', 'dns', 'ftp', 'smtp']

	_counter = 1

	_ret = """
	#######################################
	Time: %s                               
	Total Packets: %s
	#######################################	
	+--------------------------------------------------------------------------------------------+
	%s

	+------------------------------------DATA-START----------------------------------------------+
	DATA:
	%s
	+-------------------------------------DATA-END-----------------------------------------------+
	"""

	def __init__(self, queue, load=os.getcwd()):
		self._queue = queue
		self._load = load
		self._cache = {}

	def _proto_unpack(self):
		_packet = self._dequeue()
		_time_stamp = _packet.keys()[0]
		_eth_object = _packet.values()[0]
		self._cache['time'] = _time_stamp
		self._cache['ethernet'] = _eth_object		
		try:
			_proto = _eth_object.data.__class__.__name__.lower()
			self._cache[_proto] = _eth_object.data
			try:
				_proto = _eth_object.data.data.__class__.__name__.lower()
				self._cache[_proto] = _eth_object.data.data
				try:
					_proto = _eth_object.data.data.data.__class__.__name__.lower()
					self._cache[_proto] = _eth_object.data.data.data
				except AttributeError:
					pass
			except AttributeError:
				pass
		except AttributeError:
			pass
			
	def _load_handler(self):
		_handlers = [os.path.splitext(f)[0] for f in os.listdir(self._load) if os.path.splitext(f)[1] == '.py']
		return {k:__import__(k) for k in _handlers}

	def _dequeue(self):
		if self._queue.isEmpty():
			raise InvalidAccessError
		else:
			_packet = self._queue.dequeue()
			return _packet

	def _time_format(self):
		return time.strftime('%c',time.gmtime(self._cache['time']+8*3600))

	def _data_format(self):
		_data = binascii.hexlify(repr(self._cache['ethernet']))
		_part_num = int(math.ceil(len(_data) / 94.0))
		_slices = []
		for i in range(1, _part_num+1):
			if i * 94 > len(_data):
				_slices.append(_data[(i-1)*94:])
			else:
				_slices.append(_data[(i-1)*94:i*94])
		_ret = '\n\t'.join(_slices)
		return _ret
	
	def _proto_format(self, _proto_dict):
		_ret = ''
		_keys = _proto_dict.keys()
		for _proto in self.ALL_PROTOS:
			if _proto in _keys:
				_ret += _proto_dict[_proto]
		return _ret

	def _parse(self, _handlers):
		self._proto_unpack()
		_data_field = self._data_format()
		_time_stamp = self._time_format()
		del self._cache['time']
		_proto_dict = {}
		try:
			try:
				for _proto, _object in self._cache.items():
					if _proto in self.ALL_PROTOS:
						_Method = getattr(_handlers[_proto], 'getAttributes')
						_proto_dict[_proto] = _Method(_object)
				_ret = self._proto_format(_proto_dict)
				return self._ret % (_time_stamp, self._counter, _ret, _data_field)
			except KeyError:
				raise IncompatibleProtoError
		except IncompatibleProtoError as err:
			print err.__doc__

	def output(self):
		_handlers = self._load_handler()
		while True:
			try:
				_ret = self._parse(_handlers)
				print _ret
				self._counter += 1
				time.sleep(2)
			except InvalidAccessError as err:
				time.sleep(1)
				continue

if __name__ == "__main__":
	pass
