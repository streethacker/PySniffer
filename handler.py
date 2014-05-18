#!/usr/bin/env python
#-*- coding:utf-8 -*-

import dpkt, pcap
import os, sys
import time

class DefaultError(Exception):
	"Unknown Error"
	pass

class InvalidAccessError(DefaultError):
	"""
	Error: Cannot dequeue from an empty queue.
	+---------------------------------------------------------+
	Description:
		Shared queue is empty. This exception is always raised
	when the thread of Packets Handler runs much faster then
	the thread of Packets Capture.
	+---------------------------------------------------------+
	"""
	pass

class IncompatibleProtoError(DefaultError):
	"""
	Error: No compatible protocol to use.
	+----------------------------------------------------------+
	Description:
		An unsupported protocol handler is needed. You may write
	the handler by yourself, and copy the *.py file into the cur
	-rent working directory.
	+----------------------------------------------------------+
	"""
	pass


class PacketHandler:
	_ret = """
	Time: %s	
	+--------------------------------------------------------------------------------------------+
	"""

	def __init__(self, queue, load=os.getcwd()):
		self._queue = queue
		self._load = load
		self._cache = {}

	def _proto_unpack(self):
		try:
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
		except InvalidAccessError as err:
			print err.__doc__
			time.sleep(5)
			
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

	def _parse(self, _handlers):
		self._proto_unpack()
		_ret = self._ret % self._time_format()
		try:
			try:
				for _proto, _object in self._cache.items():
					if _proto == 'icmp':
						_Method = getattr(_handlers[_proto], 'getAttributes')
						_ret += _Method(_object)
				return _ret
			except KeyError:
				raise IncompatibleProtoError
		except IncompatibleProtoError as err:
			print err.__doc__

	def output(self):
		_handlers = self._load_handler()
		while True:
			_ret = self._parse(_handlers)
			print _ret
			time.sleep(2)

if __name__ == "__main__":
	pass
