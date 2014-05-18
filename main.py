#!/usr/bin/env python
#-*- coding:utf-8 -*-

import sys, os, getopt, time, threading
from queue import Queue
from capture import PacketCapture
from handler import PacketHandler

class DefaultError(Exception): pass

def usage():
	"""
	
	"""
	print __doc__

def main():
	_filterString, _name, _snaplen, _promisc, _immediate, _load = 'icmp', 'eth0', 65535, True, False, os.getcwd()
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hf:n:s:pil:", \
				["help", "filter=", "name=", "snaplen=", "promisc","immediate", "load="])
	except getopt.GetoptError as err:
		print str(err)
		usage()
		sys.exit(2)

	for opt, arg in opts:
		if opt in ("-h", "--help"):
			usage()
		elif opt in ("-f", "--filter"):
			_filterString = arg
		elif opt in ("-n", "--name"):
			_name = arg
		elif opt in ("-s", "--snaplen"):
			_snaplen = arg
		elif opt in ("-p", "--promisc"):
			_promisc = False
		elif opt in ("-i", "--immediate"):
			_immediate = True
		elif opt in ("-l", "--load"):
			_load = arg
		else:
			raise DefaultError, "Unknown Error"

	
	_queue = Queue(100)
	_capture_object = PacketCapture(queue = _queue, filterString = _filterString, name = _name, \
			snaplen = _snaplen, promisc = _promisc, immediate = _immediate)
	_handler_object = PacketHandler(queue = _queue, load = _load)


	_capture_thread = threading.Thread(target=_capture_object.pkt_capture)
	_handler_thread = threading.Thread(target=_handler_object.output)

	_capture_thread.start()

	_handler_thread.start()

if __name__ == "__main__":
	main()
