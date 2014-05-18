#!/usr/bin/env python
#-*- coding:utf-8 -*-

import sys, time, threading
from queue import Queue
from capture import PacketCapture
from handler import PacketHandler

_queue = Queue(100)
_capture_object = PacketCapture(_queue, 'icmp', 'enp9s0')
_handler_object = PacketHandler(_queue)

_capture_thread = threading.Thread(target=_capture_object.pkt_capture)
_handler_thread = threading.Thread(target=_handler_object.output)

if __name__ == "__main__":
	_capture_thread.start()
	time.sleep(10)
	_handler_thread.start()
