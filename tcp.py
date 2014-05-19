#!/usr/bin/env python
#-*- coding:utf-8 -*-

import dpkt
import binascii

"""
__hdr__ = (
	('sport', 'H', 0xdead),
	('dport', 'H', 0),
	('seq', 'I', oxdeadbeefL),
	('ack', 'I', 0),
	('off_x2', 'B', ((5 << 4) | 0)),
	('flags', 'B', TH_SYN),
	('win', 'H', TCP_WIN_MAX),
	('sum', 'H', 0),
	('urp', 'H', 0)
)
"""

def getAttributes(_tcp_object):
	_ret = """
	Proto Type: TCP
	sport: %s
	dport: %s
	seq: %s
	ack: %s
	Header Length: %s
	URG: %s 
	ACK: %s 
	PSH: %s 
	RST: %s 
	SYN: %s 
	FIN: %s
	Window Size: %s
	Sum: %s
	Urp: %X
	Options: %s
	"""

	_sport = _tcp_object.sport
	_dport = _tcp_object.dport
	_seq = _tcp_object.seq
	_ack = _tcp_object.ack
	_header_length = _tcp_object.off
	_urg = (_tcp_object.flags & dpkt.tcp.TH_URG) != 0
	_ack = (_tcp_object.flags & dpkt.tcp.TH_ACK) != 0
	_psh = (_tcp_object.flags & dpkt.tcp.TH_PUSH) != 0
	_rst = (_tcp_object.flags & dpkt.tcp.TH_RST) != 0
	_syn = (_tcp_object.flags & dpkt.tcp.TH_SYN) != 0
	_fin = (_tcp_object.flags & dpkt.tcp.TH_FIN) != 0
	_win = _tcp_object.win
	_sum = _tcp_object.sum
	_urp = _tcp_object.urp
	_opt = _tcp_object.opts and "".join(map(binascii.hexlify, _tcp_object.opts)) or None

	return _ret % (_sport, _dport, _seq, _ack, _header_length, _urg, _ack, _psh, _rst, _syn, _fin, _win, _sum, _urp, _opt)

if __name__ == "__main__":
	pass
