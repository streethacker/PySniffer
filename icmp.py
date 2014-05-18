#!/usr/bin/env python
#-*- coding:utf-8 -*-

import binascii

"""
__hdr__ = (
	('type', 'B', 8), #ICMP类型：8bit，默认8(请求回显)
	('code', 'B', 0), #代码：8bit，默认0
	('sum', 'H', 0) #校验和：16bit，默认0
)
"""

def getAttributes(_icmp_object):
	_ret = """
	Proto Type: ICMP
	type: %s
	code: %s
	sum : %s
	data: 
	%s
	"""
	_echo_object = _icmp_object.data
	_type = _icmp_object.type
	_code = _icmp_object.code
	_sum = _icmp_object.sum
	_data = binascii.hexlify(_echo_object.data)

	return _ret % (_type, _code, _sum, _data)

if __name__ == "__main__":
	pass
