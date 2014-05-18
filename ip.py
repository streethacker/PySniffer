#!/usr/bin/env python
#-*- coding:utf-8 -*-

"""
__hdr__ = (
	('v_hl', 'B', (4 << 4) | (20 >> 2)), #版本：4bit，默认值4，左移4位，首部长度：4bit，默认值20，右移2位
	('tos', 'B', 0), #服务类型TOS：8bit，默认值0
	('len', 'H', 20), #总长度：16bit，默认值20
	('id', 'H', 0), #标识：16bit，默认值0
	('off', 'H', 0), #偏移(含3bit标志)：16bit，默认值0
	('ttl', 'B', 64), #生存时间TTL：8bit，默认值64
	('p', 'B', 0), #协议：8bit，默认值0
	('sum', 'H', 0), #首部校验和：16bit，默认值0
	('src', '4s', '\x00' * 4), #源地址：4个字节，默认值0.0.0.0
	('dst', '4s', '\x00' * 4) #目的地址：4个字节，默认值0.0.0.0
)
"""

def getAttributes(_ip_objcet):
	_ret = """
	Proto Type: IP
	Version: %s
	Header Length: %s
	ToS: %s
	Total Length: %s
	ID: %s
	Offset: %s
	TTL: %s
	Upper Proto: %s
	Sum: %s
	Src: %s
	Dst: %s
	"""

	_version = _ip_objcet.v
	_header_length = _ip_objcet.hl
	_tos = _ip_objcet.tos
	_total_length = _ip_objcet.len
	_id = _ip_objcet.id
	_offset = _ip_objcet.off
	_ttl = _ip_objcet.ttl
	_upper_proto = _ip_objcet.p
	_sum = _ip_objcet.sum
	_src = '%d.%d.%d.%d' % tuple(map(ord, list(_ip_objcet.src)))  
	_dst = '%d.%d.%d.%d' % tuple(map(ord, list(_ip_objcet.dst)))

	return _ret % (_version, _header_length, _tos, _total_length, _id, _offset, _ttl, _upper_proto, _sum, _src, _dst)

if __name__ == "__main__":
	pass
