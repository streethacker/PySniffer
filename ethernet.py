#!/usr/bin/env python
#-*- coding:utf-8 -*-

"""
__hdr__ = (
	('dst', '6s', ''),
	('src', '6s', ''),
	('type', 'H', ETH_TYPE_IP)
)
"""


def getAttributes(_ethernet_object):
    _ret = """
	Proto Type: Ethernet
	HWaddr Dst: %s
	HWaddr Src: %s
	Type: %s
	"""

    _dst = '%X : %X : %X : %X : %X : %X' % tuple(
        map(ord, list(_ethernet_object.dst)))
    _src = '%X : %X : %X : %X : %X : %X' % tuple(
        map(ord, list(_ethernet_object.src)))
    _type = hex(_ethernet_object.type)

    return _ret % (_dst, _src, _type)

if __name__ == "__main__":
    pass
