#!/usr/bin/env python
#-*- coding:utf-8 -*-

import ctypes

class _ArrayIterator:
	def __init__(self, theArray):
		self._arrayRef = theArray
		self._curNdx = 0

	def __iter__(self):
		return self
	
	def next(self):
		if self._curNdx < len(self._arrayRef):
			item = self._arrayRef[self._curNdx]
			self._curNdx += 1
			return item
		else:
			raise StopIteration

class Array:
	def __init__(self, size):
		assert size > 0, "Array size must be > 0"
		self._size = size
		PyArrayType = ctypes.py_object * size
		self._elements = PyArrayType()
		self.clear(None)

	def __len__(self):
		return self._size

	def __getitem__(self, index):
		assert index >= 0 and index < self._size, "Index out of range"
		return self._elements[index]

	def __setitem__(self, index, value):
		assert index >= 0 and index < self._size, "Index out of range"
		self._elements[index] = value

	def clear(self, value):
		for i in range(self._size):
			self._elements[i] = value

	def __iter__(self):
		return _ArrayIterator(self._elements)

if __name__ == "__main__":
	import unittest
	class TestArray(unittest.TestCase):
		def testCreateOK(self):
			_array = Array(5)
			self.assertEqual(_array._size, 5)

		def testCreateFailure(self):
			self.assertRaises(AssertionError, Array, -1)
		
		def testAssignFailure(self):
			_array = Array(5)
			_pairs = {
				-1 : 10,
				-2 : 20,
				-3 : 30,
				-4 : 40,
				-5 : 50,
				5 : 10,
				6 : 20,
				7 : 30,
				8 : 40, 
				9 : 50,
			}
			for idx, val in _pairs.items():
				self.assertRaises(AssertionError, _array.__setitem__, idx, val)

		def testVisitFailure(self):
			_array = Array(5)
			_values = (10, 20, 30, 40, 50)
			_array[0], _array[1], _array[2], _array[3], _array[4] = _values

			_index = [-5, -4, -3, -2, -1, 5, 6, 7, 8, 9]
			for idx in _index:
				self.assertRaises(AssertionError, _array.__getitem__, idx)

		def testIteration(self):
			_array = Array(5)
			_values = (10, 20, 30, 40, 50)
			_array[0], _array[1], _array[2], _array[3], _array[4] = _values
			idx = 0
			for val in _array:
				self.assertEqual(val, _values[idx])
				idx += 1


	unittest.main()
