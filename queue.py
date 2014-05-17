#!/usr/bin/env python
#-*- coding:utf-8 -*-

from array import Array

class Queue:
	def __init__(self, maxSize):
		self._count = 0
		self._front = 0
		self._back = maxSize - 1
		self._qArray = Array(maxSize)

	def isEmpty(self):
		return self._count == 0

	def isFull(self):
		return self._count == len(self._qArray)

	def __len__(self):
		return self._count

	def enqueue(self, item):
		assert not self.isFull(), "Cannot enqueue to a full queue"
		maxSize = len(self._qArray)
		self._back = (self._back + 1) % maxSize
		self._qArray[self._back] = item
		self._count += 1

	def dequeue(self):
		assert not self.isEmpty(), "Cannot dequeue from an empty queue"
		item = self._qArray[self._front]
		maxSize = len(self._qArray)
		self._front = (self._front + 1) % maxSize
		self._count -= 1
		return item

if __name__ == "__main__":
	import unittest

	class TestQueue(unittest.TestCase):
		def testEnqueueOK(self):
			_queue = Queue(5)
			_values = (10, 20, 30, 40, 5)
			for val in _values:
				_queue.enqueue(val)
			self.assertEqual(_queue._count, 5)

		def testEnqueueFailure(self):
			_queue = Queue(5)
			_values = (10, 20, 30, 40, 50)
			for val in _values:
				_queue.enqueue(val)
			self.assertRaises(AssertionError, _queue.enqueue, 100)

		def testDequeueOK(self):
			_queue = Queue(5)
			_values = (10, 20, 30, 40, 50)
			for val in _values:
				_queue.enqueue(val)
			for idx in range(5):
				val = _queue.dequeue()
				self.assertEqual(val, _values[idx])

		def testDequeueFailure(self):
			_queue = Queue(1)
			_queue.enqueue(10)
			_queue.dequeue()
			self.assertRaises(AssertionError, _queue.dequeue)

	unittest.main()

