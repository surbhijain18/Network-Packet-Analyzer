import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

def findAvgPacketLength(self):
		# Hold the sum and the count of the packet lengths.
		lengthSum = 0
		count = 0
		avgLength = 0
		
		# Add all of the lengths together.
		for length in self.lengthList:
			lengthSum = lengthSum + length
			count = count + 1

		# Divide lengthSum by count to give average.
		avgLength = lengthSum / count
		self.calculationList.append('Avg Packet Length: ' + str(avgLength) + ' bytes')
