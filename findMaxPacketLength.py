import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

def findMaxPacketLength(self):
		# Find the maximum packet length of all the packets.
		maxLength = max(self.lengthList)

		# Print the maximum packet length.
		self.calculationList.append('Max Packet Length: ' + str(maxLength) + ' bytes')
