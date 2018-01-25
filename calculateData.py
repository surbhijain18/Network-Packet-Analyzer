import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

def calculateData(self):
		self.findPacketCount()
		self.findMaxDiameter()
		self.findMaxPacketLength()
		self.findAvgDiameter()
		self.findAvgPacketLength()