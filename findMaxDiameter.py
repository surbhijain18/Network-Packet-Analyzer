import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

def findMaxDiameter(self):
		# Find the maximum diameter of all the packets.
		maxDiameter = max(self.diameterList)
		
		# Print the maximum diameter.
		self.calculationList.append('Max Diameter: ' + str(maxDiameter) + ' hops')