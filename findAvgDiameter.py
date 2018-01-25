import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

def findAvgDiameter(self):
		# Hold the sum and the count of the diameters.
		diameterSum = 0
		count = 0
		avgDiameter = 0
		
		# Add all of the diameters together.
		for diameter in self.diameterList:
			diameterSum = diameterSum + diameter
			count = count + 1
			
		# Divide diameterSum by count to give average.
		avgDiameter = diameterSum / count
		self.calculationList.append('Avg Diameter: ' + str(avgDiameter) + ' hops')