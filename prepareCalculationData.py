import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

def prepareCalculationData(self, packet):
		# If the OS is Linux, unpack Ethernet's protocol.
		# If the OS is Windows, mimic unpacking Ethernet's protocol.
		if self.os == self.windows:
			ethProtocol = 8

		# Find if the Ethernet protocol is IP.
		# If the protocol is 8, meaning IP, find the diameter and find the protocol within IP.
		if ethProtocol == 8:
			# Append the IP total length to the length list.
			# Append the diameters to the diameter list using TTL.
			# These will be used for calculations.
			ipTotalLength = self.ip(packet, 3, False)
			ipTotalLength = int(ipTotalLength)
			self.lengthList.append(ipTotalLength)
				
			# Find the diameter of the network.
			# Different servers have different operating systems that have different TTLs.
			# Cisco is 255, Windows is 128, Linux is 64.
			ip_TTL = self.ip(packet, 7, False)
			ip_TTL = int(ip_TTL)
			
			if ip_TTL > 128:
				self.diameterList.append(255 - ip_TTL)
			elif ip_TTL > 64:
				self.diameterList.append(128 - ip_TTL)
			else:
				self.diameterList.append(64 - ip_TTL)
				
			return True
		else:
			return False