import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

def findProtocol(self, packet):
		# Will hold the packet protocol.
		packetProtocol = ''
		
		# If the OS is Linux, unpack Ethernet's protocol.
		# If the OS is Windows, mimic unpacking Ethernet's protocol.
		if self.os == self.windows:
			ethProtocol = 8

		# Find if the Ethernet protocol is ARP or IP.
		# If the protocol is 1544, meaning ARP, then set packetProtocol to 0.
		# If the protocol is 8, meaning IP, find the protocol within IP.
		
		if ethProtocol == 8:
			# Unpack IP's protocol.
			ipProtocol = self.ip(packet, 8, False)
			ipProtocol = int(ipProtocol)
			
			# If the protocol is 1, meaning ICMP, then set packetProtocol to 2 (Linux) or 1 (Windows).
			# If the protocol is 6, meaning TCP, then set packetProtocol to 3 (Linux) or 2 (Windows).
			# If the protocol is 17, meaning UDP, then set packetProtocol to 4 (Linux) or 3 (Windows).
			if self.os == self.windows:
				if ipProtocol == 1:
					packetProtocol = 1
				elif ipProtocol == 6:
					packetProtocol = 2
				elif ipProtocol == 17:
					packetProtocol = 3
				
		# Return the packet protocol.
		return packetProtocol