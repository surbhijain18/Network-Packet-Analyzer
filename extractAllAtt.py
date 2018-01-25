import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

def extractAllAtt(self, packet):
		# All attributes for each protocol will be displayed.
		extractedAttIndex = 0
		
		# Attributes will be printed.
		printKey = True
		
		# If the OS is Linux, unpack Ethernet's protocol.
		# If the OS is Windows, mimic unpacking Ethernet's protocol.
		if self.os == self.windows:
			ethProtocol = 8

		# Find if the Ethernet protocol is ARP or IP.
		if ethProtocol == 8:
			# Unpack IP's information.
			self.ip(packet, extractedAttIndex, printKey)
			
			# Find the packet's IP protocol.
			ipProtocol = self.ip(packet, 8, False)
			ipProtocol = int(ipProtocol)
			
			# If the protocol is 1, meaning ICMP, then unpack the ICMP information.
			# If the protocol is 6, meaning TCP, then unpack the TCP information.
			# If the protocol is 17, meaning UDP, then unpack the UDP information.
			if ipProtocol == 1:
				self.icmp(packet, extractedAttIndex, printKey)
			elif ipProtocol == 6:
				self.tcp(packet, extractedAttIndex, printKey)
			elif ipProtocol == 17:
				self.udp(packet, extractedAttIndex, printKey)