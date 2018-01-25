import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

def filterAndExtract(self, packet, filteredProtocolIndex, extractedAttIndex):
		# Get the protocol index of the packet.
		protocolIndex = self.findProtocol(packet)
		
		if self.os == self.windows:
			if (filteredProtocolIndex == protocolIndex) or (filteredProtocolIndex == 0):
				# Attributes will be printed.
				printKey = True
				
				# Find the user selected filtered protocol index.
				if filteredProtocolIndex == 0:		#All protocols
					if extractedAttIndex >= 1:
						self.ip(packet, extractedAttIndex, printKey)

						# Separator
						self.unpackedInfo.append('\n----------------------------------------')
					elif extractedAttIndex == 0:
						self.extractAllAtt(packet)
				elif filteredProtocolIndex == 1:
					# The user selected extracted attribute index will be calibrated (if needed) to specify which attribute to extract.
					if extractedAttIndex >= 14:	
						self.icmp(packet, extractedAttIndex - 13, printKey)
					elif extractedAttIndex >= 1:
						self.ip(packet, extractedAttIndex, printKey)
							
						# Separator	
						self.unpackedInfo.append('\n----------------------------------------')	
					elif extractedAttIndex == 0:
						self.extractAllAtt(packet)
				elif filteredProtocolIndex == 2:
					if extractedAttIndex >= 14:	
						self.tcp(packet, extractedAttIndex - 11, printKey)
					elif extractedAttIndex >= 1:
						self.ip(packet, extractedAttIndex, printKey)
							
						self.unpackedInfo.append('\n----------------------------------------')	
					elif extractedAttIndex == 0:
						self.extractAllAtt(packet)
				elif filteredProtocolIndex == 3:
					if extractedAttIndex >= 14:	
						self.udp(packet, extractedAttIndex - 13, printKey)
					elif extractedAttIndex >= 1:
						self.ip(packet, extractedAttIndex, printKey)
							
						self.unpackedInfo.append('\n----------------------------------------')	
					elif extractedAttIndex == 0:
						self.extractAllAtt(packet)
				return True
			else:
				return False