import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

def udp(self, packet, extractedAttIndex, printKey):
		# Header lengths.
		ethHeaderLength = 14
		ip_hlen = 20
		udpHeaderLength = 8
		
		# Get UDP header using begin and end.
		# Specific Linux and Windows calibration is needed.
		if self.os == self.windows:
			begin = ip_hlen
			end = begin + udpHeaderLength
		udpHeader = packet[begin:end]
	
		# Unpack the header because it originally in hex.
		# The regular expression helps unpack the header.
		# ! signifies we are unpacking a network endian.
		# H signifies we are unpacking an integer of size 2 bytes.
		udpHeaderUnpacked = struct.unpack('!HHHH', udpHeader)
		 
		# The first H is 2 bytes and contains the source port.
		udpSourcePort = udpHeaderUnpacked[0]
		
		# The second H is 2 bytes and contains the destination port.
		udpDestPort = udpHeaderUnpacked[1]
		
		# The third H is 2 bytes and contains the packet length.
		udpLength = udpHeaderUnpacked[2]
		
		# The fourth H is 2 bytes and contains the header checksum.
		udpChecksum = udpHeaderUnpacked[3]
		
		# Check if the print key is True.
		# If true, header information will be printed.
		# 	Check if the user selected extracted attribute index is 0.
		#	If true, all attributes will be printed.
		#	If false, the attribute the user selected extracted attribute index corresponds to will be printed.
		# If false, the attribute the user selected attribute index corresponds to will be returned.
		if printKey == True:
			# Print UDP Header
			self.unpackedInfo.append('\n*******************\n******* UDP *******\n*******************')
			
			if (extractedAttIndex == 1) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Source Port: ' + str(udpSourcePort))
			if (extractedAttIndex == 2) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Destination Port: ' + str(udpDestPort))
			if (extractedAttIndex == 3) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Length: ' + str(udpLength) + ' bytes')
			if (extractedAttIndex == 4) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Checksum: ' + format(udpChecksum, '#04X'))

			# Separator	
			self.unpackedInfo.append('\n----------------------------------------')	
		else:
			if (extractedAttIndex == 1):
				return str(udpSourcePort)
			if (extractedAttIndex == 2):
				return str(udpDestPort)
			if (extractedAttIndex == 3):
				return str(udpLength)
			if (extractedAttIndex == 4):
				return format(udpChecksum, '#04X')