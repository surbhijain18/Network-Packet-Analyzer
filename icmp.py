import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

def icmp(self, packet, extractedAttIndex, printKey):
		# Header lengths.
		ethHeaderLength = 14
		ip_hlen = 20
		icmpHeaderLength = 8
		
		# Get ICMP header using begin and end.
		# Specific Linux and Windows calibration is needed.
		if self.os == self.windows:
			begin = ip_hlen
			end = begin + icmpHeaderLength
		icmpHeader = packet[begin:end]

		# Unpack the header because it originally in hex.
		# The regular expression helps unpack the header.
		# ! signifies we are unpacking a network endian.
		# B signifies we are unpacking an integer of size 1 byte.
		# H signifies we are unpacking an integer of size 2 bytes.
		# L signifies we are unpacking a long of size 4 bytes.
		icmpHeaderUnpacked = struct.unpack('!BBHL', icmpHeader)

		# The first B is 1 byte and contains the type.
		icmpType = icmpHeaderUnpacked[0]

		# The second B is 1 byte and contains the code.
		icmpCode = icmpHeaderUnpacked[1]

		# The first H is 2 bytes and contains the checksum.
		icmpChecksum = icmpHeaderUnpacked[2]

		# Check if the type is 1 or 8, if so, unpack the identifier and sequence number.
		if (icmpType == 0) or (icmpType == 8):
			# The first L is 4 bytes and contains the rest of the header.
			icmpIdentifier = icmpHeaderUnpacked[3] >> 16
			icmpSeqNumber = icmpHeaderUnpacked[3] & 0xFFFF
		
		# Check if the print key is True.
		# If true, header information will be printed.
		# 	Check if the user selected extracted attribute index is 0.
		#	If true, all attributes will be printed.
		#	If false, the attribute the user selected extracted attribute index corresponds to will be printed.
		# If false, the attribute the user selected attribute index corresponds to will be returned.
		if printKey == True:
			if (icmpType == 0) or (icmpType == 8):
				# Print ICMP Header
				# Some segments of the header are switched back to hex form because that
				# 	is the format wireshark has it.
				self.unpackedInfo.append('\n********************\n******* ICMP *******\n********************')
				
				if (extractedAttIndex == 1) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Type: ' + str(icmpType))
				if (extractedAttIndex == 2) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Code: ' + str(icmpCode))
				if (extractedAttIndex == 3) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Checksum: ' + format(icmpChecksum, '#04X'))
				if (extractedAttIndex == 4) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Identifier: ' + str(icmpIdentifier))
				if (extractedAttIndex == 5) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Sequence Number: ' + str(icmpSeqNumber))
			else:
				self.unpackedInfo.append('\n********************\n******* ICMP *******\n********************')
				
				if (extractedAttIndex == 1) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Type: ' + str(icmpType))
				if (extractedAttIndex == 2) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Code: ' + str(icmpCode))
				if (extractedAttIndex == 3) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Checksum: ' + format(icmpChecksum, '#04X'))
				if (extractedAttIndex == 4) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Attribute not available.')
				if (extractedAttIndex == 5) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Attribute not available.')
					
			# Separator	
			self.unpackedInfo.append('\n----------------------------------------')
		else:
			if (icmpType == 0) or (icmpType == 8):
				if (extractedAttIndex == 1):
					return str(icmpType)
				if (extractedAttIndex == 2):
					return str(icmpCode)
				if (extractedAttIndex == 3):
					return format(icmpChecksum, '#04X')
				if (extractedAttIndex == 4):
					return str(icmpIdentifier)
				if (extractedAttIndex == 5):
					return str(icmpSeqNumber)
			else:			
				if (extractedAttIndex == 1):
					return str(icmpType)
				if (extractedAttIndex == 2):
					return str(icmpCode)
				if (extractedAttIndex == 3):
					return format(icmpChecksum, '#04X')
				if (extractedAttIndex == 4):
					return 'Attribute not available.'
				if (extractedAttIndex == 5):
					return 'Attribute not available.'