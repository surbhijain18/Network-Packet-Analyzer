import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

def ip(self, packet, extractedAttIndex, printKey):
		# Header lengths.
		ethHeaderLength = 14
		ip_hlen = 20
		
		# Get IP header using begin and end.
		# Specific Linux and Windows calibration is needed.
		if self.os == self.windows:
			begin = 0
			end = begin + ip_hlen
		ipHeader = packet[begin:end]

		# Unpack the header because it originally in hex.
		# The regular expression helps unpack the header.
		# ! signifies we are unpacking a network endian.
		# B signifies we are unpacking an integer of size 1 byte.
		# H signifies we are unpacking an integer of size 2 bytes.
		# 4s signifies we are unpacking a string of size 4 bytes.
		ipHeaderUnpacked = struct.unpack('!BBHHHBBH4s4s' , ipHeader)
		
		# The first B is 1 byte and contains the version and header length.
		# Both are 4 bits each, split ipHeaderUnpacked[0] in "half".
		ipVersionAndHeaderLength = ipHeaderUnpacked[0]
		ipVersion = ipVersionAndHeaderLength >> 4
		ip_hlen = ipVersionAndHeaderLength & 0xF

		# The first H is 2 bytes and contains the total length.
		ipTotalLength = ipHeaderUnpacked[2]
		
		# The second H is 2 bytes and contains the total length.
		ipIdentification = ipHeaderUnpacked[3]

		# The third H is 2 bytes and contains the flags and fragment offset.
		# Flags is 3 bits and fragment offset is 13 bits.
		# Split ipHeaderUnpacked[4].
		ipFlagsAndFragmentOffset = ipHeaderUnpacked[4]
		ipFlags = ipFlagsAndFragmentOffset >> 13
		ipFragmentOffset = ipFlagsAndFragmentOffset & 0x1FFF

		# The third B is 1 byte and contains the time to live.
		ip_TTL = ipHeaderUnpacked[5]
			
		# Our fourth B is 1 byte and contains the protocol.
		ipProtocol = ipHeaderUnpacked[6]
		
		# The fourth H is 2 bytes and contains the header checksum.
		ipHeaderChecksum = ipHeaderUnpacked[7]

		# The first 4s is 4 bytes and contains the source address.
		ip_src_addr = socket.inet_ntoa(ipHeaderUnpacked[8]);

		# The second 4s is 4 bytes and contains the dest address.
		ip_dest_addr = socket.inet_ntoa(ipHeaderUnpacked[9]);

		# Check if the print key is True.
		# If true, header information will be printed.
		# 	Check if the user selected extracted attribute index is 0.
		#	If true, all attributes will be printed.
		#	If false, the attribute the user selected extracted attribute index corresponds to will be printed.
		# If false, the attribute the user selected attribute index corresponds to will be returned.
		if printKey == True:
			# Print IP Header
			# Some segments of the header are switched back to hex form because that
			# 	is the format wireshark has it.
			self.unpackedInfo.append('\n********************\n******** IP ********\n********************')
			
			if (extractedAttIndex == 1) or (extractedAttIndex == 0):
				self.unpackedInfo.append('IP Version: ' + str(ipVersion))
			if (extractedAttIndex == 2) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Header Length: ' + str(ip_hlen) + ' 32-bit words')
			if (extractedAttIndex == 3) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Total Length: ' + str(ipTotalLength) + ' bytes')
			if (extractedAttIndex == 4) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Identification: ' + format(ipIdentification, '#04X') + ' , ' + str(ipIdentification))
			if (extractedAttIndex == 5) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Flags: ' + format(ipFlags, '#04X') + ' , ' + str(ipFlags))
			if (extractedAttIndex == 6) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Fragment Offset: ' + str(ipFragmentOffset) + ' eight-byte blocks')
			if (extractedAttIndex == 7) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Time to Live: ' + str(ip_TTL) + ' hops')
			if (extractedAttIndex == 8) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Protocol: ' + str(ipProtocol))
			if (extractedAttIndex == 9) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Header Checksum: ' + format(ipHeaderChecksum, '#04X'))
			if (extractedAttIndex == 10) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Source Address: ' + str(ip_src_addr))
			if (extractedAttIndex == 11) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Destination Address: ' + str(ip_dest_addr))
		else:
			if (extractedAttIndex == 1):
				return str(ipVersion)
			if (extractedAttIndex == 2):
				return str(ip_hlen)
			if (extractedAttIndex == 3):
				return str(ipTotalLength)
			if (extractedAttIndex == 4):
				return format(ipIdentification, '#04X')
			if (extractedAttIndex == 5):
				return format(ipFlags, '#04X')
			if (extractedAttIndex == 6):
				return str(ipFragmentOffset)
			if (extractedAttIndex == 7):
				return str(ip_TTL)
			if (extractedAttIndex == 8):
				return str(ipProtocol)
			if (extractedAttIndex == 9):
				return format(ipHeaderChecksum, '#04X')
			if (extractedAttIndex == 10):
				return str(ip_src_addr)
			if (extractedAttIndex == 11):
				return str(ip_dest_addr)