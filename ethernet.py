import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore


def eth(self, packet, extractedAttIndex, printKey):
		# Header lengths.
		ethHeaderLength = 14

		# Get Ethernet header using begin and end.
		# No need for windows calibration, Ethernet support under Linux only.
		begin = 0
		end = begin + ethHeaderLength
		ethHeader = packet[begin:end]

		# Unpack the header because it originally in hex.
		# The regular expression helps unpack the header.
		# ! signifies we are unpacking a network endian.
		# 6s signifies we are unpacking a string of size 6 bytes.
		# H signifies we are unpacking an integer of size 2 bytes.
		ethHeaderUnpacked = struct.unpack('!6s6sH', ethHeader)
			
		# The first 6s is 6 bytes and contains the destination address.
		ether_dest_addr = ethHeaderUnpacked[0]
		
		# The second 6s is 6 bytes and contains the source address.
		ether_src_addr = ethHeaderUnpacked[1]
		
		# The first H is 2 bytes and contains the packet length.
		ethType = socket.ntohs(ethHeaderUnpacked[2])
		
		# Properly unpack and format the destination address.
		ether_dest_addr = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % (ord(ether_dest_addr[0]), ord(ether_dest_addr[1]), ord(ether_dest_addr[2]), ord(ether_dest_addr[3]), ord(ether_dest_addr[4]), ord(ether_dest_addr[5]))
		
		# Properly unpack and format the source address.
		ether_src_addr = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % (ord(ether_src_addr[0]), ord(ether_src_addr[1]), ord(ether_src_addr[2]), ord(ether_src_addr[3]), ord(ether_src_addr[4]), ord(ether_src_addr[5]))
		
		# Check if the print key is True.
		# If true, header information will be printed.
		# 	Check if the user selected extracted attribute index is 0.
		#	If true, all attributes will be printed.
		#	If false, the attribute the user selected extracted attribute index corresponds to will be printed.
		# If false, the attribute the user selected attribute index corresponds to will be returned.
		if printKey == True:
			# Print Ethernet Header
			self.unpackedInfo.append('\n********************\n** Ethernet (MAC) **\n********************')
			
			if (extractedAttIndex == 1) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Destination Address: ' + str(ether_dest_addr))
			if (extractedAttIndex == 2) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Source Address: ' + str(ether_src_addr))
			if (extractedAttIndex == 3) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Ethernet Type: ' + str(ethType))
		else:
			if (extractedAttIndex == 1):
				return str(ether_dest_addr)
			if (extractedAttIndex == 2):
				return str(ether_src_addr)
			if (extractedAttIndex == 3):
				return str(ethType)