import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

def tcp(self, packet, extractedAttIndex, printKey):
		# Header lengths.
		ethHeaderLength = 14
		ip_hlen = 20
		tcp_hlen = 20

		# Get TCP header using begin and end.
		# Specific Linux and Windows calibration is needed.
		if self.os == self.windows:
			begin = ip_hlen
			end = begin + tcp_hlen
		tcp_head = packet[begin:end]

		# Unpack the header because it originally in hex. ! signifies we are unpacking a network endian.
		# H signifies we are unpacking an integer of size 2 bytes.
		# L signifies we are unpacking a long of size 4 bytes.
		# B signifies we are unpacking an integer of size 1 byte.
		tcp_header_unpacked = struct.unpack('!HHLLBBHHH', tcp_head)
		
		# The first H is 2 bytes and contains the source port.
		tcp_src_port = tcp_header_unpacked[0]
		
		# The second H is 2 bytes and contains the destination port.
		tcp_dest_port = tcp_header_unpacked[1]

		# The first L is 2 bytes and contains the sequence number.
		tcp_seq = tcp_header_unpacked[2]
		
		# The second L is 4 bytes and contains the acknowledgement number.
		tcp_ack = tcp_header_unpacked[3]
		
		# The first B is 1 byte and contains the data offset, reserved bits, and NS flag.
		# Split tcp_header_unpacked[4]
		tcpDataOffsetAndReserved = tcp_header_unpacked[4]
		tcpDataOffset = tcpDataOffsetAndReserved >> 4
		tcpReserved = (tcpDataOffsetAndReserved >> 1) & 0x7
		#tcpNSFlag = tcpDataOffsetAndReserved & 0x1
		
		# The second B is 1 byte and contains the rest of the flags.
		# Split tcp_header_unpacked[5].
		tcpRestOfFLags = tcp_header_unpacked[5]
		#tcpCWRFlag = tcpRestOfFLags >> 7
		#FsetcpECEFlag = (tcpRestOfFLags >> 6) & 0x1
		flag_URG = (tcpRestOfFLags >> 5) & 0x1
		flag_ACK = (tcpRestOfFLags >> 4) & 0x1
		flag_PSH = (tcpRestOfFLags >> 3) & 0x1
		flag_RST = (tcpRestOfFLags >> 2) & 0x1
		flag_SYN = (tcpRestOfFLags >> 1) & 0x1
		flag_FIN = tcpRestOfFLags & 0x1
		
		# The third H is 2 bytes and contains the window size.
		tcp_winsize = tcp_header_unpacked[6]
		
		# The fourth H is 2 byte and conntains the checksum.
		tcpChecksum = tcp_header_unpacked[7]
		
		# The fifth H is 2 bytes and constains the urgent pointer.
		tcpUrgentPointer = tcp_header_unpacked[8]
		
		# Check if the print key is True.
		# If true, header information will be printed.
		# 	Check if the user selected extracted attribute index is 0.
		#	If true, all attributes will be printed.
		#	If false, the attribute the user selected extracted attribute index corresponds to will be printed.
		# If false, the attribute the user selected attribute index corresponds to will be returned.
		if printKey == True:
			# Print TCP Header
			# Some segments of the header are switched back to hex form because that
			# 	is the format wireshark has it.
			self.unpackedInfo.append('\n*******************\n******* TCP *******\n*******************')
		
			if (extractedAttIndex == 1) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Source Port: ' + str(tcp_src_port))
			if (extractedAttIndex == 2) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Destination Port: ' + str(tcp_dest_port))
			if (extractedAttIndex == 3) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Sequence Number: ' + str(tcp_seq))
			if (extractedAttIndex == 4) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Acknowledgment Number: ' + str(tcp_ack))
			if (extractedAttIndex == 5) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Data Offset: ' + str(tcpDataOffset) + ' 32-bit words')
			if (extractedAttIndex == 6) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Reserved: ' + format(tcpReserved, '03b') + '. .... ....')
			if (extractedAttIndex == 7) or (extractedAttIndex == 0):
				self.unpackedInfo.append('URG Flag: ' + '.... ..' + format(flag_URG, '01b') + '. ....')
			if (extractedAttIndex == 8) or (extractedAttIndex == 0):
				self.unpackedInfo.append('ACK Flag: ' + '.... ...' + format(flag_ACK, '01b') + ' ....')
			if (extractedAttIndex == 9) or (extractedAttIndex == 0):
				self.unpackedInfo.append('PSH Flag: ' + '.... .... ' + format(flag_PSH, '01b') + '...')
			if (extractedAttIndex == 10) or (extractedAttIndex == 0):
				self.unpackedInfo.append('RST Flag: ' + '.... .... .' + format(flag_RST, '01b') + '..')
			if (extractedAttIndex == 11) or (extractedAttIndex == 0):
				self.unpackedInfo.append('SYN Flag: ' + '.... .... ..' + format(flag_SYN, '01b') + '.')
			if (extractedAttIndex == 12) or (extractedAttIndex == 0):
				self.unpackedInfo.append('FIN Flag: ' + '.... .... ...' + format(flag_FIN, '01b'))
			if (extractedAttIndex == 13) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Window Size: ' + str(tcp_winsize) + ' bytes')
			if (extractedAttIndex == 14) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Urgent Pointer: ' + str(tcpUrgentPointer))
			if (extractedAttIndex == 15) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Checksum: ' + format(tcpChecksum, '#04X'))
		
			# Separator	
			self.unpackedInfo.append('\n----------------------------------------')	
		else:
			if (extractedAttIndex == 1):
				return str(tcp_src_port)
			if (extractedAttIndex == 2):
				return str(tcp_dest_port)
			if (extractedAttIndex == 3):
				return str(tcp_seq)
			if (extractedAttIndex == 4):
				return str(tcp_ack)
			if (extractedAttIndex == 5):
				return str(tcpDataOffset)
			if (extractedAttIndex == 6):
				return format(tcpReserved, '03b')
			if (extractedAttIndex == 7):
				return format(flag_URG, '01b')
			if (extractedAttIndex == 8):
				return format(flag_ACK, '01b')
			if (extractedAttIndex == 9):
				return format(flag_PSH, '01b')
			if (extractedAttIndex == 10):
				return format(flag_RST, '01b')
			if (extractedAttIndex == 11):
				return format(flag_SYN, '01b')
			if (extractedAttIndex == 12):
				return format(flag_FIN, '01b')
			if (extractedAttIndex == 13):
				return str(tcp_winsize)
			if (extractedAttIndex == 14):
				return str(tcpUrgentPointer)
			if (extractedAttIndex == 15):
				return format(tcpChecksum, '#04X')