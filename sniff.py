import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

def sniff(self, filteredProtocolIndex, extractedAttIndex):
		# Sniff packets. Will loop until user presses Ctrl+c.
		while True:
			# Recieve the packets in the network.
			# Packet will be a tuple, use the first element in the tuple.
			packet = self.sock.recvfrom(65565)
			packet = packet[0]				
			
			# Delete the data inside the lists containing unpacked info and calculations.
			# This is needed as these lists can contain data about a current packet being sniffed.
			del self.unpackedInfo[:]
			
			# Filter and extract packet info using packet, filteredProtocolIndex and extractedAttIndex.
			# Save the packet for other operations.
			filterAndExtract = self.filterAndExtract(packet, filteredProtocolIndex, extractedAttIndex)

			# Check if the user selected filtered protocol index is supported.
			# If true, send the main thread the unpacked info.
			if filterAndExtract == True:					
				prepareCalculationData = self.prepareCalculationData(packet)

				if prepareCalculationData == True:						
					self.calculateData()

					# To reduce thread stalls, update the GUI every 5 packets.
					if (self.packetCount % 5 == 0):	
						for i in range(len(self.unpackedInfo)):
							self.emit(QtCore.SIGNAL('updatePackets(QString)'), self.unpackedInfo[i])
						
						for i in range(5):				
							index = i * 4
							
							self.emit(QtCore.SIGNAL('updateMaxDiameter(QString)'), self.calculationList[index])
							self.emit(QtCore.SIGNAL('updateMaxPacketLength(QString)'), self.calculationList[index + 1])
							self.emit(QtCore.SIGNAL('updateAvgDiameter(QString)'), self.calculationList[index + 2])
							self.emit(QtCore.SIGNAL('updateAvgPacketLength(QString)'), self.calculationList[index + 3])
							
						del self.calculationList[:]