import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

def updateAtts(self, protocol):	
		# Establish the attribute combo box content for each protocol's attributes.
		allAttributes = ['All']
		ethAttributes = ['Destination Address', 'Source Address', 'EtherType']
		
		ipAttributes = ['Version', 'Header Length', 'Total Length', 'Identification', 'Flags', 'Fragment Offset', 'Time to Live', 'Protocol', 'Header Checksum', 'Source Address', 'Destination Address']
		
		icmpAttributes = ['Type', 'Code', 'Checksum', 'Identifier (If available)', 'Sequence Number (If available)']
		
		tcpAttributes = ['Source Port', 'Destination Port', 'Sequence Number', 'Acknowledgment Number', 'Data Offset', 'Reserved','URG Flag', 'ACK Flag', 'PSH Flag', 'RST Flag', 'SYN Flag', 'FIN Flag', 'Window Size', 'Urgent Pointer', 'Checksum']
		udpAttributes = ['Source Port', 'Destination Port', 'Length', 'Checksum']
		
		# Clear the previous attribute combo box content.
		self.attComboBox.clear()
		
		if self.os == self.windows:
			attributes = allAttributes + ipAttributes
			
			if protocol == 'ICMP':
				attributes += icmpAttributes
			elif protocol == 'TCP':
				attributes += tcpAttributes
			elif protocol == 'UDP':
				attributes += udpAttributes
				
			self.attComboBox.insertItems(len(attributes), attributes)
			
		# Check if the application is sniffing.
		# If true, stop the sniffing.
		if self.sniffKey == True:
			self.stopSniff()
			self.startButton.setEnabled(True)
			self.stopButton.setEnabled(False)