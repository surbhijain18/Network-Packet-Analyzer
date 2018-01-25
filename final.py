import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore				#PyQt is a Python binding of the cross-platform GUI toolkit Qt. PyQt modules rely on module QtCore.
											#The QtGui module extends QtCore with GUI functionality.

from ethernet import *
from ip import *
from icmp import *
from tcp import *
from udp import *
from findProtocol import *
from extractAllAtt import *
from filterAndExtract import *
from prepareCalculationData import *
from sniff import *
from findPacketCount import *
from findMaxDiameter import *
from findMaxPacketLength import *
from findAvgDiameter import *
from findAvgPacketLength import *
from calculateData import *
from stop import *
from close import *
from updateAtts import *
from initGUI import *



class SniffThread(QtCore.QThread):
	def eth(self, packet, extractedAttIndex, printKey):
		return eth(self, packet, extractedAttIndex, printKey)

	def ip(self, packet, extractedAttIndex, printKey):
		return ip(self, packet, extractedAttIndex, printKey)
				
	def icmp(self, packet, extractedAttIndex, printKey):
		return icmp(self, packet, extractedAttIndex, printKey)
		
	def tcp(self, packet, extractedAttIndex, printKey):
		return tcp(self, packet, extractedAttIndex, printKey)

	def udp(self, packet, extractedAttIndex, printKey):
		return udp(self, packet, extractedAttIndex, printKey)
				
	def findProtocol(self, packet):
		return findProtocol(self, packet)
		
	def extractAllAtt(self, packet):
		return extractAllAtt(self, packet)

	def filterAndExtract(self, packet, filteredProtocolIndex, extractedAttIndex):
		return filterAndExtract(self, packet, filteredProtocolIndex, extractedAttIndex)
				
	def findMaxDiameter(self):
		return findMaxDiameter(self)
		
	def findAvgDiameter(self):
		return findAvgDiameter(self)

	def findPacketCount(self):
		return findPacketCount(self)

	def findMaxPacketLength(self):
		return findMaxPacketLength(self)

	def findAvgPacketLength(self):
		return findAvgPacketLength(self)

	def prepareCalculationData(self, packet):
		return prepareCalculationData(self, packet)
				
	def calculateData(self):
		return calculateData(self)
			
	def stop(self):
		return stop(self)
		
	def close():
		return close()

	def sniff(self, filteredProtocolIndex, extractedAttIndex):
		return sniff(self, filteredProtocolIndex, extractedAttIndex)
						
	def __init__(self, filteredProtocolIndex, extractedAttIndex):
		QtCore.QThread.__init__(self)
		
		
		self.filteredProtocolIndex = filteredProtocolIndex		#user selected protocol set to local variables.
		self.extractedAttIndex = extractedAttIndex				#user selected attribute index
		
		# lists used for calculations.
		self.lengthList = []
		self.diameterList = []
		
		# Special lists used to hold unpacked info and calculation results.
		self.unpackedInfo = []
		self.calculationList = []
		
		self.packetCount = 0

		self.os = platform.system()
		
		self.windows = 'Windows'
		
		try:
			if self.os == self.windows:
				HOST = socket.gethostbyname(socket.gethostname())
				# Create a raw socket and binding it
				self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
				self.sock.bind((HOST, 0))

				# Include IP headers
				self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

				# Receive all packages.
				self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
		except socket.error, msg:
			print('Socket could not be created. \nError code: ' + str(msg[0]) + '\nMessage: ' + msg[1])
			close()

	def __del__(self):
		self.wait()

	def run(self):
		self.sniff(self.filteredProtocolIndex, self.extractedAttIndex)

class Gui(QtGui.QWidget):	
	def startSniff(self):
		# False => currently not analyzing
		# If true, create a thread to perform the analyzing.
		if self.sniffKey == False:
			# Set analyzing to 0 (currently analyzing).
			self.sniffKey = True
			self.sniffingLabel.setText('Analyzing...')
			
		
			filteredProtocolIndex = self.protocolComboBox.currentIndex()
			extractedAttIndex = self.attComboBox.currentIndex()		
			#user selected protocol from drop down
			#user selected attributes index from drop down
			
			# Create a sniff thread to perform analyzing
			#	max diameter and max pkt length
			#	avg diameter and avg pkt length
			self.sniffThread = SniffThread(filteredProtocolIndex, extractedAttIndex)
			self.connect(self.sniffThread, QtCore.SIGNAL('updatePackets(QString)'), self.updatePackets)
			self.connect(self.sniffThread, QtCore.SIGNAL('updateMaxDiameter(QString)'), self.updateMaxDiameter)
			self.connect(self.sniffThread, QtCore.SIGNAL('updateMaxPacketLength(QString)'), self.updateMaxPacketLength)
			self.connect(self.sniffThread, QtCore.SIGNAL('updateAvgDiameter(QString)'), self.updateAvgDiameter)
			self.connect(self.sniffThread, QtCore.SIGNAL('updateAvgPacketLength(QString)'), self.updateAvgPacketLength)

			# Start the sniff thread.
			self.sniffThread.start()
			self.startButton.setEnabled(False)
			self.stopButton.setEnabled(True)
		
	def stopSniff(self):
		# Check to see if sniffing is 1 (currently sniffing).
		# If true, stop the sniffing.
		if self.sniffKey == True:
			# Set sniffing to 0 (currently sniffing).
			
			self.sniffKey = False
			self.sniffingLabel.setText('Not sniffing.')
			
			# Call the stop function from the sniff thread.
			self.sniffThread.stop()
			self.startButton.setEnabled(True)
			self.stopButton.setEnabled(False)
		
	def updatePackets(self, unpackedInfo):
		self.packetEditText.append(unpackedInfo)
		
	def updateMaxDiameter(self, maxDiameter):
		self.maxDiameterLabel.setText(maxDiameter)
		
	def updateAvgDiameter(self, avgDiameter):
		self.avgDiameterLabel.setText(avgDiameter)
		
	def updateMaxPacketLength(self, maxLength):
		self.maxLengthLabel.setText(maxLength)
		
	def updateAvgPacketLength(self, avgLength):
		self.avgLengthLabel.setText(avgLength)
			
	def updateAtts(self, protocol):	
		return updateAtts(self, protocol)

	def newAtt(self):
		# Check if the application is sniffing.
		# If true, stop the sniffing.
		if self.sniffKey == True:
			self.stopSniff()
			self.startButton.setEnabled(True)
			self.stopButton.setEnabled(False)

	def initGUI(self):
		return initGUI(self)

	def __init__(self):
		super(Gui, self).__init__()
				
		# Check the OS 
		self.os = platform.system()
		self.windows = 'Windows'	
		
		# Simple key that lets the application know whether it is sniffing.
		# False = not sniffing.
		# True = sniffing.
		self.sniffKey = False
		
		# Initilize the GUI.
		self.initGUI()

def main():
	
	os = platform.system()
	windows = 'Windows'	
	if (os == windows):
		app = QtGui.QApplication(sys.argv)
		gui = Gui()
		sys.exit(app.exec_())
	else:
		print('The OS you are running is not supported.')

if __name__ == '__main__':
    main()
