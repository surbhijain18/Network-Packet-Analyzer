import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

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
		
		# Set the recieved user selected filtered protocol index and user selected extracted att index to local variables.
		self.filteredProtocolIndex = filteredProtocolIndex
		self.extractedAttIndex = extractedAttIndex
		
		# Special lists used for calculations.
		self.lengthList = []
				
		# Special lists used to hold unpacked info and calculation results.
		self.unpackedInfo = []
		self.calculationList = []
		
		self.packetCount = 0

		# Check the OS the application is running on.
		self.os = platform.system()
		self.linux = 'Linux'
		self.windows = 'Windows'
		
		try:
			# If Linux, set up the raw socket the Linux way.
			# If Windows, set up the raw socket the Windows way.
			if self.os == self.linux:
				# Create the raw socket.
				self.sock = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
			elif self.os == self.windows:
				# The public network interface.
				HOST = socket.gethostbyname(socket.gethostname())

				# Create a raw socket and bind it to the public interface.
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
		# Check to see if sniffing is false (currently not sniffing).
		# If true, create a thread to perform the sniffing.
		if self.sniffKey == False:
			# Set sniffing to 0 (currently sniffing).
			# Set the sniffing label to sniffing in order to notify user.
			self.sniffKey = True
			self.sniffingLabel.setText('Sniffing...')
			
			# Save the user selected filtered protocol index.
			# Save the user selected extracted attribute index.
			filteredProtocolIndex = self.protocolComboBox.currentIndex()
			extractedAttIndex = self.attComboBox.currentIndex()
			
			# Create a sniff thread to perform sniffing and create different signals for all the data sent back and forth.
			# Data sent back and forth:
			#	Unpack packet info
			#	max diameter and max packet length
			#	avg diameter and avg packet length
			self.sniffThread = SniffThread(filteredProtocolIndex, extractedAttIndex)
			self.connect(self.sniffThread, QtCore.SIGNAL('updatePackets(QString)'), self.updatePackets)
			self.connect(self.sniffThread, QtCore.SIGNAL('updateMaxPacketLength(QString)'), self.updateMaxPacketLength)
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
			# Set the sniffing label to sniffing in order to notify user.
			self.sniffKey = False
			self.sniffingLabel.setText('Not sniffing.')
			
			# Call the stop function from the sniff thread.
			self.sniffThread.stop()
			self.startButton.setEnabled(True)
			self.stopButton.setEnabled(False)
		
	def updatePackets(self, unpackedInfo):
		# Append the packet edit text with the unpacked info.
		self.packetEditText.append(unpackedInfo)
		
		
	def updateMaxPacketLength(self, maxLength):
		# Append the max length label with the max length.
		self.maxLengthLabel.setText(maxLength)
		
	def updateAvgPacketLength(self, avgLength):
		# Append the avg length label with the avg length.
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
				
		# Check the OS the application is running on.
		self.os = platform.system()
		self.linux = 'Linux'
		self.windows = 'Windows'	
		
		# Simple key that lets the application know whether it is sniffing.
		# False = not sniffing.
		# True = sniffing.
		self.sniffKey = False
		
		# Initilize the GUI.
		self.initGUI()

def main():
	# Find the OS the application is running on.
	os = platform.system()
	linux = 'Linux'
	windows = 'Windows'	

	# Check if the application is running under a supported OS.
	# If true, run the rest of the application.
	# If no true, notify the user their OS is not supported.
	if (os == linux) or (os == windows):
		app = QtGui.QApplication(sys.argv)
		gui = Gui()
		sys.exit(app.exec_())
	else:
		print('The OS you are running is not supported.')

if __name__ == '__main__':
    main()
