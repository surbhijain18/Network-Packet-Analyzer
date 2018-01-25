import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

def initGUI(self):
		# Establish the attribute combo box content for each protocol's attributes.
		if self.os == self.windows:
			protocols = ['All', 'ICMP', 'TCP', 'UDP']
		
		# Set the window title and size.
		self.setWindowTitle('PACKET ANALYZER')
		self.resize(600, 800)

		# Prepare the grid layout.
		grid = QtGui.QGridLayout()
		grid.setSpacing(10)

		# Create the start and stop button.
		# These start and stop the sniffing.
		self.startButton = QtGui.QPushButton('Start Analyzing')
		self.stopButton = QtGui.QPushButton('Stop')
		self.startButton.setEnabled(True)
		self.stopButton.setEnabled(False)
		
		# Create the protocol label, protocol combobox, and insert the protocols in the protocol combobox.
		# These let the user select a protocol.
		protocolLabel = QtGui.QLabel('Select a Protocol:')
		self.protocolComboBox = QtGui.QComboBox(self)
		self.protocolComboBox.insertItems(len(protocols), protocols)

		# Create the attribute label, attribute combobox, and run updateAtts.
		# updateAtts inserts the selected protocol's corresponding attributes to the attribute combobox.
		# These let the user select an attribute.
		attLabel = QtGui.QLabel('Select the attributes:')
		self.attComboBox = QtGui.QComboBox(self)
		self.updateAtts('All')

		# Create the packet label and the packet edit text label.
		# These display the packet information to the user.
		packetLabel = QtGui.QLabel('Packets:')
		self.packetEditText = QtGui.QTextEdit()
		self.packetEditText.setFontFamily('monospace');
		self.packetEditText.setReadOnly(True)
		
		# Create the calculation label, the max diameter, max length label, avg diameter, and avg length label.
		# These let the user know important calculations about the network.
		calculationLabel = QtGui.QLabel('Calculations:')
		self.maxDiameterLabel = QtGui.QLabel('Max Diameter: ---- hops')
		self.maxLengthLabel = QtGui.QLabel('Max Packet Length: ---- bytes')
		self.avgDiameterLabel = QtGui.QLabel('Avg Diameter: ---- hops')
		self.avgLengthLabel = QtGui.QLabel('Avg Packet Length: ---- bytes')
		
		# Create the sniffing label.
		# This lets the user know what the application is doing.
		self.sniffingLabel = QtGui.QLabel('Not analyzing. Press \'Start Analyzing\' to start analyzing packets.')

		# Add the various buttons, labels, comboboxes, and edit texts to the grid.
		grid.addWidget(self.startButton, 1, 0, 1, 2)
		grid.addWidget(self.stopButton, 2, 0, 1, 2)

		grid.addWidget(protocolLabel, 3, 0, 1, 2)
		grid.addWidget(self.protocolComboBox, 4, 0, 1, 2)
		
		grid.addWidget(attLabel, 5, 0, 1, 2)
		grid.addWidget(self.attComboBox, 6, 0, 1, 2)

		grid.addWidget(packetLabel, 7, 0)
		grid.addWidget(self.packetEditText, 8, 0, 15, 1)
		
		grid.addWidget(calculationLabel, 7, 1)
		grid.addWidget(self.maxLengthLabel, 8, 1)
		
		grid.addWidget(self.avgLengthLabel, 9, 1)
		
		grid.addWidget(self.sniffingLabel, 24, 0, 1, 2)
		
		# Prepare the start button, stop button, and protocol combo box signals.
		# The protocol combo box signal calls updateAtts, which updates the attribute combobox with corresponding attributes. 
		self.startButton.clicked.connect(self.startSniff)
		self.stopButton.clicked.connect(self.stopSniff)
		self.connect(self.protocolComboBox, QtCore.SIGNAL('activated(QString)'), self.updateAtts)
		self.connect(self.attComboBox, QtCore.SIGNAL('activated(QString)'), self.newAtt)

		# Set the layout and show the window.
		self.setLayout(grid) 
		self.show()