import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

def stop(self):
		# Disable promiscuous mode under Windows.
		if self.os == self.windows:
			self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
  
		# Close the socket.
		self.sock.close()
			
		# Terminate the thread.
		self.terminate()