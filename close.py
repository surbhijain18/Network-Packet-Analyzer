import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

def close():
		try:
			# Exit the application.
			print('Goodbye.')
			time.sleep(1)
			sys.exit()
		except KeyboardInterrupt:
			sys.exit()