#!/usr/bin/env python
##########################################################################################################
#
# Python implementation of the usb_rawhid host-side functions for the Teensy (and other raw HID devices).
# Requires the libhid library.
#
# Craig Heffner
# 21-July-2011
# http://www.devttys0.com
#
##########################################################################################################

import sys
try:
	from hid import *
except Exception, e:
	print e
	print "Please install libhid: http://libhid.alioth.debian.org/"
	sys.exit(1)

class RawHID:

	READ_ENDPOINT = 0x81
	WRITE_ENDPOINT = 0x02
	INTERFACE = 0

	PACKET_LEN = 64
	TIMEOUT = 1000 # milliseconds
	CONNECT_RETRIES = 3

	def __init__(self, verbose=False):
		self.verbose = verbose
		self.hid = None
		return None

	# Initialize libhid and connect to USB device.
	#
	# @vid - Vendor ID of the USB device.
	# @pid - Product ID of the USB device.
	#
	# Returns True on success.
	# Returns False on failure.
	def open(self, vid, pid):
		retval = False

		hid_ret = hid_init()
		if hid_ret == HID_RET_SUCCESS:
			self.hid = hid_new_HIDInterface()
			match = HIDInterfaceMatcher()
			match.vendor_id = vid
			match.product_id = pid
		
			hid_ret = hid_force_open(self.hid, self.INTERFACE, match, self.CONNECT_RETRIES)
			if hid_ret == HID_RET_SUCCESS:
				retval = True
				if self.verbose:
					hid_write_identification(sys.stderr, self.hid)

			elif self.verbose:
				sys.stderr.write("hid_force_open() failed with error code: %d\n" % hid_ret);
		elif self.verbose:
			sys.stderr.write("hid_init() failed with error code: %d\n" % hid_ret)

		return retval

	# Close HID connection and clean up.
	#
	# Returns True on success.
	# Returns False on failure.
	def close(self):
		retval = False

		if hid_close(self.hid) == HID_RET_SUCCESS:
			retval = True

		hid_cleanup()

		return retval

	# Send a USB packet to the connected USB device.
	#
	# @packet  - Data, in string format, to send to the USB device.
	# @timeout - Read timeout, in milliseconds. Defaults to TIMEOUT.
	#
	# Returns True on success.
	# Returns False on failure.
	def send(self, packet, timeout=TIMEOUT):
		retval = False

		hid_ret = hid_interrupt_write(self.hid, self.WRITE_ENDPOINT, packet, timeout)

		if hid_ret == HID_RET_SUCCESS:
			retval = True
		elif self.verbose:
			sys.stderr.write("hid_interrupt_write() failed with error code: %d\n" % hid_ret)

		return retval

	# Read data from the connected USB device.
	#
	# @len     - Number of bytes to read. Defaults to PACKET_LEN.
	# @timeout - Read timeout, in milliseconds. Defaults to TIMEOUT.
	#
	# Returns the received bytes on success.
	# Returns None on failure.
	def recv(self, plen=PACKET_LEN, timeout=TIMEOUT):

		hid_ret, packet = hid_interrupt_read(self.hid, self.READ_ENDPOINT, plen, timeout)

		if hid_ret != HID_RET_SUCCESS:
			packet = None
		elif self.verbose:
			sys.stderr.write("hid_interrupt_read() failed with error code: %d\n" % hid_ret)

		return packet



# Example code to interface with the Teensy Raw HID Example firmware
if __name__ == "__main__":

	BYTES_PER_LINE = 16

	# Teensy vendor ID and product ID
	vid = 0x16C0
	pid = 0x0480

	hid = RawHID()
	
	# Open a connection to the Teensy
	if hid.open(vid, pid):

		print "\nConnected to Teensy..."

		# Turn on the Teensy pins D0-D3	
		hid.send("\x0F")
		
		try:
			# Infinite loop to read data from the Teensy
			while True:
				data = hid.recv(timeout=50)
				if data is not None:
					size = len(data)
					print ""
					print "recv %d bytes:" % size
				
					# Print out each hex byte, 16 bytes per line
					for i in range(0, (size / BYTES_PER_LINE)):
						for j in range(0, BYTES_PER_LINE):
							print "%.2X" % ord(data[(i*BYTES_PER_LINE)+j]),
						print ""
		except KeyboardInterrupt:
			pass

		# Close the Teensy connection
		hid.close()

		print "\nDisconnected from Teensy.\n"
	else:
		print "Failed to open HID device %X:%X" % (vid, pid)

