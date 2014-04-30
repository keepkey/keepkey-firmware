#!/usr/bin/env python
#
# This script talks to an STM3210E-EVAL board running USB HID firmware from
# the STMicroelectronics USB-FS-Device development kit (UM0424).
#
# On Linux, you would typically run this script like so:
#
#   sudo python stm32eval-blinky.py
#
# When an STM3210E-EVAL board running the UM0424 firmware is connected to
# the USB interface, running this script will search for the eval board and
# connect via USB.  Once this is done, if you press the Key and Tamper buttons
# on the eval board, the button presses will be conveyed to the host via USB
# and this script will use the button presses to control LED1 and LED4 on the
# eval board, also via USB.
#
# This script was written for pyusb v0.4.  If you try to run it with pyusb
# v1.0 it should run okay in legacy mode. (I haven't actually tried this.)
#
# lowell@carbondesign.com

import usb

HID_DEMO_VID = 0x0483
HID_DEMO_PID = 0x5750

# Assume first instance of each of these objects is the one to use.
mydev = None
mydevHandle = None
myconfig = None
myintf = None
myInEP = None
myOutEP = None

# Search for HID DEMO device.
busses = usb.busses()
for bus in busses:
	devices = bus.devices
	for dev in devices:
		if dev.idVendor == HID_DEMO_VID and dev.idProduct == HID_DEMO_PID:
			if mydev == None:
				mydev = dev

# If device found,
if mydev != None:
	print 
	print "Found my device!"
	print "  idVendor:  0x%04x" % (mydev.idVendor)
	print "  idProduct: 0x%04x" % (mydev.idProduct)

	# Enumerate device configs, interfaces, endpoints.
	for config in mydev.configurations:
		if myconfig == None:
			# Save first config found.
			myconfig = config
		print "   Configuration:", config.value

		for intf in config.interfaces:
			if myintf == None:
				# Save first interface found.
				myintf = intf[0]
			print "    Interface:", myintf.interfaceNumber
			for alt in intf:
				print "    Alternate Setting:", alt.alternateSetting
				print "      Interface class:", alt.interfaceClass

				for ep in alt.endpoints:
					if ep.address & usb.ENDPOINT_IN:
						myInEP  = ep
					else:
						myOutEP = ep
					print "      Endpoint:", hex(ep.address)
					print "        Type:", ep.type
					print "        Max packet size:", ep.maxPacketSize
	print 


	# Access the device.
	mydevHandle = mydev.open()
	try:
		mydevHandle.detachKernelDriver(myintf)
	except usb.USBError:
		# Kernel driver is already detached, probably.
		pass
	mydevHandle.setConfiguration(config)
	mydevHandle.claimInterface(myintf)
	mydevHandle.setAltInterface(myintf)

	# Read IN endpoint repeatedly.
	while 1:
		try:
			inData = mydevHandle.interruptRead ( myInEP.address, 2, 100)
			print "Input data:", inData

			# Translate button ID to LED ID.
			if inData[0] == 5:
				ledId = 1
			elif inData[0] == 6:
				ledId = 4

			# Translate button state to LED state.
			if inData[1] == 0:
			    ledState = 0
			elif inData[1] == 1:
			    ledState = 1

			# Write to OUT endpoint.
			outData = (ledId, ledState)
			print "Output data:", outData
			mydevHandle.interruptWrite ( myOutEP.address, outData, 100 )

		except KeyboardInterrupt: # TBD: Why doesn't this work?
			print "Terminated by user"
			sys.exit( 3 )
		except:
			pass

	# Cleanup
	try:
		mydevHandle.releaseInterface(myintf)
		del mydevHandle
	except:
		pass

else:
	print "Rats. Didn't find my device."

# Run main() function when this module is executed directly.
if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		print "Terminated by user"
		sys.exit( 3 )

