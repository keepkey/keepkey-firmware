#!/usr/bin/env python
#
# Enumerate usb devices

import usb

busses = usb.busses()

for bus in busses:
	devices = bus.devices
	for dev in devices:
		print "  idVendor: %d (0x%04x)" % (dev.idVendor, dev.idVendor)
		print "  idProduct: %d (0x%04x)" % (dev.idProduct, dev.idProduct)
		for config in dev.configurations:
			print "  Configuration:", config.value
			for intf in config.interfaces:
				print "    Interface:",intf[0].interfaceNumber
				for alt in intf:
					print "    Alternate Setting:",alt.alternateSetting
					print "      Interface class:",alt.interfaceClass
					for ep in alt.endpoints:
						print "      Endpoint:",hex(ep.address)
						print "        Type:",ep.type
						print "        Max packet size:",ep.maxPacketSize
