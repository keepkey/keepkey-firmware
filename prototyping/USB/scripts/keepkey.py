#!/usr/bin/env python
#
# Enumerate USB devices to locate the STM3210E-EVAL board running modified
# Virtual Comport Loopback firmware.  Then run our serial buffer script to
# read and write the device.
#
# lowell@carbondesign.com

# Modules imported:
import time
import usb
import serial_buffer_expanded

# Globals:
MY_DEVICE_VID = 0x0483
MY_DEVICE_PID = 0x5740

# Assume first instance of this object is the one to use.
myDevice = None
firstTime = True

# While device not detected:
while myDevice == None:

    # Search for my device.
    busses = usb.busses()
    for bus in busses:
        devices = bus.devices
        for dev in devices:
            if dev.idVendor == MY_DEVICE_VID and dev.idProduct == MY_DEVICE_PID:
                if myDevice == None:
                    myDevice = dev

    # If not found:
    if myDevice == None:
        if firstTime:
            print "Please connect the device via USB."
            firstTime = False
        time.sleep(1)

# Connect to the device for read/write.
serial_buffer_expanded.main()

