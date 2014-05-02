#!/usr/bin/env python

"""
Provides an interface to USB Printer Class devices.
"""

import usb
import types

PRINTER_CLASS			= 0x07
PRINTER_SUBCLASS		= 0x01
UNIDIRECTIONAL_PROTOCOL	= 0x01
BIDIRECTIONAL_PROTOCOL	= 0x02
IEEE1284_4_PROTOCOL		= 0x03
VENDOR_PROTOCOL			= 0xff

class Printer:
	def __init__(self, device, configuration, interface):
		"""
		__init__(device, configuration, interface) -> None

		Initialize the device.
			device: printer usb.Device object.
			configuration: printer usb.Configuration object of the Device or configuration number.
			interface: printer usb.Interface object representing the
			           interface and altenate setting.
			
		"""
		if PRINTER_CLASS != interface.interfaceClass:
			raise TypeError, "Wrong interface class"

		self.__devhandle = device.open()
		self.__devhandle.setConfiguration(configuration)
		self.__devhandle.claimInterface(interface)
		self.__devhandle.setAltInterface(interface)

		self.__intf = interface.interfaceNumber
		self.__alt	= interface.alternateSetting

		self.__conf = (type(configuration) == types.IntType \
						or type(configuration) == types.LongType) and \
						configuration or \
						configuration.value

		# initialize members
		# TODO: automatic endpoints detection
		self.__bulkout	= 1
		self.__bulkin	= 0x82
	
	def __del__(self):
		try:
			self.__devhandle.releaseInterface(self.__intf)
			del self.__devhandle
		except:
			pass

	def getDeviceID(self, maxlen, timeout = 100):
		"""
		getDeviceID(maxlen, timeout = 100) -> device_id

		Get the device capabilities information.
			maxlen: maxlength of the buffer.
			timeout: operation timeout.
		"""
		return self.__devhandle.controlMsg(requestType = 0xa1,
										   request = 0,
										   value = self.__conf - 1,
										   index = self.__alt + (self.__intf << 8),
										   buffer = maxlen,
										   timeout = timeout)
	
	def getPortStatus(self, timeout = 100):
		"""
		getPortStatus(timeout = 100) -> status

		Get the port status.
			timeout: operation timeout.
		"""
		return self.__devhandle.controlMsg(requestType = 0xa1,
										   request = 1,
										   value = 0,
										   index = self.__intf,
										   buffer = 1,
										   timeout = timeout)[0]

	def softReset(self, timeout = 100):
		"""
		softReset(timeout = 100) -> None

		Request flushes all buffers and resets the Bulk OUT
		and Bulk IN pipes to their default states.
			timeout: the operation timeout.
		"""
		self.__devhandle.controlMsg(requestType = 0x21,
								   	request = 2,
								   	value = 0,
								   	index = self.__intf,
								   	buffer = 0)

	
	def write(self, buffer, timeout = 100):
		"""
		write(buffer, timeout = 100) -> written

		Write data to printer.
			buffer: data buffer.
			timeout: operation timeout.
		"""
		return self.__devhandle.bulkWrite(self.__bulkout,
										  buffer,
										  timeout)

	def read(self, numbytes, timeout = 100):
		"""
		read(numbytes, timeout = 100) -> data

		Read data from printer.
			numbytes: number of bytes to read.
			timeout: operation timeout.
		"""
		return self.__devhandle.bulkRead(self.__bulkin,
										 numbytes,
										 timeout)


