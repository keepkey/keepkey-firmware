#! /usr/bin/python
#
# This script connects to a specified USB serial device and enables you to
# write and read characters to/from a message buffer on the device.  This
# script supports writing and reading up to 256 characters to/from the device
# in one request.
#
# Since we assume that a USB communication class device can transfer only
# 64-bytes in each USB packet, this script breaks up longer messages into
# multiple packets for transfer.  Each packet sent to the remote device begins
# with a three-byte preamble which specifies the message type (read/write),
# the message length (up to 32 bytes), and an offset into the message buffer
# on the remote device specifying where in the buffer the read or write is to
# begin.  When data is read from the remote device, each USB packet includes
# a 1-byte preamble which indicates the number of bytes of data actually sent
# (up to 32 per packet).  Note that when reading from the device, the number
# of bytes actually returned may be less than the number requested (i.e. if
# the device's message buffer has been exhausted).
#
# The payload for each USB packet consists of up to 32 data bytes.  Thus, to
# transfer 256 bytes requires eight USB packets.  This script breaks longer
# read or write requests into as many packets as needed to complete the data
# transfer.

# Modules imported:
import getopt
import os
import serial
import sys

# Globals:
MAX_MESSAGE_LENGTH = 256
MAX_PAYLOAD_LENGTH = 32
PREAMBLE_LENGTH = 3
serialDevice = ''

# Usage summary:
def usage():

    print "Usage: python " + os.path.basename( sys.argv[0] ),
    print "-c comPort"
    print "  -c Specify serial port (e.g. com1)"
    print "  -? Help: print this usage message"


# Main function:
def main():

    # Globals modified:
    global serialDevice

    # Scan for options.
    serialInterface = ''
    try:
        opts, args = getopt.getopt( sys.argv[1:], "c:h?" )
    except getopt.GetoptError, err:
        # print help information and exit:
        print str( err ) # will print something like "option -a not recognized"
        sys.exit( 2 )
    for o, a in opts:
        if o == "-c":
            serialInterface = a
        elif o in ("-h","-?"):
            usage()
            sys.exit( 0 )
        else:
            assert False, "unhandled option"
    if serialInterface == '':
        usage()
        sys.exit( 1 )
    
    # Initialize serial device object.
    serialDevice = UsbSerialDevice ( serialInterface )

    # Main menu:
    print 
    while 1:
        returnedString = ""
        msgType = raw_input ( 'Enter message type (w/r/q): ' )

        # If quiting:
        if msgType == 'q':
            print 'bye bye'
            sys.exit( 0 )
        else:

            # If writing to device:
            if msgType == 'w':

                # Get user string.
                userString = raw_input ( 'Enter a string: ' )
                userCharsToWrite = len(userString)
                if MAX_MESSAGE_LENGTH < userCharsToWrite:
                    userString = userString[:MAX_MESSAGE_LENGTH]
                    userCharsToWrite = len(userString)
                msgOffset = 0
                beginSlice = 0
                endSlice = MAX_PAYLOAD_LENGTH 

                # While more characters to write:
                while userCharsToWrite:
                    if MAX_PAYLOAD_LENGTH < userCharsToWrite:
                        msgString = msgType + chr(MAX_PAYLOAD_LENGTH) + chr(msgOffset) + userString[beginSlice:endSlice]
                        userCharsToWrite -= MAX_PAYLOAD_LENGTH
                        msgOffset        += MAX_PAYLOAD_LENGTH
                        beginSlice       += MAX_PAYLOAD_LENGTH
                        endSlice         += MAX_PAYLOAD_LENGTH
                    else:
                        msgString = msgType + chr(userCharsToWrite) + chr(msgOffset) + userString[beginSlice:]
                        userCharsToWrite = 0

                    # Send the message string.
                    serialDevice.writeSerial ( msgString )

            # Else if reading from device:
            elif msgType == 'r':

                # Get number of characters to read.
                userCharsToReadString = raw_input ( 'Number of characters to read: ' )
                userCharsToRead = int(userCharsToReadString)
                if MAX_MESSAGE_LENGTH < userCharsToRead:
                    userCharsToRead = MAX_MESSAGE_LENGTH
                returnedString = ''
                msgOffset = 0

                # While more characters to read:
                while int(userCharsToRead):
                    if MAX_PAYLOAD_LENGTH < userCharsToRead:
                        msgString = msgType + chr(MAX_PAYLOAD_LENGTH) + chr(msgOffset)
                        serialDevice.writeSerial ( msgString )
                        returnedString  += serialDevice.readSerial() 
                        userCharsToRead -= MAX_PAYLOAD_LENGTH
                        msgOffset       += MAX_PAYLOAD_LENGTH
                    else:
                        msgString = msgType + chr(int(userCharsToRead)) + chr(msgOffset)
                        serialDevice.writeSerial ( msgString )
                        returnedString  += serialDevice.readSerial() 
                        userCharsToRead = 0
                print "Device reply: " + returnedString


# UsbSerialDevice class:
class UsbSerialDevice ( object ):

    serialInterfaceBaud = 115200
    serialInterface = ''

    # Initialization:
    def __init__ ( self, serialInterfacePort ):
        self.serialInterface = serial.Serial( serialInterfacePort, int(self.serialInterfaceBaud) )

    # Write serial method:
    def writeSerial ( self, string ):
        self.serialInterface.flushInput()
        self.serialInterface.write( string + '\n' )

    # Read serial method:
    #
    # This method assumes that the first byte sent from the remote device
    # specifies the number of data bytes to follow.
    #
    def readSerial ( self ):
        string = ''
        num_bytes = self.serialInterface.read()
        length = ord ( num_bytes )
        while length:
            char = self.serialInterface.read()
            string += char
            length = length - 1
        return string


# Run main() function when this module is executed directly:
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print "Terminated by user"
        sys.exit( 3 )


