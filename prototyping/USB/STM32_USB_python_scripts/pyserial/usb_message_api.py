#! /usr/bin/python
#
# Sends a user-entered string to the specified serial port and reads a string
# returned from the serial port.  The returned string is expected to be
# terminated by a newline ('\n') character.  The script prints the returned
# string.

# Modules imported:
from datetime import datetime
import getopt
import glob
import os
import re
import serial
import sys
import time

# Globals:
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
        if msgType == 'q':
            print 'bye bye'
            sys.exit( 0 )
        else:
            msgOffset = raw_input ( 'Enter message offset: ' )
            if msgType == 'w':
                userString = raw_input ( 'Enter a string: ' )
                msgString = msgType + chr(len(userString)) + chr(int(msgOffset)) + userString
                serialDevice.writeSerial ( msgString )
            elif msgType == 'r':
                readLength = raw_input ( 'Number of characters to read: ' )
                msgString = msgType + chr(int(readLength)) + chr(int(msgOffset))
                serialDevice.writeSerial ( msgString )
                returnedString = serialDevice.readSerial ( int(readLength) )
                print "Serial reply: " + returnedString


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
    def readSerial ( self, length ):
        string = ''
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


