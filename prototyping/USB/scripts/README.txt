These python scripts can be used to interact with an STM3210E-EVAL development
board running USB virtual COM port firmware.  (See the other USB prototyping
folders here for the firmware sources.)

On Windows and Ubuntu Linux, you can run the keepkey.py script to search for
the eval board through the USB interface when it is running the modified STM
Virtual Comport Loopback firmware:

    python keepkey.py

On Linux, you'll probably need to run the above command as an argument to the
'sudo' command to give it superuser permission.

If the device is plugged into USB, the keepkey.py script will find it and
launch the serial_buffer_expanded.py script to enable you to read and write
from a buffer on the device.  Currently the serial port name (on my machine)
is wired into the buffer access script.  I need to figure out how to discover
the serial port name automatically.

On Windows, you may (probably will?) need to install libusb-win32 in order to
use pyusb (i.e. "import usb" in python).  The following website explains how
to install libusb-win32:

    http://sourceforge.net/apps/trac/libusb-win32/wiki

When installing libusb-win32, it is important to install the library as a
filter driver, not a device driver.

If you install it as a device driver, you'll end up binding your your USB
device to this driver and the device will no longer appear in the Windows
Device Manager under "Ports (COM & LPT)".  It will instead be found under
"libusb-win32 devices" in the Device Manager.  It no longer looks like a
virtual COM port, and I don't know how you can open it in pyusb, which expects
a serial port name.  Removing libusb-win32 after you make this mistake is
a rather involved process (using usbdeview and pnputil) which is briefly
described at the URL above.

So, make sure to install libusb-win32 as a filter driver.  After doing this,
you need to run the Filter Wizard which comes with the library.  (This runs as
part of the installation process, and you can run it again later by looking in
the start menu for "LibUSB-Win32 / Filter Wizard".)  The wizard associates the
filter with a device of your choosing.  This is not as automatic as we'd like
in the long run, but it makes the device appear as a virtual COM port, which
is what we need.

--
lowell@carbondesign.com
