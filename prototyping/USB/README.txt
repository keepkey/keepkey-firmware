This directory contains demonstration and/or prototyping code used to evaluate
application of the Keepkey wallet as a USB device.  

I initially looked into implementing the Keepkey wallet as a USB HID (human
interface device). I abandoned that approach because it required creating
a custom HID report descriptor, which seemed like more trouble than it was
worth.

I found it much easier to implement Keepkey as a USB communication (CDC)
device. With this approach, we can read and write character streams from/to
the device like a serial COM port.

The following directories contain stuff that I've used during this
investigation.

    scripts/
    STM3210E-EVAL_FW_V2.1.0/
    STM32_USB-FS-Device_Lib_V4.0.0/
    STM32_USB_HID_Demonstrator_V1.0.2/

The most important folder is STM32_USB-FS-Device_Lib_V4.0.0.  This folder
contains Virtual Comport Loopback demonstration firmware which runs on an
STM3210E-EVAL board and can be easily built using IAR EWARM.  This firmware
has been modified to support reading and writing 256-byte messages from/to
the evaluation board.  There are python scripts in the "scripts" folder which
interact with this firmware via a USB virtual COM port connection.

Note: Lowell Skoog has an electronic copy of Jan Axelson's "USB Complete"
book.  The book is readable using the Adobe Digital Editions application.
Being an e-book, it is a pain in the ass to share it.

Better Note: Jason Higgens has a paper copy of "USB Complete."

--
lowell@carbondesign.com

