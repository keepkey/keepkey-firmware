#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Plug and Play example

This is a port of wxPython PnP sample to PySide (in theory could work with PyQt),
but intended to show as much as possible of PyWinUSB
"""

from PySide import QtGui, QtCore
import pywinusb.hid as hid

# feel free to test
target_vendor_id = 0x1234
target_product_id = 0x0001

class HidQtPnPWindowMixin(hid.HidPnPWindowMixin):
    # a device so we could easily discriminate wich devices to look at
    my_hid_target = hid.HidDeviceFilter(vendor_id = target_vendor_id, product_id = target_product_id)
    # PnP connection/disconnection signal
    hidChange = Signal(str)
    # hid connection/disconnection signal
    hidConnect = Signal(hid.HidDevice)
    
    def __init__(self):
        # pass system window handle to trap PnP event
        hid.HidPnPWindowMixin.__init__(self, self.winId())
        self.hid_device = None # no hid device... yet
        # kick the pnp state machine for one shot polling
        self.on_hid_pnp()

    def on_hid_pnp(self, hid_event = None):
        """This function will be called on per class event changes, so we need
        to test if our device has being connected or is just gone"""
        old_device = self.device

        if hid_event:
            self.hidChange.emit(hid_event)
            
        if hid_event == "connected":
            # test if our device is available
            if self.hid_device:
                # see, at this point we could detect multiple devices!
                # but... we only want just one
                pass
            else:
                self.test_for_connection()
        elif hid_event == "disconnected":
            # the hid object is automatically closed on disconnection we just
            # test if still is plugged (important as the object might be
            # closing)
            if self.hid_device and not self.hid_device.is_plugged():
                self.hid_device = None
        else:
            # poll for devices
            self.test_for_connection()
        # update ui
        if old_device != self.device:
            self.hidConnect.emit(self.device)
        
    def test_for_connection(self):
        """ This funnction validates we have a valid HID target device
        connected, it could be extended to manage multiple HID devices
        mapped to different device paths, but so far only expects a
        single device, so in case of multiple devices being connected
        resolution it is arbitrary"""
        # poll for all connections
        all_items =  HidQtPnPWindowMixin.my_hid_target.get_devices()

        if all_items:
            # at this point, what we decided to be a valid hid target is
            # already plugged
            if len(all_items) == 1:
                # this is easy, we only have a single hid device
                self.hid_device = all_items[0]
            else:
                # at this point you might have multiple scenarios
                grouped_items = HidQtPnPWindowMixin.my_hid_target.get_devices_by_parent()
                if len(grouped_items) > 1:
                    # 1) Really you have multiple devices connected so, make
                    # your rules, how do you help your user to handle multiple
                    # devices?
                    # maybe you here will find out wich is the new device, and
                    # tag this device so is easily identified (i.e. the WiiMote
                    # uses LEDs), or just your GUI shows some arbitrary
                    # identification for the user (device 2 connected)
                    pass
                else:
                    # 2) We have a single physical device, but the descriptors
                    # might might cause the OS to report is as multiple devices
                    # (collections maybe) so, what would be your target device?
                    # if you designed the device firmware, you already know the
                    # answer...  otherwise one approach might be to browse the
                    # hid usages for a particular target...  anyway, this could
                    # be complex, especially handling multiple physical devices
                    # that are reported as multiple hid paths (objects)...
                    # so...  I recommend you creating a proxy class that is
                    # able to handle all your 'per parent id' grouped devices,
                    # (like a single .open() able to handle your buch of
                    # HidDevice() items
                    pass
                # but... we just arbitrarly select the first hid object path
                # (how creative!)
                self.hid_device = all_items[0]
        if self.hid_device:
            self.hid_device.open()

class HidPnPForm(QDialog, HidQtPnPWindowMixin):
    """PyWinUsb PnP (Plug & Play) test dialog"""

    def __init__(self, parent = None):
        super(Form, self).__init__(parent)

        # init PnP management
        HidQtPnPWindowMixin.__init__(self)

        self.deviceLabel = QLabel("Target HID device")
        self.vendorIdText  = QLineEdit()
        self.productIdText = QLineEdit()
        self.statusLabel = QLabel("Not connected")
        self.logText  = QTextEdit()

        grid = QGridLayout()
        grid.addWidget(self.deviceLabel,    0, 0)
        grid.addWidget(self.vendorIdText,   1, 0)
        grid.addWidget(self.productIdText,  1, 1)
        grid.addWidget(self.statusLabel,    2, 0)
        self.setLayout(grid)


        self.connect(self.fromComboBox, SIGNAL("currentIndexChanged(int)"), self.updateUi)
        self.connect(self.toComboBox, SIGNAL("currentIndexChanged(int)"), self.updateUi)
        self.connect(self.fromSpinBox, SIGNAL("valueChanged(double)"), self.updateUi)

    def on_close(self, event):
        event.Skip()
        if self.device:
            self.device.close()
            
if __name__ == "__main__":
    app = wx.App(False)
    frame = MyFrame(None)
    frame.Show()
    app.MainLoop()

