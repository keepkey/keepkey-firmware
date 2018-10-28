/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2015 KeepKey LLC
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef EMULATOR
#  include <libopencm3/stm32/gpio.h>
#  include <libopencm3/stm32/desig.h>
#  include <libopencm3/usb/hid.h>
#  include <libopencm3/usb/usbd.h>
#  include <libopencm3/stm32/rcc.h>
#  include "keepkey/board/keepkey_board.h"
#  include "keepkey/board/u2f.h"
#  include "keepkey/board/u2f_types.h"
#  include "keepkey/board/layout.h"
#  include "keepkey/board/timer.h"
#else
#  include <keepkey/emulator/emulator.h>
#endif

#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/usb_driver.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* This optional callback is configured by the user to handle receive events.  */
usb_rx_callback_t user_rx_callback = NULL;

#if DEBUG_LINK
usb_rx_callback_t user_debug_rx_callback = NULL;
#endif

static volatile bool u2f_transport = false;

void usb_set_u2f_transport(void) {
    u2f_transport = true;
}

void usb_set_hid_transport(void) {
    u2f_transport = false;
}

bool usb_is_u2f_transport(void) {
    return u2f_transport;
}

#ifndef EMULATOR

#define USB_INTERFACE_INDEX_MAIN 0
#if DEBUG_LINK
#define USB_INTERFACE_INDEX_DEBUG 1
#define USB_INTERFACE_INDEX_U2F 2
#else
#define USB_INTERFACE_INDEX_U2F 1
#endif

#define ENDPOINT_ADDRESS_IN         (0x81)
#define ENDPOINT_ADDRESS_OUT        (0x01)
#define ENDPOINT_ADDRESS_DEBUG_IN   (0x82)
#define ENDPOINT_ADDRESS_DEBUG_OUT  (0x02)
#define ENDPOINT_ADDRESS_U2F_IN     (0x83)
#define ENDPOINT_ADDRESS_U2F_OUT    (0x03)


#define USB_STRINGS \
        X(MANUFACTURER, "KeyHodlers, LLC") \
    X(PRODUCT, "KeepKey") \
    X(SERIAL_NUMBER, serial_uuid_str) \
    X(INTERFACE_MAIN,  "KeepKey Interface") \
    X(INTERFACE_DEBUG, "KeepKey Debug Link Interface") \
    X(INTERFACE_U2F,   "U2F Interface")

#define X(name, value) USB_STRING_##name,
enum {
    USB_STRING_LANGID_CODES, // LANGID code array
    USB_STRINGS
};
#undef X

static char serial_uuid_str[100];

#define X(name, value) value,
static const char *usb_strings[] = {
    USB_STRINGS
};
#undef X

static volatile char tiny = 0;
uint8_t v_poll = 0;

char usbTiny(char set)
{
    char old = tiny;
    tiny = set;
    return old;
}

static uint8_t usbd_control_buffer[USBD_CONTROL_BUFFER_SIZE];

/* USB Device state structure.  */
static usbd_device *usbd_dev = NULL;

/*
 * Used to track the initialization of the USB device.  Set to true after the
 * USB stack is configured.
 */
static bool usb_configured = false;

/* USB device descriptor */
static const struct usb_device_descriptor dev_descr = {
	.bLength = USB_DT_DEVICE_SIZE,
	.bDescriptorType = USB_DT_DEVICE,
	.bcdUSB = 0x0200,
	.bDeviceClass = 0,
	.bDeviceSubClass = 0,
	.bDeviceProtocol = 0,
	.bMaxPacketSize0 = USB_SEGMENT_SIZE,
	.idVendor = 0x2B24,   /* KeepKey Vendor ID */
	.idProduct = 0x0001,
	.bcdDevice = 0x0100,
	.iManufacturer = USB_STRING_MANUFACTURER,
	.iProduct = USB_STRING_PRODUCT,
	.iSerialNumber = USB_STRING_SERIAL_NUMBER,
	.bNumConfigurations = 1,
};

static const uint8_t hid_report_descriptor[] = {
    0x06, 0x00, 0xff,  // USAGE_PAGE (Vendor Defined)
    0x09, 0x01,        // USAGE (1)
    0xa1, 0x01,        // COLLECTION (Application)
    0x09, 0x20,        // USAGE (Input Report Data)
    0x15, 0x00,        // LOGICAL_MINIMUM (0)
    0x26, 0xff, 0x00,  // LOGICAL_MAXIMUM (255)
    0x75, 0x08,        // REPORT_SIZE (8)
    0x95, 0x40,        // REPORT_COUNT (64)
    0x81, 0x02,        // INPUT (Data,Var,Abs)
    0x09, 0x21,        // USAGE (Output Report Data)
    0x15, 0x00,        // LOGICAL_MINIMUM (0)
    0x26, 0xff, 0x00,  // LOGICAL_MAXIMUM (255)
    0x75, 0x08,        // REPORT_SIZE (8)
    0x95, 0x40,        // REPORT_COUNT (64)
    0x91, 0x02,        // OUTPUT (Data,Var,Abs)
    0xc0               // END_COLLECTION
};

#if DEBUG_LINK
static const uint8_t hid_report_descriptor_debug[] = {
    0x06, 0x01, 0xff,  // USAGE_PAGE (Vendor Defined)
    0x09, 0x01,        // USAGE (1)
    0xa1, 0x01,        // COLLECTION (Application)
    0x09, 0x20,        // USAGE (Input Report Data)
    0x15, 0x00,        // LOGICAL_MINIMUM (0)
    0x26, 0xff, 0x00,  // LOGICAL_MAXIMUM (255)
    0x75, 0x08,        // REPORT_SIZE (8)
    0x95, 0x40,        // REPORT_COUNT (64)
    0x81, 0x02,        // INPUT (Data,Var,Abs)
    0x09, 0x21,        // USAGE (Output Report Data)
    0x15, 0x00,        // LOGICAL_MINIMUM (0)
    0x26, 0xff, 0x00,  // LOGICAL_MAXIMUM (255)
    0x75, 0x08,        // REPORT_SIZE (8)
    0x95, 0x40,        // REPORT_COUNT (64)
    0x91, 0x02,        // OUTPUT (Data,Var,Abs)
    0xc0               // END_COLLECTION
};
#endif

static const uint8_t hid_report_descriptor_u2f[] = {
    0x06, 0xd0, 0xf1,  // USAGE_PAGE (FIDO Alliance)
    0x09, 0x01,        // USAGE (U2F HID Authenticator Device)
    0xa1, 0x01,        // COLLECTION (Application)
    0x09, 0x20,        // USAGE (Input Report Data)
    0x15, 0x00,        // LOGICAL_MINIMUM (0)
    0x26, 0xff, 0x00,  // LOGICAL_MAXIMUM (255)
    0x75, 0x08,        // REPORT_SIZE (8)
    0x95, 0x40,        // REPORT_COUNT (64)
    0x81, 0x02,        // INPUT (Data,Var,Abs)
    0x09, 0x21,        // USAGE (Output Report Data)
    0x15, 0x00,        // LOGICAL_MINIMUM (0)
    0x26, 0xff, 0x00,  // LOGICAL_MAXIMUM (255)
    0x75, 0x08,        // REPORT_SIZE (8)
    0x95, 0x40,        // REPORT_COUNT (64)
    0x91, 0x02,        // OUTPUT (Data,Var,Abs)
    0xc0               // END_COLLECTION
};


static const struct {
	struct usb_hid_descriptor hid_descriptor;
	struct {
		uint8_t bReportDescriptorType;
		uint16_t wDescriptorLength;
	} __attribute__((packed)) hid_report;
} __attribute__((packed)) hid_function = {
	.hid_descriptor = {
		.bLength = sizeof(hid_function),
		.bDescriptorType = USB_DT_HID,
		.bcdHID = 0x0111,
		.bCountryCode = 0,
		.bNumDescriptors = 1,
	},
	.hid_report = {
		.bReportDescriptorType = USB_DT_REPORT,
		.wDescriptorLength = sizeof(hid_report_descriptor),
	}
};

static const struct {
    struct usb_hid_descriptor hid_descriptor_u2f;
    struct {
        uint8_t bReportDescriptorType;
        uint16_t wDescriptorLength;
    } __attribute__((packed)) hid_report_u2f;
} __attribute__((packed)) hid_function_u2f = {
    .hid_descriptor_u2f = {
        .bLength = sizeof(hid_function_u2f),
        .bDescriptorType = USB_DT_HID,
        .bcdHID = 0x0111,
        .bCountryCode = 0,
        .bNumDescriptors = 1,
    },
    .hid_report_u2f = {
        .bReportDescriptorType = USB_DT_REPORT,
        .wDescriptorLength = sizeof(hid_report_descriptor_u2f),
    }
};

static const struct usb_endpoint_descriptor hid_endpoints[2] = {{
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = ENDPOINT_ADDRESS_IN,
	.bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
	.wMaxPacketSize = USB_SEGMENT_SIZE,
	.bInterval = 1,
}, {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = ENDPOINT_ADDRESS_OUT,
	.bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
	.wMaxPacketSize = USB_SEGMENT_SIZE,
	.bInterval = 1,
}};

static const struct usb_interface_descriptor hid_iface[] = {{
	.bLength = USB_DT_INTERFACE_SIZE,
	.bDescriptorType = USB_DT_INTERFACE,
	.bInterfaceNumber = USB_INTERFACE_INDEX_MAIN,
	.bAlternateSetting = 0,
	.bNumEndpoints = 2,
	.bInterfaceClass = USB_CLASS_HID,
	.bInterfaceSubClass = 0,
	.bInterfaceProtocol = 0,
	.iInterface = USB_STRING_INTERFACE_MAIN,
	.endpoint = hid_endpoints,
	.extra = &hid_function,
	.extralen = sizeof(hid_function),
}};

static const struct usb_endpoint_descriptor hid_endpoints_u2f[2] = {{
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = ENDPOINT_ADDRESS_U2F_IN,
    .bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
    .wMaxPacketSize = 64,
    .bInterval = 2,
}, {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = ENDPOINT_ADDRESS_U2F_OUT,
    .bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
    .wMaxPacketSize = 64,
    .bInterval = 2,
}};

static const struct usb_interface_descriptor hid_iface_u2f[] = {{
    .bLength = USB_DT_INTERFACE_SIZE,
    .bDescriptorType = USB_DT_INTERFACE,
    .bInterfaceNumber = USB_INTERFACE_INDEX_U2F,
    .bAlternateSetting = 0,
    .bNumEndpoints = 2,
    .bInterfaceClass = USB_CLASS_HID,
    .bInterfaceSubClass = 0,
    .bInterfaceProtocol = 0,
    .iInterface = USB_STRING_INTERFACE_U2F,
    .endpoint = hid_endpoints_u2f,
    .extra = &hid_function_u2f,
    .extralen = sizeof(hid_function_u2f),
}};



#if DEBUG_LINK
static const struct usb_endpoint_descriptor hid_endpoints_debug[2] = {{
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = ENDPOINT_ADDRESS_DEBUG_IN,
	.bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
	.wMaxPacketSize = USB_SEGMENT_SIZE,
	.bInterval = 1,
}, {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = ENDPOINT_ADDRESS_DEBUG_OUT,
	.bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
	.wMaxPacketSize = USB_SEGMENT_SIZE,
	.bInterval = 1,
}};

static const struct usb_interface_descriptor hid_iface_debug[] = {{
	.bLength = USB_DT_INTERFACE_SIZE,
	.bDescriptorType = USB_DT_INTERFACE,
	.bInterfaceNumber = USB_INTERFACE_INDEX_DEBUG,
	.bAlternateSetting = 0,
	.bNumEndpoints = 2,
	.bInterfaceClass = USB_CLASS_HID,
	.bInterfaceSubClass = 0,
	.bInterfaceProtocol = 0,
	.iInterface = USB_STRING_INTERFACE_DEBUG,
	.endpoint = hid_endpoints_debug,
	.extra = &hid_function,
	.extralen = sizeof(hid_function),
}};
#endif

static const struct usb_interface ifaces[] = {{
	.num_altsetting = 1,
	.altsetting = hid_iface,
#if DEBUG_LINK
}, {
	.num_altsetting = 1,
	.altsetting = hid_iface_debug,
#endif
}, {
    .num_altsetting = 1,
    .altsetting = hid_iface_u2f,
}};

static const struct usb_config_descriptor config = {
	.bLength = USB_DT_CONFIGURATION_SIZE,
	.bDescriptorType = USB_DT_CONFIGURATION,
	.wTotalLength = 0,
#if DEBUG_LINK
	.bNumInterfaces = 3,
#else
	.bNumInterfaces = 2,
#endif
	.bConfigurationValue = 1,
	.iConfiguration = 0,
	.bmAttributes = 0x80,
	.bMaxPower = 0x32,
	.interface = ifaces,
};

static enum usbd_request_return_codes
hid_control_request(usbd_device *dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len, void (**complete)(usbd_device *, struct usb_setup_data *))
{
	(void)complete;
	(void)dev;

	if ((req->bmRequestType != ENDPOINT_ADDRESS_IN) ||
	    (req->bRequest != USB_REQ_GET_DESCRIPTOR) ||
	    (req->wValue != 0x2200))
		return USBD_REQ_NOTSUPP;

    if (req->wIndex == USB_INTERFACE_INDEX_U2F) {
        *buf = (uint8_t *)hid_report_descriptor_u2f;//_u2f
        *len = sizeof(hid_report_descriptor_u2f);//_u2f
        return USBD_REQ_HANDLED;
    }

#if DEBUG_LINK
    if (req->wIndex == USB_INTERFACE_INDEX_DEBUG) {
        *buf = (uint8_t *)hid_report_descriptor_debug;//_debug
        *len = sizeof(hid_report_descriptor_debug);//_debug
        return USBD_REQ_HANDLED;
    }
#endif


	/* Handle the HID report descriptor. */
	*buf = (uint8_t *)hid_report_descriptor;
	*len = sizeof(hid_report_descriptor);
	return USBD_REQ_HANDLED;
}

/*
 * hid_rx_callback() - Callback function to process received packet from USB host
 *
 * INPUT 
 *     - dev: pointer to USB device handler
 *     - ep: unused 
 * OUTPUT 
 *     none
 *
 */
static void hid_rx_callback(usbd_device *dev, uint8_t ep)
{
    (void)ep;

    /* Receive into the message buffer. */
    UsbMessage m;
    uint16_t rx = usbd_ep_read_packet(dev, 
                                      ENDPOINT_ADDRESS_OUT, 
                                      m.message, 
                                      USB_SEGMENT_SIZE);

    if(rx && user_rx_callback)
    {
        m.len = rx;
        usb_set_hid_transport();
        user_rx_callback(&m);
    }
}

static void hid_u2f_rx_callback(usbd_device *dev, uint8_t ep)
{
    (void)ep;
    static CONFIDENTIAL uint8_t buf[64] __attribute__ ((aligned(4)));
    uint16_t rx = usbd_ep_read_packet(dev, 
                                      ENDPOINT_ADDRESS_U2F_OUT, 
                                      buf, 
                                      64);
    if (rx && user_rx_callback){
        usb_set_u2f_transport();
        u2fhid_read(tiny, (const U2FHID_FRAME *) (void*) buf);
    }
}

/*
 * hid_debug_rx_callback() - Callback function to process received packet from USB host on debug endpoint
 *
 * INPUT
 *     - dev: pointer to USB device handler
 *     - ep: unused
 * OUTPUT
 *     none
 *
 */
#if DEBUG_LINK
static void hid_debug_rx_callback(usbd_device *dev, uint8_t ep)
{
    (void)ep;

    /* Receive into the message buffer. */
    UsbMessage m;
    uint16_t rx = usbd_ep_read_packet(dev,
                                      ENDPOINT_ADDRESS_DEBUG_OUT,
                                      m.message,
                                      USB_SEGMENT_SIZE);

    if(rx && user_debug_rx_callback)
    {
        m.len = rx;
        usb_set_hid_transport();
        user_debug_rx_callback(&m);
    }
}
#endif

/*
 * hid_set_config_callback() - Config USB IN/OUT endpoints and register callbacks
 *
 * INPUT -
 *     - dev: pointer to USB device handler
 *     - wValue: not used 
 * OUTPUT -
 *      none
 */
static void hid_set_config_callback(usbd_device *dev, uint16_t wValue)
{
	(void)wValue;

	usbd_ep_setup(dev, ENDPOINT_ADDRESS_IN,  USB_ENDPOINT_ATTR_INTERRUPT, USB_SEGMENT_SIZE, 0);
	usbd_ep_setup(dev, ENDPOINT_ADDRESS_OUT, USB_ENDPOINT_ATTR_INTERRUPT, USB_SEGMENT_SIZE, hid_rx_callback);
	usbd_ep_setup(dev, ENDPOINT_ADDRESS_U2F_IN,  USB_ENDPOINT_ATTR_INTERRUPT, 64, 0);
	usbd_ep_setup(dev, ENDPOINT_ADDRESS_U2F_OUT, USB_ENDPOINT_ATTR_INTERRUPT, 64, hid_u2f_rx_callback);
#if DEBUG_LINK
	usbd_ep_setup(dev, ENDPOINT_ADDRESS_DEBUG_IN,  USB_ENDPOINT_ATTR_INTERRUPT, USB_SEGMENT_SIZE, 0);
	usbd_ep_setup(dev, ENDPOINT_ADDRESS_DEBUG_OUT, USB_ENDPOINT_ATTR_INTERRUPT, USB_SEGMENT_SIZE, hid_debug_rx_callback);
#endif

	usbd_register_control_callback(
		dev,
		USB_REQ_TYPE_STANDARD | USB_REQ_TYPE_INTERFACE,
		USB_REQ_TYPE_TYPE | USB_REQ_TYPE_RECIPIENT,
		hid_control_request);

	usb_configured = true;
}
#endif

/*
 * usb_tx_helper() - Common way to transmit USB message to host 
 *
 * INPUT
 *     - message: pointer message buffer
 *     - len: length of message
 *     - endpoint: endpoint for transmission
 * OUTPUT
 *     true/false
 */
static bool usb_tx_helper(uint8_t *message, uint32_t len, uint8_t endpoint)
{
    uint32_t pos = 1;

    /* Chunk out message */
    while(pos < len)
    {
        uint8_t tmp_buffer[USB_SEGMENT_SIZE] = { 0 };

        tmp_buffer[0] = '?';

        memcpy(tmp_buffer + 1, message + pos, USB_SEGMENT_SIZE - 1);

#ifndef EMULATOR
        while(usbd_ep_write_packet(usbd_dev, endpoint, tmp_buffer, USB_SEGMENT_SIZE) == 0) {};
#else
        emulatorSocketWrite(endpoint, tmp_buffer, sizeof(tmp_buffer));
#endif

        pos += USB_SEGMENT_SIZE - 1;
    }

    return(true);
}

#ifndef EMULATOR
bool usb_u2f_tx_helper(uint8_t *data, uint32_t len, uint8_t endpoint){

    uint32_t pos = 0;

    /* Chunk out message */
    while(pos < len)
    {
        uint8_t tmp_buffer[USB_SEGMENT_SIZE] = { 0 };

        memcpy(tmp_buffer , data + pos, USB_SEGMENT_SIZE);
        while(usbd_ep_write_packet(usbd_dev, endpoint, tmp_buffer, USB_SEGMENT_SIZE) == 0) {};

        pos += USB_SEGMENT_SIZE;
    }

    return(true);
}

/*
 * usb_init() - Initialize USB registers and set callback functions
 *
 * INPUT
 *     none
 * OUTPUT 
 *     true/false status of USB init
 */
bool usb_init(void)
{
    bool ret_stat = true;

    /* Skip initialization if alrealy initialized */
    if(usbd_dev == NULL) {
        gpio_mode_setup(USB_GPIO_PORT, GPIO_MODE_AF, GPIO_PUPD_NONE, USB_GPIO_PORT_PINS);
        gpio_set_af(USB_GPIO_PORT, GPIO_AF10, USB_GPIO_PORT_PINS);

        desig_get_unique_id_as_string(serial_uuid_str, sizeof(serial_uuid_str));
        usbd_dev = usbd_init(&otgfs_usb_driver,
                         &dev_descr,
                         &config,
                         usb_strings,
                         NUM_USB_STRINGS,
                         usbd_control_buffer,
                         sizeof(usbd_control_buffer));
        if(usbd_dev != NULL) {
            usbd_register_set_config_callback(usbd_dev, hid_set_config_callback);
        } else {
            /* error: unable init usbd_dev */
            ret_stat = false;
        }
    }

    return (ret_stat);
}

/*
 * usb_poll() - Poll USB port for message
 *  
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void usb_poll(void)
{
    usbd_poll(usbd_dev);
}
#endif

/*
 * usb_tx() - Transmit USB message to host via normal endpoint
 *
 * INPUT
 *     - message: pointer message buffer
 *     - len: length of message
 * OUTPUT
 *     true/false
 */
#ifndef EMULATOR
bool usb_tx(uint8_t *message, uint32_t len)
{
    if (usb_is_u2f_transport()) {
        memcpy(message+len, "\x00\x00\x90\x00", 4);
        send_u2f_msg(message, len + 4);
        return true;
    } else {
        return usb_tx_helper(message, len, ENDPOINT_ADDRESS_IN);
    }
}
#endif

/*
 * usb_debug_tx() - Transmit usb message to host via debug endpoint
 *
 * INPUT
 *     - message: pointer message buffer
 *     - len: length of message
 * OUTPUT
 *     true/false
 */
#if DEBUG_LINK
#ifndef EMULATOR
bool usb_debug_tx(uint8_t *message, uint32_t len)
{
    if (usb_is_u2f_transport()) {
        memcpy(message+len, "\x00\x40\x90\x00", 4);
        send_u2f_msg(message, len + 4);
        return true;
    } else {
        return usb_tx_helper(message, len, ENDPOINT_ADDRESS_DEBUG_IN);
    }
}

#endif
#endif

/*
 * usb_set_rx_callback() - Setup USB receive callback function pointer
 *
 * INPUT
 *     - callback: callback function
 * OUTPUT
 *     none
 */
void usb_set_rx_callback(usb_rx_callback_t callback)
{
    user_rx_callback = callback;
}


/*
 * usb_set_debug_rx_callback() - Setup USB receive callback function pointer for debug link
 *
 * INPUT
 *     - callback: callback function
 * OUTPUT
 *     none
 */
#if DEBUG_LINK
void usb_set_debug_rx_callback(usb_rx_callback_t callback)
{
    user_debug_rx_callback = callback;
}
#endif

#ifndef EMULATOR
/*
 * get_usb_init_stat() - Get USB initialization status
 *
 * INPUT
 *     none
 * OUTPUT
 *     USB pointer 
 */
usbd_device *get_usb_init_stat(void)
{
    return(usbd_dev);
}
#endif
