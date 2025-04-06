/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
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
#include <libopencm3/usb/usbd.h>
#include <libopencm3/usb/hid.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/desig.h>
#include <libopencm3/stm32/rcc.h>
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/timer.h"
#else
#include <keepkey/emulator/emulator.h>
#endif

#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/util.h"
#include "keepkey/board/u2f_hid.h"

#include "keepkey/board/usb21_standard.h"
#include "keepkey/board/webusb.h"
#include "keepkey/board/winusb.h"

#include <nanopb.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define debugLog(L, B, T) \
  do {                    \
  } while (0)

static bool usb_inited = false;

/* This optional callback is configured by the user to handle receive events. */
usb_rx_callback_t user_rx_callback = NULL;

#if DEBUG_LINK
usb_rx_callback_t user_debug_rx_callback = NULL;
#endif

usb_u2f_rx_callback_t user_u2f_rx_callback = NULL;

#ifndef EMULATOR

#define USB_INTERFACE_INDEX_MAIN 0
#if DEBUG_LINK
#define USB_INTERFACE_INDEX_DEBUG 1
#define USB_INTERFACE_INDEX_U2F 2
#define USB_INTERFACE_COUNT 3
#else
#define USB_INTERFACE_INDEX_U2F 1
#define USB_INTERFACE_COUNT 2
#endif

#define ENDPOINT_ADDRESS_MAIN_IN (0x81)
#define ENDPOINT_ADDRESS_MAIN_OUT (0x01)
#if DEBUG_LINK
#define ENDPOINT_ADDRESS_DEBUG_IN (0x82)
#define ENDPOINT_ADDRESS_DEBUG_OUT (0x02)
#endif
#define ENDPOINT_ADDRESS_U2F_IN (0x83)
#define ENDPOINT_ADDRESS_U2F_OUT (0x03)

#define USB_STRINGS                                  \
  X(MANUFACTURER, "KeyHodlers, LLC")                 \
  X(PRODUCT, device_label)                           \
  X(SERIAL_NUMBER, serial_uuid_str)                  \
  X(INTERFACE_MAIN, "KeepKey Interface")             \
  X(INTERFACE_DEBUG, "KeepKey Debug Link Interface") \
  X(INTERFACE_U2F, "KeepKey U2F Interface")

#define X(name, value) USB_STRING_##name,
enum {
  USB_STRING_LANGID_CODES,  // LANGID code array
  USB_STRINGS
};
#undef X

static char device_label[33];
static char serial_uuid_str[100];

#define X(name, value) value,
static const char *usb_strings[] = {USB_STRINGS};
#undef X

static const struct usb_device_descriptor dev_descr = {
    .bLength = USB_DT_DEVICE_SIZE,
    .bDescriptorType = USB_DT_DEVICE,
    .bcdUSB = 0x0210,
    .bDeviceClass = 0,
    .bDeviceSubClass = 0,
    .bDeviceProtocol = 0,
    .bMaxPacketSize0 = 64,
    .idVendor = 0x2B24, /* KeepKey Vendor ID */
    .idProduct = 0x0002,
    .bcdDevice = 0x0100,
    .iManufacturer = USB_STRING_MANUFACTURER,
    .iProduct = USB_STRING_PRODUCT,
    .iSerialNumber = USB_STRING_SERIAL_NUMBER,
    .bNumConfigurations = 1,
};

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
  struct usb_hid_descriptor hid_descriptor_u2f;
  struct {
    uint8_t bReportDescriptorType;
    uint16_t wDescriptorLength;
  } __attribute__((packed)) hid_report_u2f;
} __attribute__((packed))
hid_function_u2f = {.hid_descriptor_u2f =
                        {
                            .bLength = sizeof(hid_function_u2f),
                            .bDescriptorType = USB_DT_HID,
                            .bcdHID = 0x0111,
                            .bCountryCode = 0,
                            .bNumDescriptors = 1,
                        },
                    .hid_report_u2f = {
                        .bReportDescriptorType = USB_DT_REPORT,
                        .wDescriptorLength = sizeof(hid_report_descriptor_u2f),
                    }};

static const struct usb_endpoint_descriptor hid_endpoints_u2f[2] = {
    {
        .bLength = USB_DT_ENDPOINT_SIZE,
        .bDescriptorType = USB_DT_ENDPOINT,
        .bEndpointAddress = ENDPOINT_ADDRESS_U2F_IN,
        .bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
        .wMaxPacketSize = 64,
        .bInterval = 1,
    },
    {
        .bLength = USB_DT_ENDPOINT_SIZE,
        .bDescriptorType = USB_DT_ENDPOINT,
        .bEndpointAddress = ENDPOINT_ADDRESS_U2F_OUT,
        .bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
        .wMaxPacketSize = 64,
        .bInterval = 1,
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
static const struct usb_endpoint_descriptor webusb_endpoints_debug[2] = {
    {
        .bLength = USB_DT_ENDPOINT_SIZE,
        .bDescriptorType = USB_DT_ENDPOINT,
        .bEndpointAddress = ENDPOINT_ADDRESS_DEBUG_IN,
        .bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
        .wMaxPacketSize = 64,
        .bInterval = 1,
    },
    {
        .bLength = USB_DT_ENDPOINT_SIZE,
        .bDescriptorType = USB_DT_ENDPOINT,
        .bEndpointAddress = ENDPOINT_ADDRESS_DEBUG_OUT,
        .bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
        .wMaxPacketSize = 64,
        .bInterval = 1,
    }};

static const struct usb_interface_descriptor webusb_iface_debug[] = {{
    .bLength = USB_DT_INTERFACE_SIZE,
    .bDescriptorType = USB_DT_INTERFACE,
    .bInterfaceNumber = USB_INTERFACE_INDEX_DEBUG,
    .bAlternateSetting = 0,
    .bNumEndpoints = 2,
    .bInterfaceClass = USB_CLASS_VENDOR,
    .bInterfaceSubClass = 0,
    .bInterfaceProtocol = 0,
    .iInterface = USB_STRING_INTERFACE_DEBUG,
    .endpoint = webusb_endpoints_debug,
    .extra = NULL,
    .extralen = 0,
}};

#endif

static const struct usb_endpoint_descriptor webusb_endpoints_main[2] = {
    {
        .bLength = USB_DT_ENDPOINT_SIZE,
        .bDescriptorType = USB_DT_ENDPOINT,
        .bEndpointAddress = ENDPOINT_ADDRESS_MAIN_IN,
        .bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
        .wMaxPacketSize = 64,
        .bInterval = 1,
    },
    {
        .bLength = USB_DT_ENDPOINT_SIZE,
        .bDescriptorType = USB_DT_ENDPOINT,
        .bEndpointAddress = ENDPOINT_ADDRESS_MAIN_OUT,
        .bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
        .wMaxPacketSize = 64,
        .bInterval = 1,
    }};

static const struct usb_interface_descriptor webusb_iface_main[] = {{
    .bLength = USB_DT_INTERFACE_SIZE,
    .bDescriptorType = USB_DT_INTERFACE,
    .bInterfaceNumber = USB_INTERFACE_INDEX_MAIN,
    .bAlternateSetting = 0,
    .bNumEndpoints = 2,
    .bInterfaceClass = USB_CLASS_VENDOR,
    .bInterfaceSubClass = 0,
    .bInterfaceProtocol = 0,
    .iInterface = USB_STRING_INTERFACE_MAIN,
    .endpoint = webusb_endpoints_main,
    .extra = NULL,
    .extralen = 0,
}};

// Windows are strict about interfaces appearing
// in correct order
static const struct usb_interface ifaces[] = {
    {
        .num_altsetting = 1,
        .altsetting = webusb_iface_main,
#if DEBUG_LINK
    },
    {
        .num_altsetting = 1,
        .altsetting = webusb_iface_debug,
#endif
    },
    {
        .num_altsetting = 1,
        .altsetting = hid_iface_u2f,
    }};

static const struct usb_config_descriptor config = {
    .bLength = USB_DT_CONFIGURATION_SIZE,
    .bDescriptorType = USB_DT_CONFIGURATION,
    .wTotalLength = 0,
    .bNumInterfaces = USB_INTERFACE_COUNT,
    .bConfigurationValue = 1,
    .iConfiguration = 0,
    .bmAttributes = 0x80,
    .bMaxPower = 0x32,
    .interface = ifaces,
};

static enum usbd_request_return_codes hid_control_request(
    usbd_device *dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len,
    void (**complete)(usbd_device *, struct usb_setup_data *)) {
  (void)complete;
  (void)dev;

  if ((req->bmRequestType != 0x81) ||
      (req->bRequest != USB_REQ_GET_DESCRIPTOR) || (req->wValue != 0x2200))
    return 0;

  debugLog(0, "", "hid_control_request u2f");
  *buf = (uint8_t *)hid_report_descriptor_u2f;
  *len = MIN(*len, sizeof(hid_report_descriptor_u2f));
  return 1;
}

static volatile char tiny = 0;

static void main_rx_callback(usbd_device *dev, uint8_t ep) {
  (void)ep;
  static CONFIDENTIAL uint8_t buf[64] __attribute__((aligned(4)));
  if (usbd_ep_read_packet(dev, ENDPOINT_ADDRESS_MAIN_OUT, buf, 64) != 64)
    return;
  debugLog(0, "", "main_rx_callback");

  if (user_rx_callback) {
    user_rx_callback(buf, 64);
  }
}

static void u2f_rx_callback(usbd_device *dev, uint8_t ep) {
  (void)ep;
  static CONFIDENTIAL uint8_t buf[64] __attribute__((aligned(4)));

  debugLog(0, "", "u2f_rx_callback");
  if (usbd_ep_read_packet(dev, ENDPOINT_ADDRESS_U2F_OUT, buf, 64) != 64) return;

  if (user_u2f_rx_callback) {
    user_u2f_rx_callback(tiny, (const U2FHID_FRAME *)(void *)buf);
  }
}

#if DEBUG_LINK
static void debug_rx_callback(usbd_device *dev, uint8_t ep) {
  (void)ep;
  static uint8_t buf[64] __attribute__((aligned(4)));
  if (usbd_ep_read_packet(dev, ENDPOINT_ADDRESS_DEBUG_OUT, buf, 64) != 64)
    return;
  debugLog(0, "", "debug_rx_callback");

  if (user_debug_rx_callback) {
    user_debug_rx_callback(buf, 64);
  }
}
#endif

static void set_config(usbd_device *dev, uint16_t wValue) {
  (void)wValue;

  usbd_ep_setup(dev, ENDPOINT_ADDRESS_MAIN_IN, USB_ENDPOINT_ATTR_INTERRUPT, 64,
                0);
  usbd_ep_setup(dev, ENDPOINT_ADDRESS_MAIN_OUT, USB_ENDPOINT_ATTR_INTERRUPT, 64,
                main_rx_callback);
  usbd_ep_setup(dev, ENDPOINT_ADDRESS_U2F_IN, USB_ENDPOINT_ATTR_INTERRUPT, 64,
                0);
  usbd_ep_setup(dev, ENDPOINT_ADDRESS_U2F_OUT, USB_ENDPOINT_ATTR_INTERRUPT, 64,
                u2f_rx_callback);
#if DEBUG_LINK
  usbd_ep_setup(dev, ENDPOINT_ADDRESS_DEBUG_IN, USB_ENDPOINT_ATTR_INTERRUPT, 64,
                0);
  usbd_ep_setup(dev, ENDPOINT_ADDRESS_DEBUG_OUT, USB_ENDPOINT_ATTR_INTERRUPT,
                64, debug_rx_callback);
#endif

  usbd_register_control_callback(
      dev, USB_REQ_TYPE_STANDARD | USB_REQ_TYPE_INTERFACE,
      USB_REQ_TYPE_TYPE | USB_REQ_TYPE_RECIPIENT, hid_control_request);
}

static usbd_device *usbd_dev;
static uint8_t usbd_control_buffer[256] __attribute__((aligned(2)));

static const struct usb_device_capability_descriptor *capabilities[] = {
    (const struct usb_device_capability_descriptor
         *)&webusb_platform_capability_descriptor,
};

static const struct usb_bos_descriptor bos_descriptor = {
    .bLength = USB_DT_BOS_SIZE,
    .bDescriptorType = USB_DT_BOS,
    .bNumDeviceCaps = sizeof(capabilities) / sizeof(capabilities[0]),
    .capabilities = capabilities};

void usbInit(const char *origin_url) {
  gpio_mode_setup(USB_GPIO_PORT, GPIO_MODE_AF, GPIO_PUPD_NONE,
                  USB_GPIO_PORT_PINS);
  gpio_set_af(USB_GPIO_PORT, GPIO_AF10, USB_GPIO_PORT_PINS);

  desig_get_unique_id_as_string(serial_uuid_str, sizeof(serial_uuid_str));
  memory_getDeviceLabel(device_label, sizeof(device_label));

  usbd_dev = usbd_init(&otgfs_usb_driver, &dev_descr, &config, usb_strings,
                       sizeof(usb_strings) / sizeof(*usb_strings),
                       usbd_control_buffer, sizeof(usbd_control_buffer));
  usbd_register_set_config_callback(usbd_dev, set_config);
  usb21_setup(usbd_dev, &bos_descriptor);
  webusb_setup(usbd_dev, origin_url);
  // Debug link interface does not have WinUSB set;
  // if you really need debug link on windows, edit the descriptor in winusb.c
  winusb_setup(usbd_dev, USB_INTERFACE_INDEX_MAIN);

  usb_inited = true;
}

void usbPoll(void) {
  // poll read buffer
  usbd_poll(usbd_dev);
}

void usbReconnect(void) {
  usbd_disconnect(usbd_dev, 1);
  delay_us(1000 / 20);
  usbd_disconnect(usbd_dev, 0);
}

char usbTiny(char set) {
  char old = tiny;
  tiny = set;
  return old;
}

#endif  // EMULATOR

bool msg_write(MessageType msg_id, const void *msg) {
  const pb_msgdesc_t *fields = message_fields(NORMAL_MSG, msg_id, OUT_MSG);

  if (!fields) return false;

  TrezorFrameBuffer framebuf;
  memset(&framebuf, 0, sizeof(framebuf));
  framebuf.frame.usb_header.hid_type = '?';
  framebuf.frame.header.pre1 = '#';
  framebuf.frame.header.pre2 = '#';
  framebuf.frame.header.id = __builtin_bswap16(msg_id);

  pb_ostream_t os =
      pb_ostream_from_buffer(framebuf.buffer, sizeof(framebuf.buffer));

  if (!pb_encode(&os, fields, msg)) return false;

  framebuf.frame.header.len = __builtin_bswap32(os.bytes_written);

  // Chunk out data
  for (uint32_t pos = 1; pos < sizeof(framebuf.frame) + os.bytes_written;
       pos += 64 - 1) {
    uint8_t tmp_buffer[64] = {0};

    tmp_buffer[0] = '?';

    memcpy(tmp_buffer + 1, ((const uint8_t *)&framebuf) + pos, 64 - 1);

#ifndef EMULATOR
    while (usbd_ep_write_packet(usbd_dev, ENDPOINT_ADDRESS_IN, tmp_buffer,
                                64) == 0) {
    };
#else
    emulatorSocketWrite(0, tmp_buffer, sizeof(tmp_buffer));
#endif
  }

  return true;
}

#if DEBUG_LINK
bool msg_debug_write(MessageType msg_id, const void *msg) {
  const pb_msgdesc_t *fields = message_fields(DEBUG_MSG, msg_id, OUT_MSG);

  if (!fields) return false;

  TrezorFrameBuffer framebuf;
  memset(&framebuf, 0, sizeof(framebuf));
  framebuf.frame.usb_header.hid_type = '?';
  framebuf.frame.header.pre1 = '#';
  framebuf.frame.header.pre2 = '#';
  framebuf.frame.header.id = __builtin_bswap16(msg_id);

  pb_ostream_t os =
      pb_ostream_from_buffer(framebuf.buffer, sizeof(framebuf.buffer));

  if (!pb_encode(&os, fields, msg)) return false;

  framebuf.frame.header.len = __builtin_bswap32(os.bytes_written);

  // Chunk out data
  for (uint32_t pos = 1; pos < sizeof(framebuf.frame) + os.bytes_written;
       pos += 64 - 1) {
    uint8_t tmp_buffer[64] = {0};

    tmp_buffer[0] = '?';

    memcpy(tmp_buffer + 1, ((const uint8_t *)&framebuf) + pos, 64 - 1);

#ifndef EMULATOR
    while (usbd_ep_write_packet(usbd_dev, ENDPOINT_ADDRESS_DEBUG_IN, tmp_buffer,
                                64) == 0) {
    };
#else
    emulatorSocketWrite(1, tmp_buffer, sizeof(tmp_buffer));
#endif
  }

  return true;
}
#endif

void queue_u2f_pkt(const U2FHID_FRAME *u2f_pkt) {
#ifndef EMULATOR
  while (usbd_ep_write_packet(usbd_dev, ENDPOINT_ADDRESS_U2F_IN, u2f_pkt, 64) ==
         0) {
  };
#else
  assert(false && "Emulator does not support FIDO u2f");
#endif
}

void usb_set_rx_callback(usb_rx_callback_t callback) {
  user_rx_callback = callback;
}

#if DEBUG_LINK
void usb_set_debug_rx_callback(usb_rx_callback_t callback) {
  user_debug_rx_callback = callback;
}
#endif

void usb_set_u2f_rx_callback(usb_u2f_rx_callback_t callback) {
  user_u2f_rx_callback = callback;
}

bool usbInitialized(void) { return usb_inited; }
