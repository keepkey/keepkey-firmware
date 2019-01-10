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

#ifndef USB_H
#define USB_H

#include "keepkey/board/u2f_hid.h"

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifndef EMULATOR
#  include <libopencm3/usb/usbd.h>
#endif

/* USB Board Config */
#define USB_GPIO_PORT GPIOA
#define USB_GPIO_PORT_PINS (GPIO11 | GPIO12)

#define USB_SEGMENT_SIZE 64
#define MAX_NUM_USB_SEGMENTS 1
#define MAX_MESSAGE_SIZE (USB_SEGMENT_SIZE * MAX_NUM_USB_SEGMENTS)
#define NUM_USB_STRINGS (sizeof(usb_strings) / sizeof(usb_strings[0]))

/* USB endpoint */
#define ENDPOINT_ADDRESS_IN         (0x81)
#define ENDPOINT_ADDRESS_OUT        (0x01)

#if DEBUG_LINK
#define ENDPOINT_ADDRESS_DEBUG_IN   (0x82)
#define ENDPOINT_ADDRESS_DEBUG_OUT  (0x02)
#endif

#define ENDPOINT_ADDRESS_U2F_IN   (0x83)
#define ENDPOINT_ADDRESS_U2F_OUT  (0x03)

/* Control buffer for use by the USB stack.  We just allocate the 
   space for it.  */
#define USBD_CONTROL_BUFFER_SIZE 128

typedef void (*usb_rx_callback_t)(const void *buf, size_t len);
typedef void (*usb_u2f_rx_callback_t)(const U2FHID_FRAME *buf);

void usb_set_rx_callback(usb_rx_callback_t callback);
void usb_set_u2f_rx_callback(usb_u2f_rx_callback_t callback);

void usbInit(void);
bool usbInitialized(void);
void usbPoll(void);

typedef struct _usbd_device usbd_device;
usbd_device *get_usb_init_stat(void);

bool usb_tx(uint8_t *message, uint32_t len);
#if DEBUG_LINK
bool usb_debug_tx(uint8_t *message, uint32_t len);
void usb_set_debug_rx_callback(usb_rx_callback_t callback);
#endif

void queue_u2f_pkt(const U2FHID_FRAME *u2f_pkt);

#endif
