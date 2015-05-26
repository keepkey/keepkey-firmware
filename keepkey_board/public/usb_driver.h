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

/* === Includes ============================================================ */

#include <stdbool.h>
#include <stdint.h>

#include <libopencm3/usb/usbd.h>

/* === Defines ============================================================= */

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

/* Control buffer for use by the USB stack.  We just allocate the 
   space for it.  */
#define USBD_CONTROL_BUFFER_SIZE 128

/* === Typedefs ============================================================ */

typedef struct
{
    uint32_t len;
    uint8_t message[MAX_MESSAGE_SIZE];
} UsbMessage;

typedef void (*usb_rx_callback_t)(UsbMessage* msg);

/* === Functions =========================================================== */

void usb_set_rx_callback(usb_rx_callback_t callback);
bool usb_init(void);
void usb_poll(void);
usbd_device *get_usb_init_stat(void);
bool usb_tx(uint8_t *message, uint32_t len);
#if DEBUG_LINK
bool usb_debug_tx(uint8_t *message, uint32_t len);
void usb_set_debug_rx_callback(usb_rx_callback_t callback);
#endif

#endif