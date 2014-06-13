/* START KEEPKEY LICENSE */
/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2014 Carbon Design Group <tom@carbondesign.com>
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
 *
 */
/* END KEEPKEY LICENSE */

#ifndef USB_H
#define USB_H

#include <stdbool.h>
#include <stdint.h>

/*
 * USB Board Config
 */
#define USB_GPIO_PORT GPIOA
#define USB_GPIO_PORT_PINS (GPIO11 | GPIO12)

#define USB_SEGMENT_SIZE 64
#define MAX_NUM_USB_SEGMENTS 1
#define MAX_MESSAGE_SIZE (USB_SEGMENT_SIZE * MAX_NUM_USB_SEGMENTS)

typedef struct
{
    uint32_t len;
    uint8_t message[MAX_MESSAGE_SIZE];
} UsbMessage;

/**
 * Setup a callback to receive USB messages.  If not set, incoming USB
 * packets will just be tossed.
 */

/**
 * The callback function pointer.
 * @param msg The received message.  You need to copy it back into your context, as the 
 * USB fifo depth is limited.
 */
typedef void (*usb_rx_callback_t)(UsbMessage* msg);

/**
 * @param callback Callback function pointer.
 */
void usb_set_rx_callback(usb_rx_callback_t callback);

bool usb_init(void);

bool usb_poll(void);

bool usb_tx(void* msg, uint32_t len);

#endif
