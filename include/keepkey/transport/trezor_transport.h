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

#ifndef KEEPKEY_TRANSPORT_H
#define KEEPKEY_TRANSPORT_H

#include <stdint.h>


#ifdef EMULATOR
#  define MAX_FRAME_SIZE (64 * 1024)
#else
#  define MAX_FRAME_SIZE (12 * 1024)
#endif


#pragma pack(1)

/* This structure is derived from the Trezor protocol.  Note that the values
come in as big endian, so they'll need to be swapped. */
typedef struct
{
    uint8_t hid_type; /* First byte is always 0x3f */
} UsbHeader;

/* Trezor frame header */
typedef struct
{
    /* Start of Trezor frame */
    uint8_t pre1;
    uint8_t pre2;

    /* Protobuf ID */
    uint16_t id;

    /* Length of the following message */
    uint32_t len;

} TrezorFrameHeaderFirst;

/* Second+ continuation fragment. */
typedef struct
{
    UsbHeader header;
    uint8_t contents[0];
} TrezorFrameFragment;

typedef struct
{
    UsbHeader usb_header;
    TrezorFrameHeaderFirst header;
    uint8_t contents[0];
} TrezorFrame;

typedef struct
{
    TrezorFrame frame;
    uint8_t buffer[MAX_FRAME_SIZE+ /* VERSION + DL? + U2F_OK  */ 4];
} TrezorFrameBuffer;

#pragma pack()

#endif
