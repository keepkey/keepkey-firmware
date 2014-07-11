/*
 * This file is part of the TREZOR project.
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

#include <assert.h>
#include <string.h>

#include <usb_driver.h>

#include "messages.h"
#include "debug.h"

#include <nanopb.h>
#include <interface.h>


// SimpleSignTx_size is the largest message we operate with
#if MSG_IN_SIZE < SimpleSignTx_size
#error "MSG_IN_SIZE is too small!"
#endif

/**
 * Structure to track diagnostic and monitoring status.
 */
typedef struct
{
    uint16_t runt_packet;
    uint16_t invalid_usb_header;
    uint16_t invalid_msg_type;
    uint16_t unknown_dispatch_entry;
    uint16_t usb_tx;
    uint16_t usb_tx_err;
} MsgStats;

static MsgStats msg_stats;

static const MessagesMap_t *MessagesMap =NULL;

const MessagesMap_t* message_map_entry(MessageType type)
{
    const MessagesMap_t *m = MessagesMap;
    while(m->msg_id) {
        if(type == m->msg_id)
        {
            return m;
        }
        ++m;
    }

    return NULL;
}

const pb_field_t *message_fields(MessageType type)
{
    assert(MessagesMap != NULL);

    const MessagesMap_t *m = MessagesMap;
    while (m->msg_id) {
        if (type == m->msg_id) {
            return m->fields;
        }
        m++;
    }
    return 0;
}

void usb_write_pb(const pb_field_t* fields, const void* msg, MessageType id)
{
    assert(fields != NULL);

    TrezorFrameBuffer framebuf;
    memset(&framebuf, 0, sizeof(framebuf));
    framebuf.frame.usb_header.hid_type = '?';
    framebuf.frame.header.pre1 = '#';
    framebuf.frame.header.pre2 = '#';
    framebuf.frame.header.id = __builtin_bswap16(id);

    pb_ostream_t os = pb_ostream_from_buffer(framebuf.buffer, sizeof(framebuf.buffer));
    bool status = pb_encode(&os, fields, msg);
    assert(status);

    framebuf.frame.header.len = __builtin_bswap32(os.bytes_written);

    bool ret = usb_tx(&framebuf, sizeof(framebuf.frame) + os.bytes_written);
    ret ? msg_stats.usb_tx++ : msg_stats.usb_tx_err++;
}


bool msg_write(MessageType type, const void *msg_ptr)
{
    const pb_field_t *fields = message_fields(type);
    if (!fields) { // unknown message
        return false;
    }

    usb_write_pb(fields, msg_ptr, type);

    return true;
}

void dispatch(const MessagesMap_t* entry, uint8_t *msg, uint32_t msg_size)
{
    static uint8_t decode_buffer[MAX_DECODE_SIZE];

    pb_istream_t stream = pb_istream_from_buffer(msg, msg_size);

    bool status = pb_decode(&stream, entry->fields, decode_buffer);
    if (status) 
    {
        if(entry->process_func) 
        {
            entry->process_func(decode_buffer);
        }
    } else {
        /* TODO: Handle error response */
    }
}


/**
 * Local routine to handle messages incoming from the USB driver.
 *
 * @param msg The incoming usb message, which may be a packet fragment or a
 *      complete message.
 */
void handle_usb_rx(UsbMessage *msg)
{
    assert(msg != NULL);

    if(msg->len < sizeof(TrezorFrameHeaderFirst))
    {
        ++msg_stats.runt_packet;
        return;
    }
    TrezorFrame *frame = (TrezorFrame*)(msg->message);
    if(frame->usb_header.hid_type != '?')
    {
        ++msg_stats.invalid_usb_header;
        return;
    } 

    /*
     * Check to see if this is the first frame of a series,
     * or a continuation/fragment.
     */
    static TrezorFrameHeaderFirst last_frame_header = 
    {
        .id = 0xffff,
        .len = 0
    };

    uint8_t* contents = NULL;
    uint32_t len = 0;

    if(frame->header.pre1 == '#' && frame->header.pre2 == '#')
    {
        /*
         * Byte swap in place.
         */
        last_frame_header.id = __builtin_bswap16(frame->header.id);
        last_frame_header.len = __builtin_bswap32(frame->header.len);
        contents = frame->contents;
    } else {
        contents = ((TrezorFrameFragment*)msg->message)->contents;
    } 

    const MessagesMap_t* entry = message_map_entry(last_frame_header.id);
    if(entry)
    {
        dispatch(entry, contents, last_frame_header.len);
    } else {
        ++msg_stats.unknown_dispatch_entry;
    }
}

void msg_init(const MessagesMap_t* map)
{
    assert(map != NULL);

    MessagesMap = map;
    usb_set_rx_callback(handle_usb_rx);
}

