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


// SimpleSignTx_size is the largest message we operate with
#if MAX_FRAME_SIZE < SimpleSignTx_size
#error "MAX_FRAME_SIZE is too small!"
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

static const MessagesMap_t *MessagesMap = NULL;
static const RawMessagesMap_t *RawMessagesMap = NULL;

static msg_success_t msg_success;
static msg_failure_t msg_failure;
static msg_initialize_t msg_initialize;

/*
 * Get message map entry if one exists
 */

const MessagesMap_t* message_map_entry(MessageType type)
{
    const MessagesMap_t *m = MessagesMap;
    while(m->dir) {
        if(type == m->msg_id)
        {
            return m;
        }
        ++m;
    }

    return NULL;
}

/*
 * Get a raw message map entry if one exists
 */
const RawMessagesMap_t* raw_message_map_entry(MessageType type)
{
    const RawMessagesMap_t *m = RawMessagesMap;
    while(m->dir) {
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
    while (m->dir) {
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

bool pb_parse(const MessagesMap_t* entry, uint8_t *msg, uint32_t msg_size, uint8_t *buf)
{
	pb_istream_t stream = pb_istream_from_buffer(msg, msg_size);
	return pb_decode(&stream, entry->fields, buf);
}

void dispatch(const MessagesMap_t* entry, uint8_t *msg, uint32_t msg_size)
{
    static uint8_t decode_buffer[MAX_DECODE_SIZE];

    if(pb_parse(entry, msg, msg_size, decode_buffer))
    {
        if(entry->process_func) 
            entry->process_func(decode_buffer);
        else
        	(*msg_failure)(FailureType_Failure_UnexpectedMessage, "Unexpected message");
    } else {
    	(*msg_failure)(FailureType_Failure_UnexpectedMessage, "Could not parse protocol buffer message");
    }
}

void raw_dispatch(const RawMessagesMap_t* entry, uint8_t *msg, uint32_t msg_size, uint32_t frame_length)
{
	if(entry->process_func)
	{
		entry->process_func(msg, msg_size, frame_length);
	}
}

/*
 * Tiny messages
 */
static bool msg_tiny_flag = false;
static uint8_t msg_tiny[64];
static uint16_t msg_tiny_id = 0xFFFF;

MessageType wait_for_tiny_msg(uint8_t *buf)
{
	check_for_tiny_msg(true);
	/* copy tiny message buffer */
	memcpy(buf, msg_tiny, sizeof(msg_tiny)); 

	return(msg_tiny_id);
}

MessageType check_for_tiny_msg(bool block)
{
	msg_tiny_id = 0xFFFF; /* Init */
	msg_tiny_flag = true; /* Turn on tiny msg */

    /* poll until "msg_tiny_id" is updated */
	while(msg_tiny_id == 0xFFFF) {
		usb_poll();
		if(!block){
			break;
        }
	}
	/* Turn off tiny msg */
	msg_tiny_flag = false;

	/* Return msg id */
	return(msg_tiny_id);
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
	 * Frame content buffer, position, size, and frame tracking
	 */
	static TrezorFrameBuffer framebuf;
	static uint32_t content_pos = 0;
	static uint32_t content_size = 0;
	static bool mid_frame = false;

	/*
	 * Current segment content
	 */
	uint8_t* contents = NULL;

    /*
     * Check to see if this is the first frame of a series,
     * or a continuation/fragment.
     */
    static TrezorFrameHeaderFirst last_frame_header = 
    {
        .id = 0xffff,
        .len = 0
    };

    if(frame->header.pre1 == '#' && frame->header.pre2 == '#' && !mid_frame)
    {
        /*
         * Byte swap in place.
         */
        last_frame_header.id = __builtin_bswap16(frame->header.id);
        last_frame_header.len = __builtin_bswap32(frame->header.len);

        contents = frame->contents;

        /*
		 * Init content pos and size
		 */
		content_pos = msg->len - 9;
		content_size = content_pos;

    } else {
    	contents = ((TrezorFrameFragment*)msg->message)->contents;

    	content_pos += msg->len - 1;
		content_size = msg->len - 1;
    }

    bool last_segment = content_pos >= last_frame_header.len;
    mid_frame = !last_segment;

    /*
	 * Determine callback handler and message map type
	 */
	MessageMapType map_type;
	const void* entry;
	if(entry = message_map_entry(last_frame_header.id))
		map_type = MESSAGE_MAP;
	else if(entry = raw_message_map_entry(last_frame_header.id))
		map_type = RAW_MESSAGE_MAP;
	else
		map_type = NO_MAP;

    /*
     * Check for a message map entry for protocol buffer messages
     */
    if(map_type == MESSAGE_MAP)
    {
    	/*
    	 * Copy content to frame buffer
    	 */
    	if(content_size == content_pos)
    		memcpy(framebuf.buffer, contents, content_pos);
    	else
    		memcpy(framebuf.buffer + (content_pos - (msg->len - 1)), contents, msg->len - 1);

    /*
     * Check for raw messages that bypass protocol buffer parsing
     */
    } else if(map_type == RAW_MESSAGE_MAP) {


    	/* call dispatch for every segment since we are not buffering and parsing, and
    	 * assume the raw dispatched callbacks will handle their own state and
    	 * buffering internally
    	 */
    	raw_dispatch((RawMessagesMap_t*)entry, contents, content_size, last_frame_header.len);
    }

    /*
     * Only parse and message map if all segments have been buffered
     * and this message type is parsable
     */
    if (last_segment && map_type == MESSAGE_MAP)
    	if(!msg_tiny_flag)
    		dispatch((MessagesMap_t*)entry, framebuf.buffer, last_frame_header.len);
    	else
    	{
    		bool status = pb_parse((MessagesMap_t*)entry, framebuf.buffer, last_frame_header.len, msg_tiny);

    		if(status)
    			msg_tiny_id = last_frame_header.id;
    		else
    			call_msg_failure_handler(FailureType_Failure_UnexpectedMessage, "Could not parse protocol buffer message");
    	}

    /*
     * Catch messages that are not in message maps
     */
    else if(last_segment && map_type == NO_MAP)
	{
    	++msg_stats.unknown_dispatch_entry;

    	(*msg_failure)(FailureType_Failure_UnexpectedMessage, "Unknown message");
	}
}

void msg_map_init(const void* map, MessageMapType type)
{
    assert(map != NULL);

    if(type == MESSAGE_MAP)
    	MessagesMap = map;
    else
    	RawMessagesMap = map;
}

void set_msg_success_handler(msg_success_t success_func)
{
	msg_success = success_func;
}

void set_msg_failure_handler(msg_failure_t failure_func)
{
	msg_failure = failure_func;
}

void set_msg_initialize_handler(msg_initialize_t initialize_func)
{
	msg_initialize = initialize_func;
}

void call_msg_success_handler(const char *text)
{
	if(msg_success)
		(*msg_success)(text);
}

void call_msg_failure_handler(FailureType code, const char *text)
{
	if(msg_failure)
		(*msg_failure)(code, text);
}

void call_msg_initialize_handler(void)
{
	if(msg_initialize)
		(*msg_initialize)((Initialize *)0);
}

void msg_init()
{
    usb_set_rx_callback(handle_usb_rx);
}
