/* START KEEPKEY LICENSE */
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
 *
 */
/* END KEEPKEY LICENSE */

#include <assert.h>
#include <string.h>
#include <usb_driver.h>
#include "msg_dispatch.h"

#include <nanopb.h>


// SimpleSignTx_size is the largest message we operate with
#if MAX_FRAME_SIZE < SimpleSignTx_size
#error "MAX_FRAME_SIZE is too small!"
#endif

/*************** Static and Global variables ****************/
static MsgStats msg_stats;
static const MessagesMap_t *MessagesMap = NULL;
static msg_success_t msg_success;
static msg_failure_t msg_failure;
static msg_initialize_t msg_initialize;
#if DEBUG_LINK
static msg_debug_link_get_state_t msg_debug_link_get_state;
#endif

/* Tiny messages */
static bool msg_tiny_flag = false;
static uint8_t msg_tiny[MSG_TINY_BFR_SZ];
static uint16_t msg_tiny_id = MSG_TINY_TYPE_ERROR; /* default to error type*/

/*
 * message_map_entry() - get message map entry that matches message type
 *                       in MessagesMap[] array 
 *
 * INPUT -
 *      type - massage type
 * OUTPUT -
 *      pointer to message  
 */
const MessagesMap_t* message_map_entry(MessageMapType type, MessageMapDirection dir, MessageType msg_id)
{
    const MessagesMap_t *m = MessagesMap;
    while(m->type != END_OF_MAP) {
        if(type == m->type && dir == m->dir && msg_id == m->msg_id) {
            return m;
        }
        ++m;
    }
    return NULL;
}

/*
 * message_fields() - get protocol buffer in message map entry that matches message type 
 *                            in MessagesMap[] array
 *
 * INPUT -
 *      type - massage type
 * OUTPUT -
 *      pointer to protocol buffer
 */
const pb_field_t* message_fields(MessageMapType type, MessageMapDirection dir, MessageType msg_id)
{
    assert(MessagesMap != NULL);

    const MessagesMap_t *m = MessagesMap;
    while (m->type != END_OF_MAP) {
    	if(type == m->type && dir == m->dir && msg_id == m->msg_id) {
            return m->fields;
        }
        m++;
    }
    return NULL;
}

/*
 * usb_write_pb() - add usb frame header info to message buffer and perform usb transmission
 *
 * INPUT -
 *      *fields - 
 *      *msg - pointer to message buffer 
 *      id - message ID 
 * OUTPUT - 
 *      none
 */
void usb_write_pb(const pb_field_t* fields, const void* msg, MessageType id, usb_tx_handler_t usb_tx_handler)
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

    bool ret = (*usb_tx_handler)(&framebuf, sizeof(framebuf.frame) + os.bytes_written);
    ret ? msg_stats.usb_tx++ : msg_stats.usb_tx_err++;
}


/*
 * msg_write() - transmit message over usb port
 *
 * INPUT - 
 *      type - massage type
 *      *msg - pointer to message buffer 
 * OUTPUT -
 *      true/false status
 */
bool msg_write(MessageType type, const void *msg)
{
    const pb_field_t *fields = message_fields(NORMAL_MSG, OUT_MSG, type);
    if (!fields) { // unknown message
        return(false);
    }
    /* add frame header to message and transmit out to usb */
    usb_write_pb(fields, msg, type, &usb_tx);
    return(true);
}

/*
 * msg_debug_write() - transmit message over usb port on debug endpoint
 *
 * INPUT -
 *      type - massage type
 *      *msg - pointer to message buffer
 * OUTPUT -
 *      true/false status
 */
#if DEBUG_LINK
bool msg_debug_write(MessageType type, const void *msg)
{
    const pb_field_t *fields = message_fields(DEBUG_MSG, OUT_MSG, type);
    if (!fields) { // unknown message
        return(false);
    }
    /* add frame header to message and transmit out to usb */
    usb_write_pb(fields, msg, type, &usb_debug_tx);
    return(true);
}
#endif

/*
 * pb_parse() - process usb message by protocol buffer
 *
 * INPUT - 
 *      *entry - pointer to message entry
 *      *msg - pointer to received message buffer
 *      msg_size - size of message
 *      *buf - pointer to destination buffer
 * OUTPUT -
 *
 */
bool pb_parse(const MessagesMap_t* entry, uint8_t *msg, uint32_t msg_size, uint8_t *buf)
{
	pb_istream_t stream = pb_istream_from_buffer(msg, msg_size);
	return(pb_decode(&stream, entry->fields, buf));
}

/*
 * dispatch() - process received message and jump to corresponding process function
 *
 * INPUT - 
 *      *entry - pointer to message entry
 *      *msg - pointer to received message buffer
 *      msg_size - size of message
 * OUTPUT -
 *      none
 *
 */
void dispatch(const MessagesMap_t* entry, uint8_t *msg, uint32_t msg_size)
{
    static uint8_t decode_buffer[MAX_DECODE_SIZE];

    if(pb_parse(entry, msg, msg_size, decode_buffer)) {
        if(entry->process_func) { 
            entry->process_func(decode_buffer);
        } else {
        	(*msg_failure)(FailureType_Failure_UnexpectedMessage, "Unexpected message");
        }
    } else {
    	(*msg_failure)(FailureType_Failure_UnexpectedMessage, "Could not parse protocol buffer message");
    }
}

/*
 * raw_dispatch() - process received message and jump to corresponding 
 *                  process function (used by bootloader)
 *
 * INPUT -
 *      *entry - pointer to message entry
 *      *msg - pointer to received message buffer
 *      msg_size - size of message
 *      frame_length - 
 * OUTPUT -
 *      none
 */
void raw_dispatch(const MessagesMap_t* entry, uint8_t *msg, uint32_t msg_size, uint32_t frame_length)
{
	if(entry->process_func)
	{
		((raw_msg_handler_t)entry->process_func)(msg, msg_size, frame_length);
	}
}

/*
 * wait_for_tiny_msg() - wait for usb tiny message type from host
 *
 * INPUT -
 *      *buf - pointer to destination buffer
 * OUTPUT -
 *      message tiny type  
 *
 */
MessageType wait_for_tiny_msg(uint8_t *buf)
{
    MessageType ret_msg_tiny_type;

    ret_msg_tiny_type = tiny_msg_poll(true);

    if(ret_msg_tiny_type != MSG_TINY_TYPE_ERROR) {
	    /* copy tiny message buffer */
	    memcpy(buf, msg_tiny, sizeof(msg_tiny)); 
    } 
    return(ret_msg_tiny_type);
}

/*
 * check_for_tiny_msg() - check for usb tiny message type from host
 *
 * INPUT -
 *      *buf - pointer to destination buffer
 * OUTPUT -
 *      message tiny type
 *
 */
MessageType check_for_tiny_msg(uint8_t *buf)
{
    MessageType ret_msg_tiny_type;

    ret_msg_tiny_type = tiny_msg_poll(false);

    if(ret_msg_tiny_type != MSG_TINY_TYPE_ERROR) {
	    /* copy tiny message buffer */
	    memcpy(buf, msg_tiny, sizeof(msg_tiny));
    }
    return(ret_msg_tiny_type);
}

/*
 * poll_for_tiny_msg(bool block) - poll usb port to check for tiny message from host
 *
 * INPUT - 
 *      block - flag to continually poll usb until tiny message is received
 * OUTPUT -
 *      message type
 *      
 */
MessageType tiny_msg_poll(bool block)
{
	msg_tiny_id = MSG_TINY_TYPE_ERROR; /* Init */
	msg_tiny_flag = true; /* Turn on tiny msg */

    /* poll until "msg_tiny_id" is updated */
	while(msg_tiny_id == MSG_TINY_TYPE_ERROR) {
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


/*
 * handle_usb_rx() - handler for USB message from host
 * 
 * INPUT -
 *      *msg - pointer to message received from host
 * OUTPUT -
 *      none
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

    /* Frame content buffer, position, size, and frame tracking */
	static TrezorFrameBuffer framebuf;
	static uint32_t content_pos = 0;
	static uint32_t content_size = 0;
	static bool mid_frame = false;

	/* Current segment content */
	uint8_t* contents = NULL;

    /* Check to see if this is the first frame of a series, * or a 
       continuation/fragment.  */
    static TrezorFrameHeaderFirst last_frame_header = { .id = 0xffff, .len = 0 };

    if(frame->header.pre1 == '#' && frame->header.pre2 == '#' && !mid_frame)
    {
        /* Byte swap in place. */
        last_frame_header.id = __builtin_bswap16(frame->header.id);
        last_frame_header.len = __builtin_bswap32(frame->header.len);

        contents = frame->contents;

        /* Init content pos and size */
		content_pos = msg->len - 9;
		content_size = content_pos;

    } else {
    	contents = ((TrezorFrameFragment*)msg->message)->contents;

    	content_pos += msg->len - 1;
		content_size = msg->len - 1;
    }

    bool last_segment = content_pos >= last_frame_header.len;
    mid_frame = !last_segment;

    /* Determine callback handler and message map type */
    const MessagesMap_t* entry;
	MessageMapType map_type;

	if(entry = message_map_entry(NORMAL_MSG, IN_MSG, last_frame_header.id)) {
		map_type = NORMAL_MSG;
#if DEBUG_LINK
	} else if(entry = message_map_entry(DEBUG_MSG, IN_MSG, last_frame_header.id)) {
		map_type = DEBUG_MSG;
#endif
    } else if(entry = message_map_entry(RAW_MSG, IN_MSG, last_frame_header.id)) {
		map_type = RAW_MSG;
    } else {
		map_type = UNKNOWN_MSG;
    }

    /* Check for a message map entry for protocol buffer messages */
#if DEBUG_LINK
	if(map_type == NORMAL_MSG || map_type == DEBUG_MSG)
#else
	if(map_type == NORMAL_MSG)
#endif
    {
    	/* Copy content to frame buffer */
    	if(content_size == content_pos)
    		memcpy(framebuf.buffer, contents, content_pos);
    	else
    		memcpy(framebuf.buffer + (content_pos - (msg->len - 1)), contents, msg->len - 1);

    /* Check for raw messages that bypass protocol buffer parsing */
    } else if(map_type == RAW_MSG) {


    	/* call dispatch for every segment since we are not buffering and parsing, and
    	 * assume the raw dispatched callbacks will handle their own state and
    	 * buffering internally
    	 */
    	raw_dispatch(entry, contents, content_size, last_frame_header.len);
    }

    /*
     * Only parse and message map if all segments have been buffered
     * and this message type is parsable
     */
#if DEBUG_LINK
	if (last_segment && (map_type == NORMAL_MSG || map_type == DEBUG_MSG))
#else
	if (last_segment && map_type == NORMAL_MSG)
#endif
    	if(!msg_tiny_flag) {
    		dispatch(entry, framebuf.buffer, last_frame_header.len);
        } else {
    		bool status = pb_parse(entry, framebuf.buffer, last_frame_header.len, msg_tiny);

    		if(status) {
    			msg_tiny_id = last_frame_header.id;
            } else {
    			call_msg_failure_handler(FailureType_Failure_UnexpectedMessage, 
                        "Could not parse protocol buffer message");
            }
    	}

    /* Catch messages that are not in message maps */
    else if(last_segment && map_type == UNKNOWN_MSG)
	{
    	++msg_stats.unknown_dispatch_entry;

    	(*msg_failure)(FailureType_Failure_UnexpectedMessage, "Unknown message");
	}
}

/*
 * msg_map_init() - setup message map with corresping message type
 *
 * INPUT -
 *      *map - pointer message map array
 *      type - message type
 * OUTPUT -
 *
 */
void msg_map_init(const void *map)
{
    assert(map != NULL);
    MessagesMap = map;
}

/*
 * set_msg_success_handler() - setup usb message success handler
 *
 * INPUT - 
 *      success_func - message success handler
 * OUTPUT -
 *      none
 */
void set_msg_success_handler(msg_success_t success_func)
{
	msg_success = success_func;
}
/*
 * set_msg_failure_handler() - setup usb message failure handler
 *
 * INPUT - 
 *      failure_func - message failure handler
 * OUTPUT -
 *      none
 */
void set_msg_failure_handler(msg_failure_t failure_func)
{
	msg_failure = failure_func;
}

/*
 * set_msg_initialize_handler() - setup usb message initialization handler 
 *
 * INPUT - 
 *      initialize_func - message initialization handler
 * OUTPUT -
 *      none
 */
void set_msg_initialize_handler(msg_initialize_t initialize_func)
{
	msg_initialize = initialize_func;
}

/*
 * set_msg_debug_link_get_state_handler() - setup usb message debug link get state handler
 *
 * INPUT -
 *      debug_link_get_state_func - message initialization handler
 * OUTPUT -
 *      none
 */
#if DEBUG_LINK
void set_msg_debug_link_get_state_handler(msg_debug_link_get_state_t debug_link_get_state_func)
{
	msg_debug_link_get_state = debug_link_get_state_func;
}
#endif

/*
 * call_msg_success_handler() - call message success handler
 *
 * INPUT -
 *      *text - pointer function arguments
 * OUTPUT -
 *      none
 */
void call_msg_success_handler(const char *text)
{
	if(msg_success)
		(*msg_success)(text);
}

/*
 * call_msg_failure_handler() - call message failure handler
 *
 * INPUT -
 *      code - failure code 
 *      *text - pinter to function arguments  
 * OUTPUT -
 */
void call_msg_failure_handler(FailureType code, const char *text)
{
	if(msg_failure)
		(*msg_failure)(code, text);
}

/*
 * call_msg_initialize_handler() - call message initialization handler
 *
 * INPUT - none
 * OUTPUT - none
 */
void call_msg_initialize_handler(void)
{
	if(msg_initialize)
		(*msg_initialize)((Initialize *)0);
}

/*
 * call_msg_debug_link_get_state_handler() - call message debug link get state handler
 *
 * INPUT - none
 * OUTPUT - none
 */
#if DEBUG_LINK
void call_msg_debug_link_get_state_handler(DebugLinkGetState *msg)
{
	if(msg_debug_link_get_state)
		(*msg_debug_link_get_state)(msg);
}
#endif

/*
 * msg_init() - setup usb receive callback handler
 *
 * INPUT - none
 * OUTPUT - none
 */
void msg_init()
{
    usb_set_rx_callback(handle_usb_rx);
}
