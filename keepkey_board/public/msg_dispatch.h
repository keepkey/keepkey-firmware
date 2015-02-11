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

#ifndef __MESSAGES_H__
#define __MESSAGES_H__

#include <stdint.h>
#include <stdbool.h>
#include <interface.h>

/***************** #defines ******************************/
#define MSG_TINY_BFR_SZ     64
#define MSG_TINY_TYPE_ERROR 0xFFFF

/***************** Typedefs and enums  *******************/
typedef void (*msg_handler_t)(void *ptr);
typedef void (*raw_msg_handler_t)(uint8_t *msg, uint32_t msg_size, uint32_t frame_length);
typedef void (*msg_failure_t)(FailureType, const char *);
typedef bool (*usb_tx_handler_t)(void*, uint32_t);
#if DEBUG_LINK
typedef void (*msg_debug_link_get_state_t)(DebugLinkGetState *);
#endif

typedef enum
{
    NORMAL_MSG,
	RAW_MSG,
#if DEBUG_LINK
	DEBUG_MSG,
#endif
	UNKNOWN_MSG,
	END_OF_MAP
} MessageMapType;

typedef enum
{
    IN_MSG,
	OUT_MSG
} MessageMapDirection;

typedef struct
{
    uint16_t runt_packet;
    uint16_t invalid_usb_header;
    uint16_t invalid_msg_type;
    uint16_t unknown_dispatch_entry;
    uint16_t usb_tx;
    uint16_t usb_tx_err;
} MsgStats;

typedef struct 
{
	MessageMapType type;
	MessageMapDirection dir;
    MessageType msg_id;
    const pb_field_t *fields;
    msg_handler_t process_func;
} MessagesMap_t;

/***************** Function Declarations ******************/
bool msg_write(MessageType type, const void* msg);

#if DEBUG_LINK
bool msg_debug_write(MessageType type, const void *msg);
#endif

void msg_map_init(const void* map);

/* Message failure and debug link get state callback */
void set_msg_failure_handler(msg_failure_t failure_func);
void call_msg_failure_handler(FailureType code, const char *text);
#if DEBUG_LINK
void set_msg_debug_link_get_state_handler(msg_debug_link_get_state_t debug_link_get_state_func);
void call_msg_debug_link_get_state_handler(DebugLinkGetState *msg);
#endif

/* Assign callback for USB interrupt handling */
void msg_init();

/* Tiny messages */
MessageType wait_for_tiny_msg(uint8_t *buf);
MessageType check_for_tiny_msg(uint8_t *buf);
MessageType tiny_msg_poll(bool block);

#endif
