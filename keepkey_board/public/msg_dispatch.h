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
typedef void (*msg_success_t)(const char *);
typedef void (*msg_failure_t)(FailureType, const char *);
typedef void (*msg_initialize_t)(Initialize *);
typedef bool (*usb_tx_handler_t)(void*, uint32_t);

typedef enum
{
    NORMAL_MSG,
	RAW_MSG,
	DEBUG_MSG,
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

/* Message failure and message init callback */
void set_msg_success_handler(msg_success_t success_func);
void set_msg_failure_handler(msg_failure_t failure_func);
void set_msg_initialize_handler(msg_initialize_t initialize_func);
void call_msg_success_handler(const char *text);
void call_msg_failure_handler(FailureType code, const char *text);
void call_msg_initialize_handler(void);

/* Assign callback for USB interrupt handling */
void msg_init();

/* Tiny messages */
MessageType wait_for_tiny_msg(uint8_t *buf);
MessageType check_for_tiny_msg(uint8_t *buf);
MessageType tiny_msg_poll(bool block);

#endif
