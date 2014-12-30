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

#ifndef __MESSAGES_H__
#define __MESSAGES_H__

#include <stdint.h>
#include <stdbool.h>

#include <interface.h>

typedef enum
{
    MESSAGE_MAP,
	RAW_MESSAGE_MAP,
	NO_MAP
} MessageMapType;

typedef struct {
    char dir; 	// i = in, o = out
    MessageType msg_id;
    const pb_field_t *fields;
    void (*process_func)(void *ptr);
} MessagesMap_t;

typedef struct {
	char dir; 	// i = in, o = out
    MessageType msg_id;
    void (*process_func)(uint8_t *msg, uint32_t msg_size, uint32_t frame_length);
} RawMessagesMap_t;

typedef void (*msg_success_t)(const char *);
typedef void (*msg_failure_t)(FailureType, const char *);
typedef void (*msg_initialize_t)(Initialize *);

/*
 *
 * @param type The pb type of the message.
 * @param msg The message structure to encode and send.
 *
 * @return true if the message is successfully encoded and sent.
 */
bool msg_write(MessageType type, const void* msg);

/*
 * Initializes the messaging subsystem with a set of callback handlers for each
 * expected message type.
 */
void msg_map_init(const void* map, MessageMapType type);

/*
 * Message failure and message init callback
 */
void set_msg_success_handler(msg_success_t success_func);
void set_msg_failure_handler(msg_failure_t failure_func);
void set_msg_initialize_handler(msg_initialize_t initialize_func);
void call_msg_success_handler(const char *text);
void call_msg_failure_handler(FailureType code, const char *text);
void call_msg_initialize_handler(void);

/*
 * Assign callback for USB interrupt handling
 */
void msg_init();

/*
 * Tiny messages
 */
MessageType wait_for_tiny_msg(uint8_t *buf);
MessageType check_for_tiny_msg(bool block);

#endif
