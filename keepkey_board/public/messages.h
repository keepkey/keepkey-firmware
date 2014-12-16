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

typedef void (*msg_failure_t)(void);

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
 * Initializes message failure callback
 */
void msg_unknown_failure_init(msg_failure_t failure_func);

/*
 * Assign callback for USB interrupt handling
 */
void msg_init();

#endif
