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

#include <messages.pb.h>

#define MSG_IN_SIZE (24*1024)
#define MSG_OUT_SIZE (9*1024)

/**
 * Call prior to any other messaging routines.  This initializes the messaging subsystem 
 * and sets up any required callbacks.
 */
void msg_init(void);

/**
 *
 * @param type The pb type of the message.
 * @param msg The message structure to encode and send.
 *
 * @return true if the message is successfully encoded and sent.
 */
bool msg_write(MessageType type, const void* msg);

#endif
