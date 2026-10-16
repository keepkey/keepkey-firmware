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

#ifndef MSG_DISPATCH_H
#define MSG_DISPATCH_H

#include "keepkey/transport/interface.h"

#include "keepkey/board/usb.h"

#include <stdint.h>
#include <stdbool.h>

#define MSG_TINY_BFR_SZ 64
#define MSG_TINY_TYPE_ERROR 0xFFFF

/* True while unwinding a handler already answered by a tiny receive Failure. */
bool msg_handler_rejected(void);
/* Called from nested waits that never return to the main loop, so the
 * firmware's auto-lock clock is sampled at least about once a second. */
void keepkey_idle_clock_sample(void);
/* Reject a decoded tiny reply that does not belong to the waiting handler. */
void msg_reject_unexpected_tiny(void);
/* A short main/debug USB packet drops any partly reassembled message and,
 * inside a tiny wait, fails that wait. */
void msg_reject_short_tiny_packet(void);

/* Dense entries, linear lookup. Field order must match MessagesMap_t;
 * fsm.c guards duplicate IDs at compile time. */
#define MSG_IN(ID, STRUCT_NAME, PROCESS_FUNC) \
  {(STRUCT_NAME##_fields),                    \
   (void (*)(void*))(PROCESS_FUNC),           \
   PARSABLE,                                  \
   NORMAL_MSG,                                \
   IN_MSG,                                    \
   (ID)},

#define MSG_OUT(ID, STRUCT_NAME, PROCESS_FUNC) \
  {(STRUCT_NAME##_fields),                     \
   (void (*)(void*))(PROCESS_FUNC),            \
   PARSABLE,                                   \
   NORMAL_MSG,                                 \
   OUT_MSG,                                    \
   (ID)},

#define RAW_IN(ID, STRUCT_NAME, PROCESS_FUNC) \
  {(STRUCT_NAME##_fields),                    \
   (void (*)(void*))(void*)(PROCESS_FUNC),    \
   RAW,                                       \
   NORMAL_MSG,                                \
   IN_MSG,                                    \
   (ID)},

#define DEBUG_IN(ID, STRUCT_NAME, PROCESS_FUNC) \
  {(STRUCT_NAME##_fields),                      \
   (void (*)(void*))(PROCESS_FUNC),             \
   PARSABLE,                                    \
   DEBUG_MSG,                                   \
   IN_MSG,                                      \
   (ID)},

#define DEBUG_OUT(ID, STRUCT_NAME, PROCESS_FUNC) \
  {(STRUCT_NAME##_fields),                       \
   (void (*)(void*))(PROCESS_FUNC),              \
   PARSABLE,                                     \
   DEBUG_MSG,                                    \
   OUT_MSG,                                      \
   (ID)},

#define NO_PROCESS_FUNC 0

typedef void (*msg_handler_t)(void* ptr);
typedef void (*msg_failure_t)(FailureType, const char*);
typedef bool (*usb_tx_handler_t)(uint8_t*, uint32_t);

#if DEBUG_LINK
typedef void (*msg_debug_link_get_state_t)(DebugLinkGetState*);
#endif

typedef enum {
  NORMAL_MSG,
#if DEBUG_LINK
  DEBUG_MSG,
#endif
} MessageMapType;

typedef enum { IN_MSG, OUT_MSG } MessageMapDirection;

typedef enum { PARSABLE, RAW } MessageMapDispatch;

typedef struct {
  const pb_field_t* fields;
  msg_handler_t process_func;
  MessageMapDispatch dispatch;
  MessageMapType type;
  MessageMapDirection dir;
  MessageType msg_id;
} MessagesMap_t;

typedef struct {
  const uint8_t* buffer;
  uint32_t length;
} RawMessage;

typedef enum {
  RAW_MESSAGE_NOT_STARTED,
  RAW_MESSAGE_STARTED,
  RAW_MESSAGE_COMPLETE,
  RAW_MESSAGE_ERROR
} RawMessageState;

typedef void (*raw_msg_handler_t)(RawMessage* msg, uint32_t frame_length);

const pb_field_t* message_fields(MessageMapType type, MessageType msg_id,
                                 MessageMapDirection dir);

/* Acquiring the frame arena drops any partial inbound frame (see
 * messages.c). Single-threaded transport only. */
TrezorFrameBuffer* frame_arena_tx(void);
uint16_t* frame_arena_scratch2049(void);

/* Request storage reused as response scratch: copy needed fields first. */
void* msg_decoded_request_response_scratch(void);

bool msg_write(MessageType msg_id, const void* msg);

#if DEBUG_LINK
bool msg_debug_write(MessageType msg_id, const void* msg);
#endif

void msg_map_init(const void* map, const size_t size);
void set_msg_failure_handler(msg_failure_t failure_func);
void call_msg_failure_handler(FailureType code, const char* text);

#if DEBUG_LINK
void set_msg_debug_link_get_state_handler(
    msg_debug_link_get_state_t debug_link_get_state_func);
void call_msg_debug_link_get_state_handler(DebugLinkGetState* msg);
#endif

void msg_init(void);

void handle_usb_rx(const void* msg, size_t len);
#if DEBUG_LINK
void handle_debug_usb_rx(const void* msg, size_t len);
#endif

MessageType wait_for_tiny_msg(uint8_t* buf);
MessageType check_for_tiny_msg(uint8_t* buf);
/* Route main and debug frames to the tiny reader, which never dispatches a
 * handler. Returns the previous setting. */
bool msg_set_tiny(bool set);
/* For a tiny wait that suspends no handler (U2F): true if a frame was
 * rejected, and so a Failure was sent, since the last call. Clears it, so the
 * next rejected frame is answered too. */
bool msg_take_tiny_rejection(void);
/* For the same wait: the tiny message received since the last call, without
 * its payload, or MSG_TINY_TYPE_ERROR. Nothing else reads it there. */
MessageType msg_take_tiny_id(void);
/* The firmware's authorization boundary, run before a message is dispatched;
 * false means it was refused and answered. Board-only targets default to
 * true. */
bool keepkey_before_message_dispatch(MessageType msg_id);

uint32_t parse_pb_varint(RawMessage* msg, uint8_t varint_count);
int encode_pb(const void* source_ptr, const pb_field_t* fields, uint8_t* buffer,
              uint32_t len);
#endif
