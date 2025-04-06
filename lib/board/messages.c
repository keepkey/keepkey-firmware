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

#include "keepkey/board/usb.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/variant.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/util.h"

#include <nanopb.h>

#include <assert.h>
#include <string.h>

static const MessagesMap_t *MessagesMap = NULL;
static size_t map_size = 0;
static msg_failure_t msg_failure;

#if DEBUG_LINK
static msg_debug_link_get_state_t msg_debug_link_get_state;
#endif

/* Allow mapped messages to reset message stack.  This variable by itself
 * doesn't do much but messages down the line can use it to determine for to
 * gracefully exit from a message should the message stack been reset
 */
bool reset_msg_stack = false;

/*
 * message_map_entry() - Finds a requested message map entry
 *
 * INPUT
 *     - type: type of message (normal or debug)
 *     - msg_id: message id
 *     - dir: direction of message
 * OUTPUT
 *     entry if found
 */
static const MessagesMap_t *message_map_entry(MessageMapType type,
                                              MessageType msg_id,
                                              MessageMapDirection dir) {
  const MessagesMap_t *m = MessagesMap;

  if (map_size > msg_id && m[msg_id].msg_id == msg_id &&
      m[msg_id].type == type && m[msg_id].dir == dir) {
    return &m[msg_id];
  }

  return NULL;
}

/*
 * message_fields() - Get protocol buffer for requested message map entry
 *
 * INPUT
 *     - type: type of message (normal or debug)
 *     - msg_id: message id
 *     - dir: direction of message
 * OUTPUT
 *      protocol buffer
 */
const pb_msgdesc_t *message_fields(MessageMapType type, MessageType msg_id,
                                 MessageMapDirection dir) {
  assert(MessagesMap != NULL);

  const MessagesMap_t *m = MessagesMap;

  if (map_size > msg_id && m[msg_id].msg_id == msg_id &&
      m[msg_id].type == type && m[msg_id].dir == dir) {
    return m[msg_id].fields;
  }

  return NULL;
}

/*
 * pb_parse() - Process USB message by protocol buffer
 *
 * INPUT
 *     - entry: pointer to message entry
 *     - msg: pointer to received message buffer
 *     - msg_size: size of message
 *     - buf: pointer to destination buffer
 * OUTPUT
 *     true/false whether protocol buffers were parsed successfully
 */
static bool pb_parse(const MessagesMap_t *entry, uint8_t *msg,
                     uint32_t msg_size, uint8_t *buf) {
  pb_istream_t stream = pb_istream_from_buffer(msg, msg_size);
  return pb_decode(&stream, entry->fields, buf);
}

/*
 * dispatch() - Process received message and jump to corresponding process
 * function
 *
 * INPUT
 *     - entry: pointer to message entry
 *     - msg: pointer to received message buffer
 *     - msg_size: size of message
 * OUTPUT
 *     none
 *
 */
static void dispatch(const MessagesMap_t *entry, uint8_t *msg,
                     uint32_t msg_size) {
  static uint8_t decode_buffer[MAX_DECODE_SIZE] __attribute__((aligned(4)));
  memset(decode_buffer, 0, sizeof(decode_buffer));

  if (!pb_parse(entry, msg, msg_size, decode_buffer)) {
    (*msg_failure)(FailureType_Failure_UnexpectedMessage,
                   "Could not parse protocol buffer message");
    return;
  }

  if (!entry->process_func) {
    (*msg_failure)(FailureType_Failure_UnexpectedMessage, "Unexpected message");
    return;
  }

  entry->process_func(decode_buffer);
}

/*
 * raw_dispatch() - Process messages that will not be parsed by protocol buffers
 * and should be manually parsed at message function
 *
 * INPUT
 *     - entry: pointer to message entry
 *     - msg: pointer to received message buffer
 *     - msg_size: size of message
 *     - frame_length: total expected size
 * OUTPUT
 *     none
 */
static void raw_dispatch(const MessagesMap_t *entry, const uint8_t *msg,
                         uint32_t msg_size, uint32_t frame_length) {
  static RawMessage raw_msg;
  raw_msg.buffer = msg;
  raw_msg.length = msg_size;

  if (entry->process_func) {
    ((raw_msg_handler_t)(void *)entry->process_func)(&raw_msg, frame_length);
  }
}

#if !defined(__has_builtin)
#define __has_builtin(X) 0
#endif
#if __has_builtin(__builtin_add_overflow)
#define check_uadd_overflow(A, B, R)                               \
  ({                                                               \
    typeof(A) __a = (A);                                           \
    typeof(B) __b = (B);                                           \
    typeof(R) __r = (R);                                           \
    (void)(&__a == &__b && "types must match");                    \
    (void)(&__a == __r && "types must match");                     \
    _Static_assert(0 < (typeof(A)) - 1, "types must be unsigned"); \
    __builtin_add_overflow((A), (B), (R));                         \
  })
#else
#define check_uadd_overflow(A, B, R)                               \
  ({                                                               \
    typeof(A) __a = (A);                                           \
    typeof(B) __b = (B);                                           \
    typeof(R) __r = (R);                                           \
    (void)(&__a == &__b);                                          \
    (void)(&__a == __r);                                           \
    (void)(&__a == &__b && "types must match");                    \
    (void)(&__a == __r && "types must match");                     \
    _Static_assert(0 < (typeof(A)) - 1, "types must be unsigned"); \
    *__r = __a + __b;                                              \
    *__r < __a;                                                    \
  })
#endif

/// Common helper that handles USB messages from host
void usb_rx_helper(const uint8_t *buf, size_t length, MessageMapType type) {
  static bool firstFrame = true;

  static uint16_t msgId;
  static uint32_t msgSize;
  static uint8_t msg[MAX_FRAME_SIZE];
  static size_t
      cursor;  //< Index into msg where the current frame is to be written.
  static const MessagesMap_t *entry;

  if (firstFrame) {
    msgId = 0xffff;
    msgSize = 0;
    memset(msg, 0, sizeof(msg));
    cursor = 0;
    entry = NULL;
  }

  assert(buf != NULL);

  if (length < 1 + 2 + 2 + 4) {
    (*msg_failure)(FailureType_Failure_UnexpectedMessage, "Buffer too small");
    goto reset;
  }

  if (buf[0] != '?') {
    (*msg_failure)(FailureType_Failure_UnexpectedMessage, "Malformed packet");
    goto reset;
  }

  if (firstFrame && (buf[1] != '#' || buf[2] != '#')) {
    (*msg_failure)(FailureType_Failure_UnexpectedMessage, "Malformed packet");
    goto reset;
  }

  // Details of the chunk being copied out of the current frame.
  const uint8_t *frame;
  size_t frameSize;

  if (firstFrame) {
    // Reset the buffer that we're writing fragments into.
    memset(msg, 0, sizeof(msg));

    // Then fish out the id / size, which are big-endian uint16 /
    // uint32's respectively.
    msgId = buf[4] | ((uint16_t)buf[3]) << 8;
    msgSize = buf[8] | ((uint32_t)buf[7]) << 8 | ((uint32_t)buf[6]) << 16 |
              ((uint32_t)buf[5]) << 24;

    // Determine callback handler and message map type.
    entry = message_map_entry(type, msgId, IN_MSG);

    // And reset the cursor.
    cursor = 0;

    // Then take note of the fragment boundaries.
    frame = &buf[9];
    frameSize = MIN(length - 9, msgSize);
  } else {
    // Otherwise it's a continuation/fragment.
    frame = &buf[1];
    frameSize = length - 1;
  }

  // If the msgId wasn't in our map, bail.
  if (!entry) {
    (*msg_failure)(FailureType_Failure_UnexpectedMessage, "Unknown message");
    goto reset;
  }

  if (entry->dispatch == RAW) {
    /* Call dispatch for every segment since we are not buffering and parsing,
     * and assume the raw dispatched callbacks will handle their own state and
     * buffering internally
     */
    raw_dispatch(entry, frame, frameSize, msgSize);
    firstFrame = false;
    return;
  }

  size_t end;
  if (check_uadd_overflow(cursor, frameSize, &end) || sizeof(msg) < end) {
    (*msg_failure)(FailureType_Failure_UnexpectedMessage, "Malformed message");
    goto reset;
  }

  // Copy content to frame buffer.
  memcpy(&msg[cursor], frame, frameSize);

  // Advance the cursor.
  cursor = end;

  // Only parse and message map if all segments have been buffered.
  bool last_segment = cursor >= msgSize;
  if (!last_segment) {
    firstFrame = false;
    return;
  }

  dispatch(entry, msg, msgSize);

reset:
  msgId = 0xffff;
  msgSize = 0;
  memset(msg, 0, sizeof(msg));
  cursor = 0;
  firstFrame = true;
  entry = NULL;
}

/* Tiny messages */
static bool msg_tiny_flag = false;
static CONFIDENTIAL uint8_t msg_tiny[MSG_TINY_BFR_SZ];
static uint16_t msg_tiny_id = MSG_TINY_TYPE_ERROR; /* Default to error type */

_Static_assert(sizeof(msg_tiny) >= sizeof(Cancel), "msg_tiny too tiny");
_Static_assert(sizeof(msg_tiny) >= sizeof(Initialize), "msg_tiny too tiny");
_Static_assert(sizeof(msg_tiny) >= sizeof(PassphraseAck), "msg_tiny too tiny");
_Static_assert(sizeof(msg_tiny) >= sizeof(ButtonAck), "msg_tiny too tiny");
_Static_assert(sizeof(msg_tiny) >= sizeof(PinMatrixAck), "msg_tiny too tiny");
#if DEBUG_LINK
_Static_assert(sizeof(msg_tiny) >= sizeof(DebugLinkDecision),
               "msg_tiny too tiny");
_Static_assert(sizeof(msg_tiny) >= sizeof(DebugLinkGetState),
               "msg_tiny too tiny");
#endif

static void msg_read_tiny(const uint8_t *msg, size_t len) {
  if (len != 64) return;

  uint8_t buf[64];
  memcpy(buf, msg, sizeof(buf));

  if (buf[0] != '?' || buf[1] != '#' || buf[2] != '#') {
    (*msg_failure)(FailureType_Failure_UnexpectedMessage,
                   "Malformed tiny packet");
    return;
  }

  uint16_t msgId = buf[4] | ((uint16_t)buf[3]) << 8;
  uint32_t msgSize = buf[8] | ((uint32_t)buf[7]) << 8 |
                     ((uint32_t)buf[6]) << 16 | ((uint32_t)buf[5]) << 24;

  if (msgSize > 64 - 9) {
    (*msg_failure)(FailureType_Failure_UnexpectedMessage,
                   "Malformed tiny packet");
    return;
  }

  const pb_msgdesc_t *fields = NULL;
  pb_istream_t stream = pb_istream_from_buffer(buf + 9, msgSize);

  switch (msgId) {
    case MessageType_MessageType_PinMatrixAck:
      fields = PinMatrixAck_fields;
      break;
    case MessageType_MessageType_ButtonAck:
      fields = ButtonAck_fields;
      break;
    case MessageType_MessageType_PassphraseAck:
      fields = PassphraseAck_fields;
      break;
    case MessageType_MessageType_Cancel:
      fields = Cancel_fields;
      break;
    case MessageType_MessageType_Initialize:
      fields = Initialize_fields;
      break;
#if DEBUG_LINK
    case MessageType_MessageType_DebugLinkDecision:
      fields = DebugLinkDecision_fields;
      break;
    case MessageType_MessageType_DebugLinkGetState:
      fields = DebugLinkGetState_fields;
      break;
#endif
  }

  if (fields) {
    bool status = pb_decode(&stream, fields, msg_tiny);
    if (status) {
      msg_tiny_id = msgId;
    } else {
      (*msg_failure)(FailureType_Failure_SyntaxError, "Malformed tiny packet");
      msg_tiny_id = 0xffff;
    }
  } else {
    (*msg_failure)(FailureType_Failure_UnexpectedMessage, "Unknown message");
    msg_tiny_id = 0xffff;
  }
}

void handle_usb_rx(const void *msg, size_t len) {
  if (msg_tiny_flag) {
    msg_read_tiny(msg, len);
  } else {
    usb_rx_helper(msg, len, NORMAL_MSG);
  }
}

#if DEBUG_LINK
void handle_debug_usb_rx(const void *msg, size_t len) {
  if (msg_tiny_flag) {
    msg_read_tiny(msg, len);
  } else {
    usb_rx_helper(msg, len, DEBUG_MSG);
  }
}
#endif

/*
 * tiny_msg_poll_and_buffer() - Poll usb port to check for tiny message from
 * host
 *
 * INPUT
 *     - block: flag to continually poll usb until tiny message is received
 *     - buf: pointer to destination buffer
 * OUTPUT
 *     message type
 *
 */
static MessageType tiny_msg_poll_and_buffer(bool block, uint8_t *buf) {
  msg_tiny_id = MSG_TINY_TYPE_ERROR;
  msg_tiny_flag = true;

  while (msg_tiny_id == MSG_TINY_TYPE_ERROR) {
    usbPoll();

    if (!block) {
      break;
    }
  }

  msg_tiny_flag = false;

  if (msg_tiny_id != MSG_TINY_TYPE_ERROR) {
    memcpy(buf, msg_tiny, sizeof(msg_tiny));
  }

  return msg_tiny_id;
}

/*
 * msg_map_init() - Setup message map with corresping message type
 *
 * INPUT
 *     - map: pointer message map array
 *     - size: size of message map
 * OUTPUT
 *
 */
void msg_map_init(const void *map, const size_t size) {
  assert(map != NULL);
  MessagesMap = map;
  map_size = size;
}

/*
 * set_msg_failure_handler() - Setup usb message failure handler
 *
 * INPUT
 *     - failure_func: message failure handler
 * OUTPUT
 *     none
 */
void set_msg_failure_handler(msg_failure_t failure_func) {
  msg_failure = failure_func;
}

/*
 * set_msg_debug_link_get_state_handler() - Setup usb message debug link get
 * state handler
 *
 * INPUT
 *     - debug_link_get_state_func: message initialization handler
 * OUTPUT
 *     none
 */
#if DEBUG_LINK
void set_msg_debug_link_get_state_handler(
    msg_debug_link_get_state_t debug_link_get_state_func) {
  msg_debug_link_get_state = debug_link_get_state_func;
}
#endif

/*
 * call_msg_failure_handler() - Call message failure handler
 *
 * INPUT
 *     - code: failure code
 *     - text: pinter to function arguments
 * OUTPUT
 *     none
 */
void call_msg_failure_handler(FailureType code, const char *text) {
  if (msg_failure) {
    (*msg_failure)(code, text);
  }
}

/*
 * call_msg_debug_link_get_state_handler() - Call message debug link get state
 * handler
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
#if DEBUG_LINK
void call_msg_debug_link_get_state_handler(DebugLinkGetState *msg) {
  if (msg_debug_link_get_state) {
    (*msg_debug_link_get_state)(msg);
  }
}
#endif

/*
 * msg_init() - Setup usb receive callback handler
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void msg_init(void) {
  usb_set_rx_callback(handle_usb_rx);
#if DEBUG_LINK
  usb_set_debug_rx_callback(handle_debug_usb_rx);
#endif
}

/*
 * wait_for_tiny_msg() - Wait for usb tiny message type from host
 *
 * INPUT
 *     - buf: pointer to destination buffer
 * OUTPUT
 *     message tiny type
 *
 */
MessageType wait_for_tiny_msg(uint8_t *buf) {
  return tiny_msg_poll_and_buffer(true, buf);
}

/*
 * check_for_tiny_msg() - Check for usb tiny message type from host
 *
 * INPUT
 *     - buf: pointer to destination buffer
 * OUTPUT
 *     message tiny type
 *
 */
MessageType check_for_tiny_msg(uint8_t *buf) {
  return tiny_msg_poll_and_buffer(false, buf);
}

/*
 * parse_pb_varint() - Parses varints off of raw messages
 *
 * INPUT
 *     - msg: pointer to raw message
 *     - varint_count: how many varints to remove
 * OUTPUT
 *     bytes that were skipped
 */
uint32_t parse_pb_varint(RawMessage *msg, uint8_t varint_count) {
  uint32_t skip;
  uint8_t i;
  uint64_t pb_varint;
  pb_istream_t stream;

  /*
   * Parse varints
   */
  stream = pb_istream_from_buffer((uint8_t *)msg->buffer, msg->length);
  skip = stream.bytes_left;
  for (i = 0; i < varint_count; ++i) {
    pb_decode_varint(&stream, &pb_varint);
  }
  skip = skip - stream.bytes_left;

  /*
   * Increment skip over message
   */
  msg->length -= skip;
  msg->buffer = (uint8_t *)(msg->buffer + skip);

  return skip;
}

/*
 * encode_pb() - convert to raw pb data
 *
 * INPUT
 *     - source_ptr : pointer to struct
 *     - fields: pointer pb fields
 *     - *buffer: pointer to destination buffer
 *     - len: size of buffer
 * OUTPUT
 *     bytes written to buffer
 */
int encode_pb(const void *source_ptr, const pb_msgdesc_t *fields, uint8_t *buffer,
              uint32_t len) {
pb_ostream_t os = pb_ostream_from_buffer(buffer, len);

  if (!pb_encode(&os, fields, source_ptr)) return 0;

  return os.bytes_written;
}
