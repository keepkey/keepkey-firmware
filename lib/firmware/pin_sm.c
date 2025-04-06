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

#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/timer.h"
#include "keepkey/firmware/app_layout.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/pin_sm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/rand/rng.h"
#include "hwcrypto/crypto/memzero.h"

#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>

/* Holds random PIN matrix */
static char pin_matrix[PIN_BUF] = "XXXXXXXXX";

extern bool reset_msg_stack;

/// Send USB request for PIN entry over USB port
static void send_pin_request(PinMatrixRequestType type) {
  PinMatrixRequest resp;
  memset(&resp, 0, sizeof(PinMatrixRequest));
  resp.has_type = true;
  resp.type = type;
  msg_write(MessageType_MessageType_PinMatrixRequest, &resp);
}

/// Capture PIN entry from user over USB port
static void check_for_pin_ack(PINInfo *pin_info) {
  /* Listen for tiny messages */
  uint8_t msg_tiny_buf[MSG_TINY_BFR_SZ];
  uint16_t tiny_msg;

  tiny_msg = check_for_tiny_msg(msg_tiny_buf);

  switch (tiny_msg) {
    case MessageType_MessageType_PinMatrixAck:
      pin_info->pin_ack_msg = PIN_ACK_RECEIVED;
      PinMatrixAck *pma = (PinMatrixAck *)msg_tiny_buf;

      strlcpy(pin_info->pin, pma->pin, PIN_BUF);
      break;

    case MessageType_MessageType_Cancel: /* Check for cancel or initialize
                                            messages */
      pin_info->pin_ack_msg = PIN_ACK_CANCEL;
      break;

    case MessageType_MessageType_Initialize:
      pin_info->pin_ack_msg = PIN_ACK_CANCEL_BY_INIT;
      break;

#if DEBUG_LINK
    case MessageType_MessageType_DebugLinkGetState:
      call_msg_debug_link_get_state_handler((DebugLinkGetState *)msg_tiny_buf);
      break;
#endif

    case MSG_TINY_TYPE_ERROR:
    default:
      break;
  }
}

/// Request and receive PIN from user over USB port
/// \param pin_state state of request
/// \param pin_info buffer for user PIN
static void run_pin_state(PINState *pin_state, PINInfo *pin_info) {
  switch (*pin_state) {
    /* Send PIN request */
    case PIN_REQUEST:
      if (pin_info->type) {
        send_pin_request(pin_info->type);
      }

      pin_info->pin_ack_msg = PIN_ACK_WAITING;
      *pin_state = PIN_WAITING;
      break;

    /* Wait for a PIN */
    case PIN_WAITING:
      check_for_pin_ack(pin_info);

      if (pin_info->pin_ack_msg != PIN_ACK_WAITING) {
        *pin_state = PIN_FINISHED;
      }

      break;

    case PIN_FINISHED:
    case PIN_ACK:
    default:
      break;
  }
}

/// Make sure that PIN is at least one digit and a char from 1 to 9.
/// \returns true iff the pin is in the correct format
static bool check_pin_input(PINInfo *pin_info) {
  bool ret = true;

  /* Check that PIN is at least 1 digit and no more than 9 */
  if (!(strlen(pin_info->pin) >= 1 && strlen(pin_info->pin) <= 9)) {
    ret = false;
  }

  /* Check that PIN char is a digit from 1 to 9 */
  for (uint8_t i = 0; i < strlen(pin_info->pin); i++) {
    uint8_t num = pin_info->pin[i] - '0';

    if (num < 1 || num > 9) {
      ret = false;
    }
  }

  return ret;
}

/// Decode user PIN entry.
static void decode_pin(PINInfo *pin_info) {
  for (uint32_t i = 0; i < strlen(pin_info->pin); i++) {
    int32_t j = pin_info->pin[i] - '1';

    if (j >= 0 && (uint32_t)j < strlen(pin_matrix)) {
      pin_info->pin[i] = pin_matrix[j];
    } else {
      pin_info->pin[i] = 'X';
    }
  }
}

/// Request user for PIN entry.
/// \param prompt Text to display for the user along with PIN matrix.
/// \returns true iff the pin was received.
static bool pin_request(const char *prompt, PINInfo *pin_info) {
  bool ret = false;
  reset_msg_stack = false;
  PINState pin_state = PIN_REQUEST;

  /* Init and randomize pin matrix */
  strlcpy(pin_matrix, "123456789", PIN_BUF);
  random_permute_char(pin_matrix, 9);

  /* Show layout */
  layout_pin(prompt, pin_matrix);

  /* Run SM */
  while (1) {
    animate();
    display_refresh();

    run_pin_state(&pin_state, pin_info);

    if (pin_state == PIN_FINISHED) {
      break;
    }
  }

  /* Check for PIN cancel */
  if (pin_info->pin_ack_msg != PIN_ACK_RECEIVED) {
    if (pin_info->pin_ack_msg == PIN_ACK_CANCEL_BY_INIT) {
      reset_msg_stack = true;
    }

    fsm_sendFailure(FailureType_Failure_PinCancelled, "PIN Cancelled");
  } else {
    if (check_pin_input(pin_info)) {
      /* Decode PIN */
      decode_pin(pin_info);
      ret = true;
    } else {
      fsm_sendFailure(
          FailureType_Failure_PinCancelled,
          "PIN must be at least 1 digit consisting of numbers from 1 to 9");
    }
  }

  /* Clear PIN matrix */
  strlcpy(pin_matrix, "XXXXXXXXX", PIN_BUF);

  return (ret);
}

static char warn_msg_fmt[MEDIUM_STR_BUF];
static volatile uint32_t total_wait = 0;
static volatile uint32_t remaining_wait = 0;

static void pin_fail_wait_handler(void) {
  layoutProgress(warn_msg_fmt,
                 (total_wait - remaining_wait) * 1000 / total_wait);
}

bool pin_protect(const char *prompt) {
  if (!storage_hasPin()) {
    return true;
  }

  // Check for prior PIN failed attempts and apply exponentially longer delay
  // for each subsequent failed attempt.
  uint32_t fail_count = storage_getPinFails();
  if (fail_count > 2) {
    uint32_t wait = (fail_count < 32) ? (1u << fail_count) : 0xFFFFFFFFu;

    // snprintf: 36 + 10 (%u) + 1 (NULL) = 47
    memzero(warn_msg_fmt, sizeof(warn_msg_fmt));
    snprintf(warn_msg_fmt, sizeof(warn_msg_fmt),
             "Previous PIN Failures:\nWait %" PRIu32 " seconds", wait);
    layout_warning(warn_msg_fmt);

    remaining_wait = total_wait = wait;

    while (--remaining_wait > 0) {
      delay_ms_with_callback(ONE_SEC, &pin_fail_wait_handler, 20);
    }
  }

  // Set request type
  PINInfo pin_info;
  pin_info.type = PinMatrixRequestType_PinMatrixRequestType_Current;

  // Get PIN
  if (!pin_request(prompt, &pin_info)) {
    // PIN entry has been canceled by the user
    return false;
  }

  // Preincrement the failed counter before authentication
  storage_increasePinFails();
  bool pre_increment_cnt_flg = (fail_count >= storage_getPinFails());

  // Check if PIN entered is wipe code
  if (storage_isWipeCodeCorrect(pin_info.pin)) {
    session_clear(false);
    storage_clearKeys();
    fsm_sendFailure(FailureType_Failure_PinInvalid, "Invalid PIN");
    return false;
  }

  // Authenticate user PIN
  if (!storage_isPinCorrect(pin_info.pin) || pre_increment_cnt_flg) {
    fsm_sendFailure(FailureType_Failure_PinInvalid, "Invalid PIN");
    return false;
  }

  storage_resetPinFails();
  return true;
}

bool pin_protect_cached(void) {
    if (session_isPinCached()) {
        return true;
    }

    return pin_protect("Enter\nYour PIN");
}

bool pin_protect_uncached(void) {
    return pin_protect("Enter\nYour PIN");
}

bool change_pin(void) {
  PINInfo pin_info_first, pin_info_second;

  /* Set request types */
  pin_info_first.type = PinMatrixRequestType_PinMatrixRequestType_NewFirst;
  pin_info_second.type = PinMatrixRequestType_PinMatrixRequestType_NewSecond;

  if (!pin_request("Enter New\nPIN", &pin_info_first)) {
    return false;
  }

  if (!pin_request("Re-Enter\nNew PIN", &pin_info_second)) {
    return false;
  }

  if (strcmp(pin_info_first.pin, pin_info_second.pin) != 0) {
    return false;
  }

  storage_setPin(pin_info_first.pin);
  return true;
}

bool change_wipe_code(void) {
  PINInfo wipe_code_info_first, wipe_code_info_second;

  /* Set request types */
  wipe_code_info_first.type =
      PinMatrixRequestType_PinMatrixRequestType_NewFirst;
  wipe_code_info_second.type =
      PinMatrixRequestType_PinMatrixRequestType_NewSecond;

  if (!pin_request("Enter New Wipe Code", &wipe_code_info_first)) {
    return false;
  }

  if (!pin_request("Re-Enter New Wipe Code", &wipe_code_info_second)) {
    return false;
  }

  if (strcmp(wipe_code_info_first.pin, wipe_code_info_second.pin) != 0) {
    return false;
  }

  storage_setWipeCode(wipe_code_info_first.pin);
  return true;
}

#if DEBUG_LINK
/// Gets randomized PIN matrix
const char *get_pin_matrix(void) { return pin_matrix; }
#endif