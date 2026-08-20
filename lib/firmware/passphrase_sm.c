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

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/timer.h"
#include "keepkey/rand/rng.h"

#include "keepkey/firmware/passphrase_sm.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/storage.h"
#include "trezor/crypto/memzero.h"

#include <stdbool.h>

extern bool reset_msg_stack;

/*
 * send_passphrase_request() - Send passphrase request to USB host
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
static void send_passphrase_request(void) {
  PassphraseRequest resp;
  memset(&resp, 0, sizeof(PassphraseRequest));
  msg_write(MessageType_MessageType_PassphraseRequest, &resp);
}

/*
 * wait_for_passphrase_ack() - Wait for passphrase acknowledgement from USB host
 *
 * INPUT
 *      - passphrase_info: passphrase information
 * OUTPUT
 *     none
 */
static void wait_for_passphrase_ack(PassphraseInfo* passphrase_info) {
  /* Listen for tiny messages */
  uint8_t msg_tiny_buf[MSG_TINY_BFR_SZ];
  uint16_t tiny_msg = wait_for_tiny_msg(msg_tiny_buf);

  switch (tiny_msg) {
    /* Check for standard passphrase ack */
    case MessageType_MessageType_PassphraseAck:
      passphrase_info->passphrase_ack_msg = PASSPHRASE_ACK_RECEIVED;
      PassphraseAck* ppa = (PassphraseAck*)msg_tiny_buf;

      strlcpy(passphrase_info->passphrase, ppa->passphrase, PASSPHRASE_BUF);
      break;

    case MessageType_MessageType_Cancel: /* Check for cancel or initialize
                                            messages */
      passphrase_info->passphrase_ack_msg = PASSPHRASE_ACK_CANCEL;
      break;

    case MessageType_MessageType_Initialize:
      passphrase_info->passphrase_ack_msg = PASSPHRASE_ACK_CANCEL_BY_INIT;
      break;

    case MSG_TINY_TYPE_ERROR:
    default:
      break;
  }
}

/*
 * run_passphrase_state() - Passphrase state machine
 *
 * INPUT
 *     - passphrase_state: current passphrase input state
 *     - passphrase_info: passphrase information
 * OUTPUT
 *     none
 */
static void run_passphrase_state(PassphraseState* passphrase_state,
                                 PassphraseInfo* passphrase_info) {
  switch (*passphrase_state) {
    /* Send passphrase request */
    case PASSPHRASE_REQUEST:
      send_passphrase_request();
      *passphrase_state = PASSPHRASE_WAITING;

      layout_simple_message("Waiting for Passphrase...");

      break;

    /* Wait for a passphrase */
    case PASSPHRASE_WAITING:
      wait_for_passphrase_ack(passphrase_info);

      if (passphrase_info->passphrase_ack_msg != PASSPHRASE_ACK_WAITING) {
        *passphrase_state = PASSPHRASE_FINISHED;
      }

      break;

    case PASSPHRASE_ACK:
    case PASSPHRASE_FINISHED:
    default:
      break;
  }
}

/*
 * passphrase_request() - Request passphrase from user on USB host
 *
 * INPUT
 *     - passphrase_info: passphrase information
 * OUTPUT
 *      true/false whether passphrase was received
 */
static bool passphrase_request(PassphraseInfo* passphrase_info) {
  bool ret = false;
  reset_msg_stack = false;
  PassphraseState passphrase_state = PASSPHRASE_REQUEST;

  /* Run SM */
  while (1) {
    run_passphrase_state(&passphrase_state, passphrase_info);

    if (passphrase_state == PASSPHRASE_FINISHED) {
      break;
    }
  }

  /* Check for passphrase cancel */
  if (passphrase_info->passphrase_ack_msg == PASSPHRASE_ACK_RECEIVED) {
    /* This screen is the only place the user gets to see the passphrase their
     * keys will be derived from. review() used to discard its result and this
     * returned true regardless, so a host that answered the screen with a
     * protocol Cancel suppressed the display and still got the passphrase
     * cached -- the session then derived a different wallet than the user
     * believed they were opening, with nothing shown on the OLED.
     *
     * There is no reject button on this device: confirm_helper() returns false
     * only for a host-sent Cancel/Initialize. So a false here is precisely
     * "the host took the screen away", and the passphrase must not be cached.
     * Every caller of passphrase_protect() already tests its result. */
    ret =
        review(ButtonRequestType_ButtonRequest_Other, "passphrase confirmation",
               "If this is wrong, unplug/replug Keepkey:"
               "%51s",
               passphrase_info->passphrase);
  } else {
    if (passphrase_info->passphrase_ack_msg == PASSPHRASE_ACK_CANCEL_BY_INIT) {
      reset_msg_stack = true;
    }
  }

  return (ret);
}

/*
 * passphrase_protect() - Set passphrase protection
 *
 * INPUT
 *     none
 * OUTPUT
 *     true/false whether passphrase was received
 */
bool passphrase_protect(void) {
  bool ret = false;

  /* The passphrase selects the wallet: it is the difference between the visible
   * wallet and a hidden one. This buffer held it on the STACK, unzeroed, on
   * every path -- success, host cancel, and the early-out where passphrase
   * protection is off. Nothing else in the firmware treats key material that
   * way; compare confirm_sm.c's `static CONFIDENTIAL char strbuf[]` and the
   * session cache, which is `static SessionState CONFIDENTIAL session`.
   *
   * CONFIDENTIAL is not a comment. On device builds it is
   * __attribute__((section("confidential"))), a NOLOAD region the bootloader
   * wipes at boot (tools/bootloader/main.c). A section attribute cannot apply
   * to an automatic, so the buffer has to leave the stack to get that
   * protection -- hence `static`. passphrase_protect() is not reentrant: it is
   * called from fsm handlers on the single main loop, and it blocks in
   * passphrase_request() until the exchange finishes.
   *
   * The section only clears at boot, so it is zeroed here on entry and exit as
   * well: reboot-scope protection is not the same as call-scope protection, and
   * the residue between two calls is the part an attacker can reach without a
   * power cycle. */
  static PassphraseInfo CONFIDENTIAL passphrase_info;
  memzero(&passphrase_info, sizeof(passphrase_info));

  if (storage_getPassphraseProtected() && !session_isPassphraseCached()) {
    /* Get passphrase and cache */
    if (passphrase_request(&passphrase_info)) {
      session_cachePassphrase(passphrase_info.passphrase);
      ret = true;
    }
  } else {
    ret = true;
  }

  memzero(&passphrase_info, sizeof(passphrase_info));
  return (ret);
}
