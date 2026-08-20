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

#ifndef RESET_H
#define RESET_H

#include <stdint.h>
#include <stdbool.h>

#define MAX_WORDS 24
#define MAX_WORD_LEN 10
#define MAX_PAGES 6
#define ADDITIONAL_WORD_PAD 5
#define WORDS_PER_SCREEN 24
#define TOKENED_MNEMONIC_BUF MAX_WORDS*(MAX_WORD_LEN + 1) + 1
#define FORMATTED_MNEMONIC_BUF \
  MAX_WORDS*(MAX_WORD_LEN + ADDITIONAL_WORD_PAD) + 1
#define MNEMONIC_BY_SCREEN_BUF WORDS_PER_SCREEN*(MAX_WORD_LEN + 1) + 1

/* ---- setup ceremony -------------------------------------------------
 *
 * ResetDevice and RecoveryDevice are transactions. The settings the host
 * asks for are STAGED here, in RAM owned by reset.c, and do not reach
 * shadow_config until the ceremony reaches its single commit point, which
 * sits immediately after its last on-device hold. Abandoning a ceremony is
 * therefore a memzero: there is nothing in storage to roll back, and
 * nothing left armed for a later message to consume.
 *
 * All the state lives in one file-scope struct in reset.c. What follows is
 * the whole API; there is no other way to reach it. */
typedef enum {
  SETUP_NONE = 0,
  SETUP_RESET,
  SETUP_RECOVERY,
} SetupKind;

/// \returns true iff a ceremony is armed and awaiting its next message.
bool setup_isArmed(void);

/// \returns true iff the armed ceremony is exactly \a kind.
bool setup_isArmedAs(SetupKind kind);

/// Gate for every message that continues a ceremony. On mismatch it aborts
/// the ceremony, reports UnexpectedMessage, returns home and returns false.
bool setup_require(SetupKind kind, const char* errmsg);

/// Discard a ceremony: memzero the staged settings, the PIN, the entropy and
/// the recovery buffers, and disarm. Touches no storage. Idempotent.
void setup_abort(void);

/// Stage the host-supplied settings for a ceremony about to start. Fails,
/// and stages nothing, if a ceremony is already armed.
bool setup_stage(bool passphrase_protection, const char* language,
                 const char* label, uint32_t auto_lock_delay_ms,
                 uint32_t u2f_counter, bool no_backup);

/// Capture the PIN on-device into the staged settings; \a pin_protection
/// false stages the empty PIN. \returns false if the two entries did not
/// match or the host cancelled.
bool setup_stagePin(bool pin_protection);

/// Arm the staged ceremony. Call exactly once, as the last statement before
/// the message that hands control back to the host.
void setup_arm(SetupKind kind);

/// The ONE place staged settings reach storage. Applies them, stores \a
/// mnemonic, disarms, then commits to flash.
void setup_commit(const char* mnemonic, bool imported);

void reset_init(bool display_random, uint32_t _strength,
                bool passphrase_protection, bool pin_protection,
                const char* language, const char* label, bool _no_backup,
                uint32_t _auto_lock_delay_ms, uint32_t _u2f_counter);
void reset_entropy(const uint8_t* ext_entropy, uint32_t len);
uint32_t reset_get_int_entropy(uint8_t* entropy);
const char* reset_get_word(void);

#endif
