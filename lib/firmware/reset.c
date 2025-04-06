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

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/pin_sm.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/rand/rng.h"
#include "keepkey/transport/interface.h"
#include "hwcrypto/crypto/bip39.h"
#include "hwcrypto/crypto/memzero.h"
#include "hwcrypto/crypto/rand.h"
#include "hwcrypto/crypto/sha2.h"

#include <stdio.h>

#define _(X) (X)

static uint32_t strength;
static uint8_t CONFIDENTIAL int_entropy[32];
static bool awaiting_entropy = false;
static char CONFIDENTIAL current_words[MNEMONIC_BY_SCREEN_BUF];
static bool no_backup;

void reset_init(bool display_random, uint32_t _strength,
                bool passphrase_protection, bool pin_protection,
                const char *language, const char *label, bool _no_backup,
                uint32_t _auto_lock_delay_ms, uint32_t _u2f_counter) {
  if (_strength != 128 && _strength != 192 && _strength != 256) {
    fsm_sendFailure(
        FailureType_Failure_SyntaxError,
        _("Invalid mnemonic strength (has to be 128, 192 or 256 bits)"));
    layoutHome();
    return;
  }

  strength = _strength;
  no_backup = _no_backup;

  if (display_random && no_backup) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Can't show internal entropy when backup is skipped"));
    layoutHome();
    return;
  }

  if (no_backup) {
    // Double confirm, since this is a feature for advanced users only, and
    // there is risk of loss of funds if this mode is used incorrectly
    // (i.e. multisig is an absolute must with this scheme).
    if (!confirm(ButtonRequestType_ButtonRequest_Other, _("WARNING"),
                 _("The 'No Backup' option was selected.\n"
                   "Recovery sentence will *NOT* be shown,\n"
                   "and recovery will be IMPOSSIBLE.\n")) ||
        !confirm(ButtonRequestType_ButtonRequest_Other, _("WARNING"),
                 _("The 'No Backup' option was selected.\n\n"
                   "I understand, and accept the risks.\n"))) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Reset cancelled"));
      layoutHome();
      return;
    }
  }

  random_buffer(int_entropy, 32);

  if (display_random) {
    static char CONFIDENTIAL ent_str[4][17];
    data2hex(int_entropy, 8, ent_str[0]);
    data2hex(int_entropy + 8, 8, ent_str[1]);
    data2hex(int_entropy + 16, 8, ent_str[2]);
    data2hex(int_entropy + 24, 8, ent_str[3]);

    if (!confirm(ButtonRequestType_ButtonRequest_ResetDevice,
                 _("Internal Entropy"), "%s %s %s %s", ent_str[0], ent_str[1],
                 ent_str[2], ent_str[3])) {
      memzero(ent_str, sizeof(ent_str));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Reset cancelled"));
      layoutHome();
      return;
    }
    memzero(ent_str, sizeof(ent_str));
  }

  if (pin_protection) {
    if (!change_pin()) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("PINs do not match"));
      layoutHome();
      return;
    }
  } else {
    storage_setPin("");
  }

  storage_setPassphraseProtected(passphrase_protection);
  storage_setLanguage(language);
  storage_setLabel(label);
  storage_setAutoLockDelayMs(_auto_lock_delay_ms);
  storage_setU2FCounter(_u2f_counter);

  EntropyRequest resp;
  memset(&resp, 0, sizeof(EntropyRequest));
  msg_write(MessageType_MessageType_EntropyRequest, &resp);
  awaiting_entropy = true;
}

void reset_entropy(const uint8_t *ext_entropy, uint32_t len)
{
    if(!awaiting_entropy)
    {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage, _("Not in Reset mode"));
        return;
    }

    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, int_entropy, 32);
    sha256_Update(&ctx, ext_entropy, len);
    sha256_Final(&ctx, int_entropy);

    const char *temp_mnemonic = mnemonic_from_data(int_entropy, strength / 8);

    memzero(int_entropy, sizeof(int_entropy));
    awaiting_entropy = false;

    if (no_backup) {
        storage_setNoBackup();
        storage_setMnemonic(temp_mnemonic);
        mnemonic_clear();
        storage_commit();
        fsm_sendSuccess(_("Device reset"));
        goto exit;
    } else {
        if (!confirm(ButtonRequestType_ButtonRequest_Other, _("Recovery Seed Backup"),
                     "This recovery seed will only be shown ONCE. "
                     "Please write it down carefully,\n"
                     "and DO NOT share it with anyone. ")) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, _("Reset cancelled"));
            storage_reset();
            layoutHome();
            return;
        }
    }

    /*
     * Format mnemonic for user review
     */
    uint32_t word_count = 0, page_count = 0;
    static char CONFIDENTIAL tokened_mnemonic[TOKENED_MNEMONIC_BUF];
    static char CONFIDENTIAL mnemonic_by_screen[MAX_PAGES][MNEMONIC_BY_SCREEN_BUF];
    static char CONFIDENTIAL formatted_mnemonic[MAX_PAGES][FORMATTED_MNEMONIC_BUF];
    static char CONFIDENTIAL mnemonic_display[FORMATTED_MNEMONIC_BUF];
    static char CONFIDENTIAL formatted_word[MAX_WORD_LEN + ADDITIONAL_WORD_PAD];

    strlcpy(tokened_mnemonic, temp_mnemonic, TOKENED_MNEMONIC_BUF);

    char *tok = strtok(tokened_mnemonic, " ");

    while(tok)
    {
        snprintf(formatted_word, MAX_WORD_LEN + ADDITIONAL_WORD_PAD, (word_count & 1) ? "%lu.%s\n" : "%lu.%s",
                 (unsigned long)(word_count + 1), tok);

        /* Check that we have enough room on display to show word */
        snprintf(mnemonic_display, FORMATTED_MNEMONIC_BUF, "%s   %s",
                 formatted_mnemonic[page_count], formatted_word);

        if(calc_str_line(get_body_font(), mnemonic_display, BODY_WIDTH) > 3)
        {
            page_count++;

            if (MAX_PAGES <= page_count) {
                fsm_sendFailure(FailureType_Failure_Other, _("Too many pages of mnemonic words"));
                storage_reset();
                goto exit;
            }

            snprintf(mnemonic_display, FORMATTED_MNEMONIC_BUF, "%s   %s",
                 formatted_mnemonic[page_count], formatted_word);
        }

        strlcpy(formatted_mnemonic[page_count], mnemonic_display,
                FORMATTED_MNEMONIC_BUF);

        /* Save mnemonic for each screen */
        if(strlen(mnemonic_by_screen[page_count]) == 0)
        {
            strlcpy(mnemonic_by_screen[page_count], tok, MNEMONIC_BY_SCREEN_BUF);
        }
        else
        {
            strlcat(mnemonic_by_screen[page_count], " ", MNEMONIC_BY_SCREEN_BUF);
            strlcat(mnemonic_by_screen[page_count], tok, MNEMONIC_BY_SCREEN_BUF);
        }

        tok = strtok(NULL, " ");
        word_count++;
    }

    // Switch from 0-indexing to 1-indexing
    page_count++;

    display_constant_power(true);

    /* Have user confirm mnemonic is sets of 12 words */
    for(uint32_t current_page = 0; current_page < page_count; current_page++)
    {
        char title[MEDIUM_STR_BUF] = _("Backup");

        /* make current screen mnemonic available via debuglink */
        strlcpy(current_words, mnemonic_by_screen[current_page], MNEMONIC_BY_SCREEN_BUF);

        if(page_count > 1)
        {
            /* snprintf: 20 + 10 (%d) + 1 (NULL) = 31 */
            snprintf(title, MEDIUM_STR_BUF, _("Backup %" PRIu32 "/%" PRIu32 ""), current_page + 1, page_count);
        }

        if(!confirm_constant_power(ButtonRequestType_ButtonRequest_ConfirmWord, title, "%s",
                                   formatted_mnemonic[current_page]))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, _("Reset cancelled"));
            storage_reset();
            goto exit;
        }
    }

    /* Save mnemonic */
    storage_setMnemonic(temp_mnemonic);
    mnemonic_clear();
    storage_commit();
    fsm_sendSuccess(_("Device reset"));

exit:
  memzero(&ctx, sizeof(ctx));
  memzero(tokened_mnemonic, sizeof(tokened_mnemonic));
  memzero(mnemonic_by_screen, sizeof(mnemonic_by_screen));
  memzero(formatted_mnemonic, sizeof(formatted_mnemonic));
  memzero(mnemonic_display, sizeof(mnemonic_display));
  memzero(formatted_word, sizeof(formatted_word));
  layoutHome();
}

#if DEBUG_LINK
uint32_t reset_get_int_entropy(uint8_t *entropy) {
  memcpy(entropy, int_entropy, 32);
  return 32;
}

const char *reset_get_word(void) { return current_words; }
#endif
