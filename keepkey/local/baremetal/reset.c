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

/* === Includes ============================================================ */

#include <stdio.h>

#include <interface.h>
#include <keepkey_board.h>
#include <sha2.h>
#include <bip39.h>
#include <confirm_sm.h>

#include "reset.h"
#include "storage.h"
#include "msg_dispatch.h"
#include "fsm.h"
#include "util.h"
#include "rand.h"
#include "pin_sm.h"
#include "home_sm.h"

/* === Private Variables =================================================== */

static uint32_t strength;
static uint8_t int_entropy[32];
static bool awaiting_entropy = false;
static char current_words[MNEMONIC_BY_SCREEN_BUF];

/* === Functions =========================================================== */

void reset_init(bool display_random, uint32_t _strength, bool passphrase_protection,
                bool pin_protection, const char *language, const char *label)
{
    if(_strength != 128 && _strength != 192 && _strength != 256)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        "Invalid strength (has to be 128, 192 or 256 bits)");
        go_home();
        return;
    }

    strength = _strength;

    random_buffer(int_entropy, 32);

    char ent_str[4][17];
    data2hex(int_entropy     , 8, ent_str[0]);
    data2hex(int_entropy +  8, 8, ent_str[1]);
    data2hex(int_entropy + 16, 8, ent_str[2]);
    data2hex(int_entropy + 24, 8, ent_str[3]);

    if(display_random)
    {
        if(!confirm(ButtonRequestType_ButtonRequest_ResetDevice,
                    "Internal Entropy", "%s %s %s %s", ent_str[0], ent_str[1], ent_str[2], ent_str[3]))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Reset cancelled");
            go_home();
            return;
        }
    }

    if(pin_protection && !change_pin())
    {
        go_home();
        return;
    }

    storage_set_passphrase_protected(passphrase_protection);
    storage_set_language(language);
    storage_set_label(label);

    EntropyRequest resp;
    memset(&resp, 0, sizeof(EntropyRequest));
    msg_write(MessageType_MessageType_EntropyRequest, &resp);
    awaiting_entropy = true;
}

void reset_entropy(const uint8_t *ext_entropy, uint32_t len)
{
    if(!awaiting_entropy)
    {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage, "Not in Reset mode");
        return;
    }

    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, int_entropy, 32);
    sha256_Update(&ctx, ext_entropy, len);
    sha256_Final(int_entropy, &ctx);

    const char *temp_mnemonic = mnemonic_from_data(int_entropy, strength / 8);

    memset(int_entropy, 0, 32);
    awaiting_entropy = false;

    /*
     * Format mnemonic for user review
     */
    uint32_t word_count = 0;
    char *tok;
    char tokened_mnemonic[TOKENED_MNEMONIC_BUF];
    char mnemonic_by_screen[MAX_WORDS / WORDS_PER_SCREEN][MNEMONIC_BY_SCREEN_BUF];
    char formatted_mnemonic[MAX_WORDS / WORDS_PER_SCREEN][FORMATTED_MNEMONIC_BUF];

    strlcpy(tokened_mnemonic, temp_mnemonic, TOKENED_MNEMONIC_BUF);

    tok = strtok(tokened_mnemonic, " ");

    while(tok)
    {
        /* format word for screen */
        char formatted_word[MAX_WORD_LEN + ADDITIONAL_WORD_PAD];

        snprintf(formatted_word, MAX_WORD_LEN + ADDITIONAL_WORD_PAD, "%lu.%s   ",
                 (unsigned long)(word_count + 1), tok);

        strlcat(formatted_mnemonic[word_count / WORDS_PER_SCREEN], formatted_word,
                FORMATTED_MNEMONIC_BUF);

        /* save mnemonic for each screen */
        if(strlen(mnemonic_by_screen[word_count / WORDS_PER_SCREEN]) == 0)
        {
            strlcpy(mnemonic_by_screen[word_count / WORDS_PER_SCREEN], tok, MNEMONIC_BY_SCREEN_BUF);
        }
        else
        {
            strlcat(mnemonic_by_screen[word_count / WORDS_PER_SCREEN], " ", MNEMONIC_BY_SCREEN_BUF);
            strlcat(mnemonic_by_screen[word_count / WORDS_PER_SCREEN], tok, MNEMONIC_BY_SCREEN_BUF);
        }

        tok = strtok(NULL, " ");
        word_count++;
    }

    /* Have user confirm mnemonic is sets of 12 words */
    for(uint32_t word_group = 0; word_group * WORDS_PER_SCREEN < (strength / 32) * 3; word_group++)
    {
        char title[MEDIUM_STR_BUF] = "Recovery Sentence";

        /* make current screen mnemonic available via debuglink */
        strlcpy(current_words, mnemonic_by_screen[word_group], MNEMONIC_BY_SCREEN_BUF);

        if((strength / 32) * 3 > WORDS_PER_SCREEN)
        {
            /* snprintf: 20 + 10 (%d) + 1 (NULL) = 31 */
            snprintf(title, MEDIUM_STR_BUF, "Recovery Sentence %lu/2", word_group + 1);
        }

        if(!confirm(ButtonRequestType_ButtonRequest_ConfirmWord, title, "%s",
                    formatted_mnemonic[word_group]))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Reset cancelled");
            storage_reset();
            go_home();
            return;
        }
    }

    /* Save mnemonic */
    storage_set_mnemonic(temp_mnemonic);
    storage_commit();

    fsm_sendSuccess("Device reset");
    go_home();
}

uint32_t reset_get_int_entropy(uint8_t *entropy)
{
    memcpy(entropy, int_entropy, 32);
    return 32;
}

const char *reset_get_word(void)
{
    return current_words;
}
