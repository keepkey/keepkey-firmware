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


#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/messages.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/pin_sm.h"
#include "keepkey/firmware/recovery.h"
#include "keepkey/firmware/recovery_cipher.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/rand/rng.h"
#include "trezor/crypto/bip39.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/rand.h"

#include <string.h>
#include <stdio.h>


static uint32_t word_count;
static bool awaiting_word = false;
static bool enforce_wordlist;
static char fake_word[12];
static uint32_t word_pos;
static uint32_t word_index;
static char CONFIDENTIAL word_order[24];
static char CONFIDENTIAL words[24][12];


void next_word(void) {
	if (sizeof(word_order)/sizeof(word_order[0]) <= word_index) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "Invalid word_index");
		layoutHome();
		return;
	}

	word_pos = word_order[word_index];
	static char CONFIDENTIAL title_formatted[SMALL_STR_BUF];
	static char CONFIDENTIAL body_formatted[MEDIUM_STR_BUF];

	/* Form title */
    /* snprintf: 24 + 10 (%u) + 1 (NULL) = 35 */
	snprintf(title_formatted, SMALL_STR_BUF, "Device Recovery Step %lu/24", (unsigned long)(word_index + 1));

	if (word_pos == 0) {
		const char * const *wl = mnemonic_wordlist();
        strlcpy(fake_word, wl[random_uniform(2048)], sizeof(fake_word));

		/* Format body for fake word */
        /* snprintf: 18 + 12 (fake_word) + 1 (NULL) = 31 */
		snprintf(body_formatted, MEDIUM_STR_BUF, "Enter the word \"%s\".", fake_word);

        layout_standard_notification(title_formatted, body_formatted, NOTIFICATION_RECOVERY);
	} else {
		fake_word[0] = 0;

		char desc[] = "th word";
		if (word_pos == 1 || word_pos == 21) {
			desc[0] = 's'; desc[1] = 't';
		} else
		if (word_pos == 2 || word_pos == 22) {
			desc[0] = 'n'; desc[1] = 'd';
		} else
		if (word_pos == 3 || word_pos == 23) {
			desc[0] = 'r'; desc[1] = 'd';
		}

		/* Format body for real word */
        /* snprintf: 37 + 10 (%u) + 8 (desc) + 1 (NULL) = 56 */
		snprintf(body_formatted, MEDIUM_STR_BUF, "Enter the %lu%s of your recovery sentence.", (unsigned long)word_pos, desc);

		layout_standard_notification(title_formatted, body_formatted, NOTIFICATION_RECOVERY);
	}
	WordRequest resp;
	memset(&resp, 0, sizeof(WordRequest));
	msg_write(MessageType_MessageType_WordRequest, &resp);

    memzero(title_formatted, sizeof(title_formatted));
    memzero(body_formatted, sizeof(body_formatted));
}

void recovery_init(uint32_t _word_count, bool passphrase_protection,
                   bool pin_protection, const char *language, const char *label,
                   bool _enforce_wordlist, uint32_t _auto_lock_delay_ms,
                   uint32_t _u2f_counter)
{
	if (_word_count != 12 && _word_count != 18 && _word_count != 24) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "Invalid word count (has to be 12, 18 or 24");
		layoutHome();
		return;
	}

	word_count = _word_count;
	enforce_wordlist = _enforce_wordlist;

	if (pin_protection) {
		if (!change_pin()) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled, "PINs do not match");
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

	uint32_t i;
    for (i = 0; i < word_count; i++) {
        word_order[i] = i + 1;
    }
    for (i = word_count; i < 24; i++) {
        word_order[i] = 0;
    }
    random_permute_char(word_order, 24);
	awaiting_word = true;
	word_index = 0;
	next_word();
}

static bool isInWordList(const char *word) {
    const char * const *wl = mnemonic_wordlist();
    while (*wl)
    {
        if (strcmp(word, *wl) == 0)
        {
            // Yes, this "leaks" timing information about what the word
            // is, but in this recovery mode, the host knows what each
            // of the words are (just not their order, nor which ones
            // are fake).
            return true;
        }
        wl++;
    }
    return false;
}

void recovery_word(const char *word)
{
    if (!awaiting_word)
    {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage, "Not in Recovery mode");
        layoutHome();
        return;
    }

    volatile bool found = isInWordList(word);
    volatile bool isCorrectFake = exact_str_match(word, fake_word, strlen(word) + 1);

    if (word_pos == 0) {
        if (!isCorrectFake) {
            // Fake word
            storage_reset();
            fsm_sendFailure(FailureType_Failure_SyntaxError, "Wrong word retyped");
            layoutHome();
            return;
        }
    } else {
        // Real word
        if (enforce_wordlist & (!found)) {
            storage_reset();
            fsm_sendFailure(FailureType_Failure_SyntaxError, "Word not found in the bip39 wordlist");
            layoutHome();
            return;
        }
        strlcpy(words[word_pos - 1], word, sizeof(words[word_pos - 1]));
    }

    if (word_index + 1 == 24) {
        // last one
        storage_setMnemonicFromWords(words, word_count);

        const char *entered_mnemonic = storage_getShadowMnemonic();
        if (entered_mnemonic && (!enforce_wordlist || mnemonic_check(entered_mnemonic))) {
            storage_commit();
            fsm_sendSuccess("Device recovered");
        } else {
            storage_reset();
            fsm_sendFailure(FailureType_Failure_SyntaxError, "Invalid mnemonic, are words in correct order?");
        }
        awaiting_word = false;
        layoutHome();
    } else {
        word_index++;
        next_word();
    }
}

void recovery_abort(bool send_failure)
{
    if(awaiting_word || recovery_cipher_abort()) {
        awaiting_word = false;

        if(send_failure) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Recovery cancelled");
        }

        layoutHome();
    }
}


#if DEBUG_LINK
const char *recovery_get_fake_word(void)
{
	return fake_word;
}

uint32_t recovery_get_word_pos(void)
{
	return word_pos;
}
#endif
