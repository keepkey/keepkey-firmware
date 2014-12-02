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

#include <string.h>
#include <stdio.h>

#include <crypto.h>
#include <keepkey_board.h>
#include <layout.h>
#include <messages.h>
#include <storage.h>

#include "recovery.h"
#include "fsm.h"


static uint32_t word_count;
static bool awaiting_word = false;
static bool enforce_wordlist;
static char fake_word[12];
static uint32_t word_pos;
static uint32_t word_index;
static char word_order[24];
static char words[24][12];

void next_word(void) {
	word_pos = word_order[word_index];
	char title_formatted[26];
	char body_formatted[90];

	/*
	 * Form title
	 */
	sprintf(title_formatted, "Device Recovery Mode %d/24", word_index + 1);

	if (word_pos == 0) {
		const char **wl = mnemonic_wordlist();
		strlcpy(fake_word, wl[random32() & 0x7FF], sizeof(fake_word));

		/*
		 * Format body for fake word
		 */
		sprintf(body_formatted, "On the device connected to this KeepKey, enter the word \"%s\".", fake_word);

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

		/*
		 * Format body for real word
		 */
		sprintf(body_formatted, "On the device connected to this KeepKey, enter the %d%s of your recovery sentence.", word_pos, desc);

		layout_standard_notification(title_formatted, body_formatted, NOTIFICATION_RECOVERY);
	}
	WordRequest resp;
	memset(&resp, 0, sizeof(WordRequest));
	msg_write(MessageType_MessageType_WordRequest, &resp);
}

void recovery_init(uint32_t _word_count, bool passphrase_protection, bool pin_protection, const char *language, const char *label, bool _enforce_wordlist)
{
	if (_word_count != 12 && _word_count != 18 && _word_count != 24) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "Invalid word count (has to be 12, 18 or 24 bits)");
		layout_home();
		return;
	}

	word_count = _word_count;
	enforce_wordlist = _enforce_wordlist;

    //TODO:Implement PIN
	/*if (pin_protection && !protectChangePin()) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, "PIN change failed");
		layout_home();
		return;
	}*/

	storage_set_passphrase_protected(true);
	storage_setLanguage(language);
	storage_setLabel(label);

	uint32_t i, j, k;
	char t;
	for (i = 0; i < word_count; i++) {
		word_order[i] = i + 1;
	}
	for (i = word_count; i < 24; i++) {
		word_order[i] = 0;
	}
	for (i = 0; i < 10000; i++) {
		j = random32() % 24;
		k = random32() % 24;
		t = word_order[j];
		word_order[j] = word_order[k];
		word_order[k] = t;
	}
	awaiting_word = true;
	word_index = 0;
	next_word();
}

void recovery_word(const char *word)
{
    if (!awaiting_word) 
    {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage, "Not in Recovery mode");
        layout_home();
        return;
    }

    if (word_pos == 0) 
    { // fake word
        if (strcmp(word, fake_word) != 0) {
            storage_reset();
            fsm_sendFailure(FailureType_Failure_SyntaxError, "Wrong word retyped");
            layout_home();
            return;
        }
    } else { // real word
        if (enforce_wordlist) 
        { // check if word is valid
            const char **wl = mnemonic_wordlist();
            bool found = false;
            while (*wl) 
            {
                if (strcmp(word, *wl) == 0) 
                {
                    found = true;
                    break;
                }
                wl++;
            }
            if (!found) 
            {
                storage_reset();
                fsm_sendFailure(FailureType_Failure_SyntaxError, "Word not found in a wordlist");
                layout_home();
                return;
            }
        }
        strlcpy(words[word_pos - 1], word, sizeof(words[word_pos - 1]));
    }

    if (word_index + 1 == 24)
    { // last one
        storage_set_mnemonic_from_words(words, word_count);

        if (!enforce_wordlist || mnemonic_check(storage_get_shadow_mnemonic()))
        {
        	/*
        	 * Setup saving animation
        	 */
        	layout_loading(SAVING_ANIM);
        	force_animation_start();

        	void tick(){
        		animate();
        		display_refresh();
        		delay(3);
        	}

        	tick();
        	storage_commit_ticking(&tick);

            fsm_sendSuccess("Device recovered");
        } else {
            storage_reset();
            fsm_sendFailure(FailureType_Failure_SyntaxError, "Invalid mnemonic, are words in correct order?");
        }
        awaiting_word = false;
        layout_home();
    } else {
        word_index++;
        next_word();
    }
}

void recovery_abort(void)
{
    if (awaiting_word) {
        layout_home();
        awaiting_word = false;
    }
}

const char *recovery_get_fake_word(void)
{
	return fake_word;
}

uint32_t recovery_get_word_pos(void)
{
	return word_pos;
}
