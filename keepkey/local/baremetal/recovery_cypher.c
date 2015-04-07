/* START KEEPKEY LICENSE */
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
 *
 */
/* END KEEPKEY LICENSE */

/*
 * @brief Recovery cypher.
 */

#include <string.h>
#include <stdio.h>

#include <bip39.h>
#include <keepkey_board.h>
#include <layout.h>
#include <msg_dispatch.h>
#include <storage.h>

#include "recovery_cypher.h"
#include "rng.h"
#include "fsm.h"
#include "pin_sm.h"
#include "home_sm.h"

static bool enforce_wordlist;
static bool awaiting_character;
static char mnemonic[24 * 12];
static char english_alphabet[] = "abcdefghijklmnopqrstuvwxyz";
static char cypher[27];

void get_current_word(char *current_word);

/*
 * recovery_cypher_init() - display standard notification on LCD screen
 *
 * INPUT - 
 *      1. bool passphrase_protection - whether to use passphrase protection
 *      2. bool pin_protection - whether to use pin protection
 *      3. string language - language for device
 *      4. string label - label for device
 *      5. bool _enforce_wordlist - whether to enforce bip 39 word list
 * OUTPUT - 
 *      none
 */
void recovery_cypher_init(bool passphrase_protection, bool pin_protection, 
        const char *language, const char *label, bool _enforce_wordlist) {
	if (pin_protection && !change_pin()) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, "PIN change failed");
		go_home();
		return;
	}

	storage_set_passphrase_protected(passphrase_protection);
	storage_setLanguage(language);
	storage_setLabel(label);

    enforce_wordlist = _enforce_wordlist;

    /* Clear mnemonic */
    memset(mnemonic, 0, sizeof(mnemonic) / sizeof(char));

    /* Set to recovery cypher mode and generate and show next cypher */
    awaiting_character = true;
	next_character();
}

/*
 * next_character() - randomizes cypher and displays it for next character entry
 *
 * INPUT - 
 *      none
 * OUTPUT - 
 *      none
 */
void next_character(void) {
    char current_word[12] = "", temp;
    uint32_t i, j, k;

    strcpy(cypher, english_alphabet);

    for (i = 0; i < 10000; i++) {
        j = random32() % 26;
        delay_us(1);  /* brief pause before acquiring another random value */
        k = random32() % 26;
        delay_us(1);  /* brief pause before acquiring another random value */
        temp = cypher[j];
        cypher[j] = cypher[k];
        cypher[k] = temp;
    }

    /* Format current word and display it along with cypher */
    get_current_word(current_word);
    layout_cypher(current_word, cypher);

    CharacterRequest resp;
    memset(&resp, 0, sizeof(CharacterRequest));
    msg_write(MessageType_MessageType_CharacterRequest, &resp);
}

/*
 * recovery_character() - decodes character received from host
 *
 * INPUT - 
 *      1. string character - string to decode
 * OUTPUT - 
 *      none
 */
void recovery_character(const char *character) {
    
    char decoded_character[2] = " ", *pos;

    if(awaiting_character) {

        pos = strchr(cypher, character[0]);

        if(character[0] != ' ' && pos == NULL) {    /* If not a space and not a legitmate cypher character, send failure */
            
            awaiting_character = false;
            fsm_sendFailure(FailureType_Failure_SyntaxError, "Character must be from a to z");
            go_home();
            return;

        } else if(character[0] != ' ') {            /* Decode character using cypher if not space */
            
            decoded_character[0] = english_alphabet[(int)(pos - cypher)];

        }

        // concat to mnemonic
        strcat(mnemonic, decoded_character);

        next_character();

    } else {

        fsm_sendFailure(FailureType_Failure_UnexpectedMessage, "Not in Recovery mode");
        go_home();
        return;

    }
}

/*
 * recovery_delete_character() - deletes previously received recovery character
 *
 * INPUT - 
 *      none
 * OUTPUT - 
 *      none
 */
void recovery_delete_character(void) {
    mnemonic[strlen(mnemonic) - 1] = '\0';
    next_character();
}

/*
 * recovery_final_character() - finished mnemonic entry
 *
 * INPUT - 
 *      none
 * OUTPUT - 
 *      none
 */
void recovery_final_character(void) {
    char words[24][12], temp[] = {'\0', '\0'};
    int i, j;

    /* Parse menmonic into array */
    for(i = 0, j = 0; i < strlen(mnemonic); ++i) {
        if(mnemonic[i] == ' ') {
            j++;
            words[j][0] = '\0';
        } else {
            temp[0] = mnemonic[i];
            strcat(words[j], temp);
        }
    }

    storage_set_mnemonic_from_words((const char (*)[])words, j + 1);

    /* Go home before commiting to eliminate lag */
    go_home();

    if (!enforce_wordlist || mnemonic_check(storage_get_shadow_mnemonic()))
    {
        storage_commit();
        fsm_sendSuccess("Device recovered");
    } else {
        storage_reset();
        fsm_sendFailure(FailureType_Failure_SyntaxError, "Invalid mnemonic, are words in correct order?");
    }
    awaiting_character = false;
}

/*
 * recovery_cypher_abort() - aborts recovery cypher process
 *
 * INPUT - 
 *      none
 * OUTPUT - 
 *      bool - status of aborted
 */
bool recovery_cypher_abort(void)
{
    if (awaiting_character) {
        awaiting_character = false;
        return true;
    } else {
        return false;
    }
}

/*
 * recovery_get_cypher() - gets current cypher being show on display
 *
 * INPUT - 
 *      none
 * OUTPUT - 
 *      none
 */
const char *recovery_get_cypher(void)
{
    return cypher;
}

/*
 * get_current_word() - returns the current word of the mnemonic sentence entry
 *
 * INPUT - 
 *      1. string current_word - string to decode
 * OUTPUT - 
 *      none
 */
void get_current_word(char *current_word) {
    char *pos = strrchr(mnemonic, ' '), *pos_num = strchr(mnemonic,' ');
    int i, j, word_num = 1, pos_len;

    /* Determine word number */
    while (pos_num != NULL) {
        word_num++;
        pos_num = strchr(++pos_num, ' ');
    }

    if(pos) {
        *pos++;
        pos_len = strlen(pos);
        sprintf(current_word, "%d.%s", word_num, pos);
    } else {
        pos_len = strlen(mnemonic);
        sprintf(current_word, "1.%s", mnemonic);
    }

    /* Pad with asterix */
    for(i = 0; i < 8 - pos_len; i++) {
        strcat(current_word, "-");
    }
}