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

/* === Includes ============================================================ */

#include <string.h>
#include <stdio.h>

#include <bip39.h>
#include <keepkey_board.h>
#include <layout.h>
#include <msg_dispatch.h>

#include "storage.h"
#include "recovery_cipher.h"
#include "app_layout.h"
#include "rng.h"
#include "fsm.h"
#include "pin_sm.h"
#include "home_sm.h"

/* === Private Variables =================================================== */

static bool enforce_wordlist;
static bool awaiting_character;
static char mnemonic[MNEMONIC_BUF];
static char english_alphabet[ENGLISH_ALPHABET_BUF] = "abcdefghijklmnopqrstuvwxyz";
static char cipher[ENGLISH_ALPHABET_BUF];

#if DEBUG_LINK
static char auto_completed_word[CURRENT_WORD_BUF];
#endif

static void format_current_word(char *current_word, bool auto_completed);
static uint32_t get_current_word_pos(void);
static void get_current_word(char *current_word);
static bool exact_str_match(const char *str1, const char *str2, uint32_t len);
static bool attempt_auto_complete(char *partial_word);

/* === Private Functions =================================================== */

/*
 * format_current_word() - Formats the passed word to show position in mnemonic 
 * as well as characters left
 *
 * INPUT
 *     - current_word: string to format
 *     - auto_completed: whether to format as an auto completed word
 * OUTPUT
 *     none
 */
static void format_current_word(char *current_word, bool auto_completed)
{
    char temp_word[CURRENT_WORD_BUF];
    uint32_t i,
             pos_len,
             word_num = get_current_word_pos() + 1;

    pos_len = strlen(current_word);
    snprintf(temp_word, CURRENT_WORD_BUF, "%lu.%s", (unsigned long)word_num, current_word);

    /* Pad with dashes */
    if(strlen(current_word) < 4)
    {
        for(i = 0; i < 4 - pos_len; i++)
        {
            strlcat(temp_word, "-", CURRENT_WORD_BUF);
        }
    }

    /* Mark as auto completed */
    if(auto_completed)
    {
        temp_word[strlen(temp_word) + 1] = '\0';
        temp_word[strlen(temp_word)] = '~';
    }

    strlcpy(current_word, temp_word, CURRENT_WORD_BUF);
}

/*
 * get_current_word_pos() - Returns the current word position in the mnemonic
 *
 * INPUT
 *     none
 * OUTPUT
 *     position in mnemonic
 */
static uint32_t get_current_word_pos(void)
{
    char *pos_num = strchr(mnemonic, ' ');
    uint32_t word_pos = 0;

    while(pos_num != NULL)
    {
        word_pos++;
        pos_num = strchr(++pos_num, ' ');
    }

    return word_pos;
}

/*
 * get_current_word() - Returns the current word being entered by parsing the 
 * mnemonic thus far
 *
 * INPUT
 *     - current_word: array to populate with current word
 * OUTPUT
 *     none
 */
static void get_current_word(char *current_word)
{
    char *pos = strrchr(mnemonic, ' ');

    if(pos)
    {
        pos++;
        strlcpy(current_word, pos, CURRENT_WORD_BUF);
    }
    else
    {
        strlcpy(current_word, mnemonic, CURRENT_WORD_BUF);
    }
}

/*
 * exact_str_match() - Determines if two strings are exact matches for length passed
 * (does not stop at null termination)
 *
 * INPUT
 *     - str1: first string
 *     - str2: second string
 *     - len: length to compare string for match
 * OUTPUT
 *     true/false whether matched or not
 */
static bool exact_str_match(const char *str1, const char *str2, uint32_t len)
{
    uint32_t i = 0, match = 0;

    for(; i < len && i < CURRENT_WORD_BUF; i++)
    {
        if(str1[i] == str2[i])
        {
            match++;
        }
        else
        {
            match--;
        }
    }

    return match == len;
}

/*
 * attempt_auto_complete() - Attempts to auto complete a partial word
 *
 * INPUT
 *     - partial_word: word that will be attempted to be auto completed
 * OUTPUT
 *     true/false whether partial_word was auto completed or not
 */
static bool attempt_auto_complete(char *partial_word)
{
    const char *const *wordlist = mnemonic_wordlist();

    uint32_t partial_word_len = strlen(partial_word), i = 0, match = 0, found = 0;

    for(; wordlist[i] != 0; i++)
    {
        /* Check for match including null termination */
        if(exact_str_match(partial_word, wordlist[i], partial_word_len + 1))
        {
            strlcpy(partial_word, wordlist[i], CURRENT_WORD_BUF);
            goto matched;
        }
        /* Check for match for just characters of partial word */
        else if(exact_str_match(partial_word, wordlist[i], partial_word_len))
        {
            match++;
            found = i;
        }
    }

    /* Autocomplete if we can */
    if(match == 1)
    {
        strlcpy(partial_word, wordlist[found], CURRENT_WORD_BUF);
    }
    else
    {
        return false;
    }

matched:
    return true;
}

/* === Functions =========================================================== */

/*
 * recovery_cipher_init() - Display standard notification on LCD screen
 *
 * INPUT
 *     - passphrase_protection: whether to use passphrase protection
 *     - pin_protection: whether to use pin protection
 *     - language: language for device
 *     - label: label for device
 *     - _enforce_wordlist: whether to enforce bip 39 word list
 * OUTPUT
 *     none
 */
void recovery_cipher_init(bool passphrase_protection, bool pin_protection,
                          const char *language, const char *label, bool _enforce_wordlist)
{
    if(pin_protection && !change_pin())
    {
        go_home();
        return;
    }

    storage_set_passphrase_protected(passphrase_protection);
    storage_set_language(language);
    storage_set_label(label);

    enforce_wordlist = _enforce_wordlist;

    /* Clear mnemonic */
    memset(mnemonic, 0, sizeof(mnemonic) / sizeof(char));

    /* Set to recovery cipher mode and generate and show next cipher */
    awaiting_character = true;
    next_character();
}

/*
 * next_character() - Randomizes cipher and displays it for next character entry
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void next_character(void)
{
    char current_word[CURRENT_WORD_BUF];
    bool auto_completed = false;
    CharacterRequest resp;

    /* Scramble cipher */
    strlcpy(cipher, english_alphabet, ENGLISH_ALPHABET_BUF);
    random_permute(cipher, strlen(cipher));

    get_current_word(current_word);

    if(strlen(current_word) > 4)        /* Words should never be longer than 4 characters */
    {
        awaiting_character = false;
        go_home();

        storage_reset();
        fsm_sendFailure(FailureType_Failure_SyntaxError, "Words were not entered correctly.");
    }
    else
    {
        memset(&resp, 0, sizeof(CharacterRequest));

        resp.word_pos = get_current_word_pos();
        resp.character_pos = strlen(current_word);

        msg_write(MessageType_MessageType_CharacterRequest, &resp);

        if(strlen(current_word) >=
                3)   /* Attempt to auto complete if we have at least 3 characters */
        {
            auto_completed = attempt_auto_complete(current_word);
        }

#if DEBUG_LINK

        if(auto_completed)
        {
            strlcpy(auto_completed_word, current_word, CURRENT_WORD_BUF);
        }
        else
        {
            auto_completed_word[0] = '\0';
        }

#endif

        /* Format current word and display it along with cipher */
        format_current_word(current_word, auto_completed);

        /* Show cipher and partial word */
        layout_cipher(current_word, cipher);
    }
}

/*
 * recovery_character() - Decodes character received from host
 *
 * INPUT
 *     - character: string to decode
 * OUTPUT
 *     none
 */
void recovery_character(const char *character)
{

    char decoded_character[2] = " ", *pos;

    if(strlen(mnemonic) + 1 > MNEMONIC_BUF - 1)
    {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                        "Too many characters attempted during recovery");
        go_home();
        goto finished;
    }
    else if(awaiting_character)
    {

        pos = strchr(cipher, character[0]);

        if(character[0] != ' ' &&
                pos == NULL)      /* If not a space and not a legitmate cipher character, send failure */
        {

            awaiting_character = false;
            fsm_sendFailure(FailureType_Failure_SyntaxError, "Character must be from a to z");
            go_home();
            goto finished;

        }
        else if(character[0] !=
                ' ')                /* Decode character using cipher if not space */
        {

            decoded_character[0] = english_alphabet[(int)(pos - cipher)];

        }

        // concat to mnemonic
        strlcat(mnemonic, decoded_character, MNEMONIC_BUF);

        next_character();

    }
    else
    {

        fsm_sendFailure(FailureType_Failure_UnexpectedMessage, "Not in Recovery mode");
        go_home();
        goto finished;

    }

finished:
    return;
}

/*
 * recovery_delete_character() - Deletes previously received recovery character
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void recovery_delete_character(void)
{
    if(strlen(mnemonic) > 0)
    {
        mnemonic[strlen(mnemonic) - 1] = '\0';
    }

    next_character();
}

/*
 * recovery_cipher_finalize() - Finished mnemonic entry
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void recovery_cipher_finalize(void)
{
    char full_mnemonic[MNEMONIC_BUF] = "", temp_word[CURRENT_WORD_BUF], *tok;
    bool auto_completed = true;

    /* Attempt to autocomplete each word */
    tok = strtok(mnemonic, " ");

    while(tok)
    {
        strlcpy(temp_word, tok, CURRENT_WORD_BUF);

        if(!attempt_auto_complete(temp_word))
        {
            auto_completed = false;
        }

        strlcat(full_mnemonic, temp_word, MNEMONIC_BUF);
        strlcat(full_mnemonic, " ", MNEMONIC_BUF);

        tok = strtok(NULL, " ");
    }

    if(auto_completed)
    {
        /* Trunicate additional space at end */
        full_mnemonic[strlen(full_mnemonic) - 1] = '\0';

        storage_set_mnemonic(full_mnemonic);
    }

    if(!enforce_wordlist || mnemonic_check(storage_get_shadow_mnemonic()))
    {
        storage_commit();
        fsm_sendSuccess("Device recovered");
    }
    else if(!auto_completed)
    {
        storage_reset();
        fsm_sendFailure(FailureType_Failure_SyntaxError, "Words were not entered correctly.");
    }
    else
    {
        storage_reset();
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        "Invalid mnemonic, are words in correct order?");
    }

    awaiting_character = false;
    go_home();
}

/*
 * recovery_cipher_abort() - Aborts recovery cipher process
 *
 * INPUT
 *     none
 * OUTPUT
 *     true/false of whether recovery was aborted
 */
bool recovery_cipher_abort(void)
{
    if(awaiting_character)
    {
        awaiting_character = false;
        return true;
    }
    else
    {
        return false;
    }
}

/* === Debug Functions =========================================================== */

#if DEBUG_LINK
/*
 * recovery_get_cipher() - Gets current cipher being show on display
 *
 * INPUT
 *     none
 * OUTPUT
 *     current cipher
 */
const char *recovery_get_cipher(void)
{
    return cipher;
}

/*
 * recovery_get_auto_completed_word() - Gets last auto completed word
 *
 * INPUT
 *     none
 * OUTPUT
 *     last auto completed word
 */
const char *recovery_get_auto_completed_word(void)
{
    return auto_completed_word;
}
#endif
