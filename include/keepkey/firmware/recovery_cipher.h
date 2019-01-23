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

#ifndef RECOVERY_CIPHER_H
#define RECOVERY_CIPHER_H

#include <stdint.h>
#include <stdbool.h>

#define MNEMONIC_BUF            24 * 12
#define CURRENT_WORD_BUF        32
#define ENGLISH_ALPHABET_BUF    32
#define ENGLISH_MAX_WORD_LEN    8

void recovery_cipher_init(bool passphrase_protection, bool pin_protection, const char *language,
    const char *label, bool _enforce_wordlist, uint32_t _auto_lock_delay_ms,
    uint32_t _u2f_counter);
void next_character(void);
void recovery_character(const char *character);
void recovery_delete_character(void);
void recovery_cipher_finalize(void);
bool recovery_cipher_abort(void);

#if DEBUG_LINK
const char* recovery_get_cipher(void);
const char* recovery_get_auto_completed_word(void);
#endif


/// Determine if two strings are exact matches for length passed
/// (does not stop at null termination)
///
/// \param str1  The first string.
/// \param str2  The second string.
/// \return true iff the strings match
bool exact_str_match(const char *str1, const char *str2, uint32_t len);

/// \brief Attempts to auto complete a partial word
///
/// \param partial_word[in/out]   word that will be attempted to be auto completed.
/// \returns true iff partial_word was auto completed
bool attempt_auto_complete(char *partial_word);

#endif
