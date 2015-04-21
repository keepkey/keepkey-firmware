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
 * @brief Recovery cipher.
 */

#ifndef __RECOVERY_CIPHER_H__
#define __RECOVERY_CIPHER_H__

#include <stdint.h>
#include <stdbool.h>

#define MNEMONIC_BUF            24 * 12
#define CURRENT_WORD_BUF        12
#define ENGLISH_ALPHABET_BUF    27
#define ENGLISH_MAX_WORD_LEN    8

void recovery_cipher_init(bool passphrase_protection, bool pin_protection, const char *language,
    const char *label, bool _enforce_wordlist);
void next_character(void);
void recovery_character(const char *character);
void recovery_delete_character(void);
void recovery_cipher_finalize(void);
bool recovery_cipher_abort(void);

#if DEBUG_LINK
const char* recovery_get_cipher(void);
const char* recovery_get_auto_completed_word(void);
#endif

#endif