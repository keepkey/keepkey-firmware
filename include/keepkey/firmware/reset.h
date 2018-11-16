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

#define MAX_WORDS               24
#define MAX_WORD_LEN            10
#define MAX_PAGES               3
#define ADDITIONAL_WORD_PAD     5
#define WORDS_PER_SCREEN        24
#define TOKENED_MNEMONIC_BUF    MAX_WORDS * (MAX_WORD_LEN + 1) + 1
#define FORMATTED_MNEMONIC_BUF  MAX_WORDS * (MAX_WORD_LEN + ADDITIONAL_WORD_PAD) + 1
#define MNEMONIC_BY_SCREEN_BUF  WORDS_PER_SCREEN * (MAX_WORD_LEN + 1) + 1

void reset_init(bool display_random, uint32_t _strength, bool passphrase_protection,
                bool pin_protection, const char *language, const char *label,
                bool no_backup, uint32_t _auto_lock_delay_ms);
void reset_entropy(const uint8_t *ext_entropy, uint32_t len);
uint32_t reset_get_int_entropy(uint8_t *entropy);
const char *reset_get_word(void);

#endif
