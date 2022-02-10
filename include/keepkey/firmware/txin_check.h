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

#ifndef TXIN_CHECK_H
#define TXIN_CHECK_H

#include <stdint.h>
#include <stdbool.h>

#define DIGEST_STR_LEN (2 * SHA256_DIGEST_LENGTH) + 1
#define AMT_STR_LEN 32
#define ADDR_STR_LEN 130

void txin_dgst_addto(const uint8_t *data, size_t len);
void txin_dgst_initialize(void);
bool txin_dgst_compare(const char *amt_str, const char *addr_str);
void txin_dgst_final(void);
void txin_dgst_getstrs(char *prev, char *cur, size_t len);
void txin_dgst_save_and_reset(char *amt_str, char *addr_str);

#endif
