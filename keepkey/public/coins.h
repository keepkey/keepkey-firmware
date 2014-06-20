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

#ifndef __COINS_H__
#define __COINS_H__

#include "types.pb.h"

#define COINS_COUNT 4

extern const CoinType coins[COINS_COUNT];

const CoinType *coinByShortcut(const char *shortcut);
const CoinType *coinByName(const char *name);
const CoinType *coinByAddressType(uint8_t address_type);

/**
 * Converts the given number of satoshi's into a bbb.sssBTC format
 * suitable for printing.  NULL termination is guaranteed.
 *
 * @param satoshi The amount in satoshi
 * @param unit Set to true to append BTC to the output.
 *
 * @return static string suitable for immediate use.  If you
 * want to keep it around for awhile you'll need to copy it off.
 *
 * @note This function will assert if it encounters bogus satoshi amount.
 */
const char* satoshi_to_str(uint64_t satoshi, bool unit);

#endif
