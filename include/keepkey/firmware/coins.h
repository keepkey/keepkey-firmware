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

#ifndef COINS_H
#define COINS_H

#include "keepkey/transport/interface.h"

#define NA      0xFFFF  /*etherum does not use P2PH or P2SH */
#define ETHEREUM        "Ethereum"
#define ETHEREUM_CLS    "Ethereum Classic"

#define COINS_COUNT         40
#define NODE_STRING_LENGTH  50

#define COIN_FRACTION 100000000

extern const CoinType coins[COINS_COUNT];

const CoinType *coinByShortcut(const char *shortcut);
const CoinType *coinByName(const char *name);
const CoinType *coinByAddressType(uint32_t address_type);
void coin_amnt_to_str(const CoinType *coin, uint64_t amnt, char *buf, int len);
bool bip44_node_to_string(const CoinType *coin, char *node_str, uint32_t *address_n,
                         size_t address_n_count);

#endif
