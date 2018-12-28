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

#define COINS_COUNT         61
#define NODE_STRING_LENGTH  50

#define COIN_FRACTION 100000000

extern const CoinType coins[];

const CoinType *coinByShortcut(const char *shortcut);
const CoinType *coinByName(const char *name);
const CoinType *coinByAddressType(uint32_t address_type);
const CoinType *coinBySlip44(uint32_t bip44_account_path);
void coin_amnt_to_str(const CoinType *coin, uint64_t amnt, char *buf, int len);

/// \brief Parses node path to precise BIP32 equivalent string
bool bip32_path_to_string(char *str, size_t len, const uint32_t *address_n, size_t address_n_count);

/**
 * \brief Parses node path to human-friendly BIP32 equivalent string
 *
 * INPUT -
 * \param[out]  node_str         buffer to populate
 * \param[in]   len              size of buffer
 * \param[in]   coin             coin to use to determine bip44 path
 * \param[in]   address_n        node path
 * \param[in]   address_n_count  size of address_n array
 * \param[in]   whole_account    true iff address_n refers to an entire account (not just an address)
 * \returns true iff the path matches a known bip44/bip49/bip84/etc account
 */
bool bip32_node_to_string(char *node_str, size_t len, const CoinType *coin, uint32_t *address_n,
                          size_t address_n_count, bool whole_account);


/// \returns true iff the coin_name is for an eth-like coin.
bool isEthereumLike(const char *coin_name);

#endif
