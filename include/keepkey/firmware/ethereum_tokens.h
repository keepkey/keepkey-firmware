/*
 * This file is part of the TREZOR project, https://trezor.io/
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

#ifndef __ETHEREUM_TOKENS_H__
#define __ETHEREUM_TOKENS_H__

#include <stdbool.h>
#include <stdint.h>

#define TOKENS_COUNT 797

typedef struct _TokenType {
    uint8_t chain_id;
    const char * const address;
    const char * const ticker;
    int decimals;
} TokenType;

extern const TokenType tokens[];

extern const TokenType *UnknownToken;

const TokenType *tokenByChainAddress(uint8_t chain_id, const uint8_t *address);

/// Tokens don't have unique tickers, so this might not return the one you're looking for :/
///
/// This is necessary because the way the KeepKey client handles TRANSFER
/// messages, relying on the ticker to uniquely identify the token... which is a
/// poor assumption. We should instead put the contract address in the
/// EthereumSignTx message, and get rid of this function.
///
/// \param[out] token The found token, assuming it was uniquely determinable.
/// \returns true iff the token can be uniquely found in the list of known tokens.
bool tokenByTicker(uint8_t chain_id, const char *ticker, const TokenType **token);

#endif
