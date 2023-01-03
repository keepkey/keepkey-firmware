/*
 * 
 * Copyright (C) 2022 markrypto <cryptoakorn@gmail.com>
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

#include "keepkey/board/util.h"
#include "keepkey/firmware/tiny-json.h"

#include <stdbool.h>
#include <stdint.h>

#define TOKENS_COUNT 2

// ethereum message verify status and errors
#define MV_OK         0       // no error
#define MV_MALDATA    1       // malformed data
#define MV_INVALSIG   2       // invalid sig
#define MV_STOKOK     3       // signed token received and added status
#define MV_TDERR      4       // JSON token data error
#define MV_TRESET     5       // token reset token received status
#define MV_TLISTFULL  6       // token list full, reset list to add new token
#define IV_IDERR      7       // JSON icon data error
#define IV_ICONOK     8       // icon data ok


typedef struct _TokenType {
  bool validToken;             // false if data not validated
  uint8_t address[20];
  char ticker[10];
  uint32_t chain_id;
  uint8_t decimals;
  char name[25];
  char blockchain[25];
} TokenType;

typedef struct _CoinType CoinType;

extern TokenType tokens[];

extern const TokenType *UnknownToken;

const TokenType *tokenIter(int32_t *ctr);

const TokenType *tokenByChainAddress(uint8_t chain_id, const uint8_t *address);

/// Tokens don't have unique tickers, so this might not return the one you're
/// looking for :/
///
/// This is necessary because the way the KeepKey client handles TRANSFER
/// messages, relying on the ticker to uniquely identify the token... which is a
/// poor assumption. We should instead put the contract address in the
/// EthereumSignTx message, and get rid of this function.
///
/// \param[out] token The found token, assuming it was uniquely determinable.
/// \returns true iff the token can be uniquely found in the list of known
/// tokens.
bool tokenByTicker(uint8_t chain_id, const char *ticker,
                   const TokenType **token);

void coinFromToken(CoinType *coin, const TokenType *token);
int evp_parse(unsigned char *tokenVals);
int evpTokenParse(json_t const *jsonTV);
int evpDappVerify(json_t const *jsonDV);

#endif
