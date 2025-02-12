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
#include "keepkey/board/util.h"

#define NA 0xFFFF /*etherum does not use P2PH or P2SH */
#define ETHEREUM "Ethereum"
#define ETHEREUM_CLS "ETH Classic"
#define ETHEREUM_TST "ETH Testnet"

enum {
#define X(HAS_COIN_NAME, COIN_NAME, HAS_COIN_SHORTCUT, COIN_SHORTCUT,          \
          HAS_ADDRESS_TYPE, ADDRESS_TYPE, HAS_MAXFEE_KB, MAXFEE_KB,            \
          HAS_ADDRESS_TYPE_P2SH, ADDRESS_TYPE_P2SH, HAS_SIGNED_MESSAGE_HEADER, \
          SIGNED_MESSAGE_HEADER, HAS_BIP44_ACCOUNT_PATH, BIP44_ACCOUNT_PATH,   \
          HAS_FORKID, FORKID, HAS_DECIMALS, DECIMALS, HAS_CONTRACT_ADDRESS,    \
          CONTRACT_ADDRESS, HAS_XPUB_MAGIC, XPUB_MAGIC, HAS_SEGWIT, SEGWIT,    \
          HAS_FORCE_BIP143, FORCE_BIP143, HAS_CURVE_NAME, CURVE_NAME,          \
          HAS_CASHADDR_PREFIX, CASHADDR_PREFIX, HAS_BECH32_PREFIX,             \
          BECH32_PREFIX, HAS_DECRED, DECRED, HAS_XPUB_MAGIC_SEGWIT_P2SH,       \
          XPUB_MAGIC_SEGWIT_P2SH, HAS_XPUB_MAGIC_SEGWIT_NATIVE,                \
          XPUB_MAGIC_SEGWIT_NATIVE, HAS_NANOADDR_PREFIX, NANOADDR_PREFIX,      \
          HAS_TAPROOT, TAPROOT)                                                \
  CONCAT(CoinIndex, __COUNTER__),
#include "keepkey/firmware/coins.def"

#ifdef BITCOIN_ONLY
// For full-featured keepkey, this is defined in ethereum_tokens.h. For bitcoin only keepkey, need to
// define it here because ethereum_tokens.h is not included in any file
#define TOKENS_COUNT  0
#else
#define X(INDEX, NAME, SYMBOL, DECIMALS, CONTRACT_ADDRESS) \
  CONCAT(CoinIndex, __COUNTER__),
#include "keepkey/firmware/tokens.def"
#endif
  CoinIndexLast,
  CoinIndexFirst = 0
};


#define COINS_COUNT ((int)CoinIndexLast - (int)CoinIndexFirst)
#define NODE_STRING_LENGTH 50

#define COIN_FRACTION 100000000

// SLIP-44 hardened coin type for Bitcoin
#define SLIP44_BITCOIN 0x80000000

// SLIP-44 hardened coin type for all Testnet coins
#define SLIP44_TESTNET 0x80000001


extern const CoinType coins[];

const CoinType *coinByShortcut(const char *shortcut);
const CoinType *coinByName(const char *name);
const CoinType *coinByNameOrTicker(const char *name);
const CoinType *coinByChainAddress(uint8_t chain_id, const uint8_t *address);
const CoinType *coinByAddressType(uint32_t address_type);
const CoinType *coinBySlip44(uint32_t bip44_account_path);
void coin_amnt_to_str(const CoinType *coin, uint64_t amnt, char *buf, int len);

/// \brief Parses node path to precise BIP32 equivalent string
bool bip32_path_to_string(char *str, size_t len, const uint32_t *address_n,
                          size_t address_n_count);

/**
 * \brief Parses node path to human-friendly BIP32 equivalent string
 *
 * INPUT -
 * \param[out]  node_str         buffer to populate
 * \param[in]   len              size of buffer
 * \param[in]   coin             coin to use to determine bip44 path
 * \param[in]   address_n        node path
 * \param[in]   address_n_count  size of address_n array
 * \param[in]   whole_account    true iff address_n refers to an entire account
 * (not just an address) \param[in]   show_addridx     whether to display
 * address indexes \returns true iff the path matches a known
 * bip44/bip49/bip84/etc account
 */
bool bip32_node_to_string(char *node_str, size_t len, const CoinType *coin,
                          const uint32_t *address_n, size_t address_n_count,
                          bool whole_account, bool show_addridx);

/// \returns true iff the coin_name is for an eth-like coin.
bool isEthereumLike(const char *coin_name);

/// \returns true iff the coin_name is for an account-based coin.
bool isAccountBased(const char *coin_name);

#endif
