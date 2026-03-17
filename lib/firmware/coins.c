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

#include "keepkey/firmware/coins.h"

#include "keepkey/board/util.h"

#include <inttypes.h>
#include <string.h>
#include <stdio.h>

#define SECP256K1_STRING "secp256k1"
#define ED25519_BLAKE2B_NANO_STRING "ed25519-blake2b-nano"

const CoinType coins[COINS_COUNT] = {
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
  {HAS_COIN_NAME,                                                              \
   COIN_NAME,                                                                  \
   HAS_COIN_SHORTCUT,                                                          \
   COIN_SHORTCUT,                                                              \
   HAS_ADDRESS_TYPE,                                                           \
   ADDRESS_TYPE,                                                               \
   HAS_MAXFEE_KB,                                                              \
   MAXFEE_KB,                                                                  \
   HAS_ADDRESS_TYPE_P2SH,                                                      \
   ADDRESS_TYPE_P2SH,                                                          \
   HAS_SIGNED_MESSAGE_HEADER,                                                  \
   SIGNED_MESSAGE_HEADER,                                                      \
   HAS_BIP44_ACCOUNT_PATH,                                                     \
   BIP44_ACCOUNT_PATH,                                                         \
   HAS_FORKID,                                                                 \
   FORKID,                                                                     \
   HAS_DECIMALS,                                                               \
   DECIMALS,                                                                   \
   HAS_CONTRACT_ADDRESS,                                                       \
   CONTRACT_ADDRESS,                                                           \
   HAS_XPUB_MAGIC,                                                             \
   XPUB_MAGIC,                                                                 \
   HAS_SEGWIT,                                                                 \
   SEGWIT,                                                                     \
   HAS_FORCE_BIP143,                                                           \
   FORCE_BIP143,                                                               \
   HAS_CURVE_NAME,                                                             \
   CURVE_NAME,                                                                 \
   HAS_CASHADDR_PREFIX,                                                        \
   CASHADDR_PREFIX,                                                            \
   HAS_BECH32_PREFIX,                                                          \
   BECH32_PREFIX,                                                              \
   HAS_DECRED,                                                                 \
   DECRED,                                                                     \
   HAS_XPUB_MAGIC_SEGWIT_P2SH,                                                 \
   XPUB_MAGIC_SEGWIT_P2SH,                                                     \
   HAS_XPUB_MAGIC_SEGWIT_NATIVE,                                               \
   XPUB_MAGIC_SEGWIT_NATIVE,                                                   \
   HAS_NANOADDR_PREFIX,                                                        \
   NANOADDR_PREFIX,                                                            \
   HAS_TAPROOT,                                                                \
   TAPROOT},
#include "keepkey/firmware/coins.def"

#ifndef BITCOIN_ONLY
#define X(INDEX, NAME, SYMBOL, DECIMALS, CONTRACT_ADDRESS)                    \
  {                                                                           \
      true,                                                                   \
      (#NAME), /* has_coin_name, coin_name*/                                  \
      true,                                                                   \
      (#SYMBOL), /* has_coin_shortcut, coin_shortcut*/                        \
      false,                                                                  \
      NA, /* has_address_type, address_type*/                                 \
      true,                                                                   \
      100000, /* has_maxfee_kb, maxfee_kb*/                                   \
      false,                                                                  \
      NA, /* has_address_type_p2sh, address_type_p2sh*/                       \
      false,                                                                  \
      "", /* has_signed_message_header, signed_message_header*/               \
      true,                                                                   \
      0x8000003C, /* has_bip44_account_path, bip44_account_path*/             \
      true,                                                                   \
      1, /* has_forkid, forkid*/                                              \
      true,                                                                   \
      (DECIMALS), /* has_decimals, decimals*/                                 \
      true,                                                                   \
      {20, {(CONTRACT_ADDRESS)}}, /* has_contract_address, contract_address*/ \
      false,                                                                  \
      0, /* has_xpub_magic, xpub_magic*/                                      \
      false,                                                                  \
      false, /* has_segwit, segwit */                                         \
      false,                                                                  \
      false, /* has_force_bip143, force_bip143*/                              \
      true,                                                                   \
      SECP256K1_STRING, /* has_curve_name, curve_name*/                       \
      false,                                                                  \
      "", /* has_cashaddr_prefix, cashaddr_prefix*/                           \
      false,                                                                  \
      "", /* has_bech32_prefix, bech32_prefix*/                               \
      false,                                                                  \
      false, /* has_decred, decred */                                         \
      false,                                                                  \
      0, /* has_xpub_magic_segwit_p2sh, xpub_magic_segwit_p2sh*/              \
      false,                                                                  \
      0, /* has_xpub_magic_segwit_native, xpub_magic_segwit_native*/          \
      false,                                                                  \
      "", /* has_nanoaddr_prefix, nanoaddr_prefix*/                           \
      false, false, /* has_taproot, taproot*/                                 \
  },
#include "keepkey/firmware/tokens.def"
#endif // BITCOIN_ONLY
};

_Static_assert(sizeof(coins) / sizeof(coins[0]) == COINS_COUNT,
               "Update COINS_COUNT to match the size of the coin table");

// Borrowed from fsm_msg_coin.h
// PLEASE keep these in sync.
static bool path_mismatched(const CoinType *coin, const uint32_t *address_n,
                            uint32_t address_n_count, bool whole_account) {
  bool mismatch = false;

  // m : no path
  if (address_n_count == 0) {
    return false;
  }

  // Special case (not needed in the other copy of this function):
  // KeepKey only puts ETH-like coins on m/44'/coin'/account'/0/0 paths
  if (address_n_count == 5 &&
      (strncmp(coin->coin_name, ETHEREUM, strlen(ETHEREUM)) == 0 ||
       strncmp(coin->coin_name, ETHEREUM_CLS, sizeof(ETHEREUM_CLS)) == 0 ||
       strncmp(coin->coin_name, ETHEREUM_TST, sizeof(ETHEREUM_TST)) == 0 ||
       coin->has_contract_address)) {
    if (whole_account) return true;
    // Check that the path is m/44'/bip44_account_path/y/0/0
    if (address_n[3] != 0) return true;
    if (address_n[4] != 0) return true;
  }

  // m/44' : BIP44 Legacy
  // m / purpose' / bip44_account_path' / account' / change / address_index
  if (address_n[0] == (0x80000000 + 44)) {
    mismatch |= (address_n_count != (whole_account ? 3 : 5));
    mismatch |= (address_n[1] != coin->bip44_account_path);
    mismatch |= (address_n[2] & 0x80000000) == 0;
    if (!whole_account) {
      mismatch |= (address_n[3] & 0x80000000) == 0x80000000;
      mismatch |= (address_n[4] & 0x80000000) == 0x80000000;
    }
    return mismatch;
  }

  // m/45' - BIP45 Copay Abandoned Multisig P2SH
  // m / purpose' / cosigner_index / change / address_index
  if (address_n[0] == (0x80000000 + 45)) {
    mismatch |= (address_n_count != 4);
    mismatch |= (address_n[1] & 0x80000000) == 0x80000000;
    mismatch |= (address_n[2] & 0x80000000) == 0x80000000;
    mismatch |= (address_n[3] & 0x80000000) == 0x80000000;
    return mismatch;
  }

  // m/48' - BIP48 Copay Multisig P2SH
  // m / purpose' / bip44_account_path' / account' / change / address_index
  if (address_n[0] == (0x80000000 + 48)) {
    mismatch |= (address_n_count != (whole_account ? 3 : 5));
    mismatch |= (address_n[1] != coin->bip44_account_path);
    mismatch |= (address_n[2] & 0x80000000) == 0;
    if (!whole_account) {
      mismatch |= (address_n[3] & 0x80000000) == 0x80000000;
      mismatch |= (address_n[4] & 0x80000000) == 0x80000000;
    }
    return mismatch;
  }

  // m/49' : BIP49 SegWit
  // m / purpose' / bip44_account_path' / account' / change / address_index
  if (address_n[0] == (0x80000000 + 49)) {
    mismatch |= !coin->has_segwit || !coin->segwit;
    mismatch |= !coin->has_address_type_p2sh;
    mismatch |= (address_n_count != (whole_account ? 3 : 5));
    mismatch |= (address_n[1] != coin->bip44_account_path);
    mismatch |= (address_n[2] & 0x80000000) == 0;
    if (!whole_account) {
      mismatch |= (address_n[3] & 0x80000000) == 0x80000000;
      mismatch |= (address_n[4] & 0x80000000) == 0x80000000;
    }
    return mismatch;
  }

  // m/84' : BIP84 Native SegWit
  // m / purpose' / bip44_account_path' / account' / change / address_index
  if (address_n[0] == (0x80000000 + 84)) {
    mismatch |= !coin->has_segwit || !coin->segwit;
    mismatch |= !coin->has_bech32_prefix;
    mismatch |= (address_n_count != (whole_account ? 3 : 5));
    mismatch |= (address_n[1] != coin->bip44_account_path);
    mismatch |= (address_n[2] & 0x80000000) == 0;
    if (!whole_account) {
      mismatch |= (address_n[3] & 0x80000000) == 0x80000000;
      mismatch |= (address_n[4] & 0x80000000) == 0x80000000;
    }
    return mismatch;
  }

  return false;
}

bool bip32_path_to_string(char *str, size_t len, const uint32_t *address_n,
                          size_t address_n_count) {
  memset(str, 0, len);

  int cx = snprintf(str, len, address_n_count == 0 ? "m/" : "m");
  if (cx < 0 || len <= (size_t)cx) return false;
  str += cx;
  len -= cx;

  for (size_t i = 0; i < address_n_count; i++) {
    cx = snprintf(str, len, "/%" PRIu32, address_n[i] & 0x7fffffff);
    if (cx < 0 || len <= (size_t)cx) return false;
    str += cx;
    len -= cx;

    if ((address_n[i] & 0x80000000) == 0x80000000) {
      cx = snprintf(str, len, "'");
      if (cx < 0 || len <= (size_t)cx) return false;
      str += cx;
      len -= cx;
    }
  }

  return true;
}

const CoinType *coinByShortcut(const char *shortcut) {
  if (!shortcut) {
    return 0;
  }

  int i;

  for (i = 0; i < COINS_COUNT; i++) {
    if (strncasecmp(shortcut, coins[i].coin_shortcut,
                    sizeof(coins[i].coin_shortcut)) == 0) {
      return &coins[i];
    }
  }

  return 0;
}

const CoinType *coinByName(const char *name) {
  if (!name) {
    return 0;
  }

  int i;

  for (i = 0; i < COINS_COUNT; i++) {
    if (strncasecmp(name, coins[i].coin_name, sizeof(coins[i].coin_name)) ==
        0) {
      return &coins[i];
    }
  }

  return 0;
}

const CoinType *coinByNameOrTicker(const char *name) {
  const CoinType *coin = coinByName(name);
  if (coin) return coin;

  return coinByShortcut(name);
}

const CoinType *coinByChainAddress(uint8_t chain_id, const uint8_t *address) {
  if (chain_id != 1) return NULL;

  if (!address) return NULL;

  for (int i = 0; i < COINS_COUNT; i++) {
    if (!coins[i].has_contract_address) continue;

    if (coins[i].contract_address.size != 20) continue;

    if (memcmp(address, coins[i].contract_address.bytes, 20) == 0)
      return &coins[i];
  }

  return NULL;
}

const CoinType *coinByAddressType(uint32_t address_type) {
  int i;

  for (i = 0; i < COINS_COUNT; i++) {
    if (address_type == coins[i].address_type) {
      return &coins[i];
    }
  }

  return 0;
}

const CoinType *coinBySlip44(uint32_t bip44_account_path) {
  for (int i = 0; i < COINS_COUNT; i++) {
    if (bip44_account_path == coins[i].bip44_account_path) {
      return &coins[i];
    }
  }
  return 0;
}

/*
 * coin_amnt_to_str() - convert decimal coin amount to string for display
 *
 * INPUT -
 *      - coin: coin to use to determine bip44 path
 *      - amnt - coing amount in decimal
 *      - *buf - output buffer for coin amount in string
 *      - len - length of buffer
 * OUTPUT -
 *     none
 *
 */
void coin_amnt_to_str(const CoinType *coin, uint64_t amnt, char *buf, int len) {
  uint64_t coin_fraction_part, coin_whole_part;
  int i;
  char buf_fract[10];

  memset(buf, 0, len);
  memset(buf_fract, 0, 10);

  /*Seperate amount to whole and fraction (amount = whole.fraction)*/
  coin_whole_part = amnt / COIN_FRACTION;
  coin_fraction_part = amnt % COIN_FRACTION;

  /* Convert whole value to string */
  if (coin_whole_part > 0) {
    dec64_to_str(coin_whole_part, buf);
    strlcat(buf, ".", len);
  } else {
    strlcat(buf, "0.", len);
  }

  /* Convert Fraction value to string */
  if (coin_fraction_part > 0) {
    dec64_to_str(coin_fraction_part, buf_fract);

    /* Add zeros after decimal */
    for (i = 8 - strlen(buf_fract); i > 0; i--) {
      strlcat(buf, "0", len);
    }
    /*concantenate whole and fraction part of string */
    strlcat(buf, buf_fract, len);

    /* Drop least significant zeros in fraction part to shorten display*/
    for (i = strlen(buf); i > 0 && buf[i - 1] == '0'; i--) {
      buf[i - 1] = 0;
    }
  } else {
    strlcat(buf, "0", len);
  }
  /* Added coin type to amount */
  if (coin->has_coin_shortcut) {
    strlcat(buf, " ", len);
    strlcat(buf, coin->coin_shortcut, len);
  }
}

static const char *account_prefix(const CoinType *coin,
                                  const uint32_t *address_n,
                                  size_t address_n_count, bool whole_account) {
  if (!coin->has_segwit || !coin->segwit) return "";

  if (address_n_count < (whole_account ? 3 : 5)) return NULL;

  uint32_t purpose = address_n[address_n_count - (whole_account ? 3 : 5)];

  if (purpose == (0x80000000 | 44)) return "";

  if (purpose == (0x80000000 | 49)) return "\x01 ";

  if (purpose == (0x80000000 | 84)) return "\x01 ";

  return NULL;
}

bool isTendermint(const char *coin_name) {
  if (strcmp(coin_name, "Cosmos") == 0) return true;

  if (strcmp(coin_name, "Osmosis") == 0) return true;

  if (strcmp(coin_name, "MAYAChain") == 0) return true;

  if (strcmp(coin_name, "Binance") == 0) return true;

  if (strcmp(coin_name, "THORChain") == 0) return true;

  if (strcmp(coin_name, "Terra") == 0) return true;

  if (strcmp(coin_name, "Kava") == 0) return true;

  if (strcmp(coin_name, "Secret") == 0) return true;

  return false;
}

bool isEthereumLike(const char *coin_name) {
  if (strcmp(coin_name, ETHEREUM) == 0) return true;

  if (strcmp(coin_name, ETHEREUM_CLS) == 0) return true;

  if (strcmp(coin_name, ETHEREUM_TST) == 0) return true;

  return false;
}

static bool isEOS(const char *coin_name) {
  if (strcmp(coin_name, "EOS") == 0) return true;

  return false;
}

static bool isRipple(const char *coin_name) {
  if (strcmp(coin_name, "Ripple") == 0) return true;

  return false;
}

bool isAccountBased(const char *coin_name) {
  if (isTendermint(coin_name)) {
    return true;
  }
  if (isEthereumLike(coin_name)) {
    return true;
  }
  if (isEOS(coin_name)) {
    return true;
  }
  if (isRipple(coin_name)) {
    return true;
  }
  return false;
}

bool bip32_node_to_string(char *node_str, size_t len, const CoinType *coin,
                          const uint32_t *address_n, size_t address_n_count,
                          bool whole_account, bool show_addridx) {
  if (address_n_count != 3 && address_n_count != 5) return false;

  // If it is a token, we still refer to the destination as an Ethereum account.
  bool is_token = coin->has_contract_address;
  const char *coin_name = is_token ? "Ethereum" : coin->coin_name;

  if (!whole_account) {
    if (address_n_count != 5) return false;

    // Only 0/1 for internal/external are valid paths on UTXO coins.
    if (!isAccountBased(coin_name) && address_n[3] != 0 && address_n[3] != 1)
      return false;
  }

  if (path_mismatched(coin, address_n, address_n_count, whole_account))
    return false;

  const char *prefix =
      account_prefix(coin, address_n, address_n_count, whole_account);
  if (!prefix) return false;

  if (whole_account || isAccountBased(coin_name) || !show_addridx) {
    snprintf(node_str, len, "%s%s Account #%" PRIu32, prefix, coin_name,
             address_n[2] & 0x7fffffff);
  } else {
    bool is_change = address_n[3] == 1;
    snprintf(node_str, len, "%s%s Account #%" PRIu32 "\n%sAddress #%" PRIu32,
             prefix, coin_name, address_n[2] & 0x7fffffff,
             is_change ? "Change " : "", address_n[4]);
  }

  return true;
}
