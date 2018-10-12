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
#include "keepkey/firmware/util.h"

#include <inttypes.h>
#include <string.h>
#include <stdio.h>

#define SECP256K1_STRING "secp256k1"

#define TOKEN_ENTRY(INDEX, NAME, SYMBOL, DECIMALS, CONTRACT_ADDRESS, GAS_LIMIT) \
{   \
true, (#NAME),                     /* has_coin_name, coin_name*/ \
true, (#SYMBOL),                   /* has_coin_shortcut, coin_shortcut*/ \
false, NA,                         /* has_address_type, address_type*/ \
true, 100000,                      /* has_maxfee_kb, maxfee_kb*/ \
false, NA,                         /* has_address_type_p2sh, address_type_p2sh*/ \
false, 0,                          /* has_address_type_p2wpkh, address_type_p2wpkh*/ \
false, 0,                          /* has_address_type_p2wsh, address_type_p2wsh*/ \
false, "",                         /* has_signed_message_header, signed_message_header*/ \
true, 0x8000003C,                  /* has_bip44_account_path, bip44_account_path*/ \
false, 0,                          /* has_forkid, forkid*/ \
true, (DECIMALS),                  /* has_decimals, decimals*/ \
true, {20, {(CONTRACT_ADDRESS)}},  /* has_contract_address, contract_address*/ \
true, {32, {(GAS_LIMIT)}},         /* has_gas_limit, gas_limit*/ \
false, 0,                          /* has_xpub_magic, xpub_magic*/ \
false, 0,                          /* has_xprv_magic, xprv_magic*/ \
false, false,                      /* has_segwit, segwit */ \
false, false,                      /* has_force_bip143, force_bip143*/ \
true, SECP256K1_STRING,            /* has_curve_name, curve_name*/ \
false, "",                         /* has_cashaddr_prefix, cashaddr_prefix*/ \
false, "",                         /* has_bech32_prefix, bech32_prefix*/ \
false, false,                      /* has_decred, decred */ \
false, 0,                          /* has_version_group_id, version_group_id*/ \
false, 0,                          /* has_xpub_magic_segwit_p2sh, xpub_magic_segwit_p2sh*/ \
false, 0,                          /* has_xpub_magic_segwit_native, xpub_magic_segwit_native*/ \
},

const CoinType coins[COINS_COUNT] = {
//   coin_name             coin_shortcut  address_type  maxfee_kb          p2sh        p2wpkh     p2wsh      signed_message_header                           bip44_account_path  forkid/chain_id decimals    contract_address  gas_limit         xpub_magic       xprv_magic       segwit        force_bip143  curve_name               cashaddr_prefix       bech32_prefix  decred         version_group_id  xpub_magic_segwit_p2sh  xpub_mmagic_segwit_native
    {true, "Bitcoin",      true, "BTC",   true,   0,    true,     100000,  true,   5,  true,  6,  true, 10,  true, "\x18" "Bitcoin Signed Message:\n",       true, 0x80000000,   false,   0,     true,   8,  false, {0, {0}},  false, {0, {0}},  true, 76067358,  true, 76066276,  true, true,   true, false,  true, SECP256K1_STRING,  false, "",            true, "bc",    false, false,  false, 0,         true,  77429938,        true, 78792518 },
    {true, "Testnet",      true, "TEST",  true, 111,    true,   10000000,  true, 196,  true,  3,  true, 40,  true, "\x18" "Bitcoin Signed Message:\n",       true, 0x80000001,   false,   0,     true,   8,  false, {0, {0}},  false, {0, {0}},  true, 70617039,  true, 70615956,  true, true,   true, false,  true, SECP256K1_STRING,  false, "",            true, "tb",    false, false,  false, 0,         true,  71979618,        true, 73342198 },
    {true, "BitcoinCash",  true, "BCH",   true,   0,    true,     500000,  true,   5,  false, 0,  false, 0,  true, "\x18" "Bitcoin Signed Message:\n",       true, 0x80000091,   true,    0,     true,   8,  false, {0, {0}},  false, {0, {0}},  true, 76067358,  true, 76066276,  true, false,  true, true,   true, SECP256K1_STRING,  true, "bitcoincash",  false, "",     false, false,  false, 0,         false,        0,        false,       0 },
    {true, "Namecoin",     true, "NMC",   true,  52,    true,   10000000,  true,   5,  false, 0,  false, 0,  true, "\x19" "Namecoin Signed Message:\n",      true, 0x80000007,   false,   0,     true,   8,  false, {0, {0}},  false, {0, {0}},  true, 27108450,  true, 27106558,  true, false,  true, false,  true, SECP256K1_STRING,  false, "",            false, "",     false, false,  false, 0,         false,        0,        false,       0 },
    {true, "Litecoin",     true, "LTC",   true,  48,    true,    1000000,  true,  50,  false, 0,  false, 0,  true, "\x19" "Litecoin Signed Message:\n",      true, 0x80000002,   false,   0,     true,   8,  false, {0, {0}},  false, {0, {0}},  true, 27108450,  true, 27106558,  true, true,   true, false,  true, SECP256K1_STRING,  false, "",            true, "ltc",   false, false,  false, 0,         false,        0,        false,       0 },
    {true, "Dogecoin",     true, "DOGE",  true,  30,    true, 1000000000,  true,  22,  false, 0,  false, 0,  true, "\x19" "Dogecoin Signed Message:\n",      true, 0x80000003,   false,   0,     true,   8,  false, {0, {0}},  false, {0, {0}},  true, 49990397,  true, 49988504,  true, false,  true, false,  true, SECP256K1_STRING,  false, "",            false, "",     false, false,  false, 0,         false,        0,        false,       0 },
    {true, "Dash",         true, "DASH",  true,  76,    true,     100000,  true,  16,  false, 0,  false, 0,  true, "\x19" "DarkCoin Signed Message:\n",      true, 0x80000005,   false,   0,     true,   8,  false, {0, {0}},  false, {0, {0}},  true, 50221772,  true, 50221816,  true, false,  true, false,  true, SECP256K1_STRING,  false, "",            false, "",     false, false,  false, 0,         false,        0,        false,       0 },
    {true, ETHEREUM,       true, "ETH",   true,  NA,    true,     100000,  true,  NA,  false, 0,  false, 0,  true, "\x19" "Ethereum Signed Message:\n",      true, 0x8000003c,   true,    1,     true,  18,  false, {0, {0}},  false, {0, {0}},  false, 0,        false, 0,        true, false,  true, false,  true, SECP256K1_STRING,  false, "",            false, "",     false, false,  false, 0,         false,        0,        false,       0 },
    {true, ETHEREUM_CLS,   true, "ETC",   true,  NA,    true,     100000,  true,  NA,  false, 0,  false, 0,  true, "\x19" "Ethereum Signed Message:\n",      true, 0x8000003d,   true,   62,     true,  18,  false, {0, {0}},  false, {0, {0}},  false, 0,        false, 0,        true, false,  true, false,  true, SECP256K1_STRING,  false, "",            false, "",     false, false,  false, 0,         false,        0,        false,       0 },
    {true, "BitcoinGold",  true, "BTG",   true,  38,    true,     500000,  true,  23,  false, 0,  false, 0,  true, "\x1d" "Bitcoin Gold Signed Message:\n",  true, 0x8000009c,   true,   79,     true,   8,  false, {0, {0}},  false, {0, {0}},  true, 76067358,  true, 76066276,  true, true,   true, true,   true, SECP256K1_STRING,  false, "",            true, "btg",   false, false,  false, 0,         true,  77429938,        false,       0 },
    {true, "ZCash",        true, "ZEC",   true, 7352,   true,    1000000,  true, 7357, false, 0,  false, 0,  true, "\x16" "ZCash Signed Message:\n",         true, 0x80000085,   false,   0,     true,   8,  false, {0, {0}},  false, {0, {0}},  true, 76067358,  true, 76066276,  false, false, false, false, true, SECP256K1_STRING,  false, "",            false, "",     false, false,  true, 63210096,   false,        0,        false,       0 },
    {true, "Zcash Testnet",true, "TAZ",   true, 7461,   true,   10000000,  true, 7354, false, 0,  false, 0,  true, "\x16" "Zcash Signed Message:\n",         true, 0x80000085,   false,   0,     true,   8,  false, {0, {0}},  false, {0, {0}},  true, 70617039,  true, 70615956,  false, false, false, false, true, SECP256K1_STRING,  false, "",            false, "",     false, false,  true, 63210096,   false,        0,        false,       0 },
    #include "keepkey/firmware/tokens.def"
};

_Static_assert(sizeof(coins) / sizeof(coins[0]) == COINS_COUNT,
               "Update COINS_COUNT to match the size of the coin table");

// Borrowed from fsm_msg_coin.h
// PLEASE keep these in sync.
static bool path_mismatched(const CoinType *coin, const uint32_t *address_n,
                            uint32_t address_n_count, bool whole_account)
{
	bool mismatch = false;

	// m : no path
	if (address_n_count == 0) {
		return false;
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

	// Special case (not needed in the other copy of this function):
	if (address_n_count == 5 &&
		(strncmp(coin->coin_name, ETHEREUM, strlen(ETHEREUM)) == 0 ||
		 strncmp(coin->coin_name, ETHEREUM_CLS, sizeof(ETHEREUM_CLS)) == 0)) {
		// Check that the path is m/44'/bip44_account_path/y/0/0
		if (address_n[3] != 0)
			return true;
		if (address_n[4] != 0)
			return true;
	}

	return false;
}

bool bip32_path_to_string(char *str, size_t len, const uint32_t *address_n,
                          size_t address_n_count) {
    memset(str, 0, len);

    int cx = snprintf(str, len, "m");
    if (cx < 0 || len <= (size_t)cx)
        return false;
    str += cx;
    len -= cx;

    for (size_t i = 0; i < address_n_count; i++) {
        cx = snprintf(str, len, "/%" PRIu32, address_n[i] & 0x7fffffff);
        if (cx < 0 || len <= (size_t)cx)
            return false;
        str += cx;
        len -= cx;

        if ((address_n[i] & 0x80000000) == 0x80000000) {
            cx = snprintf(str, len, "'");
            if (cx < 0 || len <= (size_t)cx)
                return false;
            str += cx;
            len -= cx;
        }
    }

    return true;
}

const CoinType *coinByShortcut(const char *shortcut)
{
    if(!shortcut) { return 0; }

    int i;

    for(i = 0; i < COINS_COUNT; i++)
    {
        if(strncasecmp(shortcut, coins[i].coin_shortcut,
                       sizeof(coins[i].coin_shortcut)) == 0)
        {
            return &coins[i];
        }
    }

    return 0;
}

const CoinType *coinByName(const char *name)
{
    if(!name) { return 0; }

    int i;

    for(i = 0; i < COINS_COUNT; i++)
    {
        if(strncasecmp(name, coins[i].coin_name,
                       sizeof(coins[i].coin_name)) == 0)
        {
            return &coins[i];
        }
    }

    return 0;
}

const CoinType *coinByAddressType(uint32_t address_type)
{
    int i;

    for(i = 0; i < COINS_COUNT; i++)
    {
        if(address_type == coins[i].address_type)
        {
            return &coins[i];
        }
    }

    return 0;
}

const CoinType *coinBySlip44(uint32_t bip44_account_path)
{
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
void coin_amnt_to_str(const CoinType *coin, uint64_t amnt, char *buf, int len)
{
    uint64_t coin_fraction_part, coin_whole_part;
    int i;
    char buf_fract[10];

    memset(buf, 0, len);
    memset(buf_fract, 0, 10);

    /*Seperate amount to whole and fraction (amount = whole.fraction)*/
    coin_whole_part = amnt / COIN_FRACTION ;
    coin_fraction_part = amnt % COIN_FRACTION;

    /* Convert whole value to string */
    if(coin_whole_part > 0)
    {
        dec64_to_str(coin_whole_part, buf);
        buf[strlen(buf)] = '.';
    }
    else
    {
        strncpy(buf, "0.", 2);
    }

    /* Convert Fraction value to string */
    if(coin_fraction_part > 0)
    {
        dec64_to_str(coin_fraction_part, buf_fract);

        /* Add zeros after decimal */
        i = 8 - strlen(buf_fract);
        while(i)
        {
            buf[strlen(buf)+i-1] = '0';
            i--;
        }
        /*concantenate whole and fraction part of string */
        strncpy(buf+strlen(buf), buf_fract, strlen(buf_fract));

        /* Drop least significant zeros in fraction part to shorten display*/
        i = strlen(buf); 
        while(buf[i-1] == '0')
        {
            buf[i-1] = 0;
            i--;
        }
    }
    else
    {
        buf[strlen(buf)] = '0';
    }
    /* Added coin type to amount */
    if(coin->has_coin_shortcut)
    {
        buf[strlen(buf)] = ' ';
        strncpy(buf + strlen(buf), coin->coin_shortcut, strlen(coin->coin_shortcut));
    }
}

static const char *account_prefix(const CoinType *coin,
                                  const uint32_t *address_n,
                                  size_t address_n_count,
                                  bool whole_account) {
    if (!coin->has_segwit || !coin->segwit)
        return "";

    if (address_n_count < (whole_account ? 3 : 5))
        return NULL;

    uint32_t purpose = address_n[address_n_count - (whole_account ? 3 : 5)];

    if (purpose == (0x80000000 | 44))
        return "Legacy ";

    if (purpose == (0x80000000 | 49))
        return "SegWit ";

    if (purpose == (0x80000000 | 84))
        return "";

    return NULL;
}

bool bip32_node_to_string(char *node_str, size_t len, const CoinType *coin, uint32_t *address_n,
                          size_t address_n_count, bool whole_account)
{
    if (address_n_count != 3 && address_n_count != 5)
        return false;

    if (path_mismatched(coin, address_n, address_n_count, whole_account))
        return false;

    const char *prefix = account_prefix(coin, address_n, address_n_count, whole_account);
    if (!prefix)
        return false;

    // If it is a token, we still refer to the destination as an Ethereum account.
    bool is_token = coin->has_contract_address;
    const char *coin_name = is_token ? "Ethereum" : coin->coin_name;

    snprintf(node_str, len, "%s%s Account #%" PRIu32, prefix, coin_name,
             address_n[2] & 0x7ffffff);
    return true;
}

bool isEthereumLike(const char *coin_name)
{
    if (strcmp(coin_name, ETHEREUM) == 0)
        return true;

    if (strcmp(coin_name, ETHEREUM_CLS) == 0)
        return true;

    return false;
}
