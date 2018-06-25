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

/* === Includes ============================================================ */

#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/util.h"

#include <inttypes.h>
#include <string.h>
#include <stdio.h>

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
},


/* === Variables =========================================================== */

const CoinTable coins = {
        .table = {
	    {true, "Bitcoin",      true, "BTC",  true,   0, true,     100000, true,   5, true,  6, true, 10, true, "\x18" "Bitcoin Signed Message:\n",      true, 0x80000000, false, 0, true,   8, false, {0, {0}}, false, {0, {0}}},
	    {true, "Testnet",      true, "TEST", true, 111, true,   10000000, true, 196, true,  3, true, 40, true, "\x18" "Bitcoin Signed Message:\n",      true, 0x80000001, false, 0, true,   8, false, {0, {0}}, false, {0, {0}}},
	    {true, "BitcoinCash",  true, "BCH",  true,   0, true,     500000, true,   5, false, 0, false, 0, true, "\x18" "Bitcoin Signed Message:\n",      true, 0x80000091, true,  0, true,   8, false, {0, {0}}, false, {0, {0}}},
	    {true, "Namecoin",     true, "NMC",  true,  52, true,   10000000, true,   5, false, 0, false, 0, true, "\x19" "Namecoin Signed Message:\n",     true, 0x80000007, false, 0, true,   8, false, {0, {0}}, false, {0, {0}}},
	    {true, "Litecoin",     true, "LTC",  true,  48, true,    1000000, true,   5, false, 0, false, 0, true, "\x19" "Litecoin Signed Message:\n",     true, 0x80000002, false, 0, true,   8, false, {0, {0}}, false, {0, {0}}},
	    {true, "Dogecoin",     true, "DOGE", true,  30, true, 1000000000, true,  22, false, 0, false, 0, true, "\x19" "Dogecoin Signed Message:\n",     true, 0x80000003, false, 0, true,   8, false, {0, {0}}, false, {0, {0}}},
	    {true, "Dash",         true, "DASH", true,  76, true,     100000, true,  16, false, 0, false, 0, true, "\x19" "DarkCoin Signed Message:\n",     true, 0x80000005, false, 0, true,   8, false, {0, {0}}, false, {0, {0}}},
	    {true, ETHEREUM,       true, "ETH",  true,  NA, true,     100000, true,  NA, false, 0, false, 0, true, "\x19" "Ethereum Signed Message:\n",     true, 0x8000003c, false, 0, true,  18, false, {0, {0}}, false, {0, {0}}},
	    {true, ETHEREUM_CLS,   true, "ETC",  true,  NA, true,     100000, true,  NA, false, 0, false, 0, true, "\x19" "Ethereum Signed Message:\n",     true, 0x8000003d, false, 0, true,  18, false, {0, {0}}, false, {0, {0}}},
	    {true, "BitcoinGold",  true, "BTG",  true,  38, true,     500000, true,  23, false, 0, false, 0, true, "\x1d" "Bitcoin Gold Signed Message:\n", true, 0x8000009c, true, 79, true,   8, false, {0, {0}}, false, {0, {0}}},
	    {true, "ZCash",        true, "ZEC",  true, 7352, true,   1000000, true, 7357, false, 0, false, 0, true, "\x16" "ZCash Signed Message:\n",       true, 0x80000085, false, 0, true,   8, false, {0, {0}}, false, {0, {0}}},
//	    {true, "Zcash Testnet",true, "TAZ",  true, 7461, true,  10000000, true, 7354, false, 0, false, 0, true, "\x16" "Zcash Signed Message:\n",       true, 0x80000085, false, 0, true,   8, false, {0, {0}}, false, {0, {0}}},
	    #include "keepkey/firmware/tokens.def"
        }
};


/* === Private Functions =================================================== */
/*
 * verify_bip44_node() - Checks node is valid bip44
 *
 * INPUT
 *     *coin - coin type pointer
 *     address_n - node path
 *     address_n_count - number of nodes in path
 * OUTPUT
 *     true/false status
 *
 * Note : address_n[5] = {/44'/bip44_account_path/account #/0/0 }
 *
 * bip44 account path:
 *      Bitcoin  - 0x8000_0000
 *      Litecoin - 0x8000_0002
 *      Dogecoin - 0x8000_0003
 *      Ethereum - 0x8000_003c
 *      ...
 *      ...
 */
static bool verify_bip44_node(const CoinType *coin, uint32_t *address_n, size_t address_n_count)
{
    bool ret_stat = false;
    if(address_n_count == 5 && address_n[3] == 0)
    {
        if(strncmp(coin->coin_name, ETHEREUM, strlen(ETHEREUM)) == 0  || strncmp(coin->coin_name, ETHEREUM_CLS, sizeof(ETHEREUM_CLS)) == 0 )
        {
            if(address_n[4] != 0)
            {
                goto verify_bip44_node_exit;
            }
        }
        if(address_n[0] == 0x8000002C && address_n[1] == coin->bip44_account_path)
        {
            ret_stat = true;
        }
    }
verify_bip44_node_exit:
    return(ret_stat);
}

/* === Functions =========================================================== */
const CoinType *coinByShortcut(const char *shortcut)
{
    if(!shortcut) { return 0; }

    int i;

    for(i = 0; i < COINS_COUNT; i++)
    {
        if(strncasecmp(shortcut, coins.table[i].coin_shortcut,
                       sizeof(coins.table[i].coin_shortcut)) == 0)
        {
            return &(coins.table[i]);
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
        if(strncasecmp(name, coins.table[i].coin_name,
                       sizeof(coins.table[i].coin_name)) == 0)
        {
            return &(coins.table[i]);
        }
    }

    return 0;
}

const CoinType *coinByAddressType(uint32_t address_type)
{
    int i;

    for(i = 0; i < COINS_COUNT; i++)
    {
        if(address_type == coins.table[i].address_type)
        {
            return &(coins.table[i]);
        }
    }

    return 0;
}

/* === Functions =========================================================== */

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

/*
 * bip44_node_to_string() - Parses node path to BIP 44 equivalent string
 *
 * INPUT -
 *      - coin: coin to use to determine bip44 path
 *      - node_str: buffer to populate
 *      - address_n: node path
 *      - address_n_coin: size of address_n array
 * OUTPUT -
 *     true/false whether node path was bip 44 string or just regular node
 *
 */
bool bip44_node_to_string(const CoinType *coin, char *node_str, uint32_t *address_n,
                         size_t address_n_count)
{
    bool ret_stat = false;
    bool is_token = coin->has_contract_address;

    if(verify_bip44_node(coin, address_n, address_n_count))
    {
        // If it is a token we still refer to the destination as an Ethereum account
        if (is_token) {
            snprintf(node_str, NODE_STRING_LENGTH, "%s account #%" PRIu32, "Ethereum",
                    address_n[2] & 0x7ffffff);
        } else {
            snprintf(node_str, NODE_STRING_LENGTH, "%s account #%" PRIu32, coin->coin_name,
                    address_n[2] & 0x7ffffff);
        }
        ret_stat = true;
    }
    return(ret_stat);
}
