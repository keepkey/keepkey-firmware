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

#include <string.h>
#include <stdio.h>

#include "coins.h"
#include <util.h>

/* === Variables =========================================================== */

const CoinType coins[COINS_COUNT] = {                                                                                                                                                                    
	{true, "Bitcoin",     true, "BTC",  true,   0, true,     100000, true,   5, true,  6, true, 10, true, "\x18" "Bitcoin Signed Message:\n",  true, 0x80000000, false, 0, false, 0, false, "", false, {0, {0}}}, 
	{true, "Testnet",     true, "TEST", true, 111, true,   10000000, true, 196, true,  3, true, 40, true, "\x18" "Bitcoin Signed Message:\n",  true, 0x80000001, false, 0, false, 0, false, "", false, {0, {0}}},  
	{true, "BitcoinCash", true, "BCH",  true,   0, true,     500000, true,   5, false, 0, false, 0, true, "\x18" "Bitcoin Signed Message:\n",  true, 0x80000091, true,  0, false, 0, false, "", false, {0, {0}}}, 
	{true, "Namecoin",    true, "NMC",  true,  52, true,   10000000, true,   5, false, 0, false, 0, true, "\x19" "Namecoin Signed Message:\n", true, 0x80000007, false, 0, false, 0, false, "", false, {0, {0}}}, 
	{true, "Litecoin",    true, "LTC",  true,  48, true,    1000000, true,   5, false, 0, false, 0, true, "\x19" "Litecoin Signed Message:\n", true, 0x80000002, false, 0, false, 0, false, "", false, {0, {0}}},
	{true, "Dogecoin",    true, "DOGE", true,  30, true, 1000000000, true,  22, false, 0, false, 0, true, "\x19" "Dogecoin Signed Message:\n", true, 0x80000003, false, 0, false, 0, false, "", false, {0, {0}}},
	{true, "Dash",        true, "DASH", true,  76, true,     100000, true,  16, false, 0, false, 0, true, "\x19" "DarkCoin Signed Message:\n", true, 0x80000005, false, 0, false, 0, false, "", false, {0, {0}}},
	{true, ETHEREUM,      true, "ETH",  true,  NA, true,     100000, true,  NA, false, 0, false, 0, true, "\x19" "Ethereum Signed Message:\n", true, 0x8000003c, false, 0, false, 0, false, "", false, {0, {0}}},
	{true, ETHEREUM_CLS,  true, "ETC",  true,  NA, true,     100000, true,  NA, false, 0, false, 0, true, "\x19" "Ethereum Signed Message:\n", true, 0x8000003d, false, 0, false, 0, false, "", false, {0, {0}}}, 
	{true, "Salt",        true, "SALT", true,  NA, true,     100000, true,  NA, false, 0, false, 0, true, "\x19" "Salt Signed Message:\n",     true, 0x8000003c, false, 0, true,  8, true, "0x4156D3342D5c385a87D264F90653733592000581", true, {32, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x24\xf8"}},
	{true, "Aragon",        true, "ANT", true,  NA, true,     100000, true,  NA, false, 0, false, 0, true, "\x19" "Aragon Signed Message:\n",  true, 0x8000003c, false, 0, true,  18, true, "0x960b236A07cf122663c4303350609A66A7B288C0", true, {32, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xad\xb0"}},
	{true, "Augur",        true, "REP", true,  NA, true,     100000, true,  NA, false, 0, false, 0, true, "\x19" "Augur Signed Message:\n",    true, 0x8000003c, false, 0, true,  18, true, "0xe94327d07fc17907b4db788e5adf2ed424addff6", true, {32, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x24\xf8"}},
	{true, "BAT",        true, "BAT", true,  NA, true,     100000, true,  NA, false, 0, false, 0, true, "\x19" "BAT Signed Message:\n",     true, 0x8000003c, false, 0, true,  18, true, "0x0d8775f648430679a709e98d2b0cb6250d2887ef", true, {32, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x24\xf8"}},
	{true, "Civic",        true, "CVC", true,  NA, true,     100000, true,  NA, false, 0, false, 0, true, "\x19" "Civic Signed Message:\n",     true, 0x8000003c, false, 0, true,  8, true, "0x41e5560054824ea6b0732e656e3ad64e20e94e45", true, {32, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x24\xf8"}},
	{true, "Golem",        true, "GNT", true,  NA, true,     100000, true,  NA, false, 0, false, 0, true, "\x19" "Golem Signed Message:\n",     true, 0x8000003c, false, 0, true,  18, true, "0xa74476443119A942dE498590Fe1f2454d7D4aC0d", true, {32, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x24\xf8"}},
	{true, "Gnosis",        true, "GNO", true,  NA, true,     100000, true,  NA, false, 0, false, 0, true, "\x19" "Gnosis Signed Message:\n",     true, 0x8000003c, false, 0, true,  18, true, "0x6810e776880c02933d47db1b9fc05908e5386b96", true, {32, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x24\xf8"}},
	{true, "OmiseGo",        true, "OMG", true,  NA, true,     100000, true,  NA, false, 0, false, 0, true, "\x19" "OmiseGo Signed Message:\n",     true, 0x8000003c, false, 0, true,  18, true, "0xd26114cd6EE289AccF82350c8d8487fedB8A0C07", true, {32, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x24\xf8"}},
	{true, "district0x",        true, "DNT", true,  NA, true,     100000, true,  NA, false, 0, false, 0, true, "\x19" "district0x Signed Message:\n",     true, 0x8000003c, false, 0, true,  18, true, "0x0abdace70d3790235af448c88547603b945604ea", true, {32, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xad\xb0"}},
	{true, "FunFair",        true, "FUN", true,  NA, true,     100000, true,  NA, false, 0, false, 0, true, "\x19" "FunFair Signed Message:\n",     true, 0x8000003c, false, 0, true,  8, true, "0x419d0d8bdd9af5e606ae2232ed285aff190e711b", true, {32, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x24\xf8"}}
};
// TODO: how do we want to specify the bip44 path at all here? Also do we want a distinct signing message?

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
        if(strcmp(shortcut, coins[i].coin_shortcut) == 0)
        {
            return &(coins[i]);
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
        if(strcmp(name, coins[i].coin_name) == 0)
        {
            return &(coins[i]);
        }
    }

    return 0;
}

const CoinType *coinByAddressType(uint8_t address_type)
{
    int i;

    for(i = 0; i < COINS_COUNT; i++)
    {
        if(address_type == coins[i].address_type)
        {
            return &(coins[i]);
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

    if(verify_bip44_node(coin, address_n, address_n_count))
    {
        snprintf(node_str, NODE_STRING_LENGTH, "%s account #%lu", coin->coin_name,
                    address_n[2] & 0x7ffffff);
        ret_stat = true;
    }
    return(ret_stat);
}
