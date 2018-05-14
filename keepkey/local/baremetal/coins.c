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
#include <inttypes.h>

/* === Variables =========================================================== */

const CoinType coins[COINS_COUNT] = {
        {true, "Bitcoin",     true, "BTC",  true,   0, true,     100000, true,   5, true,  6, true, 10, true,  "\x18" "Bitcoin Signed Message:\n",  true, 0x80000000, false, 0, true,   8, false, {0, {0}},                                          false, {0, {0}}},
        {true, "Testnet",     true, "TEST", true, 111, true,   10000000, true, 196, true,  3, true, 40, true,  "\x18" "Bitcoin Signed Message:\n",  true, 0x80000001, false, 0, true,   8, false, {0, {0}},                                          false, {0, {0}}},
        {true, "BitcoinCash", true, "BCH",  true,   0, true,     500000, true,   5, false, 0, false, 0, true,  "\x18" "Bitcoin Signed Message:\n",  true, 0x80000091, true,  0, true,   8, false, {0, {0}},                                          false, {0, {0}}},
        {true, "Namecoin",    true, "NMC",  true,  52, true,   10000000, true,   5, false, 0, false, 0, true,  "\x19" "Namecoin Signed Message:\n", true, 0x80000007, false, 0, true,   8, false, {0, {0}},                                          false, {0, {0}}},
        {true, "Litecoin",    true, "LTC",  true,  48, true,    1000000, true,   5, false, 0, false, 0, true,  "\x19" "Litecoin Signed Message:\n", true, 0x80000002, false, 0, true,   8, false, {0, {0}},                                          false, {0, {0}}},
        {true, "Dogecoin",    true, "DOGE", true,  30, true, 1000000000, true,  22, false, 0, false, 0, true,  "\x19" "Dogecoin Signed Message:\n", true, 0x80000003, false, 0, true,   8, false, {0, {0}},                                          false, {0, {0}}},
        {true, "Dash",        true, "DASH", true,  76, true,     100000, true,  16, false, 0, false, 0, true,  "\x19" "DarkCoin Signed Message:\n", true, 0x80000005, false, 0, true,   8, false, {0, {0}},                                          false, {0, {0}}},
        {true, ETHEREUM,      true, "ETH",  true,  NA, true,     100000, true,  NA, false, 0, false, 0, true,  "\x19" "Ethereum Signed Message:\n", true, 0x8000003c, false, 0, true,  18, false, {0, {0}},                                          false, {0, {0}}},
        {true, ETHEREUM_CLS,  true, "ETC",  true,  NA, true,     100000, true,  NA, false, 0, false, 0, true,  "\x19" "Ethereum Signed Message:\n", true, 0x8000003d, false, 0, true,  18, false, {0, {0}},                                          false, {0, {0}}},

#define TOKEN(NAME, SYMBOL, DECIMALS, CONTRACT_ADDRESS, GAS_LIMIT) \
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

TOKEN(0x,             ZRX,   18, "\xE4\x1d\x24\x89\x57\x1d\x32\x21\x89\x24\x6D\xaF\xA5\xeb\xDe\x1F\x46\x99\xF4\x98", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(Aragon,         ANT,   18, "\x96\x0b\x23\x6A\x07\xcf\x12\x26\x63\xc4\x30\x33\x50\x60\x9A\x66\xA7\xB2\x88\xC0", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(Augur,          REP,   18, "\xE9\x43\x27\xD0\x7F\xc1\x79\x07\xb4\xDB\x78\x8E\x5a\xDf\x2e\xd4\x24\xad\xDf\xf6", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(BAT,            BAT,   18, "\x0D\x87\x75\xF6\x48\x43\x06\x79\xA7\x09\xE9\x8d\x2b\x0C\xb6\x25\x0d\x28\x87\xEF", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(Bancor,         BNT,   18, "\x1F\x57\x3D\x6F\xb3\xF1\x3d\x68\x9F\xF8\x44\xB4\xcE\x37\x79\x4d\x79\xa7\xFF\x1C", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(Civic,          CVC,    8, "\x41\xe5\x56\x00\x54\x82\x4e\xa6\xb0\x73\x2e\x65\x6e\x3a\xd6\x4e\x20\xe9\x4e\x45", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(DigixDAO,       DGD,    9, "\xE0\xB7\x92\x7c\x4a\xF2\x37\x65\xCb\x51\x31\x4A\x0E\x05\x21\xA9\x64\x5F\x0E\x2A", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(Edgeless,       EDG,    0, "\x08\x71\x1D\x3B\x02\xC8\x75\x8F\x2F\xB3\xab\x4e\x80\x22\x84\x18\xa7\xF8\xe3\x9c", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(FirstBlood,     1ST,   18, "\xAf\x30\xD2\xa7\xE9\x0d\x7D\xC3\x61\xc8\xC4\x58\x5e\x9B\xB7\xD2\xF6\xf1\x5b\xc7", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(FunFair,        FUN,    8, "\x41\x9D\x0d\x8B\xdD\x9a\xF5\xe6\x06\xAe\x22\x32\xed\x28\x5A\xff\x19\x0E\x71\x1b", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(Gnosis,         GNO,   18, "\x68\x10\xe7\x76\x88\x0c\x02\x93\x3d\x47\xdb\x1b\x9f\xc0\x59\x08\xe5\x38\x6b\x96", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(Golem,          GNT,   18, "\xa7\x44\x76\x44\x31\x19\xA9\x42\xdE\x49\x85\x90\xFe\x1f\x24\x54\xd7\xD4\xaC\x0d", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(Iconomi,        ICN,   18, "\x88\x86\x66\xCA\x69\xE0\xf1\x78\xDE\xD6\xD7\x5b\x57\x26\xCe\xe9\x9A\x87\xD6\x98", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(MatchPool,      GUP,    3, "\xf7\xb0\x98\x29\x8f\x7c\x69\xfc\x14\x61\x0b\xf7\x1d\x5e\x02\xc6\x07\x92\x89\x4c", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(Melon,          MLN,   18, "\xBE\xB9\xeF\x51\x4a\x37\x9B\x99\x7e\x07\x98\xFD\xcC\x90\x1E\xe4\x74\xB6\xD9\xA1", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(Metal,          MTL,    8, "\xF4\x33\x08\x93\x66\x89\x9D\x83\xa9\xf2\x6A\x77\x3D\x59\xec\x7e\xCF\x30\x35\x5e", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(Numeraire,      NMR,   18, "\x17\x76\xe1\xF2\x6f\x98\xb1\xA5\xdF\x9c\xD3\x47\x95\x3a\x26\xdd\x3C\xb4\x66\x71", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(OmiseGo,        OMG,   18, "\xd2\x61\x14\xcd\x6E\xE2\x89\xAc\xcF\x82\x35\x0c\x8d\x84\x87\xfe\xdB\x8A\x0C\x07", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(Qtum,           QTUM,  18, "\x9a\x64\x2d\x6b\x33\x68\xdd\xc6\x62\xCA\x24\x4b\xAd\xf3\x2c\xDA\x71\x60\x05\xBC", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(Ripio,          RCN,   18, "\xf9\x70\xb8\xe3\x6e\x23\xf7\xfc\x3f\xd7\x52\xee\xa8\x6f\x8b\xe8\xd8\x33\x75\xa6", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(SALT,           SALT,   8, "\x41\x56\xD3\x34\x2D\x5c\x38\x5a\x87\xD2\x64\xF9\x06\x53\x73\x35\x92\x00\x05\x81", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(SingularDTV,    SNGLS,  0, "\xae\xc2\xe8\x7e\x0a\x23\x52\x66\xd9\xc5\xad\xc9\xde\xb4\xb2\xe2\x9b\x54\xd0\x09", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(Status,         SNT,   18, "\x74\x4d\x70\xFD\xBE\x2B\xa4\xCF\x95\x13\x16\x26\x61\x4a\x17\x63\xDF\x80\x5B\x9E", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(Storj,          STORJ,  8, "\xb6\x4e\xf5\x1c\x88\x89\x72\xc9\x08\xcf\xac\xf5\x9b\x47\xc1\xaf\xbc\x0a\xb8\xac", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(SwarmCity,      SWT,   18, "\xb9\xe7\xf8\x56\x8e\x08\xd5\x65\x9f\x5d\x29\xc4\x99\x71\x73\xd8\x4c\xdf\x26\x07", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(TenX,           PAY,   18, "\xB9\x70\x48\x62\x8D\xB6\xB6\x61\xD4\xC2\xaA\x83\x3e\x95\xDb\xe1\xA9\x05\xB2\x80", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(WeTrust,        TRST,   6, "\xcb\x94\xbe\x6f\x13\xa1\x18\x2e\x4a\x4b\x61\x40\xcb\x7b\xf2\x02\x5d\x28\xe4\x1b", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(Wings,          WINGS, 18, "\x66\x70\x88\xb2\x12\xce\x3d\x06\xa1\xb5\x53\xa7\x22\x1E\x1f\xD1\x90\x00\xd9\xaF", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(district0x,     DNT,   18, "\x0a\xbd\xac\xe7\x0d\x37\x90\x23\x5a\xf4\x48\xc8\x85\x47\x60\x3b\x94\x56\x04\xea", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
TOKEN(iExec,          RLC,    9, "\x60\x7F\x4C\x5B\xB6\x72\x23\x0e\x86\x72\x08\x55\x32\xf7\xe9\x01\x54\x4a\x73\x75", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xe8\x48")
#undef TOKEN
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
        if(strncasecmp(shortcut, coins[i].coin_shortcut,
                       sizeof(coins[i].coin_shortcut)) == 0)
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
        if(strncasecmp(name, coins[i].coin_name,
                       sizeof(coins[i].coin_name)) == 0)
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
