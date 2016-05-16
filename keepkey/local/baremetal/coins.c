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

#include "coins.h"

/* === Variables =========================================================== */

const CoinType coins[COINS_COUNT] =
{
    {true, "Bitcoin",          true, "BTC",  true,   0, true,            100000, true,   5, true, NetworkType_BITCOIN},
    {true, "Testnet",          true, "TEST", true, 111, true,          10000000, true, 196, true, NetworkType_BITCOIN},
    {true, "Namecoin",         true, "NMC",  true,  52, true,          10000000, true,   5, true, NetworkType_BITCOIN},
    {true, "Litecoin",         true, "LTC",  true,  48, true,           1000000, true,   5, true, NetworkType_BITCOIN},
    {true, "Dogecoin",         true, "DOGE", true,  30, true,        1000000000, true,  22, true, NetworkType_BITCOIN},
    {true, "Dash",             true, "DASH", true,  76, true,            100000, true,  16, true, NetworkType_BITCOIN},
// Ethereum definitions remain commented out until transaction signing is implemented.
//    {true, "Ethereum",         true, "ETH",  false,  0, true, 10000000000000000, false,  0, true, NetworkType_ETHEREUM},
//    {true, "Ethereum Testnet", true, "ETH",  false,  0, true, 10000000000000000, false,  0, true, NetworkType_ETHEREUM},
};

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

void coin_amnt_to_str(const CoinType *coin, uint64_t amnt, char *buf, int len)
{
    memset(buf, 0, len);
    uint64_t a = amnt, b = 1;
    int i;

    for(i = 0; i < 8; i++)
    {
        buf[16 - i] = '0' + (a / b) % 10;
        b *= 10;
    }

    buf[8] = '.';

    for(i = 0; i < 8; i++)
    {
        buf[7 - i] = '0' + (a / b) % 10;
        b *= 10;
    }

    i = 17;

    while(i > 10 && buf[i - 1] == '0')  // drop trailing zeroes
    {
        i--;
    }

    if(coin->has_coin_shortcut)
    {
        buf[i] = ' ';
        strlcpy(buf + i + 1, coin->coin_shortcut, len - i - 1);
    }
    else
    {
        buf[i] = 0;
    }

    while(buf[0] == '0' && buf[1] != '.')  // drop leading zeroes
    {
        i = 0;

        while((buf[i] = buf[i + 1])) { i++; }
    }
}
