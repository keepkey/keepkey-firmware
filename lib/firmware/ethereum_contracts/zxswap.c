/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2021 ShapeShift
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

#include "keepkey/firmware/ethereum_contracts/zxswap.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/fsm.h"
#include "hwcrypto/crypto/address.h"

static bool isSellToUniswapCall(const EthereumSignTx *msg) {
    if (memcmp(msg->data_initial_chunk.bytes, "\xd9\x62\x7a\xa4", 4) == 0)
        return true;

    return false;
}

bool zx_isZxSwap(const EthereumSignTx *msg) {

    if (memcmp(msg->to.bytes, ZXSWAP_ADDRESS, 20) == 0) {   // correct proxy address?
        if (isSellToUniswapCall(msg)) {                     // does kk handle call?
            return true;
        }
    }
    return false;
}

bool zx_confirmZxSwap(uint32_t data_total, const EthereumSignTx *msg) {
    (void)data_total;
    const TokenType *from, *to;
    uint8_t *fromAddress, *toAddress;
    char constr1[40], constr2[40];
    uint32_t numOfTokens, adder, isSushi;
    char *exchange;

    numOfTokens = read_be(msg->data_initial_chunk.bytes + 4 + 5*32 - 4);
    isSushi = read_be(msg->data_initial_chunk.bytes + 4 + 4*32 - 4);
    if (isSushi == 0) {
        exchange = "Uniswap";
    } else {
        exchange = "Sushiswap";
    }

    switch (numOfTokens) {
        case 2:
            adder = 0;  // only two tokens, swap to token second
            break;
        case 3:
            adder = 1;  // swap to token last in the list of 3
            break;
        default:        // can't interpret 0, 1, or >3 tokens
            return false;
            break;
    }

    fromAddress = (uint8_t *)(msg->data_initial_chunk.bytes + 4 + 5*32 + 12);
    toAddress = (uint8_t *)(msg->data_initial_chunk.bytes + 4 + (6+adder)*32 + 12);


    from = tokenByChainAddress(msg->chain_id, fromAddress);
    to = tokenByChainAddress(msg->chain_id, toAddress);
    
    // Get token trade amount data
    bignum256 sellTokenAmount, minBuyTokenAmount;
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 32, 32, &sellTokenAmount);
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 2*32, 32, &minBuyTokenAmount);

    char sellToken[32];
    char minBuyToken[32];
    ethereumFormatAmount(&sellTokenAmount, from, msg->chain_id, sellToken,
                       sizeof(sellToken));
    ethereumFormatAmount(&minBuyTokenAmount, to, msg->chain_id, minBuyToken,
                       sizeof(minBuyToken));

    snprintf(constr1, 32, "%s", sellToken);
    snprintf(constr2, 32, "%s", minBuyToken);

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, exchange,
                 "Sell %s\nBuy at least %s", constr1, constr2);
    
    return true;
}
