/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2019 ShapeShift
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
#include "trezor/crypto/address.h"

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
    char constr1[20], constr2[20];
    //bignum256 sellTokenAmount, minBuyTokenAmount;
    (void)constr2;
    
    fromAddress = (uint8_t *)(msg->data_initial_chunk.bytes + 4 + 6*32 + 12);
    toAddress = (uint8_t *)(msg->data_initial_chunk.bytes + 4 + 7*32 + 4 + 12);

    from = tokenByChainAddress(msg->chain_id, fromAddress);
    to = tokenByChainAddress(msg->chain_id, toAddress);

    snprintf(constr1, 20, "%s for %s", from->ticker, to->ticker);

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Uniswap",
                 "Confirm Uniswap Swap:\n%s", constr1)) {
        return false;
    }
    /*
    // Get trade value data
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 32, 32, &sellTokenAmount);
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 2*32, 32, &minBuyTokenAmount);

    char withdraw[32];
    ethereumFormatAmount(&sellTokenAmount, DAI, msg->chain_id, withdraw,
                       sizeof(withdraw));


    snprintf(constr1, 20, "%s %d", from->ticker, to->ticker);

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Uniswap",
                 "Sell %s:\nBuy at least: %s", constr1, constr2);
    */
   return true;
}
