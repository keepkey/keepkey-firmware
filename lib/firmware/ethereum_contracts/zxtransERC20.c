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

#include "keepkey/firmware/ethereum_contracts/zxtransERC20.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/fsm.h"
#include "hwcrypto/crypto/address.h"

static bool isTransERC20Call(const EthereumSignTx *msg) {
    if (memcmp(msg->data_initial_chunk.bytes, "\x41\x55\x65\xb0", 4) == 0)
        return true;

    return false;
}

bool zx_isZxTransformERC20(const EthereumSignTx *msg) {

    if (memcmp(msg->to.bytes, ZXSWAP_ADDRESS, 20) == 0) {   // correct proxy address?
        if (isTransERC20Call(msg)) {                     // does kk handle call?
            return true;
        }
    }
    return false;
}

bool zx_confirmZxTransERC20(uint32_t data_total, const EthereumSignTx *msg) {
    (void)data_total;
    const TokenType *in, *out;
    uint8_t *inAddress, *outAddress;
    char constr1[40], constr2[40];
    bignum256 inAmount, outAmount;
    char inToken[32], outToken[32];


    inAddress = (uint8_t *)(msg->data_initial_chunk.bytes + 4 + 12);
    outAddress = (uint8_t *)(msg->data_initial_chunk.bytes + 4 + 32 + 12);
    in = tokenByChainAddress(msg->chain_id, inAddress);
    out = tokenByChainAddress(msg->chain_id, outAddress);
    
    // Get amount data
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 2*32, 32, &inAmount);
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 3*32, 32, &outAmount);

    ethereumFormatAmount(&inAmount, in, msg->chain_id, inToken,
                       sizeof(inToken));
    ethereumFormatAmount(&outAmount, out, msg->chain_id, outToken,
                       sizeof(outToken));
    snprintf(constr1, 32, "%s", inToken);
    snprintf(constr2, 32, "%s", outToken);

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Transform ERC20",
                 "Input %s\nOutput %s", constr1, constr2);
    
    return true;
}
