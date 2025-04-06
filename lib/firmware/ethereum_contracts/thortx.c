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

#include "keepkey/firmware/ethereum_contracts/thortx.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/thorchain.h"
#include "hwcrypto/crypto/address.h"

bool thor_isThorchainTx(const EthereumSignTx *msg) {
  if (msg->has_to && msg->to.size == 20 &&
      memcmp(msg->data_initial_chunk.bytes,
             "\x1f\xec\xe7\xb4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 
             16) == 0) {
    return true;
  }
  return false;
}

bool thor_confirmThorTx(uint32_t data_total, const EthereumSignTx *msg) {  
    (void)data_total;

    char confStr[41], *conf;
    const TokenType *assetToken;
    uint8_t *thorchainData, *vaultAddress, *assetAddress, *contractAssetAddress;
    uint32_t ctr;
    bignum256 Amount;

    vaultAddress = (uint8_t *)(msg->data_initial_chunk.bytes + 4 + 12);
    contractAssetAddress = (uint8_t *)(msg->data_initial_chunk.bytes + 4 + 32 + 12);
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 2*32, 32, &Amount);
    thorchainData = (uint8_t *)(msg->data_initial_chunk.bytes + 4 + 5*32);

    // Start confirmations    
    for (ctr=0; ctr<20; ctr++) {
        snprintf(&confStr[ctr*2], 3, "%02x", msg->to.bytes[ctr]);
    }
    if (strncmp(confStr, THOR_ROUTER, sizeof(THOR_ROUTER)) == 0) {
        conf = "Thorchain router";
    } else {
        conf = confStr;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
             "Thorchain data", "Routing through %s", conf)) {
        return false;
    }

    // just display token address and amount as string
    for (ctr=0; ctr<20; ctr++) {
        snprintf(&confStr[ctr*2], 3, "%02x", vaultAddress[ctr]);
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
             "Thorchain data", "Using Asgard vault %s", confStr)) {
        return false;
    }

    if (memcmp(contractAssetAddress, ETH_ADDRESS, sizeof(ETH_ADDRESS)) == 0) {
        assetAddress = (uint8_t *)ETH_NATIVE;      // get eth native parameters if asset is not a token
    } else {
        assetAddress = contractAssetAddress;
    }
    
    assetToken = tokenByChainAddress(msg->chain_id, assetAddress);

    if (strncmp(assetToken->ticker, " UNKN", 5) == 0) {
 
        // just display token address and amount as string
        for (ctr=0; ctr<20; ctr++) {
            snprintf(&confStr[ctr*2], 3, "%02x", assetAddress[ctr]);
        }
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain data", "from asset %s", confStr)) {
            return false;
        }
        // We don't know what the exponent should be so just confirm raw unformatted number
        bn_format(&Amount, NULL, " unformatted", 0, 0, false, confStr, sizeof(confStr));

        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain data", "amount %s", confStr)) {
            return false;
        }

    } else {
        ethereumFormatAmount(&Amount, assetToken, msg->chain_id, confStr,
                           sizeof(confStr));
    
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                     "Thorchain data", "Confirm sending %s", confStr)) {
            return false;
        }
    }

    if (!thorchain_parseConfirmMemo((const char *)thorchainData, 64))
        return false;

    return true;
}


