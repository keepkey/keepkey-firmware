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

#include "keepkey/firmware/ethereum_contracts/zxappliquid.h"
#include "keepkey/firmware/ethereum_contracts/zxliquidtx.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/storage.h"
#include "hwcrypto/crypto/address.h"
#include "hwcrypto/crypto/bip32.h"
#include "hwcrypto/crypto/curves.h"
#include "hwcrypto/crypto/memzero.h"
#include "hwcrypto/crypto/sha3.h"

bool zx_confirmApproveLiquidity(uint32_t data_total, const EthereumSignTx *msg) {
    (void)data_total;
    const char *to, *tikstr, *poolstr, *allowance, *amt;
    unsigned char data[40];
    uint8_t digest[SHA3_256_DIGEST_LENGTH] = {0};
    uint8_t tokdigest[SHA3_256_DIGEST_LENGTH] = {0};
    char digestStr[2*SHA3_256_DIGEST_LENGTH+1], amtStr[2*32+1] = {0};
    int32_t ctr, tokctr;
    uint32_t wethord, ttokenord;
    const TokenType *WETH, *ttoken;

    if (!tokenByTicker(msg->chain_id, "WETH", &WETH)) return false;
    wethord = read_be((const uint8_t *)WETH->address);
    to = (const char *)msg->to.bytes;
    tokctr = 0;
    while (tokctr != -1) {
        ttoken = tokenIter(&tokctr);

        //https://uniswap.org/docs/v2/smart-contract-integration/getting-pair-addresses/
        ttokenord = read_be((const uint8_t *)ttoken->address);
        if (ttokenord < wethord) {
            memcpy(data, ttoken->address, 20);
            memcpy(&data[20], WETH->address, 20);
        } else {
            memcpy(data, WETH->address, 20);
            memcpy(&data[20], ttoken->address, 20);
        }
        keccak_256(data, sizeof(data), tokdigest);
    	SHA3_CTX ctx = {0};
    	keccak_256_Init(&ctx);
    	keccak_Update(&ctx, (unsigned char *)"\xff", 1);
    	keccak_Update(&ctx, (unsigned char *)"\x5C\x69\xbE\xe7\x01\xef\x81\x4a\x2B\x6a\x3E\xDD\x4B\x16\x52\xCB\x9c\xc5\xaA\x6f", 20);
    	keccak_Update(&ctx, tokdigest, sizeof(tokdigest));
    	keccak_Update(&ctx, (unsigned char *)"\x96\xe8\xac\x42\x77\x19\x8f\xf8\xb6\xf7\x85\x47\x8a\xa9\xa3\x9f\x40\x3c\xb7\x68\xdd\x02\xcb\xee\x32\x6c\x3e\x7d\xa3\x48\x84\x5f", 32);
    	keccak_Final(&ctx, digest);
        if (memcmp(to, &digest[12], 20) == 0) break;
    }

    if (tokctr != -1) {
        for (ctr=0; ctr<SHA3_256_DIGEST_LENGTH; ctr++) {
            snprintf(&digestStr[ctr*2], 3, "%02x", digest[ctr]);
        }
        tikstr = ttoken->ticker;
        poolstr = &digestStr[12*2];
    } else {
        for (ctr=0; ctr<20; ctr++) {
            snprintf(&digestStr[ctr*2], 3, "%02x", to[ctr]);
        }
        tikstr = "";
        poolstr = digestStr;
    }

    allowance = (char *)(msg->data_initial_chunk.bytes + 4 +32);
    if (memcmp(allowance, (uint8_t *)&MAX_ALLOWANCE, 32) == 0) {
        amt = "full balance";
    } else {
        for (ctr=0; ctr<32; ctr++) {
            snprintf(&amtStr[ctr*2], 3, "%02x", allowance[ctr]);
        }
        amt = amtStr;
    }

    char *appStr = "uniswap approve liquidity";
    confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, appStr,
                 "Amount: %s", amt);
    confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, appStr,
                 "approve for pool %s %s", tikstr, poolstr);
    return true;
}

bool zx_isZxApproveLiquid(const EthereumSignTx *msg) {
    if (memcmp(msg->data_initial_chunk.bytes, "\x09\x5e\xa7\xb3", 4) == 0) 
        if (memcmp((uint8_t *)(msg->data_initial_chunk.bytes + 4 + 32 - 20), UNISWAP_ROUTER_ADDRESS, 20) == 0)
            return true;
    return false;
}
