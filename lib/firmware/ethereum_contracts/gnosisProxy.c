/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2022 markrypto
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

#include "keepkey/firmware/ethereum_contracts/gnosisproxy.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/fsm.h"
#include "trezor/crypto/address.h"

static bool isExecTx(const EthereumSignTx *msg) {
    if (memcmp(msg->data_initial_chunk.bytes, "\x6a\x76\x12\x02", 4) == 0)
        return true;

    return false;
}

bool gn_isGnosisProxy(const EthereumSignTx *msg) {

    if (memcmp(msg->to.bytes, GNOSISPROXY_ADDRESS, 20) == 0) {  // correct proxy address?
        if (isExecTx(msg)) {                                    // does kk handle call?
            return true;
        }
    }
    return false;
}

bool gn_confirmExecTx(uint32_t data_total, const EthereumSignTx *msg) {
    (void)data_total;
    char confStr[131];
    char contractStr[41];
    uint8_t *to, *gasToken, *refundReceiver, *data;
    bignum256 bnNum;
    char txStr[32], safeGasStr[32], baseGasStr[32], gasPriceStr[32];
    TokenType const *TokenData;
    int8_t *operation;
    uint32_t offset, dlen;
    char const *confDatStr;
    unsigned ctr, n, chunk, chunkSize;
    const char *title = "Gnosis exec_tx";

    to = (uint8_t *)(msg->data_initial_chunk.bytes + 4 + 0*32 + 12);
    for (ctr=0; ctr<20; ctr++) {
        snprintf(&confStr[ctr*2], 3, "%02x", to[ctr]);
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
             title, "Sending to %s", confStr)) {
        return false;
    }

    // value
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 1*32, 32, &bnNum);
    ethereumFormatAmount(&bnNum, NULL, 1 /*chainId*/, txStr, sizeof(txStr));
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
             title, "amount %s", txStr)) {
        return false;
    }

    // get data bytes
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 2*32, 32, &bnNum);        // data offset
    offset = bn_write_uint32(&bnNum);
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + offset, 32, &bnNum);      // data len
    dlen = bn_write_uint32(&bnNum);
    data = (uint8_t *)(msg->data_initial_chunk.bytes + 4 + 32 + offset);

    n = 1;
    chunkSize = 20;
    while (true) {
        chunk=chunkSize*(n-1);
        for (ctr=chunk; ctr<chunkSize+chunk && ctr<dlen; ctr++) {
            snprintf(&confStr[(ctr-chunk)*2], 3, "%02x", data[ctr]);
        }
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 title, "Data bytes %d: %s", n, confStr)) {
            return false;
        }
        if (ctr >= dlen) {
            break;
        }
        n++;
    }

    // operation is an enum: https://github.com/safe-global/safe-contracts/blob/main/contracts/common/Enum.sol#L7
    operation = (int8_t *)(msg->data_initial_chunk.bytes + 4 + 3*32);
    {
        char *opStr;
        switch (*operation) {
            case 0:
                opStr = "Call";
                break;
            case 1:
                opStr = "DelegateCall";
                break;
            default:
                opStr = "Unknown";
        }
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 title, "Operation: %s", opStr)) {
            return false;
        }
    }


    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 4*32, 32, &bnNum);    // safe transaction gas
    ethereumFormatAmount(&bnNum, NULL,  1 /*chainId*/, safeGasStr, sizeof(safeGasStr));
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 5*32, 32, &bnNum);      // independent gas needed
    ethereumFormatAmount(&bnNum, NULL,  1 /*chainId*/, baseGasStr, sizeof(baseGasStr));
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
        title, "Safe tx gas: %s\nBase gas: %s", safeGasStr, baseGasStr)) {
        return false;
    }

    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 6*32, 32, &bnNum);     // used for payment calc
    ethereumFormatAmount(&bnNum, NULL,  1 /*chainId*/, gasPriceStr, sizeof(gasPriceStr));
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
        title, "Gas price: %s", gasPriceStr)) {
        return false;
    }

    // gas token
    gasToken = (uint8_t *)(msg->data_initial_chunk.bytes + 4 + 7*32 + 12);        // token to be used for gas payment
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 7*32, 32, &bnNum);     // used to check for zero
    if (bn_is_zero(&bnNum)) {
        // gas payment in ETH
        confDatStr = "ETH";
    } else {
        // gas payment in token
        TokenData = tokenByChainAddress(1 /*chainId*/, (uint8_t *)gasToken);
        if (strncmp(TokenData->ticker, " UNKN", 5) == 0) {
            for (ctr=0; ctr<20; ctr++) {
                snprintf(&contractStr[2*ctr], 3, "%02x", TokenData->address[ctr]);
            }
            confDatStr = contractStr;
        } else {
            confDatStr = TokenData->ticker;
        }
    }

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
        title, "Gas payment token: %s", confDatStr)) {
        return false;
    }

    refundReceiver = (uint8_t *)(msg->data_initial_chunk.bytes + 4 + 8*32 + 12);     // gas refund receiver
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 8*32, 32, &bnNum);     // used to check for zero
    if (bn_is_zero(&bnNum)) {
        // gas refund receiver is origin
        confDatStr = "tx origin";
    } else {
        // gas refund receiver address
        for (ctr=0; ctr<20; ctr++) {
            snprintf(&contractStr[2*ctr], 3, "%02x", refundReceiver[ctr]);
        }
        confDatStr = contractStr;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
        title, "Gas refund address: %s", confDatStr)) {
        return false;
    }

    // get signature data
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 9*32, 32, &bnNum);    // sig offset
    offset = bn_write_uint32(&bnNum);
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + offset, 32, &bnNum);  // sig data len
    dlen = bn_write_uint32(&bnNum);
    data = (uint8_t *)(msg->data_initial_chunk.bytes + 4 + 32 + offset);


    n = 1;
    chunkSize = 65;
    while (true) {
        chunk=chunkSize*(n-1);
        for (ctr=chunk; ctr<chunkSize+chunk && ctr<dlen; ctr++) {
            snprintf(&confStr[(ctr-chunk)*2], 3, "%02x", data[ctr]);
        }
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 title, "Signature %d: %s", n, confStr)) {
            return false;
        }
            // {
            //     char bf[41] = {0};
            //     snprintf(bf, 20, "%d %ld", ctr, dlen);
            //     DEBUG_DISPLAY(bf);
            // }
        if (ctr >= dlen) {
            break;
        }
        n++;
    }
    return true;
}
