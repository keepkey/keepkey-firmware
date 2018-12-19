/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2018 KeepKey
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

#include "keepkey/firmware/eos-contracts/eosio.token.h"

#include "eos.h"

#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/eos.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"

#include "messages-eos.pb.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#define CHECK_COMMON(ACTION) \
    do { \
        CHECK_PARAM_RET(common->account == EOS_eosio_token, \
                        "Incorrect account name", false); \
        CHECK_PARAM_RET(common->name == (ACTION), \
                        "Incorrect action name", false); \
    } while(0)

bool eos_compileActionTransfer(const EosActionCommon *common,
                               const EosActionTransfer *action) {
    CHECK_COMMON(EOS_Transfer);

    CHECK_PARAM_RET(action->has_quantity, "Required field missing", false);
    CHECK_PARAM_RET(action->has_sender, "Required field missing", false);
    CHECK_PARAM_RET(action->has_receiver, "Required field missing", false);
    CHECK_PARAM_RET(action->has_memo, "Required field missing", false);

    size_t memo_len = strlen(action->memo);

    if (256 < memo_len) {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "Memo too long");
        eos_signingAbort();
        layoutHome();
        return false;
    }

    char asset[EOS_ASSET_STR_SIZE];
    CHECK_PARAM_RET(eos_formatAsset(&action->quantity, asset),
                    "Invalid asset format", false);

    char sender[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->sender, sender),
                    "Invalid name", false);

    char receiver[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->receiver, receiver),
                    "Invalid name", false);

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction,
                 "Transfer", "Do you want to send %s from %s to %s?",
                 asset, sender, receiver)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
        eos_signingAbort();
        layoutHome();
        return false;
    }

    char title[MEDIUM_STR_BUF];
    snprintf(title, sizeof(title), "Confirm Memo (%" PRIu32 " bytes)", (uint32_t)memo_len);
    if (!confirm_data(ButtonRequestType_ButtonRequest_ConfirmMemo,
                      title, (const uint8_t*)action->memo, memo_len)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
        eos_signingAbort();
        layoutHome();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    "Cannot compile ActionCommon", false);

    uint32_t size = 8 + 8 + 16 + eos_hashUInt(NULL, memo_len) + memo_len;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->sender, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->receiver, 8);

    CHECK_PARAM_RET(eos_compileAsset(&action->quantity),
                    "Cannot compile asset: quantity", false);

    eos_hashUInt(&hasher_preimage, memo_len);
    hasher_Update(&hasher_preimage, (const uint8_t*)action->memo, memo_len);

    return true;
}

