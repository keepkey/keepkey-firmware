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

#include "keepkey/firmware/eos-contracts/eosio.system.h"

#include "eos.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/eos.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"

#include "messages-eos.pb.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#define CHECK_COMMON(ACTION) \
    do { \
        CHECK_PARAM_RET(common->account == EOS_eosio || \
                        common->account == EOS_eosio_token, \
                        "Incorrect account name", false); \
        CHECK_PARAM_RET(common->name == (ACTION), \
                        "Incorrect action name", false); \
    } while(0)

bool eos_compileActionDelegate(const EosActionCommon *common,
                               const EosActionDelegate *action) {
    CHECK_COMMON(EOS_DelegateBW);

    CHECK_PARAM_RET(action->has_sender, "Required field missing", false);
    CHECK_PARAM_RET(action->has_receiver, "Required field missing", false);
    CHECK_PARAM_RET(action->has_cpu_quantity, "Required field missing", false);
    CHECK_PARAM_RET(action->has_net_quantity, "Required field missing", false);

    char sender[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->sender, sender),
                    "Invalid name", false);

    char receiver[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->receiver, receiver),
                    "Invalid name", false);

    char cpu[EOS_ASSET_STR_SIZE];
    CHECK_PARAM_RET(eos_formatAsset(&action->cpu_quantity, cpu),
                    "Invalid asset format", false);

    char net[EOS_ASSET_STR_SIZE];
    CHECK_PARAM_RET(eos_formatAsset(&action->net_quantity, net),
                    "Invalid asset format", false);

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction, "Delegate",
                 ((action->has_transfer && action->transfer)
                      ? "Delegate %s CPU and %s RAM from %s to %s?"
                      : "Transfer %s CPU and %s RAM from %s to %s?"),
                 cpu, net, sender, receiver)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
        eos_signingAbort();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    "Cannot compile ActionCommon", false);

    uint32_t size = 8 + 8 + 16 + 16 + 1;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->sender, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->receiver, 8);

    CHECK_PARAM_RET(eos_compileAsset(&action->net_quantity),
                    "Cannot compile asset: net_quantity", false);

    CHECK_PARAM_RET(eos_compileAsset(&action->cpu_quantity),
                    "Cannot compile asset: cpu_quantity", false);

    uint8_t is_transfer = (action->has_transfer && action->transfer) ? 1 : 0;
    hasher_Update(&hasher_preimage, &is_transfer, 1);

    return true;
}

bool eos_compileActionUndelegate(const EosActionCommon *common,
                                 const EosActionUndelegate *action) {
    CHECK_COMMON(EOS_UndelegateBW);

    CHECK_PARAM_RET(action->has_sender, "Required field missing", false);
    CHECK_PARAM_RET(action->has_receiver, "Required field missing", false);
    CHECK_PARAM_RET(action->has_cpu_quantity, "Required field missing", false);
    CHECK_PARAM_RET(action->has_net_quantity, "Required field missing", false);

    char sender[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->sender, sender),
                    "Invalid name", false);

    char receiver[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->receiver, receiver),
                    "Invalid name", false);

    char cpu[EOS_ASSET_STR_SIZE];
    CHECK_PARAM_RET(eos_formatAsset(&action->cpu_quantity, cpu),
                    "Invalid asset format", false);

    char net[EOS_ASSET_STR_SIZE];
    CHECK_PARAM_RET(eos_formatAsset(&action->net_quantity, net),
                    "Invalid asset format", false);

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction,
                 "Undelegate", "Revoke delegation of %s CPU and %s RAM from %s to %s?\n",
                 cpu, net, sender, receiver)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
        eos_signingAbort();
        layoutHome();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    "Cannot compile ActionCommon", false);

    uint32_t size = 8 + 8 + 16 + 16;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->sender, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->receiver, 8);

    CHECK_PARAM_RET(eos_compileAsset(&action->net_quantity),
                    "Cannot compile asset: net_quantity", false);

    CHECK_PARAM_RET(eos_compileAsset(&action->cpu_quantity),
                    "Cannot compile asset: cpu_quantity", false);

    return true;
}

bool eos_compileActionRefund(const EosActionCommon *common,
                             const EosActionRefund *action) {
    CHECK_COMMON(EOS_Refund);

    CHECK_PARAM_RET(action->has_owner, "Required field missing", false);

    char owner[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->owner, owner),
                    "Invalid name", false);

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction,
                 "Refund", "Do you want reclaim all pending unstaked tokens from your %s account?",
                 owner)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
        eos_signingAbort();
        layoutHome();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    "Cannot compile ActionCommon", false);

    uint32_t size = 8;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->owner, 8);

    return true;
}

bool eos_compileActionBuyRam(const EosActionCommon *common,
                             const EosActionBuyRam *action) {
    CHECK_COMMON(EOS_BuyRam);

    CHECK_PARAM_RET(action->has_payer, "Required field missing", false);
    CHECK_PARAM_RET(action->has_receiver, "Required field missing", false);
    CHECK_PARAM_RET(action->has_quantity, "Required field missing", false);

    char payer[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->payer, payer),
                    "Invalid name", false);

    char receiver[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->receiver, receiver),
                    "Invalid name", false);

    char quantity[EOS_ASSET_STR_SIZE];
    CHECK_PARAM_RET(eos_formatAsset(&action->quantity, quantity),
                    "Invalid asset format", false);

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction,
                 "Buy Ram", "Using your %s account, buy %s worth of RAM for %s at market price?",
                 payer, quantity, receiver)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
        eos_signingAbort();
        layoutHome();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    "Cannot compile ActionCommon", false);

    uint32_t size = 8 + 8 + 16;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->payer, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->receiver, 8);

    CHECK_PARAM_RET(eos_compileAsset(&action->quantity),
                    "Cannot compile asset: quantity", false);

    return true;
}

bool eos_compileActionBuyRamBytes(const EosActionCommon *common,
                                  const EosActionBuyRamBytes *action) {
    CHECK_COMMON(EOS_BuyRamBytes);

    CHECK_PARAM_RET(action->has_payer, "Required field missing", false);
    CHECK_PARAM_RET(action->has_receiver, "Required field missing", false);
    CHECK_PARAM_RET(action->has_bytes, "Required field missing", false);

    char payer[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->payer, payer),
                    "Invalid name", false);

    char receiver[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->receiver, receiver),
                    "Invalid name", false);

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction,
                 "Buy Ram Bytes", "Using your %s account, buy %" PRIu32 " bytes of RAM for %s?",
                 payer, action->bytes, receiver)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
        eos_signingAbort();
        layoutHome();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    "Cannot compile ActionCommon", false);

    uint32_t size = 8 + 8 + 4;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->payer, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->receiver, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->bytes, 4);

    return true;
}

bool eos_compileActionSellRam(const EosActionCommon *common,
                              const EosActionSellRam *action) {
    CHECK_COMMON(EOS_SellRam);

    CHECK_PARAM_RET(action->has_account, "Required field missing", false);
    CHECK_PARAM_RET(action->has_bytes, "Required field missing", false);

    char account[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->account, account),
                    "Invalid name", false);

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction,
                 "Sell Ram", "Using your %s account, sell %" PRIu64 " bytes of RAM at market price?",
                 account, action->bytes)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
        eos_signingAbort();
        layoutHome();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    "Cannot compile ActionCommon", false);

    uint32_t size = 8 + 8;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->account, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->bytes, 8);

    return true;
}

bool eos_compileActionVoteProducer(const EosActionCommon *common,
                                   const EosActionVoteProducer *action) {
    CHECK_COMMON(EOS_VoteProducer);

    CHECK_PARAM_RET(action->has_voter, "Required field missing", false);

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    "Cannot compile ActionCommon", false);

    if (action->has_proxy && action->proxy != 0) {
        char voter[EOS_NAME_STR_SIZE];
        CHECK_PARAM_RET(eos_formatName(action->voter, voter),
                        "Invalid name", false);

        char proxy[EOS_NAME_STR_SIZE];
        CHECK_PARAM_RET(eos_formatName(action->proxy, proxy),
                        "Invalid name", false);

        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction,
                     "Vote Producer", "Using your %s account, vote for %s as your proxy?",
                     voter, proxy)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
            eos_signingAbort();
            layoutHome();
            return false;
        }

        uint32_t size = 8 + 8 + eos_hashUInt(NULL, 0) + 0;
        eos_hashUInt(&hasher_preimage, size);

        hasher_Update(&hasher_preimage, (const uint8_t*)&action->voter, 8);
        hasher_Update(&hasher_preimage, (const uint8_t*)&action->proxy, 8);

        eos_hashUInt(&hasher_preimage, /*producers_count=*/0);

    } else if (action->producers_count != 0) {
        // Sanity check, which the contract also enforces
        for (size_t i = 1; i < action->producers_count; i++) {
            CHECK_PARAM_RET(action->producers[i - 1] < action->producers[i],
                            "Producer votes must be unique and sorted", false);
        }

        char voter[EOS_NAME_STR_SIZE];
        CHECK_PARAM_RET(eos_formatName(action->voter, voter),
                        "Invalid name", false);

        const size_t chunk_size = 6;
        char producers[(EOS_NAME_STR_SIZE + 2) * chunk_size + 1];
        const uint8_t pages = (uint8_t)((action->producers_count / chunk_size) + 1) + 1;

        uint8_t page_no = 1;
        char title[SMALL_STR_BUF];
        snprintf(title, sizeof(title),
                 "Vote Producer %" PRIu8 "/%" PRIu8,
                 page_no, pages);

        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction,
                     title, "Using your %s account, vote for the following producers?",
                     voter)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
            eos_signingAbort();
            layoutHome();
            return false;
        }

        for (size_t i = 0; i < action->producers_count; i += chunk_size) {
            memset(producers, 0, sizeof(producers));
            for (size_t p = 0; p < chunk_size && p + i < action->producers_count; p++) {
                char producer[EOS_NAME_STR_SIZE];
                CHECK_PARAM_RET(eos_formatName(action->producers[p + i], producer),
                                "Invalid name", false);
                (void)strlcat(producers, producer, sizeof(producers));
                if (p + i + 1 != action->producers_count) {
                    (void)strlcat(producers, ", ", sizeof(producers));
                }
            }

            page_no = (uint8_t)((i / chunk_size) + 1) + 1;
            snprintf(title, sizeof(title),
                     "Vote Producer %" PRIu8 "/%" PRIu8,
                     page_no, pages);
            if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction,
                         title, "%s", producers)) {
                fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
                eos_signingAbort();
                layoutHome();
                return false;
            }
        }

        uint32_t size = 8 + 8 + eos_hashUInt(NULL, action->producers_count) +
                        8 * action->producers_count;
        eos_hashUInt(&hasher_preimage, size);

        hasher_Update(&hasher_preimage, (const uint8_t*)&action->voter, 8);
        hasher_Update(&hasher_preimage, (const uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00", 8);

        eos_hashUInt(&hasher_preimage, action->producers_count);
        for (size_t p = 0; p < action->producers_count; p++) {
            hasher_Update(&hasher_preimage, (const uint8_t*)&action->producers[p], 8);
        }
    } else {
        char voter[EOS_NAME_STR_SIZE];
        CHECK_PARAM_RET(eos_formatName(action->voter, voter),
                        "Invalid name", false);

        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction,
                     "Vote Producer", "Using your %s account, do you want to cancel your vote?",
                     voter)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
            eos_signingAbort();
            layoutHome();
            return false;
        }

        uint32_t size = 8 + 8 + eos_hashUInt(NULL, 0) + 0;
        eos_hashUInt(&hasher_preimage, size);

        hasher_Update(&hasher_preimage, (const uint8_t*)&action->voter, 8);
        hasher_Update(&hasher_preimage, (const uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00", 8);
        eos_hashUInt(&hasher_preimage, /*producers_count=*/0);
    }

    return true;
}

static size_t eos_hashAuthorization(Hasher *h, const EosAuthorization *auth) {
    size_t count = 0;

    count += 4;
    if (h) hasher_Update(h, (const uint8_t*)&auth->threshold, 4);

    count += eos_hashUInt(h, auth->keys_count);
    for (size_t i = 0; i < auth->keys_count; i++) {
        const EosAuthorizationKey *auth_key = &auth->keys[i];

        count += eos_hashUInt(NULL, auth_key->type);
        if (h) eos_hashUInt(h, auth_key->type);

        if (auth_key->address_n_count != 0) {
            uint8_t public_key[33];
            if (!eos_derivePublicKey(auth_key->address_n, auth_key->address_n_count,
                                     public_key, sizeof(public_key))) {
                return 0;
            }

            count += sizeof(public_key);
            if (h) hasher_Update(h, public_key, sizeof(public_key));
        } else {
            count += auth_key->key.size;
            if (h) hasher_Update(h, auth_key->key.bytes, auth_key->key.size);
        }

        count += 2;
        if (h) hasher_Update(h, (const uint8_t*)&auth_key->weight, 2);
    }

    count += eos_hashUInt(h, auth->accounts_count);
    for (size_t i = 0; i < auth->accounts_count; i++) {
        count += 8;
        if (h) hasher_Update(h, (const uint8_t*)&auth->accounts[i].account.actor, 8);

        count += 8;
        if (h) hasher_Update(h, (const uint8_t*)&auth->accounts[i].account.permission, 8);

        count += 2;
        if (h) hasher_Update(h, (const uint8_t*)&auth->accounts[i].weight, 2);
    }

    count += eos_hashUInt(h, auth->waits_count);
    for (size_t i = 0; i < auth->accounts_count; i++) {
        count += 4;
        if (h) hasher_Update(h, (const uint8_t*)&auth->waits[i].wait_sec, 4);

        count += 2;
        if (h) hasher_Update(h, (const uint8_t*)&auth->waits[i].weight, 2);
    }

    return count;
}

static bool authorizationIsDeviceControlled(const EosAuthorization *auth) {
    if (!auth->has_threshold || auth->threshold != 1)
        return false;

    if (auth->keys_count != 1)
        return false;

    if (auth->keys[0].key.size != 0)
        return false;

    if (auth->keys[0].address_n_count == 0)
        return false;

    if (auth->keys[0].weight != 1)
        return false;

    if (auth->waits_count != 0)
        return false;

    return true;
}

bool eos_compileAuthorization(const char *title, const EosAuthorization *auth,
                              SLIP48Role role) {
    CHECK_PARAM_RET(auth->has_threshold, "Required field missing", false);


    if (authorizationIsDeviceControlled(auth) &&
        coin_isSLIP48(coinByName("EOS"), auth->keys[0].address_n,
                      auth->keys[0].address_n_count, role)) {
        const EosAuthorizationKey *auth_key = &auth->keys[0];

        char node_str[NODE_STRING_LENGTH];
        const CoinType *coin;
        if ((coin = coinByName("EOS")) &&
            !bip32_node_to_string(node_str, sizeof(node_str), coin,
                                  auth_key->address_n,
                                  auth_key->address_n_count,
                                  /*whole_account=*/false,
                                  /*allow_change=*/false,
                                  /*show_addridx=*/true) &&
            !bip32_path_to_string(node_str, sizeof(node_str),
                                  auth_key->address_n, auth_key->address_n_count)) {
            memset(node_str, 0, sizeof(node_str));
            fsm_sendFailure(FailureType_Failure_SyntaxError, "Cannot encode derived pubkey");
            eos_signingAbort();
            layoutHome();
            return false;
        }

        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction,
                     title, "Do you want to assign signing auth for\n%s to\n%s?",
                     title, node_str)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
            eos_signingAbort();
            layoutHome();
            return false;
        }

        return true;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction,
                 title, "Require an authorization threshold of %" PRIu32 "?",
                 auth->threshold)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
        eos_signingAbort();
        layoutHome();
        return false;
    }

    for (size_t i = 0; i < auth->keys_count; i++) {
        const EosAuthorizationKey *auth_key = &auth->keys[i];

        CHECK_PARAM_RET(auth_key->has_weight, "Required field missing", false);
        CHECK_PARAM_RET((auth_key->key.size == 33) ^ (auth_key->address_n_count != 0),
                        "Required field missing", false);

        char pubkey[MAX(65, NODE_STRING_LENGTH)];
        if (auth_key->key.size != 0) {
            if (!eos_publicKeyToWif(auth_key->key.bytes, EosPublicKeyKind_EOS, pubkey, sizeof(pubkey))) {
                fsm_sendFailure(FailureType_Failure_SyntaxError, "Cannot encode pubkey");
                eos_signingAbort();
                layoutHome();
                return false;
            }
        } else {
            const CoinType *coin;
            if ((coin = coinByName("EOS")) &&
                !bip32_path_to_string(pubkey, sizeof(pubkey),
                                      auth_key->address_n, auth_key->address_n_count)) {
                memset(pubkey, 0, sizeof(pubkey));
                fsm_sendFailure(FailureType_Failure_SyntaxError, "Cannot encode derived pubkey");
                eos_signingAbort();
                layoutHome();
                return false;
            }
        }

        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction,
                     title, "Key #%" PRIu8 ":\n%s\nWeight: %" PRIu16,
                     (uint8_t)(i + 1), pubkey, (uint16_t)auth_key->weight)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
            eos_signingAbort();
            layoutHome();
            return false;
        }
    }

    for (size_t i = 0; i < auth->accounts_count; i++) {
        CHECK_PARAM_RET(auth->accounts[i].account.has_actor, "Required field missing", false);
        CHECK_PARAM_RET(auth->accounts[i].account.has_permission, "Required field missing", false);

        char account[EOS_NAME_STR_SIZE];
        CHECK_PARAM_RET(eos_formatName(auth->accounts[i].account.actor, account),
                        "Invalid name", false);

        char permission[EOS_NAME_STR_SIZE];
        CHECK_PARAM_RET(eos_formatName(auth->accounts[i].account.permission, permission),
                        "Invalid name", false);

        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction,
                     title, "Account #%" PRIu8 ":\nDo you want to assign %s permission to %s with weight %" PRIu16 "?",
                     (uint8_t)(i + 1), permission, account,
                     (uint16_t)auth->accounts[i].weight)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
            eos_signingAbort();
            layoutHome();
            return false;
        }
    }

    for (size_t i = 0; i < auth->waits_count; i++) {
        CHECK_PARAM_RET(auth->waits[i].has_wait_sec, "Required field missing", false);

        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction,
                     title, "Delay #%" PRIu8 ":\nDo you want to require a delay of %" PRIu32 "s with weight %" PRIu16 "?",
                     (uint8_t)(i + 1), auth->waits[i].wait_sec,
                     (uint16_t)auth->waits[i].weight)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
            eos_signingAbort();
            layoutHome();
            return false;
        }
    }

    if (!eos_hashAuthorization(&hasher_preimage, auth))
        return false;

    return true;
}

static SLIP48Role roleFromPermission(uint64_t permission) {
    switch (permission) {
    case EOS_Owner: return SLIP48_owner;
    case EOS_Active: return SLIP48_active;
    default: return SLIP48_UNKNOWN;
    }
}

bool eos_compileActionUpdateAuth(const EosActionCommon *common,
                                 const EosActionUpdateAuth *action) {
    CHECK_COMMON(EOS_UpdateAuth);

    CHECK_PARAM_RET(action->has_account, "Required field missing", false);
    CHECK_PARAM_RET(action->has_permission, "Required field missing", false);
    CHECK_PARAM_RET(action->has_parent, "Required field missing", false);

    char account[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->account, account),
                    "Invalid name", false);

    char permission[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->permission, permission),
                    "Invalid name", false);

    char parent[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->parent, parent),
                    "Invalid name", false);

    char title[SMALL_STR_BUF];
    snprintf(title, sizeof(title), "Update Auth: %s", account);

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction, title,
                 "Update auth for %s with %s permission and %s parent?",
                 account, permission, parent)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
        eos_signingAbort();
        layoutHome();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    "Cannot compile ActionCommon", false);

    size_t auth_size = eos_hashAuthorization(NULL, &action->auth);
    CHECK_PARAM_RET(0 < auth_size, "EosAuthorization hash failed", false);

    size_t size = 8 + 8 + 8 + auth_size;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->account, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->permission, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->parent, 8);

    snprintf(title, sizeof(title), "%s@%s", account, permission);
    if (!eos_compileAuthorization(title, &action->auth,
                                  roleFromPermission(action->permission)))
        return false;

    return true;
}

bool eos_compileActionDeleteAuth(const EosActionCommon *common,
                                 const EosActionDeleteAuth *action) {
    CHECK_COMMON(EOS_DeleteAuth);

    CHECK_PARAM_RET(action->has_account, "Required field missing", false);
    CHECK_PARAM_RET(action->has_permission, "Required field missing", false);

    char account[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->account, account),
                    "Invalid name", false);

    char permission[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->permission, permission),
                    "Invalid name", false);

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction,
                 "Delete Auth", "Remove %s permission from %s?",
                 permission, account)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
        eos_signingAbort();
        layoutHome();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    "Cannot compile ActionCommon", false);

    size_t size = 8 + 8;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->account, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->permission, 8);

    return true;
}

bool eos_compileActionLinkAuth(const EosActionCommon *common,
                               const EosActionLinkAuth *action) {
    CHECK_COMMON(EOS_LinkAuth);

    CHECK_PARAM_RET(action->has_account, "Required field missing", false);
    CHECK_PARAM_RET(action->has_code, "Required field missing", false);
    CHECK_PARAM_RET(action->has_type, "Required field missing", false);
    CHECK_PARAM_RET(action->has_requirement, "Required field missing", false);

    char account[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->account, account),
                    "Invalid name", false);

    char code[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->code, code),
                    "Invalid name", false);

    char type[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->type, type),
                    "Invalid name", false);

    char requirement[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->requirement, requirement),
                    "Invalid name", false);

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction,
                 "Link Auth", "Grant %s permission for the %s contract to %s@%s?",
                 type, code, account, requirement)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
        eos_signingAbort();
        layoutHome();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    "Cannot compile ActionCommon", false);

    size_t size = 8 + 8 + 8 + 8;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->account, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->code, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->type, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->requirement, 8);

    return true;
}

bool eos_compileActionUnlinkAuth(const EosActionCommon *common,
                                 const EosActionUnlinkAuth *action) {
    CHECK_COMMON(EOS_UnlinkAuth);

    CHECK_PARAM_RET(action->has_account, "Required field missing", false);
    CHECK_PARAM_RET(action->has_code, "Required field missing", false);
    CHECK_PARAM_RET(action->has_type, "Required field missing", false);

    char account[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->account, account),
                    "Invalid name", false);

    char code[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->code, code),
                    "Invalid name", false);

    char type[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->type, type),
                    "Invalid name", false);

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction,
                 "Unlink Auth", "Unlink %s from auth to %s for %s?",
                 account, code, type)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
        eos_signingAbort();
        layoutHome();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    "Cannot compile ActionCommon", false);

    size_t size = 8 + 8 + 8;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->account, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->code, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->type, 8);

    return true;
}

bool eos_compileActionNewAccount(const EosActionCommon *common,
                                 const EosActionNewAccount *action) {
    CHECK_COMMON(EOS_NewAccount);

    CHECK_PARAM_RET(action->has_creator, "Required field missing", false);
    CHECK_PARAM_RET(action->has_name, "Required field missing", false);
    CHECK_PARAM_RET(action->has_owner, "Required field missing", false);
    CHECK_PARAM_RET(action->has_active, "Required field missing", false);

    CHECK_PARAM_RET(authorizationIsDeviceControlled(&action->owner),
                    "Bad owner permissions", false);

    CHECK_PARAM_RET(authorizationIsDeviceControlled(&action->active),
                    "Bad active permissions", false);

    char creator[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->creator, creator),
                    "Invalid name", false);

    char name[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->name, name),
                    "Invalid name", false);

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction,
                 "New Account", "Using your %s account, create a new account named %s?",
                 creator, name)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
        eos_signingAbort();
        layoutHome();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    "Cannot compile ActionCommon", false);

    size_t owner_size = eos_hashAuthorization(NULL, &action->owner);
    CHECK_PARAM_RET(0 < owner_size, "EosAuthorization hash failed", false);

    size_t active_size = eos_hashAuthorization(NULL, &action->active);
    CHECK_PARAM_RET(0 < active_size, "EosAuthorization hash failed", false);

    size_t size = 8 + 8 + owner_size + active_size;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->creator, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->name, 8);

    char title[SMALL_STR_BUF];
    snprintf(title, sizeof(title), "%s@owner", name);
    if (!eos_compileAuthorization(title, &action->owner, SLIP48_owner))
        return false;

    snprintf(title, sizeof(title), "%s@active", name);
    if (!eos_compileAuthorization(title, &action->active, SLIP48_active))
        return false;

    return true;
}
