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

void fsm_msgEosGetPublicKey(const EosGetPublicKey *msg) {
    CHECK_INITIALIZED

    CHECK_PIN

    const CoinType *coin = fsm_getCoin(true, "EOS");
    if (!coin) return;

    const curve_info *curve = get_curve_by_name(coin->curve_name);
    if (!curve) return;

    uint32_t fingerprint;
    HDNode *node = fsm_getDerivedNode(coin->curve_name, msg->address_n, msg->address_n_count, &fingerprint);
    if (!node) return;
    hdnode_fill_public_key(node);

    RESP_INIT(EosPublicKey);

    if (!eos_getPublicKey(node, curve, msg->kind,
                          resp->wif_public_key, sizeof(resp->wif_public_key))) {
        fsm_sendFailure(FailureType_Failure_Other, "Could not derive EOS pubkey");
        layoutHome();
        return;
    }
    resp->has_wif_public_key = true;

    resp->has_raw_public_key = true;
    resp->raw_public_key.size = 33;
    memcpy(resp->raw_public_key.bytes, node->public_key, 33);
    _Static_assert(sizeof(resp->raw_public_key.bytes) == 33, "size mismatch");

    if (msg->has_show_display && msg->show_display) {
        char node_str[NODE_STRING_LENGTH];
        if (!bip32_node_to_string(node_str, sizeof(node_str), coin,
                                  msg->address_n,
                                  msg->address_n_count,
                                  /*whole_account=*/false) &&
            !bip32_path_to_string(node_str, sizeof(node_str),
                                  msg->address_n, msg->address_n_count)) {
            memset(node_str, 0, sizeof(node_str));
        }

        if (!confirm(ButtonRequestType_ButtonRequest_Address, node_str,
                     "%s", resp->wif_public_key)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            "Show EOS public key cancelled.");
            layoutHome();
            return;
        }
    }

    layoutHome();
    msg_write(MessageType_MessageType_EosPublicKey, resp);
}

void fsm_msgEosSignTx(const EosSignTx *msg) {
    CHECK_PARAM(msg->chain_id.size == 32, "Wrong chain_id size");
    CHECK_PARAM(msg->has_header, "Must have transaction header");
    CHECK_PARAM(msg->has_num_actions && 0 < msg->num_actions,
                "Eos transaction must have actions");

    CHECK_PARAM(msg->header.max_cpu_usage_ms <= UINT8_MAX,
                "Value overflow");
    CHECK_PARAM(msg->header.ref_block_num <= UINT16_MAX,
                "Value overflow");

    CHECK_INITIALIZED

    CHECK_PIN_TXSIGN

    CHECK_PARAM(storage_isPolicyEnabled("Experimental"),
                "EOS support is experimental. Use at your own risk.");

    HDNode *root = fsm_getDerivedNode(SECP256K1_NAME, 0, 0, NULL);
    if (!root) return;
    hdnode_fill_public_key(root);

    eos_signingInit(msg->chain_id.bytes, msg->num_actions, &msg->header,
                    root, msg->address_n, msg->address_n_count);

    RESP_INIT(EosTxActionRequest);
    msg_write(MessageType_MessageType_EosTxActionRequest, resp);
}

void fsm_msgEosTxActionAck(const EosTxActionAck *msg) {
    CHECK_PARAM(eos_signingIsInited(), "Must call EosSignTx to initiate signing");
    CHECK_PARAM(msg->has_common, "Must have common");

    int action_count =
        (int)msg->has_transfer +
        (int)msg->has_delegate +
        (int)msg->has_undelegate +
        (int)msg->has_refund +
        (int)msg->has_buy_ram +
        (int)msg->has_buy_ram_bytes +
        (int)msg->has_sell_ram +
        (int)msg->has_vote_producer +
        (int)msg->has_update_auth +
        (int)msg->has_delete_auth +
        (int)msg->has_link_auth +
        (int)msg->has_unlink_auth +
        (int)msg->has_new_account +
        (int)msg->has_unknown +
        0;
    CHECK_PARAM(action_count == 1, "Eos signing can only handle one action at a time");

    if (eos_hasActionUnknownDataRemaining()) {
        if (!msg->has_unknown) {
            fsm_sendFailure(FailureType_Failure_SyntaxError, "Expected more EOSActionUnknown data chunks");
            eos_signingAbort();
            layoutHome();
            return;
        }
    } else if (eos_actionsRemaining() < 1) {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "Action count mismatch");
        eos_signingAbort();
        layoutHome();
        return;
    }

    if (msg->has_transfer) {
        if (!eos_compileActionTransfer(&msg->common, &msg->transfer))
            goto action_compile_failed;
    } else if (msg->has_delegate) {
        if (!eos_compileActionDelegate(&msg->common, &msg->delegate))
            goto action_compile_failed;
    } else if (msg->has_undelegate) {
        if (!eos_compileActionUndelegate(&msg->common, &msg->undelegate))
            goto action_compile_failed;
    } else if (msg->has_refund) {
        if (!eos_compileActionRefund(&msg->common, &msg->refund))
            goto action_compile_failed;
    } else if (msg->has_buy_ram) {
        if (!eos_compileActionBuyRam(&msg->common, &msg->buy_ram))
            goto action_compile_failed;
    } else if (msg->has_buy_ram_bytes) {
        if (!eos_compileActionBuyRamBytes(&msg->common, &msg->buy_ram_bytes))
            goto action_compile_failed;
    } else if (msg->has_sell_ram) {
        if (!eos_compileActionSellRam(&msg->common, &msg->sell_ram))
            goto action_compile_failed;
    } else if (msg->has_vote_producer) {
        if (!eos_compileActionVoteProducer(&msg->common, &msg->vote_producer))
            goto action_compile_failed;
    } else if (msg->has_update_auth) {
        if (!eos_compileActionUpdateAuth(&msg->common, &msg->update_auth))
            goto action_compile_failed;
    } else if (msg->has_delete_auth) {
        if (!eos_compileActionDeleteAuth(&msg->common, &msg->delete_auth))
            goto action_compile_failed;
    } else if (msg->has_link_auth) {
        if (!eos_compileActionLinkAuth(&msg->common, &msg->link_auth))
            goto action_compile_failed;
    } else if (msg->has_unlink_auth) {
        if (!eos_compileActionUnlinkAuth(&msg->common, &msg->unlink_auth))
            goto action_compile_failed;
    } else if (msg->has_new_account) {
        if (!eos_compileActionNewAccount(&msg->common, &msg->new_account))
            goto action_compile_failed;
    } else if (msg->has_unknown) {
        if (!eos_compileActionUnknown(&msg->common, &msg->unknown))
            goto action_compile_failed;
    } else {
        fsm_sendFailure(FailureType_Failure_Other, "Unknown action");
        eos_signingAbort();
        layoutHome();
        return;
    }

    if (!eos_signingIsFinished()) {
        RESP_INIT(EosTxActionRequest);
        msg_write(MessageType_MessageType_EosTxActionRequest, resp);
        return;
    }

    RESP_INIT(EosSignedTx);

    if (!eos_signTx(resp))
        return;

    layoutHome();
    msg_write(MessageType_MessageType_EosSignedTx, resp);
    return;

action_compile_failed:
    eos_signingAbort();
    layoutHome();
    return;
}
