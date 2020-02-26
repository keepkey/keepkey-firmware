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

void fsm_msgRippleGetAddress(const RippleGetAddress *msg)
{
    RESP_INIT(RippleAddress);

    CHECK_INITIALIZED

    CHECK_PIN

    HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n, msg->address_n_count, NULL);
    if (!node) return;
    hdnode_fill_public_key(node);

    const CoinType *coin = fsm_getCoin(true, "Ripple");

    if (!ripple_getAddress(node->public_key, resp->address)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_Other, _("Address derivation failed"));
        layoutHome();
        return;
    }

    resp->has_address = true;

    if (msg->has_show_display && msg->show_display) {
        char node_str[NODE_STRING_LENGTH];
        if (!(bip32_node_to_string(node_str, sizeof(node_str), coin,
                                   msg->address_n,
                                   msg->address_n_count,
                                   /*whole_account=*/false,
                                   /*show_addridx=*/false)) &&
            !bip32_path_to_string(node_str, sizeof(node_str),
                                  msg->address_n, msg->address_n_count)) {
            memset(node_str, 0, sizeof(node_str));
        }

        if (!confirm_ethereum_address(node_str, resp->address)) {
            memzero(node, sizeof(*node));
            fsm_sendFailure(FailureType_Failure_ActionCancelled, _("Show address cancelled"));
            layoutHome();
            return;
        }
    }

    memzero(node, sizeof(*node));
    msg_write(MessageType_MessageType_RippleAddress, resp);
    layoutHome();
}

void fsm_msgRippleSignTx(RippleSignTx *msg)
{
    RESP_INIT(RippleSignedTx);

    CHECK_INITIALIZED

    CHECK_PIN

    bool needs_confirm = true;

    // TODO: handle trades and transfers

    HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                      msg->address_n_count, NULL);
    if (!node) return;
    hdnode_fill_public_key(node);

    if (!msg->has_fee || msg->fee < RIPPLE_MIN_FEE || msg->fee > RIPPLE_MAX_FEE) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Fee must be between 10 and 1,000,000 drops"));
        return;
    }

    char amount_string[20 + 4 + 1];
    ripple_formatAmount(amount_string, sizeof(amount_string), msg->payment.amount);

    char fee_string[20 + 4 + 1];
    ripple_formatAmount(fee_string, sizeof(fee_string), msg->fee);

    if (needs_confirm) {
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                     "Send", msg->payment.has_destination_tag
                       ? "Send %s to %s, with destination tag %" PRIu32 "?"
                       : "Send %s to %s?",
                     amount_string,
                     msg->payment.destination,
                     msg->payment.destination_tag)) {
            memzero(node, sizeof(*node));
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
            layoutHome();
            return;
        }
    }

    if (!confirm(ButtonRequestType_ButtonRequest_SignTx,
                 "Transaction", "Really send %s, with a transaction fee of %s?",
                 amount_string, fee_string)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
        layoutHome();
        return;
    }

    ripple_signTx(node, msg, resp);
    memzero(node, sizeof(*node));
    msg_write(MessageType_MessageType_RippleSignedTx, resp);
    layoutHome();
}
