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

void fsm_msgRippleGetAddress(const RippleGetAddress* msg) {
  RESP_INIT(RippleAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  const CoinType* coin = fsm_getCoin(true, "Ripple");

  /* ripple_getAddress() hands ripple_encode_check() a MAX_ADDR_SIZE (130 byte)
     destination, but RippleAddress.address is capped at 36 by the proto
     options. Encode into a correctly sized local and copy the result, so the
     encoder's bound matches the buffer it is actually writing. Today a Ripple
     address encodes to ~35 characters and happens to fit, but that is a
     property of the input, not of the contract -- and it is a one byte margin.
     gcc 14 rejects the direct call outright (-Werror=stringop-overflow);
     gcc 10, which CI uses, does not. */
  char ripple_addr[MAX_ADDR_SIZE];
  if (!ripple_getAddress(node->public_key, ripple_addr)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("Address derivation failed"));
    layoutHome();
    return;
  }

  strlcpy(resp->address, ripple_addr, sizeof(resp->address));
  resp->has_address = true;

  if (msg->has_show_display && msg->show_display) {
    char node_str[NODE_STRING_LENGTH];
    if (!(bip32_node_to_string(node_str, sizeof(node_str), coin, msg->address_n,
                               msg->address_n_count,
                               /*whole_account=*/false,
                               /*show_addridx=*/false)) &&
        !bip32_path_to_string(node_str, sizeof(node_str), msg->address_n,
                              msg->address_n_count)) {
      memset(node_str, 0, sizeof(node_str));
    }

    if (!confirm_ethereum_address(node_str, resp->address)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Show address cancelled"));
      layoutHome();
      return;
    }
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_RippleAddress, resp);
  layoutHome();
}

void fsm_msgRippleSignTx(RippleSignTx* msg) {
  RESP_INIT(RippleSignedTx);

  CHECK_INITIALIZED

  CHECK_PIN

  bool needs_confirm = true;

  // TODO: handle trades and transfers

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  /* Absent fields are not zero-valued fields. Without these, an omitted
     payment/amount/destination reached the screens as 0 XRP to an empty
     address, and ripple_serialize() simply omitted what was missing -- so the
     owner approved one transaction and the device signed another. The
     destination is checked here too: ripple_serializeAddress() enforces the
     21-byte decode with assert(), which is compiled out of release builds, and
     runs only after both confirmations. */
  if (!msg->has_payment || !msg->payment.has_amount ||
      !msg->payment.has_destination ||
      !ripple_validateAddress(msg->payment.destination)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Payment amount and destination are required"));
    layoutHome();
    return;
  }

  if (!msg->has_fee || msg->fee < RIPPLE_MIN_FEE || msg->fee > RIPPLE_MAX_FEE) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Fee must be between 10 and 1,000,000 drops"));
    layoutHome();
    return;
  }

  /* Above RIPPLE_MAX_DROPS the serializer's own bound is exceeded; it guarded
     that with assert(), which is compiled out of release builds, so the amount
     would be encoded differently from the one supplied. Refuse here instead,
     before anything is shown. */
  if (msg->payment.amount > RIPPLE_MAX_DROPS) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Amount exceeds the largest XRP value this device can "
                      "sign"));
    layoutHome();
    return;
  }

  /* Both renders must succeed BEFORE any confirmation. These used to be void
     calls, so an unrenderable amount put "AMOUNT TOO LARGE TO DISPLAY" on the
     screen and the numeric amount into the signature. */
  char amount_string[20 + 4 + 1];
  char fee_string[20 + 4 + 1];
  if (!ripple_formatAmount(amount_string, sizeof(amount_string),
                           msg->payment.amount) ||
      !ripple_formatAmount(fee_string, sizeof(fee_string), msg->fee)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Cannot display this XRP amount"));
    layoutHome();
    return;
  }

  if (needs_confirm) {
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Send",
                 msg->payment.has_destination_tag
                     ? "Send %s to %s, with destination tag %" PRIu32 "?"
                     : "Send %s to %s?",
                 amount_string, msg->payment.destination,
                 msg->payment.destination_tag)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
      layoutHome();
      return;
    }
  }

  if (msg->has_memo && msg->memo[0] != '\0') {
    /* Page the COMPLETE memo (72-char ASCII / 40-byte hex pages) like every
     * other memo surface. A single unpaged confirm renders only 3 OLED lines,
     * silently drops the overflow, and honors embedded newlines — so a memo
     * whose visible first line looks benign could carry ~180 signed-but-unseen
     * bytes into the Memos field that exchanges and bridges use for deposit
     * routing. */
    if (!thorchain_confirm_full_memo("Memo", msg->memo, strlen(msg->memo))) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
      layoutHome();
      return;
    }
  }

  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Transaction",
               "Really send %s, with a transaction fee of %s?", amount_string,
               fee_string)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
    layoutHome();
    return;
  }

  /* A failed sign left has_signature/has_serialized_tx false, and the response
     went out anyway -- the host saw an empty success where an error belonged.
   */
  if (!ripple_signTx(node, msg, resp)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("Ripple signing failed"));
    layoutHome();
    return;
  }
  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_RippleSignedTx, resp);
  layoutHome();
}
