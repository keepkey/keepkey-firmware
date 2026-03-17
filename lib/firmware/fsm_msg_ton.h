/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2024 KeepKey
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

void fsm_msgTonGetAddress(const TonGetAddress *msg) {
  RESP_INIT(TonAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  // Validate path: m/44'/607'/x'/x'/x'/x' (all hardened for TON)
  if (msg->address_n_count < 6) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid path for TON address"));
    layoutHome();
    return;
  }

  // Derive node using Ed25519 curve
  HDNode *node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  // Extract TON-specific parameters with defaults
  bool bounceable = msg->has_bounceable ? msg->bounceable : true;
  bool testnet = msg->has_testnet ? msg->testnet : false;
  int32_t workchain = msg->has_workchain ? msg->workchain : 0;

  // Get TON address from public key (Base64 URL-safe encoding)
  char address[MAX_ADDR_SIZE];
  char raw_address[MAX_ADDR_SIZE];
  if (!ton_get_address(&node->public_key[1], bounceable, testnet, workchain,
                       address, sizeof(address), raw_address,
                       sizeof(raw_address))) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("Can't encode address"));
    layoutHome();
    return;
  }

  resp->has_address = true;
  strlcpy(resp->address, address, sizeof(resp->address));
  resp->has_raw_address = true;
  strlcpy(resp->raw_address, raw_address, sizeof(resp->raw_address));

  // Show address on display if requested
  if (msg->has_show_display && msg->show_display) {
    char node_str[NODE_STRING_LENGTH];
    if (!bip32_path_to_string(node_str, sizeof(node_str), msg->address_n,
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
  msg_write(MessageType_MessageType_TonAddress, resp);
  layoutHome();
}

void fsm_msgTonSignTx(TonSignTx *msg) {
  RESP_INIT(TonSignedTx);

  CHECK_INITIALIZED

  CHECK_PIN

  // Derive node using Ed25519 curve
  HDNode *node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  if (!msg->has_raw_tx || msg->raw_tx.size == 0) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Missing transaction data"));
    layoutHome();
    return;
  }

  bool needs_confirm = true;

  // Display transaction details if available
  if (needs_confirm && msg->has_to_address && msg->has_amount) {
    char amount_str[32];
    ton_formatAmount(amount_str, sizeof(amount_str), msg->amount);

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Send", "Send %s TON to %s?",
                 amount_str, msg->to_address)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
      layoutHome();
      return;
    }
  }

  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Transaction",
               "Really sign this TON transaction?")) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
    layoutHome();
    return;
  }

  // Sign the transaction with Ed25519
  ton_signTx(node, msg, resp);

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_TonSignedTx, resp);
  layoutHome();
}
