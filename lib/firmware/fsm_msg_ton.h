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

  // Validate path: m/44'/607'/... (all hardened for TON)
  if (msg->address_n_count < 2 ||
      msg->address_n[0] != (0x80000000 | 44) ||
      msg->address_n[1] != (0x80000000 | 607)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid TON path (expected m/44'/607'/...)"));
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

  // Restrict workchain to valid values: 0 (basechain) or -1 (masterchain)
  if (workchain != 0 && workchain != -1) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Workchain must be 0 or -1"));
    layoutHome();
    return;
  }

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

  // Validate path: m/44'/607'/...
  if (msg->address_n_count < 2 ||
      msg->address_n[0] != (0x80000000 | 44) ||
      msg->address_n[1] != (0x80000000 | 607)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid TON path (expected m/44'/607'/...)"));
    layoutHome();
    return;
  }

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

  // Restrict workchain to valid values if provided
  if (msg->has_workchain && msg->workchain != 0 && msg->workchain != -1) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Workchain must be 0 or -1"));
    layoutHome();
    return;
  }

  // Validate destination address if provided
  if (msg->has_to_address) {
    if (!ton_validateAddress(msg->to_address)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Invalid TON destination address"));
      layoutHome();
      return;
    }
  }

  // Determine clear-sign vs blind-sign mode
  // Deploy txs (is_deploy=true) include StateInit which changes the cell tree;
  // firmware cannot reconstruct that, so deploy always uses blind-sign.
  bool is_deploy = msg->has_is_deploy && msg->is_deploy;
  bool clear_sign = false;
  if (!is_deploy &&
      msg->has_to_address && msg->has_amount &&
      msg->has_seqno && msg->has_expire_at &&
      msg->raw_tx.size == 32) {
    // All clear-sign fields present and raw_tx is a 32-byte hash — attempt verification
    bool bounce = msg->has_bounce ? msg->bounce : true;
    const char *memo = (msg->has_memo && msg->memo[0] != '\0') ? msg->memo : NULL;
    size_t memo_len = memo ? strlen(memo) : 0;

    clear_sign = ton_verify_transfer_hash(
        msg->to_address, msg->amount,
        msg->seqno, msg->expire_at, bounce,
        memo, memo_len,
        msg->raw_tx.bytes);
  }

  if (clear_sign) {
    // ── Clear-sign: verified fields match raw_tx hash ──────────────
    char amount_str[32];
    ton_formatAmount(amount_str, sizeof(amount_str), msg->amount);

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "TON Transfer", "Send %s to\n%s?",
                 amount_str, msg->to_address)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }

    // Show memo if present
    if (msg->has_memo && msg->memo[0] != '\0') {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Memo", "%s", msg->memo)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        _("Signing cancelled"));
        layoutHome();
        return;
      }
    }
  } else {
    // ── Blind-sign: show fields if available + explicit warning ─────
    if (msg->has_to_address && msg->has_amount) {
      char amount_str[32];
      ton_formatAmount(amount_str, sizeof(amount_str), msg->amount);

      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "TON Transfer", "Send %s to\n%s?",
                   amount_str, msg->to_address)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        _("Signing cancelled"));
        layoutHome();
        return;
      }
    }

    const char *blind_msg = is_deploy
        ? "Wallet deployment TX\ncannot be verified on\ndevice. Sign only if you\ntrust the sending app."
        : "TON TX details cannot be\nverified on device.\nSign only if you trust\nthe sending app.";
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Blind Signature",
                 "%s", blind_msg)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  }

  // Sign the transaction with Ed25519
  if (!ton_signTx(node, msg, resp)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("TON signing failed"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_TonSignedTx, resp);
  layoutHome();
}
