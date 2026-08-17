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

void fsm_msgTonGetAddress(const TonGetAddress* msg) {
  RESP_INIT(TonAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  // Validate path: m/44'/607'/... (all hardened for TON)
  if (msg->address_n_count < 2 || msg->address_n[0] != (0x80000000 | 44) ||
      msg->address_n[1] != (0x80000000 | 607)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid TON path (expected m/44'/607'/...)"));
    layoutHome();
    return;
  }

  // Derive node using Ed25519 curve
  HDNode* node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
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

void fsm_msgTonSignTx(TonSignTx* msg) {
  RESP_INIT(TonSignedTx);

  CHECK_INITIALIZED

  CHECK_PIN

  // Validate path: m/44'/607'/...
  if (msg->address_n_count < 2 || msg->address_n[0] != (0x80000000 | 44) ||
      msg->address_n[1] != (0x80000000 | 607)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid TON path (expected m/44'/607'/...)"));
    layoutHome();
    return;
  }

  /* AdvancedMode gate: to_address, amount and memo are display-only fields
   * that are NOT derived from or checked against raw_tx, so this handler can
   * only ever blind-sign opaque bytes. Same fence as fsm_msgTonSignMessage
   * below, until the displayed fields are parsed out of raw_tx and verified
   * against the bytes that actually get signed. */
  if (!storage_isPolicyEnabled("AdvancedMode")) {
    (void)review(ButtonRequestType_ButtonRequest_Other, "Blocked",
                 "TON transaction signing is blind-only. "
                 "Enable AdvancedMode in device settings.");
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Transaction signing disabled by policy"));
    layoutHome();
    return;
  }

  // Derive node using Ed25519 curve
  HDNode* node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  if (!msg->has_raw_tx || msg->raw_tx.size == 0) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("Missing transaction data"));
    layoutHome();
    return;
  }

  /* Never render to_address/amount here: they are unbound to the signed
   * bytes, so a hostile host can show one recipient on the OLED and get a
   * completely different transaction signed. Name only what the device can
   * actually verify -- how many bytes it is about to sign. */
  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "TON Blind Sign",
               "Sign %u-byte TON transaction?", (unsigned)msg->raw_tx.size)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
    layoutHome();
    return;
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

void fsm_msgTonSignMessage(const TonSignMessage* msg) {
  RESP_INIT(TonMessageSignature);

  CHECK_INITIALIZED
  CHECK_PIN

  if (!msg->has_message || msg->message.size == 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Missing message"));
    layoutHome();
    return;
  }

  // Validate path: m/44'/607'/...
  if (msg->address_n_count < 2 || msg->address_n[0] != (0x80000000 | 44) ||
      msg->address_n[1] != (0x80000000 | 607)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid TON path (expected m/44'/607'/...)"));
    layoutHome();
    return;
  }

  /* AdvancedMode gate: TON message signing is bare Ed25519 over arbitrary
   * bytes — no domain separation. A signed message is indistinguishable
   * over the wire from a signed transaction. Same fence as SolanaSignMessage
   * (see fsm_msg_solana.h:461) until TON Connect's ton_proof envelope is
   * added as a separate handler. */
  if (!storage_isPolicyEnabled("AdvancedMode")) {
    (void)review(ButtonRequestType_ButtonRequest_Other, "Blocked",
                 "TON message signing is experimental. "
                 "Enable AdvancedMode in device settings.");
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Message signing disabled by policy"));
    layoutHome();
    return;
  }

  HDNode* node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  /* Always require on-device confirmation. Display message content if
   * printable, hex preview otherwise. */
  {
    char msgBuf[129] = {0};
    const char* typeLabel;
    bool printable = true;
    for (unsigned i = 0; i < msg->message.size; i++) {
      if (msg->message.bytes[i] < 0x20 || msg->message.bytes[i] > 0x7e) {
        printable = false;
        break;
      }
    }
    if (printable && msg->message.size <= sizeof(msgBuf) - 1) {
      typeLabel = "Sign TON Message";
      memcpy(msgBuf, msg->message.bytes, msg->message.size);
      msgBuf[msg->message.size] = '\0';
    } else {
      typeLabel = "Sign TON Bytes";
      unsigned show = msg->message.size;
      if (show > 32) show = 32;
      for (unsigned i = 0; i < show; i++) {
        snprintf(&msgBuf[2 * i], 3, "%02x", msg->message.bytes[i]);
      }
      msgBuf[2 * show] = '\0';
      if (msg->message.size > 32) {
        snprintf(&msgBuf[64], sizeof(msgBuf) - 64, "... (%u bytes)",
                 (unsigned)msg->message.size);
      }
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, _(typeLabel),
                 "%s", msgBuf)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  }

  if (!ton_message_sign(node, msg, resp)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("TON message signing failed"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_TonMessageSignature, resp);
  layoutHome();
}
