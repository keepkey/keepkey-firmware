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

void fsm_msgTronGetAddress(const TronGetAddress* msg) {
  RESP_INIT(TronAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  // Validate path: m/44'/195'/...
  if (msg->address_n_count < 3 || msg->address_n[0] != (0x80000000 | 44) ||
      msg->address_n[1] != (0x80000000 | 195)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid TRON path (expected m/44'/195'/...)"));
    layoutHome();
    return;
  }

  // Derive node using secp256k1 curve
  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  // Get TRON address from public key (Base58Check with prefix 'T')
  char address[MAX_ADDR_SIZE];
  if (!tron_getAddress(node->public_key, address, sizeof(address))) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("Address derivation failed"));
    layoutHome();
    return;
  }

  resp->has_address = true;
  strlcpy(resp->address, address, sizeof(resp->address));

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
  msg_write(MessageType_MessageType_TronAddress, resp);
  layoutHome();
}

void fsm_msgTronSignTx(TronSignTx* msg) {
  RESP_INIT(TronSignedTx);

  CHECK_INITIALIZED

  CHECK_PIN

  // Validate path: m/44'/195'/...
  if (msg->address_n_count < 3 || msg->address_n[0] != (0x80000000 | 44) ||
      msg->address_n[1] != (0x80000000 | 195)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid TRON path (expected m/44'/195'/...)"));
    layoutHome();
    return;
  }

  // Derive node using secp256k1 curve
  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  if (!msg->has_raw_data || msg->raw_data.size == 0) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("Missing transaction data"));
    layoutHome();
    return;
  }

  /* The signature covers raw_data and nothing else (tron.c: sha256_Raw over
   * msg->raw_data, then ecdsa_sign_digest). The proto's to_address/amount
   * fields are a host-supplied side channel that is never hashed, so the old
   * "Send %s TRX to %s?" screen asserted a destination and an amount the
   * device had no way to vouch for: a host could display one payee and get a
   * signature over a transfer to another, and a host that simply omitted both
   * optional fields suppressed the screen altogether. This firmware has no
   * TRON protobuf parser, so every TronSignTx is a blind signature. Disclose
   * that instead of displaying unbound data, behind the same AdvancedMode
   * policy used for opaque Solana transactions and unknown-data ETH calls. */
  if (!storage_isPolicyEnabled("AdvancedMode")) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Enable AdvancedMode to blind-sign"));
    layoutHome();
    return;
  }

  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Blind Sign",
               "Sign unverified %u-byte TRON transaction? Amount and "
               "destination unknown.",
               (unsigned)msg->raw_data.size)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
    layoutHome();
    return;
  }

  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Transaction",
               "Really sign this TRON transaction?")) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
    layoutHome();
    return;
  }

  // Sign the transaction with secp256k1
  if (!tron_signTx(node, msg, resp)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("TRON signing failed"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_TronSignedTx, resp);
  layoutHome();
}

void fsm_msgTronSignMessage(TronSignMessage* msg) {
  RESP_INIT(TronMessageSignature);

  CHECK_INITIALIZED

  CHECK_PIN

  /* An omitted or zero-length message is not a message. confirm_bytes()
     renders size 0 as the literal "(empty)" and returns whatever the owner
     pressed, so without this the device would sign a payload no screen ever
     showed -- the same hole already closed on the TON and Solana paths. */
  if (!msg->has_message || msg->message.size == 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Missing message"));
    layoutHome();
    return;
  }

  /* Merge note (#432 vs this branch): #432 gated TRON message signing behind
   * AdvancedMode because the message was a blind sign. It is not any more —
   * confirm_bytes() below paginates and displays EVERY signed byte, which is
   * the property the gate was standing in for.
   *
   * The gate is dropped here for the same reason it was dropped from
   * fsm_msgEthereumSignMessage: full disclosure is the stronger guarantee, and
   * keeping it would block a default device until the user explicitly enables
   * blind signing. AdvancedMode persists across power cycles until explicitly
   * disabled. Leaving ETH ungated while TRON stayed gated would also be an
   * inconsistency with no principled basis, since both now show the user every
   * byte.
   *
   * Note this is NOT the same call as the TRON SignTx fence (#405), which
   * stays: a TRON *transaction* still cannot be parsed or bound on this line,
   * so it remains genuinely blind and keeps its AdvancedMode gate. */

  // Validate path: m/44'/195'/...
  if (msg->address_n_count < 3 || msg->address_n[0] != (0x80000000 | 44) ||
      msg->address_n[1] != (0x80000000 | 195)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid TRON path (expected m/44'/195'/...)"));
    layoutHome();
    return;
  }

  if (!confirm_bytes(ButtonRequestType_ButtonRequest_ProtectCall,
                     _("Sign TRON Message"), msg->message.bytes,
                     msg->message.size)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  if (!tron_message_sign(node, msg, resp)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other,
                    _("TRON message signing failed"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_TronMessageSignature, resp);
  layoutHome();
}

void fsm_msgTronVerifyMessage(const TronVerifyMessage* msg) {
  CHECK_PARAM(msg->has_address, _("No address provided"));
  CHECK_PARAM(msg->has_message, _("No message provided"));
  CHECK_PARAM(msg->has_signature, _("No signature provided"));

  if (tron_message_verify(msg) != 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Invalid signature"));
    return;
  }

  if (!confirm_address(_("Confirm Signer"), msg->address)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  if (!confirm_bytes(ButtonRequestType_ButtonRequest_Other,
                     _("TRON Message Verified"), msg->message.bytes,
                     msg->message.size)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }
  fsm_sendSuccess(_("Message verified"));
  layoutHome();
}
void fsm_msgTronSignTypedHash(const TronSignTypedHash* msg) {
  RESP_INIT(TronTypedDataSignature);

  CHECK_INITIALIZED

  CHECK_PIN

  // Validate path: m/44'/195'/...
  if (msg->address_n_count < 3 || msg->address_n[0] != (0x80000000 | 44) ||
      msg->address_n[1] != (0x80000000 | 195)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid TRON path (expected m/44'/195'/...)"));
    layoutHome();
    return;
  }

  if (msg->domain_separator_hash.size != 32 ||
      (msg->has_message_hash && msg->message_hash.size != 32)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid TIP-712 hash length"));
    layoutHome();
    return;
  }

  if (!tron_typed_hash_policy_allows(storage_isPolicyEnabled("AdvancedMode"))) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Enable AdvancedMode to blind-sign typed hashes"));
    layoutHome();
    return;
  }

  if (!confirm(ButtonRequestType_ButtonRequest_Other, "TIP-712 Blind Sign",
               "Cannot verify these hashes. Trust the host?")) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  // Derive Base58Check address for confirm dialog + response.
  char address[TRON_ADDRESS_MAX_LEN];
  if (!tron_getAddress(node->public_key, address, sizeof(address))) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("Address derivation failed"));
    layoutHome();
    return;
  }

  if (!confirm(ButtonRequestType_ButtonRequest_Other, "Verify Address",
               "Confirm address: %s", address)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  // Show domain separator hash as 64-char hex.
  char str[64 + 1];
  for (int ctr = 0; ctr < 64 / 2; ctr++) {
    snprintf(&str[2 * ctr], 3, "%02x", msg->domain_separator_hash.bytes[ctr]);
  }
  if (!confirm(ButtonRequestType_ButtonRequest_Other, "TIP-712 domain",
               "Confirm hash digest: %s", str)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  if (msg->has_message_hash) {
    for (int ctr = 0; ctr < 64 / 2; ctr++) {
      snprintf(&str[2 * ctr], 3, "%02x", msg->message_hash.bytes[ctr]);
    }
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "TIP-712 message",
                 "Confirm hash digest: %s", str)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  } else {
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "TIP-712 message",
                 "Confirm: No message")) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  if (!tron_typed_hash_sign(node, msg, resp)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other,
                    _("TIP-712 hash signing failed"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_TronTypedDataSignature, resp);
  layoutHome();
}
