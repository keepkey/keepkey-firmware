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

  /* to_address and amount are deprecated fields not included in raw_data.
   * Displaying them would show data that is not part of what is being signed.
   * Show only the raw_data size so the user knows what they are authorising. */
  char blind_msg[48];
  snprintf(blind_msg, sizeof(blind_msg), "Sign %u-byte TRON transaction?",
           (unsigned)msg->raw_data.size);
  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "TRON Blind Sign", "%s",
               blind_msg)) {
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

#ifndef TRON_MSG_DISPLAY_MAX
#define TRON_MSG_DISPLAY_MAX \
  (38 * 3)  // mirrors ETH MSG_MAX (3 lines × 38 chars)
#endif

void fsm_msgTronSignMessage(TronSignMessage* msg) {
  RESP_INIT(TronMessageSignature);

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

  char msgBuf[TRON_MSG_DISPLAY_MAX + 1] = {0};
  const char* typeIndicator;
  bool canPrint = true;
  unsigned ctr;

  for (ctr = 0; ctr < msg->message.size; ctr++) {
    if (isprint(msg->message.bytes[ctr]) == false) {
      canPrint = false;
      break;
    }
  }

  if (canPrint) {
    typeIndicator = "Sign TRON Message";
    unsigned copy = msg->message.size;
    if (copy > TRON_MSG_DISPLAY_MAX) copy = TRON_MSG_DISPLAY_MAX;
    memcpy(msgBuf, msg->message.bytes, copy);
    msgBuf[copy] = '\0';
  } else {
    typeIndicator = "Sign TRON Bytes";
    unsigned hexBytes = msg->message.size;
    if (hexBytes * 2 > TRON_MSG_DISPLAY_MAX) {
      hexBytes = TRON_MSG_DISPLAY_MAX / 2;
    }
    for (ctr = 0; ctr < hexBytes; ctr++) {
      snprintf(&msgBuf[2 * ctr], 3, "%02x", msg->message.bytes[ctr]);
    }
  }

  if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, _(typeIndicator),
               "%s", msgBuf)) {
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

  char msgBuf[TRON_MSG_DISPLAY_MAX + 1] = {0};
  const char* typeIndicator;
  bool canPrint = true;
  unsigned ctr;

  for (ctr = 0; ctr < msg->message.size; ctr++) {
    if (isprint(msg->message.bytes[ctr]) == false) {
      canPrint = false;
      break;
    }
  }

  if (canPrint) {
    typeIndicator = "Message Verified";
    unsigned copy = msg->message.size;
    if (copy > TRON_MSG_DISPLAY_MAX) copy = TRON_MSG_DISPLAY_MAX;
    memcpy(msgBuf, msg->message.bytes, copy);
    msgBuf[copy] = '\0';
  } else {
    typeIndicator = "Bytes Verified";
    unsigned hexBytes = msg->message.size;
    if (hexBytes * 2 > TRON_MSG_DISPLAY_MAX) {
      hexBytes = TRON_MSG_DISPLAY_MAX / 2;
    }
    for (ctr = 0; ctr < hexBytes; ctr++) {
      snprintf(&msgBuf[2 * ctr], 3, "%02x", msg->message.bytes[ctr]);
    }
  }

  if (!confirm(ButtonRequestType_ButtonRequest_Other, _(typeIndicator), "%s",
               msgBuf)) {
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
