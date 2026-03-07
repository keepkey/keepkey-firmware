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

#include "keepkey/firmware/solana_tx.h"

void fsm_msgSolanaGetAddress(const SolanaGetAddress *msg) {
  RESP_INIT(SolanaAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  // Derive Ed25519 key for Solana (uses Ed25519 curve, not secp256k1)
  HDNode *node = fsm_getDerivedNode("ed25519", msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  // Get Ed25519 public key
  uint8_t public_key[32];
  ed25519_publickey(node->private_key, public_key);

  // Convert to Solana address (Base58 encoding)
  char address[SOLANA_ADDRESS_SIZE];
  if (!solana_publicKeyToAddress(public_key, address, sizeof(address))) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Solana address derivation failed"));
    layoutHome();
    return;
  }

  // Copy address to response
  resp->has_address = true;
  strlcpy(resp->address, address, sizeof(resp->address));

  // Show address on display if requested
  if (msg->has_show_display && msg->show_display) {
    const CoinType *coin = fsm_getCoin(true, "Solana");
    char node_str[NODE_STRING_LENGTH];

    // Try to format the BIP32 path in a user-friendly way
    if (!(bip32_node_to_string(node_str, sizeof(node_str), coin, msg->address_n,
                               msg->address_n_count,
                               /*whole_account=*/false,
                               /*show_addridx=*/false)) &&
        !bip32_path_to_string(node_str, sizeof(node_str), msg->address_n,
                              msg->address_n_count)) {
      memset(node_str, 0, sizeof(node_str));
    }

    // Confirm address display with user
    if (!confirm_ethereum_address(node_str, address)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Show address cancelled"));
      layoutHome();
      return;
    }
  }

  // Clean up and send response
  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_SolanaAddress, resp);
  layoutHome();
}

void fsm_msgSolanaSignTx(SolanaSignTx *msg) {
  RESP_INIT(SolanaSignedTx);

  CHECK_INITIALIZED

  CHECK_PIN

  // Validate transaction data
  if (!msg->has_raw_tx || msg->raw_tx.size == 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("No transaction data provided"));
    layoutHome();
    return;
  }

  // Derive Ed25519 key for Solana
  HDNode *node = fsm_getDerivedNode("ed25519", msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  // Get public key for signer identification
  uint8_t public_key[32];
  ed25519_publickey(node->private_key, public_key);

  // Parse transaction to display details to user
  SolanaParsedTransaction parsed_tx;
  if (!solana_parseTransaction(msg->raw_tx.bytes, msg->raw_tx.size, &parsed_tx)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Failed to parse transaction"));
    layoutHome();
    return;
  }

  // Confirm transaction with user (shows parsed details)
  if (!solana_confirmTransaction(&parsed_tx, public_key)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
    layoutHome();
    return;
  }

  // Sign the transaction
  solana_signTx(node, msg, resp);

  // Clean up and send response
  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_SolanaSignedTx, resp);
  layoutHome();
}

void fsm_msgSolanaSignMessage(SolanaSignMessage *msg) {
  RESP_INIT(SolanaMessageSignature);

  CHECK_INITIALIZED

  CHECK_PIN

  // Validate message data
  if (!msg->has_message || msg->message.size == 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("No message provided"));
    layoutHome();
    return;
  }

  // Derive Ed25519 key for Solana
  HDNode *node = fsm_getDerivedNode("ed25519", msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  // Get public key
  uint8_t public_key[32];
  ed25519_publickey(node->private_key, public_key);

  // Confirm message signing with user (shows message preview)
  if (msg->show_display) {
    if (!solana_confirmMessage(msg->message.bytes, msg->message.size)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Message signing cancelled"));
      layoutHome();
      return;
    }
  }

  // Sign the message
  uint8_t signature[SOLANA_SIGNATURE_SIZE];
  solana_signMessage(node, msg->message.bytes, msg->message.size, signature);

  // Copy public key and signature to response
  resp->has_public_key = true;
  resp->public_key.size = 32;
  memcpy(resp->public_key.bytes, public_key, 32);

  resp->has_signature = true;
  resp->signature.size = SOLANA_SIGNATURE_SIZE;
  memcpy(resp->signature.bytes, signature, SOLANA_SIGNATURE_SIZE);

  // Clean up sensitive data
  memzero(signature, sizeof(signature));
  memzero(node, sizeof(*node));

  msg_write(MessageType_MessageType_SolanaMessageSignature, resp);
  layoutHome();
}
