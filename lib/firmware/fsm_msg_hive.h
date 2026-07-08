/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

// ── HiveGetPublicKey ──────────────────────────────────────────────────────
// Returns a single STM-prefixed public key for the given SLIP-0048 path.
// Path format: m/48'/13'/role'/account'/0' (all 5 components hardened).

void fsm_msgHiveGetPublicKey(const HiveGetPublicKey* msg) {
  RESP_INIT(HivePublicKey);

  CHECK_INITIALIZED
  CHECK_PIN

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  resp->has_raw_public_key = true;
  resp->raw_public_key.size = 33;
  memcpy(resp->raw_public_key.bytes, node->public_key, 33);

  resp->has_public_key = true;
  if (!hive_getPublicKey(node->public_key, resp->public_key,
                         sizeof(resp->public_key))) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to encode Hive public key"));
    layoutHome();
    return;
  }

  if (msg->has_show_display && msg->show_display) {
    // Determine role label for display
    const char* role_label = "Hive Public Key";
    if (msg->has_role) {
      switch (msg->role) {
        case 0:
          role_label = "Hive Owner Key";
          break;
        case 1:
          role_label = "Hive Active Key";
          break;
        case 3:
          role_label = "Hive Memo Key";
          break;
        case 4:
          role_label = "Hive Posting Key";
          break;
        default:
          break;
      }
    }
    if (!confirm_ethereum_address(role_label, resp->public_key)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, _("Cancelled"));
      layoutHome();
      return;
    }
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_HivePublicKey, resp);
  layoutHome();
}

// ── HiveGetPublicKeys ─────────────────────────────────────────────────────
// Returns all four SLIP-0048 role keys (owner/active/memo/posting) for a
// given account index in a single device interaction.

void fsm_msgHiveGetPublicKeys(const HiveGetPublicKeys* msg) {
  RESP_INIT(HivePublicKeys);

  CHECK_INITIALIZED
  CHECK_PIN

  uint32_t account_index = msg->has_account_index ? msg->account_index : 0;

  HDNode* root = fsm_getDerivedNode(SECP256K1_NAME, NULL, 0, NULL);
  if (!root) return;

  resp->has_owner_key = true;
  resp->has_active_key = true;
  resp->has_memo_key = true;
  resp->has_posting_key = true;

  if (!hive_getPublicKeys(root, account_index, resp->owner_key,
                          sizeof(resp->owner_key), resp->active_key,
                          sizeof(resp->active_key), resp->memo_key,
                          sizeof(resp->memo_key), resp->posting_key,
                          sizeof(resp->posting_key))) {
    memzero(root, sizeof(*root));
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to derive Hive keys"));
    layoutHome();
    return;
  }

  if (msg->has_show_display && msg->show_display) {
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Hive Keys",
                 "Export all Hive keys for account %u?",
                 (unsigned int)account_index)) {
      memzero(root, sizeof(*root));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, _("Cancelled"));
      layoutHome();
      return;
    }
  }

  memzero(root, sizeof(*root));
  msg_write(MessageType_MessageType_HivePublicKeys, resp);
  layoutHome();
}

// ── HiveSignTx (transfer) ─────────────────────────────────────────────────

void fsm_msgHiveSignTx(const HiveSignTx* msg) {
  RESP_INIT(HiveSignedTx);

  CHECK_INITIALIZED
  CHECK_PIN

  if (!msg->has_from || !msg->has_to || !msg->has_amount ||
      !msg->has_ref_block_num || !msg->has_ref_block_prefix ||
      !msg->has_expiration) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Missing required Hive transaction fields"));
    layoutHome();
    return;
  }

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  const char* symbol = msg->has_asset_symbol ? msg->asset_symbol : "HIVE";
  char amount_str[32];
  snprintf(amount_str, sizeof(amount_str), "%" PRIu64 ".%03" PRIu64 " %s",
           msg->amount / 1000, msg->amount % 1000, symbol);

  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Send Hive",
               "Send %s to @%s?", amount_str, msg->to)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  if (msg->has_memo && strlen(msg->memo) > 0) {
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmMemo, "Memo", "%s",
                 msg->memo)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Sign Transaction",
               "Sign Hive transaction from @%s?", msg->from)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  hive_signTx(node, msg, resp);
  memzero(node, sizeof(*node));

  if (!resp->has_signature) {
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Hive signing failed"));
    layoutHome();
    return;
  }

  msg_write(MessageType_MessageType_HiveSignedTx, resp);
  layoutHome();
}

// ── HiveSignAccountCreate ─────────────────────────────────────────────────
// Signs a Graphene account_create operation.
// Device derives all four role keys internally; host-supplied key strings
// are informational only (displayed for confirmation) and never used for
// the actual transaction. KeepKey is the sole root of trust from genesis.

void fsm_msgHiveSignAccountCreate(const HiveSignAccountCreate* msg) {
  RESP_INIT(HiveSignedAccountCreate);

  CHECK_INITIALIZED
  CHECK_PIN

  if (!msg->has_new_account_name || !msg->has_creator ||
      !msg->has_ref_block_num || !msg->has_ref_block_prefix ||
      !msg->has_expiration) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Missing required account_create fields"));
    layoutHome();
    return;
  }

  // Path must have at least 4 components so we can extract account_index.
  // Expected: m/48'/13'/0'/account_index'/0' (count = 5)
  if (msg->address_n_count < 4) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Hive path too short"));
    layoutHome();
    return;
  }
  uint32_t account_index = msg->address_n[3] & 0x7FFFFFFFu;

  // Derive all four role keys from the device root.
  // Do this BEFORE fetching the signing node so the root static buffer
  // is not clobbered by the second fsm_getDerivedNode call.
  const HDNode* root = fsm_getDerivedNode(SECP256K1_NAME, NULL, 0, NULL);
  if (!root) return;

  uint8_t owner_raw[33], active_raw[33], posting_raw[33], memo_raw[33];
  uint32_t acc_hardened = account_index | 0x80000000u;
  bool keys_ok =
      hive_deriveRawKey(root, HIVE_ROLE_OWNER, acc_hardened, owner_raw) &&
      hive_deriveRawKey(root, HIVE_ROLE_ACTIVE, acc_hardened, active_raw) &&
      hive_deriveRawKey(root, HIVE_ROLE_POSTING, acc_hardened, posting_raw) &&
      hive_deriveRawKey(root, HIVE_ROLE_MEMO, acc_hardened, memo_raw);
  // root static buffer is done with; signing node derivation may overwrite it.

  if (!keys_ok) {
    memzero(owner_raw, sizeof(owner_raw));
    memzero(active_raw, sizeof(active_raw));
    memzero(posting_raw, sizeof(posting_raw));
    memzero(memo_raw, sizeof(memo_raw));
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to derive Hive keys"));
    layoutHome();
    return;
  }

  // Now get the signing node (owner key, overwrites root static buffer).
  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) {
    memzero(owner_raw, sizeof(owner_raw));
    memzero(active_raw, sizeof(active_raw));
    memzero(posting_raw, sizeof(posting_raw));
    memzero(memo_raw, sizeof(memo_raw));
    return;
  }
  hdnode_fill_public_key(node);

  // Encode the device-derived owner key for display confirmation.
  char owner_stm[64];
  if (!hive_getPublicKey(owner_raw, owner_stm, sizeof(owner_stm))) {
    memzero(node, sizeof(*node));
    memzero(owner_raw, sizeof(owner_raw));
    memzero(active_raw, sizeof(active_raw));
    memzero(posting_raw, sizeof(posting_raw));
    memzero(memo_raw, sizeof(memo_raw));
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to encode Hive owner key"));
    layoutHome();
    return;
  }

  // Primary confirmation: show the new username prominently.
  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
               "Create Hive Account",
               "Create @%s secured by KeepKey?\n\nAll keys from your device.",
               msg->new_account_name)) {
    memzero(node, sizeof(*node));
    memzero(owner_raw, sizeof(owner_raw));
    memzero(active_raw, sizeof(active_raw));
    memzero(posting_raw, sizeof(posting_raw));
    memzero(memo_raw, sizeof(memo_raw));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  // Secondary confirmation: show device-derived owner key so user can verify.
  if (!confirm(ButtonRequestType_ButtonRequest_Other, "Owner Key", "%s",
               owner_stm)) {
    memzero(node, sizeof(*node));
    memzero(owner_raw, sizeof(owner_raw));
    memzero(active_raw, sizeof(active_raw));
    memzero(posting_raw, sizeof(posting_raw));
    memzero(memo_raw, sizeof(memo_raw));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  // Tertiary confirmation: show sponsor + fee.
  char fee_str[32];
  uint64_t fee = msg->has_fee_amount ? msg->fee_amount : 3000;
  snprintf(fee_str, sizeof(fee_str), "%" PRIu64 ".%03" PRIu64 " HIVE",
           fee / 1000, fee % 1000);
  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Creation Fee",
               "Fee: %s paid by @%s", fee_str, msg->creator)) {
    memzero(node, sizeof(*node));
    memzero(owner_raw, sizeof(owner_raw));
    memzero(active_raw, sizeof(active_raw));
    memzero(posting_raw, sizeof(posting_raw));
    memzero(memo_raw, sizeof(memo_raw));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  hive_signAccountCreate(node, msg, owner_raw, active_raw, posting_raw,
                         memo_raw, resp);
  memzero(node, sizeof(*node));
  memzero(owner_raw, sizeof(owner_raw));
  memzero(active_raw, sizeof(active_raw));
  memzero(posting_raw, sizeof(posting_raw));
  memzero(memo_raw, sizeof(memo_raw));

  if (!resp->has_signature) {
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Hive account_create signing failed"));
    layoutHome();
    return;
  }

  msg_write(MessageType_MessageType_HiveSignedAccountCreate, resp);
  layoutHome();
}

// ── HiveSignAccountUpdate ─────────────────────────────────────────────────
// Signs a Graphene account_update operation.
// Device derives all four new role keys internally; host-supplied new_*_key
// strings are not used for signing. The device-derived owner key is shown
// so the user can verify it matches their device before replacing all keys.

void fsm_msgHiveSignAccountUpdate(const HiveSignAccountUpdate* msg) {
  RESP_INIT(HiveSignedAccountUpdate);

  CHECK_INITIALIZED
  CHECK_PIN

  if (!msg->has_account || !msg->has_ref_block_num ||
      !msg->has_ref_block_prefix || !msg->has_expiration) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Missing required account_update fields"));
    layoutHome();
    return;
  }

  if (msg->address_n_count < 4) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Hive path too short"));
    layoutHome();
    return;
  }
  uint32_t account_index = msg->address_n[3] & 0x7FFFFFFFu;

  // Derive all four role keys before fetching the signing node.
  const HDNode* root = fsm_getDerivedNode(SECP256K1_NAME, NULL, 0, NULL);
  if (!root) return;

  uint8_t owner_raw[33], active_raw[33], posting_raw[33], memo_raw[33];
  uint32_t acc_hardened = account_index | 0x80000000u;
  bool keys_ok =
      hive_deriveRawKey(root, HIVE_ROLE_OWNER, acc_hardened, owner_raw) &&
      hive_deriveRawKey(root, HIVE_ROLE_ACTIVE, acc_hardened, active_raw) &&
      hive_deriveRawKey(root, HIVE_ROLE_POSTING, acc_hardened, posting_raw) &&
      hive_deriveRawKey(root, HIVE_ROLE_MEMO, acc_hardened, memo_raw);

  if (!keys_ok) {
    memzero(owner_raw, sizeof(owner_raw));
    memzero(active_raw, sizeof(active_raw));
    memzero(posting_raw, sizeof(posting_raw));
    memzero(memo_raw, sizeof(memo_raw));
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to derive Hive keys"));
    layoutHome();
    return;
  }

  // Signing node (overwrites root static buffer).
  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) {
    memzero(owner_raw, sizeof(owner_raw));
    memzero(active_raw, sizeof(active_raw));
    memzero(posting_raw, sizeof(posting_raw));
    memzero(memo_raw, sizeof(memo_raw));
    return;
  }
  hdnode_fill_public_key(node);

  // Encode device-derived owner key for display.
  char owner_stm[64];
  if (!hive_getPublicKey(owner_raw, owner_stm, sizeof(owner_stm))) {
    memzero(node, sizeof(*node));
    memzero(owner_raw, sizeof(owner_raw));
    memzero(active_raw, sizeof(active_raw));
    memzero(posting_raw, sizeof(posting_raw));
    memzero(memo_raw, sizeof(memo_raw));
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to encode Hive owner key"));
    layoutHome();
    return;
  }

  // Warning: this replaces all existing keys.
  if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall,
               "Secure Hive Account",
               "Replace ALL keys for @%s with KeepKey keys?\n\nOld keys will "
               "be retired.",
               msg->account)) {
    memzero(node, sizeof(*node));
    memzero(owner_raw, sizeof(owner_raw));
    memzero(active_raw, sizeof(active_raw));
    memzero(posting_raw, sizeof(posting_raw));
    memzero(memo_raw, sizeof(memo_raw));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  // Show device-derived owner key so user can verify it's their device.
  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "New Owner Key", "%s",
               owner_stm)) {
    memzero(node, sizeof(*node));
    memzero(owner_raw, sizeof(owner_raw));
    memzero(active_raw, sizeof(active_raw));
    memzero(posting_raw, sizeof(posting_raw));
    memzero(memo_raw, sizeof(memo_raw));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  hive_signAccountUpdate(node, msg, owner_raw, active_raw, posting_raw,
                         memo_raw, resp);
  memzero(node, sizeof(*node));
  memzero(owner_raw, sizeof(owner_raw));
  memzero(active_raw, sizeof(active_raw));
  memzero(posting_raw, sizeof(posting_raw));
  memzero(memo_raw, sizeof(memo_raw));

  if (!resp->has_signature) {
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Hive account_update signing failed"));
    layoutHome();
    return;
  }

  msg_write(MessageType_MessageType_HiveSignedAccountUpdate, resp);
  layoutHome();
}
