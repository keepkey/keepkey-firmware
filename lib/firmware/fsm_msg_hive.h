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

static bool hive_slip48_path_ok(const uint32_t* address_n, uint32_t count);

// ── HiveGetPublicKey ──────────────────────────────────────────────────────

void fsm_msgHiveGetPublicKey(const HiveGetPublicKey* msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  // Only a full Hive SLIP-0048 path may be derived and labelled as a Hive key.
  if (!hive_slip48_path_ok(msg->address_n, msg->address_n_count)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid Hive SLIP-0048 path"));
    layoutHome();
    return;
  }

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  // Debug-link reads during confirms reuse msg_resp: build it last.
  uint8_t raw_public_key[33];
  memcpy(raw_public_key, node->public_key, sizeof(raw_public_key));
  memzero(node, sizeof(*node));
  char public_key[sizeof(((HivePublicKey*)0)->public_key)];
  if (!hive_getPublicKey(raw_public_key, public_key, sizeof(public_key))) {
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to encode Hive public key"));
    layoutHome();
    return;
  }

  if (msg->has_show_display && msg->show_display) {
    // Label from the derived path, never the host-supplied msg->role.
    const char* role_label = "Hive Public Key";
    if (msg->address_n_count >= 3) {
      switch (msg->address_n[2] & 0x7FFFFFFFu) {
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
    /* An STM key outgrows the address layout's text area, which truncates
     * silently; confirm_bytes() pages it so every character is shown, and the
     * QR follows on its own screen. */
    if (!confirm_bytes(ButtonRequestType_ButtonRequest_Address, role_label,
                       (const uint8_t*)public_key, strlen(public_key)) ||
        !confirm_qr(role_label, public_key)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, _("Cancelled"));
      layoutHome();
      return;
    }
  }

  RESP_INIT(HivePublicKey);
  resp->has_raw_public_key = true;
  resp->raw_public_key.size = 33;
  memcpy(resp->raw_public_key.bytes, raw_public_key, 33);
  resp->has_public_key = true;
  strlcpy(resp->public_key, public_key, sizeof(resp->public_key));
  msg_write(MessageType_MessageType_HivePublicKey, resp);
  layoutHome();
}

// ── HiveGetPublicKeys ─────────────────────────────────────────────────────

void fsm_msgHiveGetPublicKeys(const HiveGetPublicKeys* msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  uint32_t account_index = msg->has_account_index ? msg->account_index : 0;
  // Bit 31 is the hardening flag; accepting it would alias a lower account.
  if (account_index > 0x7FFFFFFFu) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid Hive account index"));
    layoutHome();
    return;
  }

  HDNode* root = fsm_getDerivedNode(SECP256K1_NAME, NULL, 0, NULL);
  if (!root) return;

  char keys[4][sizeof(((HivePublicKeys*)0)->owner_key)];
  bool keys_ok = hive_getPublicKeys(
      root, account_index, keys[0], sizeof(keys[0]), keys[1], sizeof(keys[1]),
      keys[2], sizeof(keys[2]), keys[3], sizeof(keys[3]));
  memzero(root, sizeof(*root));
  if (!keys_ok) {
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to derive Hive keys"));
    layoutHome();
    return;
  }

  if (msg->has_show_display && msg->show_display) {
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Hive Keys",
                 "Export all Hive keys for account %u?",
                 (unsigned int)account_index)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, _("Cancelled"));
      layoutHome();
      return;
    }
  }

  RESP_INIT(HivePublicKeys);
  resp->has_owner_key = true;
  resp->has_active_key = true;
  resp->has_memo_key = true;
  resp->has_posting_key = true;
  strlcpy(resp->owner_key, keys[0], sizeof(resp->owner_key));
  strlcpy(resp->active_key, keys[1], sizeof(resp->active_key));
  strlcpy(resp->memo_key, keys[2], sizeof(resp->memo_key));
  strlcpy(resp->posting_key, keys[3], sizeof(resp->posting_key));
  msg_write(MessageType_MessageType_HivePublicKeys, resp);
  layoutHome();
}

// ── HiveSignTx (transfer) ─────────────────────────────────────────────────

// A non-mainnet chain id must be part of consent.
static bool hive_confirm_chain(bool present, const uint8_t* chain) {
  const uint8_t mainnet[32] = HIVE_CHAIN_ID;
  if (!present || memcmp(chain, mainnet, sizeof(mainnet)) == 0) return true;
  char hex[65];
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < 32; ++i) {
    hex[2 * i] = digits[chain[i] >> 4];
    hex[2 * i + 1] = digits[chain[i] & 15];
  }
  hex[64] = 0;
  return confirm_bytes(ButtonRequestType_ButtonRequest_ProtectCall,
                       "Custom Hive chain", (const uint8_t*)hex, 64);
}

void fsm_msgHiveSignTx(const HiveSignTx* msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  if (msg->has_memo &&
      strnlen(msg->memo, sizeof(msg->memo)) > HIVE_MAX_MEMO_LEN) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Hive memo too long (max 440 bytes)"));
    layoutHome();
    return;
  }

  if (!hive_validateTransfer(msg)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid Hive transaction fields"));
    layoutHome();
    return;
  }

  if (!hive_slip48_path_ok(msg->address_n, msg->address_n_count) ||
      msg->address_n[2] != HIVE_ROLE_ACTIVE) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid Hive SLIP-0048 path"));
    layoutHome();
    return;
  }

  if (!hive_confirm_chain(msg->has_chain_id, msg->chain_id.bytes)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  const char* wire_symbol;
  const char* display_symbol;
  uint8_t prec;
  if (!hive_transferAsset(msg, &wire_symbol, &display_symbol, &prec)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Unsupported Hive asset symbol or precision"));
    layoutHome();
    return;
  }
  (void)wire_symbol;
  char suffix[sizeof(msg->asset_symbol) + 2];  // leading space + symbol + NUL
  snprintf(suffix, sizeof(suffix), " %s", display_symbol);
  char amount_str[32];
  bn_format_uint64(msg->amount, NULL, suffix, prec, 0, false, amount_str,
                   sizeof(amount_str));

  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Send Hive",
               "Send %s to @%s?", amount_str, msg->to)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  if (msg->has_memo && strlen(msg->memo) > 0) {
    if (!confirm_bytes(ButtonRequestType_ButtonRequest_ConfirmMemo, "Memo",
                       (const uint8_t*)msg->memo, strlen(msg->memo))) {
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

  // Debug-link reads during the confirms reuse msg_resp; init it here.
  RESP_INIT(HiveSignedTx);
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

// ── SLIP-0048 path validation ─────────────────────────────────────────────
// Enforce m/48'/13'/role'/account'/0' before deriving or signing anything.

static bool hive_slip48_path_ok(const uint32_t* address_n, uint32_t count) {
  if (count != 5) return false;
  if (address_n[0] != HIVE_SLIP48_PURPOSE) return false;
  if (address_n[1] != HIVE_SLIP48_NETWORK) return false;
  if (address_n[2] != HIVE_ROLE_OWNER && address_n[2] != HIVE_ROLE_ACTIVE &&
      address_n[2] != HIVE_ROLE_MEMO && address_n[2] != HIVE_ROLE_POSTING) {
    return false;
  }
  if ((address_n[3] & 0x80000000u) == 0) return false;
  if (address_n[4] != 0x80000000u) return false;  // key index 0'
  return true;
}

// ── Account create/update shared preparation ──────────────────────────────
// Owner-role path check, chain consent, the four device-derived role keys
// (owner, active, posting, memo) and the signing node. On NULL nothing secret
// remains and the host has been answered.

static HDNode* hive_prepare_account_keys(
    const uint32_t* address_n, uint32_t address_n_count, bool has_chain_id,
    const uint8_t* chain_id, uint8_t keys[4][33], char owner_stm[64]) {
  if (!hive_slip48_path_ok(address_n, address_n_count) ||
      address_n[2] != HIVE_ROLE_OWNER) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid Hive SLIP-0048 path"));
    layoutHome();
    return NULL;
  }
  if (!hive_confirm_chain(has_chain_id, chain_id)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return NULL;
  }

  // Derive the role keys BEFORE the signing node: it overwrites the root
  // static buffer.
  HDNode* root = fsm_getDerivedNode(SECP256K1_NAME, NULL, 0, NULL);
  if (!root) return NULL;
  const uint32_t acc_hardened = address_n[3] | 0x80000000u;
  const bool keys_ok =
      hive_deriveRawKey(root, HIVE_ROLE_OWNER, acc_hardened, keys[0]) &&
      hive_deriveRawKey(root, HIVE_ROLE_ACTIVE, acc_hardened, keys[1]) &&
      hive_deriveRawKey(root, HIVE_ROLE_POSTING, acc_hardened, keys[2]) &&
      hive_deriveRawKey(root, HIVE_ROLE_MEMO, acc_hardened, keys[3]);
  memzero(root, sizeof(*root));
  if (!keys_ok) {
    memzero(keys, 4 * 33);
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to derive Hive keys"));
    layoutHome();
    return NULL;
  }

  HDNode* node =
      fsm_getDerivedNode(SECP256K1_NAME, address_n, address_n_count, NULL);
  if (!node) {
    memzero(keys, 4 * 33);
    return NULL;
  }
  hdnode_fill_public_key(node);

  // The device-derived owner key is shown so the user can verify it.
  if (!hive_getPublicKey(keys[0], owner_stm, 64)) {
    memzero(node, sizeof(*node));
    memzero(keys, 4 * 33);
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to encode Hive owner key"));
    layoutHome();
    return NULL;
  }
  return node;
}

static void hive_account_cancel(HDNode* node, uint8_t keys[4][33]) {
  memzero(node, sizeof(*node));
  memzero(keys, 4 * 33);
  fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
  layoutHome();
}

// ── HiveSignAccountCreate ─────────────────────────────────────────────────
// Role keys are device-derived; host-supplied key strings are never signed.

void fsm_msgHiveSignAccountCreate(const HiveSignAccountCreate* msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  if (!hive_validateAccountCreate(msg)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid Hive transaction fields"));
    layoutHome();
    return;
  }

  uint8_t keys[4][33];
  char owner_stm[64];
  HDNode* node = hive_prepare_account_keys(
      msg->address_n, msg->address_n_count, msg->has_chain_id,
      msg->chain_id.bytes, keys, owner_stm);
  if (!node) return;

  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
               "Create Hive Account",
               "Create @%s secured by KeepKey?\n\nAll keys from your device.",
               msg->new_account_name)) {
    hive_account_cancel(node, keys);
    return;
  }

  if (!confirm(ButtonRequestType_ButtonRequest_Other, "Owner Key", "%s",
               owner_stm)) {
    hive_account_cancel(node, keys);
    return;
  }

  char fee_str[32];
  uint64_t fee = msg->has_fee_amount ? msg->fee_amount : 3000;
  snprintf(fee_str, sizeof(fee_str), "%" PRIu64 ".%03" PRIu64 " HIVE",
           fee / 1000, fee % 1000);
  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Creation Fee",
               "Fee: %s paid by @%s", fee_str, msg->creator)) {
    hive_account_cancel(node, keys);
    return;
  }

  RESP_INIT(HiveSignedAccountCreate);
  hive_signAccountCreate(node, msg, keys[0], keys[1], keys[2], keys[3], resp);
  memzero(node, sizeof(*node));
  memzero(keys, sizeof(keys));

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
// New role keys are device-derived; host new_*_key strings are never signed.

void fsm_msgHiveSignAccountUpdate(const HiveSignAccountUpdate* msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  if (!hive_validateAccountUpdate(msg)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid Hive transaction fields"));
    layoutHome();
    return;
  }

  uint8_t keys[4][33];
  char owner_stm[64];
  HDNode* node = hive_prepare_account_keys(
      msg->address_n, msg->address_n_count, msg->has_chain_id,
      msg->chain_id.bytes, keys, owner_stm);
  if (!node) return;

  if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall,
               "Secure Hive Account",
               "Replace ALL keys for @%s with KeepKey keys?\n\nOld keys will "
               "be retired.",
               msg->account)) {
    hive_account_cancel(node, keys);
    return;
  }

  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "New Owner Key", "%s",
               owner_stm)) {
    hive_account_cancel(node, keys);
    return;
  }

  RESP_INIT(HiveSignedAccountUpdate);
  hive_signAccountUpdate(node, msg, keys[0], keys[1], keys[2], keys[3], resp);
  memzero(node, sizeof(*node));
  memzero(keys, sizeof(keys));

  if (!resp->has_signature) {
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Hive account_update signing failed"));
    layoutHome();
    return;
  }

  msg_write(MessageType_MessageType_HiveSignedAccountUpdate, resp);
  layoutHome();
}
