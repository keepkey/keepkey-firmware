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

  if (!hive_slip48_path_valid(msg->address_n, msg->address_n_count)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid Hive SLIP-0048 path"));
    layoutHome();
    return;
  }

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
    // Label the key by the role in the ACTUAL derivation path
    // (m/48'/13'/role'/account'/0'), never the host-supplied msg->role,
    // which could mislabel the exported key.
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

// ── SLIP-0048 path validation ─────────────────────────────────────────────
// All three sign handlers enforce the full path shape before anything is
// derived or signed: m/48'/13'/role'/account'/0' (all 5 components hardened),
// with the role pinned to the one the operation needs on-chain:
//   transfer       -> active' (post-HF28 hived no longer accepts higher-role
//                    substitution, and the cold owner key must not be spent)
//   create/update  -> owner'  (the attestation contract: the sponsor verifies
//                    the signature recovers to the device OWNER key, and
//                    account_update replaces the owner authority itself)
// Rejecting arbitrary host paths means a compromised host can never make the
// device produce a Hive signature with a key from another coin's derivation
// tree, nor with the wrong role's key.

static bool hive_slip48_path_ok(const uint32_t* address_n, uint32_t count,
                                uint32_t required_role) {
  return hive_slip48_path_valid_for_role(address_n, count, required_role);
}

static bool hive_confirm_slice(ButtonRequestType type, const char* title,
                               const uint8_t* s, uint16_t len);

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

  if (!hive_slip48_path_ok(msg->address_n, msg->address_n_count,
                           HIVE_ROLE_ACTIVE)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid Hive SLIP-0048 path (transfer needs active')"));
    layoutHome();
    return;
  }

  // Reject over-long memos up front with a specific error; the serializer's
  // own bounds check would otherwise surface as a generic signing failure.
  if (msg->has_memo && strlen(msg->memo) > HIVE_MAX_MEMO_LEN) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Hive memo too long (max 440 bytes)"));
    layoutHome();
    return;
  }

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  // Display precision MUST match the precision the serializer signs
  // (append_asset uses msg->decimals), otherwise the user approves an
  // amount that differs from what is signed. Reject implausible precision.
  uint8_t prec = msg->has_decimals ? (uint8_t)msg->decimals : HIVE_DECIMALS;
  if (prec > 18) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid Hive asset precision"));
    layoutHome();
    return;
  }
  const char* symbol = msg->has_asset_symbol ? msg->asset_symbol : "HIVE";
  char suffix[sizeof(msg->asset_symbol) + 2];  // leading space + symbol + NUL
  snprintf(suffix, sizeof(suffix), " %s", symbol);
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
    if (!hive_confirm_slice(ButtonRequestType_ButtonRequest_ConfirmMemo, "Memo",
                            (const uint8_t*)msg->memo,
                            (uint16_t)strlen(msg->memo))) {
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

typedef struct {
  uint8_t owner[33];
  uint8_t active[33];
  uint8_t posting[33];
  uint8_t memo[33];
} HiveRoleKeys;

static bool hive_prepare_account_sign(const uint32_t* address_n,
                                      uint32_t address_n_count,
                                      HiveRoleKeys* keys, HDNode** node_out,
                                      char* owner_stm, size_t owner_stm_len) {
  if (!hive_slip48_path_ok(address_n, address_n_count, HIVE_ROLE_OWNER)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid Hive SLIP-0048 path (needs owner')"));
    layoutHome();
    return false;
  }
  uint32_t account_index = address_n[3] & 0x7FFFFFFFu;

  // Derive all four role keys from the device root.
  // Do this BEFORE fetching the signing node so the root static buffer
  // is not clobbered by the second fsm_getDerivedNode call.
  const HDNode* root = fsm_getDerivedNode(SECP256K1_NAME, NULL, 0, NULL);
  if (!root) return false;

  uint32_t acc_hardened = account_index | 0x80000000u;
  bool keys_ok =
      hive_deriveRawKey(root, HIVE_ROLE_OWNER, acc_hardened, keys->owner) &&
      hive_deriveRawKey(root, HIVE_ROLE_ACTIVE, acc_hardened, keys->active) &&
      hive_deriveRawKey(root, HIVE_ROLE_POSTING, acc_hardened, keys->posting) &&
      hive_deriveRawKey(root, HIVE_ROLE_MEMO, acc_hardened, keys->memo);
  // root static buffer is done with; signing node derivation may overwrite it.

  if (!keys_ok) {
    memzero(keys, sizeof(*keys));
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to derive Hive keys"));
    layoutHome();
    return false;
  }

  // Now get the signing node (owner key, overwrites root static buffer).
  HDNode* node =
      fsm_getDerivedNode(SECP256K1_NAME, address_n, address_n_count, NULL);
  if (!node) {
    memzero(keys, sizeof(*keys));
    return false;
  }
  hdnode_fill_public_key(node);

  // Encode the device-derived owner key for display confirmation.
  if (!hive_getPublicKey(keys->owner, owner_stm, owner_stm_len)) {
    memzero(node, sizeof(*node));
    memzero(keys, sizeof(*keys));
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to encode Hive owner key"));
    layoutHome();
    return false;
  }

  *node_out = node;
  return true;
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

  HiveRoleKeys keys;
  HDNode* node = NULL;
  char owner_stm[64];
  if (!hive_prepare_account_sign(msg->address_n, msg->address_n_count, &keys,
                                 &node, owner_stm, sizeof(owner_stm))) {
    return;
  }

  // Primary confirmation: show the new username prominently.
  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
               "Create Hive Account",
               "Create @%s secured by KeepKey?\n\nAll keys from your device.",
               msg->new_account_name)) {
    memzero(node, sizeof(*node));
    memzero(&keys, sizeof(keys));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  // Secondary confirmation: show device-derived owner key so user can verify.
  if (!confirm(ButtonRequestType_ButtonRequest_Other, "Owner Key", "%s",
               owner_stm)) {
    memzero(node, sizeof(*node));
    memzero(&keys, sizeof(keys));
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
    memzero(&keys, sizeof(keys));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  hive_signAccountCreate(node, msg, keys.owner, keys.active, keys.posting,
                         keys.memo, resp);
  memzero(node, sizeof(*node));
  memzero(&keys, sizeof(keys));

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

  HiveRoleKeys keys;
  HDNode* node = NULL;
  char owner_stm[64];
  if (!hive_prepare_account_sign(msg->address_n, msg->address_n_count, &keys,
                                 &node, owner_stm, sizeof(owner_stm))) {
    return;
  }

  // Warning: this replaces all existing keys.
  if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall,
               "Secure Hive Account",
               "Replace ALL keys for @%s with KeepKey keys?\n\nOld keys will "
               "be retired.",
               msg->account)) {
    memzero(node, sizeof(*node));
    memzero(&keys, sizeof(keys));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  // Show device-derived owner key so user can verify it's their device.
  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "New Owner Key", "%s",
               owner_stm)) {
    memzero(node, sizeof(*node));
    memzero(&keys, sizeof(keys));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  hive_signAccountUpdate(node, msg, keys.owner, keys.active, keys.posting,
                         keys.memo, resp);
  memzero(node, sizeof(*node));
  memzero(&keys, sizeof(keys));

  if (!resp->has_signature) {
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Hive account_update signing failed"));
    layoutHome();
    return;
  }

  msg_write(MessageType_MessageType_HiveSignedAccountUpdate, resp);
  layoutHome();
}

// ── HiveSignMessage (Keychain signBuffer) ─────────────────────────────────
// The Hive dApp login primitive: Aioha / Keychain-SDK dApps authenticate by
// having the account sign a challenge string, then recover the pubkey and
// check it against the account's authority on-chain. Contract (hive-js
// Signature.signBuffer): sig over SHA256(raw message bytes) — no chain_id,
// no prefix. Roles: posting/active/memo, Keychain's requestSignBuffer
// surface. owner' is deliberately rejected — no consumer offers it, and the
// cold owner key must not be normalized into dApp flows. The full path
// shape is still enforced like the tx handlers.

static bool hive_slip48_message_path_ok(const uint32_t* address_n,
                                        uint32_t count,
                                        const char** role_label) {
  if (!hive_slip48_path_valid(address_n, count)) return false;
  switch (address_n[2]) {
    case HIVE_ROLE_ACTIVE:
      *role_label = "active";
      return true;
    case HIVE_ROLE_MEMO:
      *role_label = "memo";
      return true;
    case HIVE_ROLE_POSTING:
      *role_label = "posting";
      return true;
    default:
      return false;
  }
}

void fsm_msgHiveSignMessage(const HiveSignMessage* msg) {
  RESP_INIT(HiveSignedMessage);

  CHECK_INITIALIZED
  CHECK_PIN

  if (!msg->has_message || msg->message.size == 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Missing message"));
    layoutHome();
    return;
  }

  // Mirrors the proto max_size cap so proto and code can never disagree
  // (the memo-length lesson from the transfer handler).
  if (msg->message.size > HIVE_MAX_MESSAGE_LEN) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Hive message too long (max 1024 bytes)"));
    layoutHome();
    return;
  }

  // A Hive TRANSACTION digest is SHA256(chain_id || tx), and this message
  // digest is SHA256(message) — so a "message" that begins with the mainnet
  // chain-id bytes would hash to a broadcastable transaction's digest. No
  // legitimate challenge starts with the chain id; refuse the collision.
  const uint8_t hive_chain_id[HIVE_CHAIN_ID_LEN] = HIVE_CHAIN_ID;
  if (msg->message.size >= HIVE_CHAIN_ID_LEN &&
      memcmp(msg->message.bytes, hive_chain_id, HIVE_CHAIN_ID_LEN) == 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Message must not start with the Hive chain ID"));
    layoutHome();
    return;
  }

  const char* role_label = NULL;
  if (!hive_slip48_message_path_ok(msg->address_n, msg->address_n_count,
                                   &role_label)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid Hive SLIP-0048 path"));
    layoutHome();
    return;
  }

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  // Domain-separate messages from transactions. A Hive TRANSACTION digest is
  // SHA256(chain_id || serialized_tx), where the 32-byte chain_id and the
  // serialized Graphene fields (ref_block_prefix, expiration, ...) are BINARY.
  // Constraining signable messages to printable ASCII puts them in a domain
  // disjoint from every transaction preimage — for ANY chain id, not just
  // mainnet — so a binary "message" equal to C || serialized_tx can no longer
  // be signed into a valid transaction signature on a fork chain C. This is the
  // real fix; the mainnet-only prefix reject above is a belt-and-suspenders
  // subset of it. hive-js signBuffer signs printable challenges, so nothing
  // legitimate is lost. (A prefix blacklist could never be complete because the
  // host chooses the chain id; a printable-only whitelist is complete by
  // construction against binary preimages.)
  if (!hive_message_is_printable(msg->message.bytes, msg->message.size)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Hive messages must be printable text"));
    layoutHome();
    return;
  }

  // Page the FULL message (72-char ASCII pages) so no trailing content is ever
  // truncated behind a benign-looking prefix, and name the signing key.
  if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, "Sign Hive Message",
               "Signing with %s key", role_label) ||
      !hive_confirm_slice(ButtonRequestType_ButtonRequest_ProtectCall,
                          "Hive Message", msg->message.bytes,
                          (uint16_t)msg->message.size)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  hive_signMessage(node, msg, resp);
  memzero(node, sizeof(*node));

  if (!resp->has_signature) {
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Hive message signing failed"));
    layoutHome();
    return;
  }

  msg_write(MessageType_MessageType_HiveSignedMessage, resp);
  layoutHome();
}

// ── HiveSignOperations (parsed generic op signing) ────────────────────────
// The host serializes the transaction; firmware parses the Graphene bytes,
// clear-signs the ops it recognizes (vote, comment, custom_json), and
// refuses everything else — no blind-sign fallback. Everything shown on the
// OLED is re-derived from the bytes being signed, so a host serializer bug
// can only produce a node rejection, never a silent wrong-sign.

// Dedicated path validator: {posting', active'} ONLY, pinned to the tx tier.
// Do NOT fold into hive_slip48_message_path_ok — that one deliberately
// accepts memo' (a legitimate signBuffer target), but no Graphene operation
// uses memo authority; a memo-path vote must be refused here, not
// discovered at the chain. owner' is likewise excluded.
static bool hive_slip48_ops_path_ok(const uint32_t* address_n, uint32_t count,
                                    bool needs_active) {
  return hive_slip48_path_valid_for_role(
      address_n, count, needs_active ? HIVE_ROLE_ACTIVE : HIVE_ROLE_POSTING);
}

// User-controlled string fields are paged in full. Printable fields are shown
// as text; fields containing non-ASCII bytes are shown as complete hex rather
// than a short preview. Page boundaries are selected with the same font and
// word-wrapping calculation used by draw_string(), so no signed suffix can be
// pushed below the OLED's three visible body rows.

static bool hive_slice_is_ascii(const uint8_t* s, uint16_t len) {
  bool ascii = true;
  for (uint16_t i = 0; i < len; i++) {
    if (s[i] < 0x20 || s[i] > 0x7e) {
      ascii = false;
      break;
    }
  }
  return ascii;
}

static uint16_t hive_rendered_page_len(const uint8_t* s, uint16_t len,
                                       bool ascii) {
  if (len == 0) return 0;

  if (ascii) {
    size_t candidate = len;
    if (candidate >= BODY_CHAR_MAX) candidate = BODY_CHAR_MAX - 1;
    return (uint16_t)calc_str_page(get_body_font(), (const char*)s, candidate,
                                   BODY_WIDTH, BODY_ROWS);
  }

  uint16_t candidate = len;
  if (candidate > (BODY_CHAR_MAX - 1) / 2) candidate = (BODY_CHAR_MAX - 1) / 2;
  char rendered[BODY_CHAR_MAX];
  for (uint16_t i = 0; i < candidate; i++) {
    snprintf(rendered + 2 * i, 3, "%02x", s[i]);
  }
  size_t chars = calc_str_page(get_body_font(), rendered, 2 * candidate,
                               BODY_WIDTH, BODY_ROWS);
  return (uint16_t)(chars / 2);
}

static bool hive_confirm_slice(ButtonRequestType type, const char* title,
                               const uint8_t* s, uint16_t len) {
  if (len == 0) return confirm(type, title, "(empty)");

  bool ascii = hive_slice_is_ascii(s, len);
  uint16_t pages = 0;
  uint16_t offset = 0;
  while (offset < len) {
    uint16_t take = hive_rendered_page_len(s + offset, len - offset, ascii);
    if (take == 0) return false;
    offset = (uint16_t)(offset + take);
    pages++;
  }

  offset = 0;
  for (uint16_t page = 0; page < pages; page++) {
    uint16_t take = hive_rendered_page_len(s + offset, len - offset, ascii);
    if (take == 0) return false;

    char page_title[TITLE_CHAR_MAX];
    if (pages > 1 || !ascii) {
      snprintf(page_title, sizeof(page_title),
               ascii ? "%s %u/%u" : "%s Hex %u/%u", title, (unsigned)(page + 1),
               (unsigned)pages);
    } else {
      strlcpy(page_title, title, sizeof(page_title));
    }

    if (ascii) {
      char rendered[BODY_CHAR_MAX];
      memcpy(rendered, s + offset, take);
      rendered[take] = '\0';
      if (!confirm(type, page_title, "%s", rendered)) return false;
    } else {
      char rendered[BODY_CHAR_MAX];
      for (uint16_t i = 0; i < take; i++) {
        snprintf(rendered + 2 * i, 3, "%02x", s[offset + i]);
      }
      if (!confirm(type, page_title, "%s", rendered)) return false;
    }
    offset = (uint16_t)(offset + take);
  }
  return true;
}

// "1.234 HIVE" — precision comes from the asset bytes being signed, which
// the parser has already pinned to the symbol's protocol-fixed value.
static void hive_format_asset(const uint8_t* a, char* out, size_t out_len) {
  char suffix[9];  // space + longest symbol ("VESTS") + NUL
  snprintf(suffix, sizeof(suffix), " %s", hive_assetSymbol(a));
  bn_format_uint64(hive_assetAmount(a), NULL, suffix, hive_assetPrecision(a), 0,
                   false, out, out_len);
}

// Basis points (0..10000) as "12.34%".
static void hive_format_percent(int16_t bp, char* out, size_t out_len) {
  snprintf(out, out_len, "%d.%02d%%", bp / 100, bp % 100);
}

static void hive_copy_slice(char* out, size_t out_len, const uint8_t* s,
                            uint16_t len) {
  if (out_len == 0) return;
  size_t take = len;
  if (take >= out_len) take = out_len - 1;
  memcpy(out, s, take);
  out[take] = '\0';
}

void fsm_msgHiveSignOperations(const HiveSignOperations* msg) {
  RESP_INIT(HiveSignedOperations);

  CHECK_INITIALIZED
  CHECK_PIN

  if (!msg->has_serialized_tx || msg->serialized_tx.size == 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Missing serialized transaction"));
    layoutHome();
    return;
  }

  static HiveParsedTx parsed;  // slices borrow from the static msg buffer
  const char* parse_err = hive_parseOperations(
      msg->serialized_tx.bytes, msg->serialized_tx.size, &parsed);
  if (parse_err) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _(parse_err));
    layoutHome();
    return;
  }

  if (!hive_slip48_ops_path_ok(msg->address_n, msg->address_n_count,
                               parsed.needs_active)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    parsed.needs_active
                        ? _("Invalid Hive SLIP-0048 path (needs active')")
                        : _("Invalid Hive SLIP-0048 path (needs posting')"));
    layoutHome();
    return;
  }

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  // Confirm operation summaries and payloads, then show a final sign prompt.
  for (uint8_t i = 0; i < parsed.num_ops; i++) {
    const HiveTxOp* op = &parsed.ops[i];
    char name[17];  // hive account names are <= 16 chars, length-validated
    hive_copy_slice(name, sizeof(name), op->acct, op->acct_len);

    bool approved = false;
    switch (op->op_type) {
      case HIVE_OP_VOTE: {
        char target[17];
        hive_copy_slice(target, sizeof(target), op->target, op->target_len);
        int w = op->weight < 0 ? -op->weight : op->weight;
        approved =
            confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                    op->weight < 0 ? "Downvote" : "Vote",
                    "@%s -> @%s at %d.%02d%%", name, target, w / 100, w % 100);
        if (approved) {
          approved =
              hive_confirm_slice(ButtonRequestType_ButtonRequest_ConfirmOutput,
                                 "Vote Target", op->detail, op->detail_len);
        }
        break;
      }
      case HIVE_OP_COMMENT: {
        char parent[17];
        hive_copy_slice(parent, sizeof(parent), op->parent_author,
                        op->parent_author_len);
        approved =
            op->is_top_level
                ? confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Post",
                          "Create post by @%s?", name)
                : confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                          "Comment", "Reply by @%s to @%s?", name, parent);
        if (approved) {
          approved = hive_confirm_slice(
              ButtonRequestType_ButtonRequest_ConfirmOutput,
              op->is_top_level ? "Post Category" : "Reply Target",
              op->parent_permlink, op->parent_permlink_len);
        }
        if (approved) {
          approved = hive_confirm_slice(
              ButtonRequestType_ButtonRequest_ConfirmOutput, "Post Permlink",
              op->permlink, op->permlink_len);
        }
        if (approved && op->target_len > 0) {
          approved =
              hive_confirm_slice(ButtonRequestType_ButtonRequest_ConfirmOutput,
                                 "Post Title", op->target, op->target_len);
        }
        if (approved) {
          approved =
              hive_confirm_slice(ButtonRequestType_ButtonRequest_ConfirmOutput,
                                 "Post Body", op->detail, op->detail_len);
        }
        if (approved && op->json_metadata_len > 0) {
          approved = hive_confirm_slice(
              ButtonRequestType_ButtonRequest_ConfirmOutput, "Post Metadata",
              op->json_metadata, op->json_metadata_len);
        }
        break;
      }
      case HIVE_OP_CUSTOM_JSON: {
        approved = true;
        for (uint8_t a = 0; approved && a < op->n_auths; a++) {
          char auth_name[17];
          hive_copy_slice(auth_name, sizeof(auth_name), op->auth_acct[a],
                          op->auth_acct_len[a]);
          approved = confirm(
              ButtonRequestType_ButtonRequest_ConfirmOutput, "Custom JSON Auth",
              "%u/%u: @%s\n%s key", (unsigned)(a + 1), (unsigned)op->n_auths,
              auth_name, op->needs_active ? "Active" : "Posting");
        }
        if (approved) {
          approved =
              hive_confirm_slice(ButtonRequestType_ButtonRequest_ConfirmOutput,
                                 "Custom JSON ID", op->target, op->target_len);
        }
        if (approved) {
          approved =
              hive_confirm_slice(ButtonRequestType_ButtonRequest_ConfirmOutput,
                                 "Custom JSON", op->detail, op->detail_len);
        }
        break;
      }
      case HIVE_OP_TRANSFER_TO_VESTING: {
        char amount[40], target[17];
        hive_format_asset(op->assets[0], amount, sizeof(amount));
        hive_copy_slice(target, sizeof(target), op->target, op->target_len);
        approved =
            op->target_len == 0
                ? confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                          "Power Up", "Power up\n%s\nto @%s", amount, name)
                : confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                          "Power Up", "%s\nfrom @%s\nto @%s", amount, name,
                          target);
        break;
      }
      case HIVE_OP_WITHDRAW_VESTING: {
        char amount[40];
        hive_format_asset(op->assets[0], amount, sizeof(amount));
        approved =
            hive_assetAmount(op->assets[0]) == 0
                ? confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                          "Stop Power Down", "Cancel power down\nfor @%s", name)
                : confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                          "Power Down", "Power down\n%s\nfrom @%s", amount,
                          name);
        break;
      }
      case HIVE_OP_LIMIT_ORDER_CREATE: {
        char sell[40], receive[40];
        hive_format_asset(op->assets[0], sell, sizeof(sell));
        hive_format_asset(op->assets[1], receive, sizeof(receive));
        approved = confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           "Market Order", "@%s sells\n%s\nfor >= %s", name,
                           sell, receive);
        if (approved) {
          // Order id and fill_or_kill decide whether an unfilled order rests
          // on the book or is discarded, so they get their own screen rather
          // than being crowded off the first one.
          approved = confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                             "Order Terms", "Order #%u\n%s\nExpires %u",
                             (unsigned)op->req_id,
                             op->flag ? "Fill or kill" : "Rests on book",
                             (unsigned)op->expiration);
        }
        break;
      }
      case HIVE_OP_LIMIT_ORDER_CANCEL:
        approved = confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           "Cancel Order", "Cancel order #%u\nfor @%s?",
                           (unsigned)op->req_id, name);
        break;
      case HIVE_OP_CONVERT: {
        char amount[40];
        hive_format_asset(op->assets[0], amount, sizeof(amount));
        approved = confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           "Convert", "Convert %s\nto HIVE for @%s\n(#%u)",
                           amount, name, (unsigned)op->req_id);
        break;
      }
      case HIVE_OP_COMMENT_OPTIONS: {
        char max_payout[40], percent[16];
        hive_format_asset(op->assets[0], max_payout, sizeof(max_payout));
        hive_format_percent(op->weight, percent, sizeof(percent));
        approved = confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           "Payout Options", "@%s\nMax %s\nHBD split %s", name,
                           max_payout, percent);
        if (approved) {
          approved = confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                             "Payout Options", "Votes: %s\nCuration: %s",
                             op->flag ? "allowed" : "disabled",
                             op->flag2 ? "allowed" : "disabled");
        }
        // Beneficiaries divert payout to other accounts — each one is
        // confirmed individually rather than summarized as a count.
        for (uint8_t b = 0; approved && b < op->n_benef; b++) {
          char benef[17], benef_pct[16];
          hive_copy_slice(benef, sizeof(benef), op->benef_acct[b],
                          op->benef_acct_len[b]);
          hive_format_percent((int16_t)op->benef_weight[b], benef_pct,
                              sizeof(benef_pct));
          approved = confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                             "Payout Beneficiary", "%u/%u: @%s\ngets %s",
                             (unsigned)(b + 1), (unsigned)op->n_benef, benef,
                             benef_pct);
        }
        if (approved) {
          approved = hive_confirm_slice(
              ButtonRequestType_ButtonRequest_ConfirmOutput, "Payout Permlink",
              op->permlink, op->permlink_len);
        }
        break;
      }
      case HIVE_OP_TRANSFER_TO_SAVINGS:
      case HIVE_OP_TRANSFER_FROM_SAVINGS: {
        char amount[40], target[17];
        bool deposit = (op->op_type == HIVE_OP_TRANSFER_TO_SAVINGS);
        hive_format_asset(op->assets[0], amount, sizeof(amount));
        hive_copy_slice(target, sizeof(target), op->target, op->target_len);
        // One variable per row. A 16-character account name sharing a row
        // with a label can wrap into a fourth row, which the display drops
        // silently — and here that row carries the destination account.
        // req_id is deliberately not shown: it is a cancellation handle, not
        // a fund-routing field, and crowding it in costs the destination row.
        approved = confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           deposit ? "Savings Deposit" : "Savings Withdraw",
                           "%s\nfrom @%s\nto @%s", amount, name, target);
        if (approved && op->detail_len > 0) {
          approved =
              hive_confirm_slice(ButtonRequestType_ButtonRequest_ConfirmOutput,
                                 "Savings Memo", op->detail, op->detail_len);
        }
        break;
      }
      case HIVE_OP_CLAIM_REWARD_BALANCE: {
        char hive_amt[40], hbd_amt[40], vests_amt[40];
        hive_format_asset(op->assets[0], hive_amt, sizeof(hive_amt));
        hive_format_asset(op->assets[1], hbd_amt, sizeof(hbd_amt));
        hive_format_asset(op->assets[2], vests_amt, sizeof(vests_amt));
        // Three assets plus the account name cannot share one screen: the
        // OLED body fits exactly three rows (layout.c places rows at y =
        // 24/38/52 and draw_char_with_shift silently drops any glyph past
        // y+height > 64), so a fourth row would be signed but never shown.
        approved = confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           "Claim Rewards", "@%s claims\n%s\n%s", name,
                           hive_amt, hbd_amt);
        if (approved) {
          approved =
              confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                      "Claim Rewards", "@%s claims\n%s", name, vests_amt);
        }
        break;
      }
      case HIVE_OP_DELEGATE_VESTING_SHARES: {
        char amount[40], target[17];
        hive_format_asset(op->assets[0], amount, sizeof(amount));
        hive_copy_slice(target, sizeof(target), op->target, op->target_len);
        approved =
            hive_assetAmount(op->assets[0]) == 0
                ? confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                          "Remove Delegation",
                          "@%s removes its\ndelegation to @%s?", name, target)
                : confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                          "Delegate", "@%s delegates\n%s\nto @%s", name, amount,
                          target);
        break;
      }
      case HIVE_OP_ACCOUNT_UPDATE2:
        approved = confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           "Profile Update", "Update profile\nof @%s?", name);
        if (approved && op->detail_len > 0) {
          approved = hive_confirm_slice(
              ButtonRequestType_ButtonRequest_ConfirmOutput, "Account Metadata",
              op->detail, op->detail_len);
        }
        if (approved && op->json_metadata_len > 0) {
          approved = hive_confirm_slice(
              ButtonRequestType_ButtonRequest_ConfirmOutput, "Profile Metadata",
              op->json_metadata, op->json_metadata_len);
        }
        break;
      default:
        break;  // unreachable — parser rejected unknown ops
    }
    if (!approved) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Sign Transaction",
               "Sign %u Hive operation%s with the %s key?",
               (unsigned)parsed.num_ops, parsed.num_ops == 1 ? "" : "s",
               parsed.needs_active ? "active" : "posting")) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  hive_signOperations(node, msg, resp);
  memzero(node, sizeof(*node));

  if (!resp->has_signature) {
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Hive operation signing failed"));
    layoutHome();
    return;
  }

  msg_write(MessageType_MessageType_HiveSignedOperations, resp);
  layoutHome();
}
