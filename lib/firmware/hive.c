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

#include "keepkey/firmware/hive.h"
#include "keepkey/firmware/eos.h"

#include "trezor/crypto/base58.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"

#include <string.h>
#include <stdint.h>

// ── STM public key encoding ───────────────────────────────────────────────

bool hive_getPublicKey(const uint8_t public_key[33], char* out,
                       size_t out_len) {
  const size_t prefix_len = strlen(HIVE_PUBKEY_PREFIX);
  if (out_len < prefix_len + 1) return false;
  strlcpy(out, HIVE_PUBKEY_PREFIX, out_len);
  // Graphene uses RIPEMD checksum (not SHA256d) for public key encoding
  return base58_encode_check(public_key, 33, HASHER_RIPEMD, out + prefix_len,
                             out_len - prefix_len);
}

// Path: m/48'/13'/role_hardened/account_index_hardened/0'

bool hive_deriveRawKey(const HDNode* root, uint32_t role_hardened,
                       uint32_t account_index_hardened, uint8_t out[33]) {
  /* The contract is a Hive role key: refuse any other role or a
   * non-hardened account index rather than derive an unrelated path. */
  if (role_hardened != HIVE_ROLE_OWNER && role_hardened != HIVE_ROLE_ACTIVE &&
      role_hardened != HIVE_ROLE_MEMO && role_hardened != HIVE_ROLE_POSTING) {
    return false;
  }
  if ((account_index_hardened & 0x80000000u) == 0) return false;
  HDNode node;
  memcpy(&node, root, sizeof(HDNode));
  if (!hdnode_private_ckd(&node, HIVE_SLIP48_PURPOSE)) goto fail;
  if (!hdnode_private_ckd(&node, HIVE_SLIP48_NETWORK)) goto fail;
  if (!hdnode_private_ckd(&node, role_hardened)) goto fail;
  if (!hdnode_private_ckd(&node, account_index_hardened)) goto fail;
  if (!hdnode_private_ckd(&node, 0x80000000u)) goto fail;
  hdnode_fill_public_key(&node);
  memcpy(out, node.public_key, 33);
  memzero(&node, sizeof(node));
  return true;
fail:
  memzero(&node, sizeof(node));
  return false;
}

bool hive_getPublicKeys(const HDNode* root, uint32_t account_index,
                        char* owner_out, size_t owner_len, char* active_out,
                        size_t active_len, char* memo_out, size_t memo_len,
                        char* posting_out, size_t posting_len) {
  const uint32_t roles[4] = {
      HIVE_ROLE_OWNER,
      HIVE_ROLE_ACTIVE,
      HIVE_ROLE_MEMO,
      HIVE_ROLE_POSTING,
  };
  char* outs[4] = {owner_out, active_out, memo_out, posting_out};
  const size_t lens[4] = {owner_len, active_len, memo_len, posting_len};

  // Bit 31 is the hardening flag; accepting it would alias a lower account.
  if (account_index > 0x7FFFFFFFu) return false;
  uint32_t account_hardened = account_index | 0x80000000u;

  for (int i = 0; i < 4; i++) {
    uint8_t raw[33];
    if (!hive_deriveRawKey(root, roles[i], account_hardened, raw)) return false;
    if (!hive_getPublicKey(raw, outs[i], lens[i])) {
      memzero(raw, sizeof(raw));
      return false;
    }
    memzero(raw, sizeof(raw));
  }
  return true;
}

// ── Graphene binary serialization helpers ─────────────────────────────────

static void append_u8(uint8_t** buf, const uint8_t* end, uint8_t v) {
  if (*buf < end) {
    **buf = v;
    (*buf)++;
  }
}

static void append_u16_le(uint8_t** buf, const uint8_t* end, uint16_t v) {
  append_u8(buf, end, v & 0xFF);
  append_u8(buf, end, (v >> 8) & 0xFF);
}

static void append_u32_le(uint8_t** buf, const uint8_t* end, uint32_t v) {
  append_u8(buf, end, v & 0xFF);
  append_u8(buf, end, (v >> 8) & 0xFF);
  append_u8(buf, end, (v >> 16) & 0xFF);
  append_u8(buf, end, (v >> 24) & 0xFF);
}

static void append_u64_le(uint8_t** buf, const uint8_t* end, uint64_t v) {
  for (int i = 0; i < 8; i++) {
    append_u8(buf, end, v & 0xFF);
    v >>= 8;
  }
}

static void append_varint(uint8_t** buf, const uint8_t* end, uint64_t v) {
  do {
    uint8_t b = v & 0x7F;
    v >>= 7;
    if (v) b |= 0x80;
    append_u8(buf, end, b);
  } while (v);
}

static void append_string(uint8_t** buf, const uint8_t* end, const char* s) {
  size_t len = s ? strlen(s) : 0;
  append_varint(buf, end, len);
  for (size_t i = 0; i < len && *buf < end; i++)
    append_u8(buf, end, (uint8_t)s[i]);
}

/* Graphene asset: int64 LE amount + uint8 precision + 7-byte symbol */
static void append_asset(uint8_t** buf, const uint8_t* end, uint64_t amount,
                         uint8_t precision, const char* symbol) {
  append_u64_le(buf, end, amount);
  append_u8(buf, end, precision);
  char sym[7] = {0};
  if (symbol) strncpy(sym, symbol, 6);
  for (int i = 0; i < 7 && *buf < end; i++)
    append_u8(buf, end, (uint8_t)sym[i]);
}

/* Graphene authority: threshold u32=1, account_auths varint=0, key_auths
 * varint=1, 33-byte key (NO type prefix), weight u16=1. */
static void append_authority(uint8_t** buf, const uint8_t* end,
                             const uint8_t pubkey[33]) {
  append_u32_le(buf, end, 1);  // weight_threshold = 1
  append_varint(buf, end, 0);  // 0 account auths
  append_varint(buf, end, 1);  // 1 key auth
  for (int i = 0; i < 33 && *buf < end; i++) append_u8(buf, end, pubkey[i]);
  append_u16_le(buf, end, 1);  // weight = 1
}

/* ref_block_num, ref_block_prefix, expiration, op count 1, op type. */
static void append_tx_header(uint8_t** buf, const uint8_t* end,
                             uint16_t ref_block_num, uint32_t ref_block_prefix,
                             uint32_t expiration, uint32_t op_type) {
  append_u16_le(buf, end, ref_block_num);
  append_u32_le(buf, end, ref_block_prefix);
  append_u32_le(buf, end, expiration);
  append_varint(buf, end, 1);  // 1 operation
  append_varint(buf, end, op_type);
}

static void append_tx_footer(uint8_t** buf, const uint8_t* end) {
  append_varint(buf, end, 0);  // 0 extensions
}

/* 65-byte recoverable sig over SHA256(chain_id || serialized_tx); hived
 * rejects non-canonical sigs as EOS does, so retry until canonical. */
static bool hive_sign_digest(const HDNode* node, const uint8_t* chain_id,
                             const uint8_t* tx_buf, size_t tx_len,
                             uint8_t sig[65]) {
  SHA256_CTX sha;
  sha256_Init(&sha);
  sha256_Update(&sha, chain_id, HIVE_CHAIN_ID_LEN);
  sha256_Update(&sha, tx_buf, tx_len);
  uint8_t digest[32];
  sha256_Final(&sha, digest);

  uint8_t pby;
  if (ecdsa_sign_digest(&secp256k1, node->private_key, digest, sig + 1, &pby,
                        eos_is_canonic) != 0) {
    memzero(digest, sizeof(digest));
    return false;
  }
  // Compact signature header: 27 + recovery_id + 4 (compressed key flag)
  sig[0] = 27 + pby + 4;
  memzero(digest, sizeof(digest));
  return true;
}

/* Shared tail of every Hive signer: sign chain_id (mainnet when absent) ||
 * tx, fill the response's signature + serialized tx, wipe the buffers. */
static void hive_sign_finish(const HDNode* node, bool has_chain_id,
                             const uint8_t* chain_id_in, uint8_t tx_buf[512],
                             size_t tx_len, bool* has_sig, pb_size_t* sig_size,
                             uint8_t sig_out[65], bool* has_tx,
                             pb_size_t* tx_size, uint8_t* tx_out) {
  const uint8_t default_chain_id[32] = HIVE_CHAIN_ID;
  const uint8_t* chain_id = has_chain_id ? chain_id_in : default_chain_id;

  uint8_t sig[65];
  if (hive_sign_digest(node, chain_id, tx_buf, tx_len, sig)) {
    *has_sig = true;
    *sig_size = 65;
    memcpy(sig_out, sig, 65);
    *has_tx = true;
    *tx_size = (pb_size_t)tx_len;
    memcpy(tx_out, tx_buf, tx_len);
  }
  memzero(sig, sizeof(sig));
  memzero(tx_buf, 512);
}

// ── Transfer (op type 2) ──────────────────────────────────────────────────

// Resolve the requested asset symbol to the symbol signed on the wire, the
// symbol shown at consent and its precision. Returns false for any symbol the
// device does not sign.
bool hive_transferAsset(const HiveSignTx* msg, const char** wire,
                        const char** display, uint8_t* precision) {
  const char* symbol = msg->has_asset_symbol ? msg->asset_symbol : "HIVE";

  if (strcmp(symbol, "HIVE") == 0 ||
      strcmp(symbol, HIVE_WIRE_SYMBOL_HIVE) == 0) {
    *wire = HIVE_WIRE_SYMBOL_HIVE;
    *display = "HIVE";
  } else if (strcmp(symbol, "HBD") == 0 ||
             strcmp(symbol, HIVE_WIRE_SYMBOL_HBD) == 0) {
    *wire = HIVE_WIRE_SYMBOL_HBD;
    *display = "HBD";
  } else {
    return false;
  }

  if (msg->has_decimals && msg->decimals != HIVE_DECIMALS) return false;
  *precision = HIVE_DECIMALS;
  return true;
}

// Account labels are rendered verbatim. Accept Hive's bounded lowercase DNS
// labels only: each dot-separated component starts with a letter, ends with a
// letter/digit and has at least three characters.
static bool hive_account_name_ok(const char* name) {
  size_t length = strnlen(name, HIVE_MAX_ACCOUNT_LEN + 1);
  if (length < 3 || length > HIVE_MAX_ACCOUNT_LEN) return false;
  size_t component = 0;
  for (size_t i = 0; i <= length; ++i) {
    const char c = name[i];
    if (c == '.' || c == '\0') {
      if (component < 3 || name[i - 1] == '-') return false;
      component = 0;
      continue;
    }
    const bool letter = c >= 'a' && c <= 'z';
    const bool digit = c >= '0' && c <= '9';
    if ((!letter && !digit && c != '-') || (component == 0 && !letter))
      return false;
    ++component;
  }
  return true;
}

/* TaPoS references a 16-bit block number. A wider host value is refused,
 * never silently masked to a different block. */
static bool hive_ref_block_num_ok(uint32_t ref_block_num) {
  return ref_block_num <= 0xFFFF;
}

bool hive_validateTransfer(const HiveSignTx* msg) {
  const char *wire, *display;
  uint8_t precision;
  return msg->has_from && msg->has_to && msg->has_amount &&
         msg->has_ref_block_num && hive_ref_block_num_ok(msg->ref_block_num) &&
         msg->has_ref_block_prefix && msg->has_expiration &&
         hive_account_name_ok(msg->from) && hive_account_name_ok(msg->to) &&
         msg->amount > 0 && msg->amount <= INT64_MAX &&
         (!msg->has_chain_id || msg->chain_id.size == HIVE_CHAIN_ID_LEN) &&
         (!msg->has_memo ||
          strnlen(msg->memo, sizeof(msg->memo)) <= HIVE_MAX_MEMO_LEN) &&
         hive_transferAsset(msg, &wire, &display, &precision);
}

bool hive_validateAccountCreate(const HiveSignAccountCreate* msg) {
  return msg->has_creator && msg->has_new_account_name &&
         msg->has_ref_block_num && hive_ref_block_num_ok(msg->ref_block_num) &&
         msg->has_ref_block_prefix && msg->has_expiration &&
         hive_account_name_ok(msg->creator) &&
         hive_account_name_ok(msg->new_account_name) &&
         (!msg->has_fee_amount || msg->fee_amount <= INT64_MAX) &&
         (!msg->has_chain_id || msg->chain_id.size == HIVE_CHAIN_ID_LEN);
}

bool hive_validateAccountUpdate(const HiveSignAccountUpdate* msg) {
  return msg->has_account && msg->has_ref_block_num &&
         hive_ref_block_num_ok(msg->ref_block_num) &&
         msg->has_ref_block_prefix && msg->has_expiration &&
         hive_account_name_ok(msg->account) &&
         (!msg->has_chain_id || msg->chain_id.size == HIVE_CHAIN_ID_LEN);
}

static size_t hive_serialize_transfer(const HiveSignTx* msg, uint8_t* buf,
                                      size_t buf_len) {
  const char* wire_symbol;
  const char* display_symbol;
  uint8_t precision;
  if (!hive_transferAsset(msg, &wire_symbol, &display_symbol, &precision)) {
    return 0;
  }
  (void)display_symbol;

  uint8_t* p = buf;
  const uint8_t* end = buf + buf_len;

  append_tx_header(&p, end, (uint16_t)(msg->ref_block_num & 0xFFFF),
                   msg->ref_block_prefix, msg->expiration, HIVE_OP_TRANSFER);

  append_string(&p, end, msg->has_from ? msg->from : "");
  append_string(&p, end, msg->has_to ? msg->to : "");

  append_asset(&p, end, msg->amount, precision, wire_symbol);

  append_string(&p, end, msg->has_memo ? msg->memo : "");
  append_tx_footer(&p, end);
  return (size_t)(p - buf);
}

void hive_signTx(const HDNode* node, const HiveSignTx* msg,
                 HiveSignedTx* resp) {
  if (!hive_validateTransfer(msg)) return;

  uint8_t tx_buf[512];
  size_t tx_len = hive_serialize_transfer(msg, tx_buf, sizeof(tx_buf));
  if (tx_len == 0) return;

  hive_sign_finish(node, msg->has_chain_id, msg->chain_id.bytes, tx_buf, tx_len,
                   &resp->has_signature, &resp->signature.size,
                   resp->signature.bytes, &resp->has_serialized_tx,
                   &resp->serialized_tx.size, resp->serialized_tx.bytes);
}

// Account create (op 9): all role keys are device-derived; host-supplied key
// strings are never signed.

static size_t hive_serialize_account_create(const HiveSignAccountCreate* msg,
                                            const uint8_t owner_raw[33],
                                            const uint8_t active_raw[33],
                                            const uint8_t posting_raw[33],
                                            const uint8_t memo_raw[33],
                                            uint8_t* buf, size_t buf_len) {
  uint8_t* p = buf;
  const uint8_t* end = buf + buf_len;

  append_tx_header(&p, end, (uint16_t)(msg->ref_block_num & 0xFFFF),
                   msg->ref_block_prefix, msg->expiration,
                   HIVE_OP_ACCOUNT_CREATE);

  uint64_t fee = msg->has_fee_amount ? msg->fee_amount : 3000;
  append_asset(&p, end, fee, HIVE_DECIMALS, HIVE_WIRE_SYMBOL_HIVE);

  append_string(&p, end, msg->has_creator ? msg->creator : "");

  append_string(&p, end,
                msg->has_new_account_name ? msg->new_account_name : "");

  append_authority(&p, end, owner_raw);
  append_authority(&p, end, active_raw);
  append_authority(&p, end, posting_raw);

  // memo_key: 33 raw bytes, no authority wrapper, no type prefix byte
  for (int i = 0; i < 33 && p < end; i++) append_u8(&p, end, memo_raw[i]);

  append_string(&p, end, "");
  append_tx_footer(&p, end);

  return (size_t)(p - buf);
}

void hive_signAccountCreate(const HDNode* signing_node,
                            const HiveSignAccountCreate* msg,
                            const uint8_t owner_raw[33],
                            const uint8_t active_raw[33],
                            const uint8_t posting_raw[33],
                            const uint8_t memo_raw[33],
                            HiveSignedAccountCreate* resp) {
  if (!hive_validateAccountCreate(msg)) return;

  uint8_t tx_buf[512];
  size_t tx_len =
      hive_serialize_account_create(msg, owner_raw, active_raw, posting_raw,
                                    memo_raw, tx_buf, sizeof(tx_buf));

  hive_sign_finish(signing_node, msg->has_chain_id, msg->chain_id.bytes, tx_buf,
                   tx_len, &resp->has_signature, &resp->signature.size,
                   resp->signature.bytes, &resp->has_serialized_tx,
                   &resp->serialized_tx.size, resp->serialized_tx.bytes);
}

// Account update (op 10): device-derived keys; new_*_key fields are ignored.

static size_t hive_serialize_account_update(const HiveSignAccountUpdate* msg,
                                            const uint8_t owner_raw[33],
                                            const uint8_t active_raw[33],
                                            const uint8_t posting_raw[33],
                                            const uint8_t memo_raw[33],
                                            uint8_t* buf, size_t buf_len) {
  uint8_t* p = buf;
  const uint8_t* end = buf + buf_len;

  append_tx_header(&p, end, (uint16_t)(msg->ref_block_num & 0xFFFF),
                   msg->ref_block_prefix, msg->expiration,
                   HIVE_OP_ACCOUNT_UPDATE);

  append_string(&p, end, msg->has_account ? msg->account : "");

  /* Optional wrapper (0x01 + authority); all are present and replaced. */
  append_u8(&p, end, 0x01);  // owner present
  append_authority(&p, end, owner_raw);
  append_u8(&p, end, 0x01);  // active present
  append_authority(&p, end, active_raw);
  append_u8(&p, end, 0x01);  // posting present
  append_authority(&p, end, posting_raw);

  // memo_key: 33 raw bytes, always present, no type prefix byte
  for (int i = 0; i < 33 && p < end; i++) append_u8(&p, end, memo_raw[i]);

  append_string(&p, end, "");
  append_tx_footer(&p, end);

  return (size_t)(p - buf);
}

void hive_signAccountUpdate(const HDNode* signing_node,
                            const HiveSignAccountUpdate* msg,
                            const uint8_t owner_raw[33],
                            const uint8_t active_raw[33],
                            const uint8_t posting_raw[33],
                            const uint8_t memo_raw[33],
                            HiveSignedAccountUpdate* resp) {
  if (!hive_validateAccountUpdate(msg)) return;

  uint8_t tx_buf[512];
  size_t tx_len =
      hive_serialize_account_update(msg, owner_raw, active_raw, posting_raw,
                                    memo_raw, tx_buf, sizeof(tx_buf));

  hive_sign_finish(signing_node, msg->has_chain_id, msg->chain_id.bytes, tx_buf,
                   tx_len, &resp->has_signature, &resp->signature.size,
                   resp->signature.bytes, &resp->has_serialized_tx,
                   &resp->serialized_tx.size, resp->serialized_tx.bytes);
}
