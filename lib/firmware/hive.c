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

// ── Single-role key derivation to raw 33 bytes ────────────────────────────
// Path: m/48'/13'/role_hardened/account_index_hardened/0'
// hdnode_private_ckd() returns 1 on success, 0 on failure.

bool hive_deriveRawKey(const HDNode* root, uint32_t role_hardened,
                       uint32_t account_index_hardened, uint8_t out[33]) {
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

// ── SLIP-0048 multi-role key derivation ───────────────────────────────────

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

/*
 * Graphene asset encoding: int64 LE amount + uint8 precision + 7-byte symbol
 */
static void append_asset(uint8_t** buf, const uint8_t* end, uint64_t amount,
                         uint8_t precision, const char* symbol) {
  append_u64_le(buf, end, amount);
  append_u8(buf, end, precision);
  char sym[7] = {0};
  if (symbol) strncpy(sym, symbol, 6);
  for (int i = 0; i < 7 && *buf < end; i++)
    append_u8(buf, end, (uint8_t)sym[i]);
}

/*
 * Graphene authority structure (Hive wire format):
 *   weight_threshold (uint32 LE) = 1
 *   num_account_auths (varint)   = 0
 *   num_key_auths (varint)       = 1
 *     compressed public key      (33 bytes, no type prefix)
 *     weight (uint16 LE)         = 1
 *
 * Note: Hive does NOT use a key-type prefix byte before the 33 raw bytes.
 */
static void append_authority(uint8_t** buf, const uint8_t* end,
                             const uint8_t pubkey[33]) {
  append_u32_le(buf, end, 1);  // weight_threshold = 1
  append_varint(buf, end, 0);  // 0 account auths
  append_varint(buf, end, 1);  // 1 key auth
  for (int i = 0; i < 33 && *buf < end; i++) append_u8(buf, end, pubkey[i]);
  append_u16_le(buf, end, 1);  // weight = 1
}

/*
 * Common transaction header: ref_block_num, ref_block_prefix, expiration,
 * then a varint op count = 1, then the op type varint.
 */
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

/*
 * Sign helper: SHA256(chain_id || serialized_tx) → secp256k1 recoverable sig.
 * Writes 65 bytes into sig[]. Returns true on success.
 */
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
                        NULL) != 0) {
    memzero(digest, sizeof(digest));
    return false;
  }
  // Compact signature header: 27 + recovery_id + 4 (compressed key flag)
  sig[0] = 27 + pby + 4;
  memzero(digest, sizeof(digest));
  return true;
}

// ── Transfer (op type 2) ──────────────────────────────────────────────────

// Maximum memo length that fits safely in tx_buf[512] with all other fields.
// Non-memo overhead: header(12) + from(17) + to(17) + asset(16) + footer(1) =
// ~63 bytes. 512 - 63 - 3 (varint) = 446; use 440 as the conservative limit.
#define HIVE_MAX_MEMO_LEN 440

static size_t hive_serialize_transfer(const HiveSignTx* msg, uint8_t* buf,
                                      size_t buf_len) {
  uint8_t* p = buf;
  const uint8_t* end = buf + buf_len;

  append_tx_header(&p, end, (uint16_t)(msg->ref_block_num & 0xFFFF),
                   msg->ref_block_prefix, msg->expiration, HIVE_OP_TRANSFER);

  append_string(&p, end, msg->has_from ? msg->from : "");
  append_string(&p, end, msg->has_to ? msg->to : "");

  const char* sym = msg->has_asset_symbol ? msg->asset_symbol : "HIVE";
  uint8_t prec = (uint8_t)(msg->has_decimals ? msg->decimals : HIVE_DECIMALS);
  append_asset(&p, end, msg->amount, prec, sym);

  append_string(&p, end, msg->has_memo ? msg->memo : "");
  append_tx_footer(&p, end);
  return (size_t)(p - buf);
}

void hive_signTx(const HDNode* node, const HiveSignTx* msg,
                 HiveSignedTx* resp) {
  // Reject memos that would overflow the fixed-size tx_buf.
  if (msg->has_memo && strlen(msg->memo) > HIVE_MAX_MEMO_LEN) return;

  uint8_t tx_buf[512];
  size_t tx_len = hive_serialize_transfer(msg, tx_buf, sizeof(tx_buf));

  const uint8_t default_chain_id[32] = HIVE_CHAIN_ID;
  const uint8_t* chain_id =
      (msg->has_chain_id && msg->chain_id.size == HIVE_CHAIN_ID_LEN)
          ? msg->chain_id.bytes
          : default_chain_id;

  uint8_t sig[65];
  if (!hive_sign_digest(node, chain_id, tx_buf, tx_len, sig)) {
    memzero(sig, sizeof(sig));
    return;
  }

  resp->has_signature = true;
  resp->signature.size = 65;
  memcpy(resp->signature.bytes, sig, 65);

  resp->has_serialized_tx = true;
  resp->serialized_tx.size = tx_len;
  memcpy(resp->serialized_tx.bytes, tx_buf, tx_len);

  memzero(sig, sizeof(sig));
  memzero(tx_buf, tx_len);
}

// ── Account create (op type 9) ────────────────────────────────────────────
//
// All four role keys are device-derived by the caller (FSM handler) and
// passed as raw 33-byte compressed public keys. The firmware never uses
// host-supplied key strings for the actual transaction.

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

  // fee (asset)
  uint64_t fee = msg->has_fee_amount ? msg->fee_amount : 3000;
  append_asset(&p, end, fee, HIVE_DECIMALS, "HIVE");

  // creator
  append_string(&p, end, msg->has_creator ? msg->creator : "");

  // new_account_name
  append_string(&p, end,
                msg->has_new_account_name ? msg->new_account_name : "");

  // authority fields use device-derived raw bytes (no host trust, no type
  // prefix)
  append_authority(&p, end, owner_raw);
  append_authority(&p, end, active_raw);
  append_authority(&p, end, posting_raw);

  // memo_key: 33 raw bytes, no authority wrapper, no type prefix byte
  for (int i = 0; i < 33 && p < end; i++) append_u8(&p, end, memo_raw[i]);

  // json_metadata (empty)
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
  uint8_t tx_buf[512];
  size_t tx_len =
      hive_serialize_account_create(msg, owner_raw, active_raw, posting_raw,
                                    memo_raw, tx_buf, sizeof(tx_buf));

  const uint8_t default_chain_id[32] = HIVE_CHAIN_ID;
  const uint8_t* chain_id =
      (msg->has_chain_id && msg->chain_id.size == HIVE_CHAIN_ID_LEN)
          ? msg->chain_id.bytes
          : default_chain_id;

  uint8_t sig[65];
  if (!hive_sign_digest(signing_node, chain_id, tx_buf, tx_len, sig)) {
    memzero(sig, sizeof(sig));
    memzero(tx_buf, sizeof(tx_buf));
    return;
  }

  resp->has_signature = true;
  resp->signature.size = 65;
  memcpy(resp->signature.bytes, sig, 65);

  resp->has_serialized_tx = true;
  resp->serialized_tx.size = tx_len;
  memcpy(resp->serialized_tx.bytes, tx_buf, tx_len);

  memzero(sig, sizeof(sig));
  memzero(tx_buf, tx_len);
}

// ── Account update (op type 10) ───────────────────────────────────────────
//
// All four new role keys are device-derived by the caller (FSM handler).
// The host-supplied new_*_key fields in the message are not used for signing.

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

  // account name
  append_string(&p, end, msg->has_account ? msg->account : "");

  /*
   * account_update optional authority fields use a Graphene "optional" wrapper:
   *   present: 0x01 + authority bytes
   *   absent:  0x00
   * We always include all four — this replaces all authorities.
   */
  append_u8(&p, end, 0x01);  // owner present
  append_authority(&p, end, owner_raw);
  append_u8(&p, end, 0x01);  // active present
  append_authority(&p, end, active_raw);
  append_u8(&p, end, 0x01);  // posting present
  append_authority(&p, end, posting_raw);

  // memo_key: 33 raw bytes, always present, no type prefix byte
  for (int i = 0; i < 33 && p < end; i++) append_u8(&p, end, memo_raw[i]);

  // json_metadata (empty)
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
  uint8_t tx_buf[512];
  size_t tx_len =
      hive_serialize_account_update(msg, owner_raw, active_raw, posting_raw,
                                    memo_raw, tx_buf, sizeof(tx_buf));

  const uint8_t default_chain_id[32] = HIVE_CHAIN_ID;
  const uint8_t* chain_id =
      (msg->has_chain_id && msg->chain_id.size == HIVE_CHAIN_ID_LEN)
          ? msg->chain_id.bytes
          : default_chain_id;

  uint8_t sig[65];
  if (!hive_sign_digest(signing_node, chain_id, tx_buf, tx_len, sig)) {
    memzero(sig, sizeof(sig));
    memzero(tx_buf, sizeof(tx_buf));
    return;
  }

  resp->has_signature = true;
  resp->signature.size = 65;
  memcpy(resp->signature.bytes, sig, 65);

  resp->has_serialized_tx = true;
  resp->serialized_tx.size = tx_len;
  memcpy(resp->serialized_tx.bytes, tx_buf, tx_len);

  memzero(sig, sizeof(sig));
  memzero(tx_buf, tx_len);
}
