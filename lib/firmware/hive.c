/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
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

#include "keepkey/firmware/hive.h"

#include "trezor/crypto/base58.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"

#include <string.h>
#include <stdint.h>

/*
 * Encode a compressed public key in Hive/Steem format:
 *   "STM" + base58check_ripemd(pubkey_33)
 *
 * This matches the EOS encoding (HASHER_RIPEMD checksum), which Hive inherited
 * from the Graphene framework.
 */
bool hive_getPublicKey(const uint8_t public_key[33], char* out,
                       size_t out_len) {
  const size_t prefix_len = strlen(HIVE_PUBKEY_PREFIX);
  if (out_len < prefix_len + 1) {
    return false;
  }

  strlcpy(out, HIVE_PUBKEY_PREFIX, out_len);

  if (!base58_encode_check(public_key, 33, HASHER_RIPEMD, out + prefix_len,
                           out_len - prefix_len)) {
    return false;
  }

  return true;
}

// ---- Graphene binary serialization helpers ----

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

// Graphene varint (uleb128)
static void append_varint(uint8_t** buf, const uint8_t* end, uint64_t v) {
  do {
    uint8_t b = v & 0x7F;
    v >>= 7;
    if (v) b |= 0x80;
    append_u8(buf, end, b);
  } while (v);
}

// Length-prefixed string (varint length + bytes, no null terminator)
static void append_string(uint8_t** buf, const uint8_t* end, const char* s) {
  size_t len = s ? strlen(s) : 0;
  append_varint(buf, end, len);
  for (size_t i = 0; i < len && *buf < end; i++) {
    append_u8(buf, end, (uint8_t)s[i]);
  }
}

/*
 * Serialize a Hive transfer operation (op type 2) in Graphene binary format.
 *
 * Transaction wire format:
 *   ref_block_num   (uint16 LE)
 *   ref_block_prefix (uint32 LE)
 *   expiration      (uint32 LE)
 *   num_ops         (varint, = 1)
 *   op_type         (varint, = 2 for transfer)
 *   from            (string)
 *   to              (string)
 *   amount          (int64 LE) + precision (uint8) + symbol (7 bytes, padded)
 *   memo            (string)
 *   num_extensions  (varint, = 0)
 */
static size_t hive_serialize_tx(const HiveSignTx* msg, uint8_t* buf,
                                size_t buf_len) {
  uint8_t* p = buf;
  const uint8_t* end = buf + buf_len;

  append_u16_le(&p, end, (uint16_t)(msg->ref_block_num & 0xFFFF));
  append_u32_le(&p, end, msg->ref_block_prefix);
  append_u32_le(&p, end, msg->expiration);

  // 1 operation
  append_varint(&p, end, 1);
  // transfer op type = 2
  append_varint(&p, end, HIVE_OP_TRANSFER);

  append_string(&p, end, msg->has_from ? msg->from : "");
  append_string(&p, end, msg->has_to ? msg->to : "");

  // Asset: int64 amount + uint8 precision + 7-byte symbol (null-padded)
  append_u64_le(&p, end, (uint64_t)msg->amount);
  append_u8(&p, end,
            (uint8_t)(msg->has_decimals ? msg->decimals : HIVE_DECIMALS));
  char sym[7] = {0};
  if (msg->has_asset_symbol) {
    strncpy(sym, msg->asset_symbol, sizeof(sym) - 1);
  } else {
    memcpy(sym, "HIVE", 4);
  }
  for (int i = 0; i < 7 && p < end; i++) {
    append_u8(&p, end, (uint8_t)sym[i]);
  }

  // Memo
  append_string(&p, end, msg->has_memo ? msg->memo : "");

  // 0 extensions
  append_varint(&p, end, 0);

  return (size_t)(p - buf);
}

void hive_signTx(const HDNode* node, const HiveSignTx* msg,
                 HiveSignedTx* resp) {
  // Serialize transaction body
  uint8_t tx_buf[512];
  size_t tx_len = hive_serialize_tx(msg, tx_buf, sizeof(tx_buf));

  // Determine chain ID (use mainnet default if not provided)
  const uint8_t* chain_id;
  uint8_t default_chain_id[32] = HIVE_CHAIN_ID;
  if (msg->has_chain_id && msg->chain_id.size == HIVE_CHAIN_ID_LEN) {
    chain_id = msg->chain_id.bytes;
  } else {
    chain_id = default_chain_id;
  }

  // Digest = SHA256(chain_id || serialized_tx)
  SHA256_CTX sha_ctx;
  sha256_Init(&sha_ctx);
  sha256_Update(&sha_ctx, chain_id, HIVE_CHAIN_ID_LEN);
  sha256_Update(&sha_ctx, tx_buf, tx_len);
  uint8_t digest[32];
  sha256_Final(&sha_ctx, digest);

  // Sign with secp256k1 (recoverable signature)
  uint8_t sig[65];
  uint8_t pby;
  if (ecdsa_sign_digest(&secp256k1, node->private_key, digest, sig + 1, &pby,
                        NULL) != 0) {
    memzero(sig, sizeof(sig));
    return;
  }
  sig[0] = 27 + pby + 4;  // compact signature header byte (compressed key)

  // Fill response
  resp->has_signature = true;
  resp->signature.size = 65;
  memcpy(resp->signature.bytes, sig, 65);

  resp->has_serialized_tx = true;
  resp->serialized_tx.size = tx_len;
  memcpy(resp->serialized_tx.bytes, tx_buf, tx_len);

  memzero(sig, sizeof(sig));
  memzero(digest, sizeof(digest));
}
