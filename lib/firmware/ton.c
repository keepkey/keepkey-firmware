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

#include "keepkey/firmware/ton.h"

#include "trezor/crypto/ed25519-donna/ed25519.h"
#include "trezor/crypto/hasher.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/sha2.h"

#include <stdio.h>
#include <string.h>

// Base64 URL-safe alphabet (RFC 4648)
static const char base64_url_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Encode data to Base64 URL-safe format (without padding)
 */
static bool base64_url_encode(const uint8_t *data, size_t data_len, char *out,
                               size_t out_len) {
  size_t required_len = ((data_len + 2) / 3) * 4;
  if (out_len < required_len + 1) {
    return false;
  }

  size_t i = 0, j = 0;
  while (i < data_len) {
    uint32_t octet_a = i < data_len ? data[i++] : 0;
    uint32_t octet_b = i < data_len ? data[i++] : 0;
    uint32_t octet_c = i < data_len ? data[i++] : 0;

    uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

    out[j++] = base64_url_alphabet[(triple >> 18) & 0x3F];
    out[j++] = base64_url_alphabet[(triple >> 12) & 0x3F];
    out[j++] = base64_url_alphabet[(triple >> 6) & 0x3F];
    out[j++] = base64_url_alphabet[triple & 0x3F];
  }

  // Remove padding for URL-safe variant
  size_t padding = (3 - (data_len % 3)) % 3;
  j -= padding;
  out[j] = '\0';

  return true;
}

/**
 * Compute CRC16-XMODEM checksum for TON address
 */
static uint16_t ton_crc16(const uint8_t *data, size_t len) {
  uint16_t crc = 0;

  for (size_t i = 0; i < len; i++) {
    crc ^= (uint16_t)data[i] << 8;
    for (int j = 0; j < 8; j++) {
      if (crc & 0x8000) {
        crc = (crc << 1) ^ 0x1021;
      } else {
        crc <<= 1;
      }
    }
  }

  return crc;
}

// Well-known v4r2 wallet contract code cell hash (constant)
// Source: https://github.com/ton-blockchain/wallet-contract (WalletV4R2)
static const uint8_t V4R2_CODE_HASH[32] = {
    0xfe, 0xb5, 0xff, 0x68, 0x20, 0xe2, 0xff, 0x0d,
    0x94, 0x83, 0xe7, 0xe0, 0xd6, 0x2c, 0x81, 0x7d,
    0x84, 0x67, 0x89, 0xfb, 0x4a, 0xe5, 0x80, 0xc8,
    0x78, 0x86, 0x6d, 0x95, 0x9d, 0xab, 0xd5, 0xc0};
// Code cell depth in the cell tree
#define V4R2_CODE_DEPTH 7
// Standard v4r2 wallet_id for mainnet workchain 0
#define V4R2_WALLET_ID 698983191u  // 0x29A9A317

/**
 * Compute the v4r2 data cell representation hash.
 * Data cell layout: seqno(32b=0) + wallet_id(32b) + pubkey(256b) + plugins(1b=0)
 * Total: 321 bits, d1=0x00 (no refs), d2=0x51 (floor(321/8)+ceil(321/8)=40+41=81)
 * Augmented data: 40 full bytes + 0x40 (plugin=0, completion=1, pad=000000)
 */
static void ton_data_cell_hash(const uint8_t *public_key, uint8_t *out) {
  // repr = d1(1) + d2(1) + augmented_data(41) = 43 bytes
  uint8_t repr[43];
  repr[0] = 0x00;  // d1: no refs
  repr[1] = 0x51;  // d2: 81 decimal

  // seqno = 0 (4 bytes)
  memset(repr + 2, 0, 4);

  // wallet_id = 698983191 = 0x29A9A317 (4 bytes big-endian)
  repr[6]  = (V4R2_WALLET_ID >> 24) & 0xFF;
  repr[7]  = (V4R2_WALLET_ID >> 16) & 0xFF;
  repr[8]  = (V4R2_WALLET_ID >> 8)  & 0xFF;
  repr[9]  = (V4R2_WALLET_ID)       & 0xFF;

  // public key (32 bytes)
  memcpy(repr + 10, public_key, 32);

  // plugins = 0 (1 bit) + completion tag (1 bit) + padding (6 bits) = 0x40
  repr[42] = 0x40;

  sha256_Raw(repr, 43, out);
}

/**
 * Compute the v4r2 StateInit representation hash.
 * StateInit: split_depth(0) + special(0) + code(1,ref) + data(1,ref) + library(0)
 * Total: 5 bits, d1=0x02 (2 refs), d2=0x01
 * Augmented: 00110 + 100 = 0x34
 * repr = d1 + d2 + data + depth(code) + depth(data) + hash(code) + hash(data)
 */
static void ton_stateinit_hash(const uint8_t *public_key, uint8_t *out) {
  uint8_t data_hash[32];
  ton_data_cell_hash(public_key, data_hash);

  // repr = d1(1) + d2(1) + augmented(1) + code_depth(2) + data_depth(2) +
  //        code_hash(32) + data_hash(32) = 71 bytes
  uint8_t repr[71];
  repr[0] = 0x02;  // d1: 2 refs
  repr[1] = 0x01;  // d2: 1
  repr[2] = 0x34;  // augmented: 00110100

  // code cell depth = 7 (2 bytes big-endian)
  repr[3] = 0x00;
  repr[4] = V4R2_CODE_DEPTH;

  // data cell depth = 0 (no refs)
  repr[5] = 0x00;
  repr[6] = 0x00;

  // code cell hash (32 bytes)
  memcpy(repr + 7, V4R2_CODE_HASH, 32);

  // data cell hash (32 bytes)
  memcpy(repr + 39, data_hash, 32);

  sha256_Raw(repr, 71, out);
  memzero(data_hash, sizeof(data_hash));
}

/**
 * Generate TON v4r2 wallet address from Ed25519 public key.
 * Address = base64url(tag || workchain || sha256(StateInit) || crc16)
 * where StateInit = code_cell(v4r2) + data_cell(seqno=0, walletId, pubkey)
 */
bool ton_get_address(const ed25519_public_key public_key, bool bounceable,
                     bool testnet, int32_t workchain, char *address,
                     size_t address_len, char *raw_address,
                     size_t raw_address_len) {
  if (address_len < TON_ADDRESS_MAX_LEN ||
      raw_address_len < TON_RAW_ADDRESS_MAX_LEN) {
    return false;
  }

  // Compute the v4r2 StateInit representation hash — this IS the address hash
  uint8_t hash[32];
  ton_stateinit_hash(public_key, hash);

  // Construct address data: [tag][workchain][hash][crc16]
  uint8_t addr_data[36];
  uint8_t tag = bounceable ? 0x11 : 0x51;
  if (testnet) tag |= 0x80;

  addr_data[0] = tag;
  addr_data[1] = (uint8_t)workchain;
  memcpy(addr_data + 2, hash, 32);

  // Compute CRC16 checksum
  uint16_t crc = ton_crc16(addr_data, 34);
  addr_data[34] = (crc >> 8) & 0xFF;
  addr_data[35] = crc & 0xFF;

  // Encode to Base64 URL-safe
  if (!base64_url_encode(addr_data, 36, address, address_len)) {
    memzero(hash, sizeof(hash));
    memzero(addr_data, sizeof(addr_data));
    return false;
  }

  // Generate raw address format: workchain:hash_hex
  char hash_hex[65];
  for (int i = 0; i < 32; i++) {
    snprintf(hash_hex + (i * 2), 3, "%02x", hash[i]);
  }
  snprintf(raw_address, raw_address_len, "%ld:%s", (long)workchain, hash_hex);

  // Clean up sensitive data
  memzero(hash, sizeof(hash));
  memzero(addr_data, sizeof(addr_data));

  return true;
}

/**
 * Decode Base64 URL-safe string to bytes.
 * Returns decoded length, or -1 on error.
 */
static int base64_url_decode(const char *in, size_t in_len,
                             uint8_t *out, size_t out_cap) {
  /* Build reverse lookup table */
  int8_t lut[128];
  memset(lut, -1, sizeof(lut));
  for (int i = 0; i < 64; i++) {
    lut[(unsigned char)base64_url_alphabet[i]] = (int8_t)i;
  }

  size_t op = 0;
  uint32_t accum = 0;
  int bits = 0;
  for (size_t i = 0; i < in_len; i++) {
    unsigned char c = (unsigned char)in[i];
    if (c >= 128 || lut[c] < 0) return -1;
    accum = (accum << 6) | (uint32_t)lut[c];
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (op >= out_cap) return -1;
      out[op++] = (uint8_t)((accum >> bits) & 0xFF);
    }
  }
  return (int)op;
}

/**
 * Validate a TON user-friendly address (Base64 URL-safe with CRC16-XMODEM).
 * TON addresses are 48 chars Base64 → 36 bytes = [tag(1) + workchain(1) +
 * hash(32) + crc16(2)].
 */
bool ton_validateAddress(const char *address) {
  if (!address) return false;
  size_t len = strlen(address);
  if (len != 48) return false;

  uint8_t decoded[36];
  int dlen = base64_url_decode(address, len, decoded, sizeof(decoded));
  if (dlen != 36) return false;

  /* Validate tag byte: bounceable=0x11, non-bounceable=0x51,
     testnet variants have 0x80 set */
  uint8_t tag = decoded[0];
  uint8_t base_tag = tag & 0x7F;
  if (base_tag != 0x11 && base_tag != 0x51) return false;

  /* Validate CRC16-XMODEM over first 34 bytes */
  uint16_t expected_crc = ((uint16_t)decoded[34] << 8) | decoded[35];
  uint16_t actual_crc = ton_crc16(decoded, 34);
  if (expected_crc != actual_crc) return false;

  return true;
}

/**
 * Format TON amount (nanoTON) for display
 * 1 TON = 1,000,000,000 nanoTON
 */
void ton_formatAmount(char *buf, size_t len, uint64_t amount) {
  bignum256 val;
  bn_read_uint64(amount, &val);
  bn_format(&val, NULL, " TON", TON_DECIMALS, 0, false, buf, len);
}

// ── Bit-level writer for cell construction ──────────────────────────

typedef struct {
  uint8_t buf[256]; // max 2048 bits
  uint16_t len;     // bits written
} BitWriter;

static void bw_init(BitWriter *w) {
  memset(w->buf, 0, sizeof(w->buf));
  w->len = 0;
}

static void bw_write_bit(BitWriter *w, bool v) {
  if (v) w->buf[w->len >> 3] |= (0x80 >> (w->len & 7));
  w->len++;
}

static void bw_write_uint(BitWriter *w, uint64_t value, int bits) {
  for (int i = bits - 1; i >= 0; i--) {
    bw_write_bit(w, (value >> i) & 1);
  }
}

static void bw_write_bytes(BitWriter *w, const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) bw_write_uint(w, data[i], 8);
}

static void bw_write_coins(BitWriter *w, uint64_t amount) {
  if (amount == 0) { bw_write_uint(w, 0, 4); return; }
  int byte_len = 0;
  uint64_t v = amount;
  while (v > 0) { byte_len++; v >>= 8; }
  bw_write_uint(w, byte_len, 4);
  for (int i = byte_len - 1; i >= 0; i--) {
    bw_write_uint(w, (amount >> (i * 8)) & 0xFF, 8);
  }
}

/** Compute cell representation hash: SHA256(d1 || d2 || data [|| ref_depths || ref_hashes]) */
static void cell_hash(const BitWriter *bits, const uint8_t ref_hashes[][32],
                       const uint16_t *ref_depths, int ref_count, uint8_t *out) {
  uint8_t d1 = (uint8_t)ref_count;
  uint8_t d2 = (uint8_t)((bits->len + 7) / 8 + bits->len / 8);

  uint8_t aug_data[256];
  size_t aug_len = (bits->len + 7) / 8;
  memcpy(aug_data, bits->buf, aug_len);
  if (bits->len % 8 != 0) {
    aug_data[aug_len - 1] |= (0x80 >> (bits->len & 7));
  }

  SHA256_CTX ctx;
  sha256_Init(&ctx);
  sha256_Update(&ctx, &d1, 1);
  sha256_Update(&ctx, &d2, 1);
  sha256_Update(&ctx, aug_data, aug_len);

  for (int i = 0; i < ref_count; i++) {
    uint8_t depth_be[2] = { (ref_depths[i] >> 8) & 0xFF, ref_depths[i] & 0xFF };
    sha256_Update(&ctx, depth_be, 2);
  }
  for (int i = 0; i < ref_count; i++) {
    sha256_Update(&ctx, ref_hashes[i], 32);
  }
  sha256_Final(&ctx, out);
}

// ── Base64 URL-safe decode ──────────────────────────────────────────

/**
 * Parse a TON user-friendly address → workchain + 32-byte hash.
 * Uses the base64_url_decode() already defined above.
 */
static bool ton_parse_address(const char *address, int8_t *workchain, uint8_t *hash) {
  if (!address) return false;
  size_t addr_len = strlen(address);
  if (addr_len != 48) return false;

  uint8_t raw[36];
  int dlen = base64_url_decode(address, addr_len, raw, sizeof(raw));
  if (dlen != 36) return false;

  uint16_t expected_crc = ((uint16_t)raw[34] << 8) | raw[35];
  uint16_t actual_crc = ton_crc16(raw, 34);
  if (expected_crc != actual_crc) return false;

  *workchain = (int8_t)raw[1];
  memcpy(hash, raw + 2, 32);
  return true;
}

/**
 * Verify a v4r2 transfer body hash by reconstructing it from structured fields.
 * Reproduces the exact same cell tree as the host-side buildUnsignedBody().
 */
bool ton_verify_transfer_hash(
    const char *to_address, uint64_t amount,
    uint32_t seqno, uint32_t expire_at, bool bounce,
    const char *memo, size_t memo_len,
    const uint8_t *expected_hash) {

  // Parse destination address
  int8_t dest_wc;
  uint8_t dest_hash[32];
  if (!ton_parse_address(to_address, &dest_wc, dest_hash)) return false;

  // ── Build memo body cell (if present) ────────────────────────────
  uint8_t memo_cell_hash[32];
  uint16_t memo_cell_depth = 0;
  bool has_memo = (memo != NULL && memo_len > 0);

  if (has_memo) {
    BitWriter memo_bits;
    bw_init(&memo_bits);
    bw_write_uint(&memo_bits, 0, 32); // op = 0 (text comment)
    bw_write_bytes(&memo_bits, (const uint8_t *)memo, memo_len);
    cell_hash(&memo_bits, NULL, NULL, 0, memo_cell_hash);
  }

  // ── Build internal message cell ──────────────────────────────────
  BitWriter im_bits;
  bw_init(&im_bits);

  bw_write_bit(&im_bits, false);  // int_msg_info tag = 0
  bw_write_bit(&im_bits, true);   // ihr_disabled
  bw_write_bit(&im_bits, bounce); // bounce
  bw_write_bit(&im_bits, false);  // bounced
  bw_write_uint(&im_bits, 0, 2);  // src = addr_none

  // dest = addr_std$10 + no anycast + workchain(8) + hash(256)
  bw_write_uint(&im_bits, 2, 2);  // addr_std tag
  bw_write_bit(&im_bits, false);  // no anycast
  bw_write_uint(&im_bits, (uint8_t)dest_wc, 8);
  bw_write_bytes(&im_bits, dest_hash, 32);

  bw_write_coins(&im_bits, amount);
  bw_write_bit(&im_bits, false);  // no extra_currencies
  bw_write_coins(&im_bits, 0);    // ihr_fee = 0
  bw_write_coins(&im_bits, 0);    // fwd_fee = 0
  bw_write_uint(&im_bits, 0, 64); // created_lt = 0
  bw_write_uint(&im_bits, 0, 32); // created_at = 0
  bw_write_bit(&im_bits, false);  // no StateInit

  if (has_memo) {
    bw_write_bit(&im_bits, true); // body is ref
  } else {
    bw_write_bit(&im_bits, false); // no body
  }

  uint8_t im_hash[32];
  uint16_t im_depth;

  if (has_memo) {
    uint8_t ref_hashes[1][32];
    memcpy(ref_hashes[0], memo_cell_hash, 32);
    uint16_t ref_depths[1] = { memo_cell_depth };
    cell_hash(&im_bits, ref_hashes, ref_depths, 1, im_hash);
    im_depth = 1 + memo_cell_depth;
  } else {
    cell_hash(&im_bits, NULL, NULL, 0, im_hash);
    im_depth = 0;
  }

  // ── Build unsigned body cell ─────────────────────────────────────
  BitWriter ub_bits;
  bw_init(&ub_bits);

  bw_write_uint(&ub_bits, V4R2_WALLET_ID, 32); // wallet_id
  bw_write_uint(&ub_bits, expire_at, 32);       // valid_until
  bw_write_uint(&ub_bits, seqno, 32);           // seqno
  bw_write_uint(&ub_bits, 0, 8);                // op = 0 (simple send)
  bw_write_uint(&ub_bits, 3, 8);                // send_mode = 3

  uint8_t ub_hash[32];
  {
    uint8_t ref_hashes[1][32];
    memcpy(ref_hashes[0], im_hash, 32);
    uint16_t ref_depths[1] = { im_depth };
    cell_hash(&ub_bits, ref_hashes, ref_depths, 1, ub_hash);
  }

  // ── Compare with expected hash ───────────────────────────────────
  bool match = (memcmp(ub_hash, expected_hash, 32) == 0);

  // Clean up
  memzero(&im_bits, sizeof(im_bits));
  memzero(&ub_bits, sizeof(ub_bits));

  return match;
}

/**
 * Sign a TON transaction with Ed25519
 */
bool ton_signTx(const HDNode *node, const TonSignTx *msg, TonSignedTx *resp) {
  if (!node || !msg || !resp) {
    return false;
  }

  // Verify we have raw transaction data
  if (!msg->has_raw_tx || msg->raw_tx.size == 0) {
    return false;
  }

  // Ed25519 sign the transaction
  ed25519_signature signature;
  ed25519_sign(msg->raw_tx.bytes, msg->raw_tx.size, node->private_key,
               &node->public_key[1], signature);

  // Copy signature to response (64 bytes)
  resp->has_signature = true;
  resp->signature.size = 64;
  memcpy(resp->signature.bytes, signature, 64);

  // Zero out the signature buffer for security
  memzero(signature, sizeof(signature));

  return true;
}
