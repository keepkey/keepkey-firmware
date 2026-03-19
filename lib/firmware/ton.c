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

/* ── Cell representation hash helpers for clear-signing ──────────────── */

/**
 * Write a variable-length coins value (VarUInteger 16) into a bit buffer.
 * TON coins encoding: 4-bit length prefix + value bytes (big-endian).
 * Returns number of bits written.
 */
static int write_coins_bits(uint8_t *buf, int bit_offset, uint64_t amount) {
  if (amount == 0) {
    /* 0 coins = 4-bit length of 0 */
    /* bits[offset..offset+3] = 0000 */
    int byte_idx = bit_offset / 8;
    int bit_idx = bit_offset % 8;
    /* Clear 4 bits */
    for (int i = 0; i < 4; i++) {
      int bi = bit_idx + i;
      buf[byte_idx + bi / 8] &= ~(0x80 >> (bi % 8));
    }
    return 4;
  }

  /* Count bytes needed for amount */
  int nbytes = 0;
  uint64_t tmp = amount;
  while (tmp > 0) { nbytes++; tmp >>= 8; }

  /* Write 4-bit length */
  for (int i = 0; i < 4; i++) {
    int b = (nbytes >> (3 - i)) & 1;
    int bi = bit_offset + i;
    if (b)
      buf[bi / 8] |= (0x80 >> (bi % 8));
    else
      buf[bi / 8] &= ~(0x80 >> (bi % 8));
  }

  /* Write amount bytes big-endian */
  int bit_pos = bit_offset + 4;
  for (int i = nbytes - 1; i >= 0; i--) {
    uint8_t byte = (amount >> (i * 8)) & 0xFF;
    for (int j = 0; j < 8; j++) {
      int b = (byte >> (7 - j)) & 1;
      int bi = bit_pos;
      if (b)
        buf[bi / 8] |= (0x80 >> (bi % 8));
      else
        buf[bi / 8] &= ~(0x80 >> (bi % 8));
      bit_pos++;
    }
  }

  return 4 + nbytes * 8;
}

/**
 * Write a single bit at a given offset in a byte buffer.
 */
static void write_bit(uint8_t *buf, int bit_offset, int value) {
  if (value)
    buf[bit_offset / 8] |= (0x80 >> (bit_offset % 8));
  else
    buf[bit_offset / 8] &= ~(0x80 >> (bit_offset % 8));
}

/**
 * Write N bits of a uint32 value (big-endian) at a given offset.
 */
static void write_uint_bits(uint8_t *buf, int bit_offset, uint32_t value, int nbits) {
  for (int i = 0; i < nbits; i++) {
    int b = (value >> (nbits - 1 - i)) & 1;
    write_bit(buf, bit_offset + i, b);
  }
}

/**
 * Write N bits of a uint64 value (big-endian) at a given offset.
 */
static void write_uint64_bits(uint8_t *buf, int bit_offset, uint64_t value, int nbits) {
  for (int i = 0; i < nbits; i++) {
    int b = (value >> (nbits - 1 - i)) & 1;
    write_bit(buf, bit_offset + i, b);
  }
}

/**
 * Compute cell representation hash.
 * repr = d1 || d2 || augmented_data || child_depths(2 bytes each) || child_hashes(32 bytes each)
 * hash = SHA256(repr)
 */
static void cell_repr_hash(int num_refs, int num_bits,
                           const uint8_t *data, int data_bytes,
                           const uint8_t child_depths[][2],
                           const uint8_t child_hashes[][32],
                           uint8_t *out_hash) {
  /* d1 = num_refs */
  /* d2 = ceil(bits/8) + floor(bits/8) */
  uint8_t d1 = (uint8_t)num_refs;
  uint8_t d2 = (uint8_t)(((num_bits + 7) / 8) + (num_bits / 8));

  SHA256_CTX ctx;
  sha256_Init(&ctx);
  sha256_Update(&ctx, &d1, 1);
  sha256_Update(&ctx, &d2, 1);
  sha256_Update(&ctx, data, data_bytes);

  for (int i = 0; i < num_refs; i++) {
    sha256_Update(&ctx, child_depths[i], 2);
  }
  for (int i = 0; i < num_refs; i++) {
    sha256_Update(&ctx, child_hashes[i], 32);
  }

  sha256_Final(&ctx, out_hash);
}

/**
 * Verify a v4r2 transfer body hash by reconstructing it from structured fields.
 */
bool ton_verify_transfer_hash(
    const char *to_address, uint64_t amount,
    uint32_t seqno, uint32_t expire_at, bool bounce,
    const char *memo, size_t memo_len,
    const uint8_t *expected_hash)
{
  /* Step 1: Parse destination address → workchain + hash */
  uint8_t addr_decoded[36];
  int dlen = base64_url_decode(to_address, strlen(to_address),
                                addr_decoded, sizeof(addr_decoded));
  if (dlen != 36) return false;

  int8_t dest_workchain = (int8_t)addr_decoded[1];
  const uint8_t *dest_hash = &addr_decoded[2]; /* 32 bytes */

  /* Step 2: Build memo cell hash (if memo exists) */
  uint8_t memo_cell_hash[32];
  int memo_cell_depth = 0;
  bool has_memo = (memo != NULL && memo_len > 0);

  if (has_memo) {
    /* Memo cell: op(32 bits) = 0x00000000 + UTF-8 bytes */
    int memo_bits = 32 + (int)(memo_len * 8);
    int memo_data_bytes = (memo_bits + 7) / 8;
    /* Add completion tag */
    int augmented_bytes = (memo_bits + 1 + 7) / 8;
    uint8_t memo_data[164]; /* 128 bytes memo + 4 bytes op + padding */
    memset(memo_data, 0, sizeof(memo_data));

    /* op = 0 (32 bits) — already zero */
    /* Copy memo bytes starting at bit 32 */
    for (size_t i = 0; i < memo_len; i++) {
      for (int j = 0; j < 8; j++) {
        int b = (memo[i] >> (7 - j)) & 1;
        write_bit(memo_data, 32 + (int)(i * 8) + j, b);
      }
    }
    /* Add completion tag: 1-bit after data, rest zeros */
    write_bit(memo_data, memo_bits, 1);

    cell_repr_hash(0, memo_bits, memo_data, augmented_bytes,
                   NULL, NULL, memo_cell_hash);
    memo_cell_depth = 0;
  }

  /* Step 3: Build InternalMessage cell */
  /* Layout: tag(1) + ihr_disabled(1) + bounce(1) + bounced(1) + src_none(2) +
   *         dest_addr(3+8+256=267) + coins(4+N*8) + extra_curr(1) +
   *         ihr_fee(4) + fwd_fee(4) + created_lt(64) + created_at(32) +
   *         stateinit(1) + body(1) */
  uint8_t int_msg_data[128];
  memset(int_msg_data, 0, sizeof(int_msg_data));
  int bp = 0;

  write_bit(int_msg_data, bp++, 0);       /* int_msg_info tag = 0 */
  write_bit(int_msg_data, bp++, 1);       /* ihr_disabled = true */
  write_bit(int_msg_data, bp++, bounce ? 1 : 0);
  write_bit(int_msg_data, bp++, 0);       /* bounced = false */

  /* src = addr_none (00) */
  write_bit(int_msg_data, bp++, 0);
  write_bit(int_msg_data, bp++, 0);

  /* dest = addr_std (10 + anycast=0 + workchain(8) + hash(256)) */
  write_bit(int_msg_data, bp++, 1);
  write_bit(int_msg_data, bp++, 0);
  write_bit(int_msg_data, bp++, 0);       /* anycast = 0 */
  write_uint_bits(int_msg_data, bp, (uint32_t)(uint8_t)dest_workchain, 8);
  bp += 8;
  for (int i = 0; i < 32; i++) {
    for (int j = 0; j < 8; j++) {
      write_bit(int_msg_data, bp++, (dest_hash[i] >> (7 - j)) & 1);
    }
  }

  /* value (coins) */
  bp += write_coins_bits(int_msg_data, bp, amount);
  /* extra_currencies = 0 (1 bit) */
  write_bit(int_msg_data, bp++, 0);
  /* ihr_fee = 0 coins */
  bp += write_coins_bits(int_msg_data, bp, 0);
  /* fwd_fee = 0 coins */
  bp += write_coins_bits(int_msg_data, bp, 0);
  /* created_lt = 0 (64 bits) */
  write_uint64_bits(int_msg_data, bp, 0, 64);
  bp += 64;
  /* created_at = 0 (32 bits) */
  write_uint_bits(int_msg_data, bp, 0, 32);
  bp += 32;
  /* no StateInit */
  write_bit(int_msg_data, bp++, 0);

  if (has_memo) {
    write_bit(int_msg_data, bp++, 1);  /* body is ref */
  } else {
    write_bit(int_msg_data, bp++, 0);  /* no body */
  }

  int int_msg_bits = bp;
  int int_msg_augmented_bytes = (int_msg_bits + 1 + 7) / 8;
  /* Add completion tag */
  write_bit(int_msg_data, int_msg_bits, 1);

  /* Compute InternalMessage hash */
  uint8_t int_msg_hash[32];
  int int_msg_num_refs = has_memo ? 1 : 0;

  if (has_memo) {
    uint8_t depths[1][2] = {{0, (uint8_t)memo_cell_depth}};
    uint8_t hashes[1][32];
    memcpy(hashes[0], memo_cell_hash, 32);
    cell_repr_hash(1, int_msg_bits, int_msg_data, int_msg_augmented_bytes,
                   depths, hashes, int_msg_hash);
  } else {
    cell_repr_hash(0, int_msg_bits, int_msg_data, int_msg_augmented_bytes,
                   NULL, NULL, int_msg_hash);
  }

  /* Compute InternalMessage depth */
  int int_msg_depth = has_memo ? 1 : 0;

  /* Step 4: Build UnsignedBody cell */
  /* Layout: wallet_id(32) + expire_at(32) + seqno(32) + op(8) + send_mode(8) = 112 bits
   * 1 ref (InternalMessage) */
  uint8_t body_data[16]; /* 112 bits = 14 bytes + completion tag → 15 bytes max */
  memset(body_data, 0, sizeof(body_data));
  bp = 0;
  write_uint_bits(body_data, bp, V4R2_WALLET_ID, 32); bp += 32;
  write_uint_bits(body_data, bp, expire_at, 32); bp += 32;
  write_uint_bits(body_data, bp, seqno, 32); bp += 32;
  write_uint_bits(body_data, bp, 0, 8); bp += 8;  /* op = 0 (simple send) */
  write_uint_bits(body_data, bp, 3, 8); bp += 8;  /* send_mode = 3 */

  int body_bits = bp; /* 112 */
  int body_augmented_bytes = (body_bits + 1 + 7) / 8; /* 15 */
  write_bit(body_data, body_bits, 1); /* completion tag */

  uint8_t body_hash[32];
  uint8_t body_depths[1][2] = {{0, (uint8_t)(int_msg_depth + 1)}};
  uint8_t body_hashes[1][32];
  memcpy(body_hashes[0], int_msg_hash, 32);

  cell_repr_hash(1, body_bits, body_data, body_augmented_bytes,
                 body_depths, body_hashes, body_hash);

  /* Step 5: Compare */
  return memcmp(body_hash, expected_hash, 32) == 0;
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
