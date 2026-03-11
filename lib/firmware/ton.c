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

/**
 * Generate TON address from Ed25519 public key
 * TON uses a specific format with workchain, bounceable/testnet flags, and
 * CRC16
 */
bool ton_get_address(const ed25519_public_key public_key, bool bounceable,
                     bool testnet, int32_t workchain, char *address,
                     size_t address_len, char *raw_address,
                     size_t raw_address_len) {
  if (address_len < TON_ADDRESS_MAX_LEN ||
      raw_address_len < TON_RAW_ADDRESS_MAX_LEN) {
    return false;
  }

  // Hash the public key with SHA256
  uint8_t hash[32];
  sha256_Raw(public_key, 32, hash);

  // Construct address data: [tag][workchain][hash][crc16]
  uint8_t addr_data[36];
  uint8_t tag = 0x11;  // Base tag
  if (bounceable) tag |= 0x11;
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
 * Format TON amount (nanoTON) for display
 * 1 TON = 1,000,000,000 nanoTON
 */
void ton_formatAmount(char *buf, size_t len, uint64_t amount) {
  bignum256 val;
  bn_read_uint64(amount, &val);
  bn_format(&val, NULL, " TON", TON_DECIMALS, 0, false, buf, len);
}

/**
 * Sign a TON transaction with Ed25519
 */
void ton_signTx(const HDNode *node, const TonSignTx *msg, TonSignedTx *resp) {
  if (!node || !msg || !resp) {
    return;
  }

  // Verify we have raw transaction data
  if (!msg->has_raw_tx || msg->raw_tx.size == 0) {
    return;
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
}
