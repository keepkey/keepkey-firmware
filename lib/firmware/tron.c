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

#include "keepkey/firmware/tron.h"

#include "keepkey/crypto/curves.h"
#include "trezor/crypto/base58.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha3.h"

#include <string.h>

#define TRON_ADDRESS_PREFIX 0x41  // Mainnet addresses start with 'T'

/**
 * Generate TRON address from secp256k1 public key
 * TRON uses Keccak256(uncompressed_pubkey) and takes last 20 bytes,
 * then prepends 0x41 and Base58Check encodes it
 */
bool tron_getAddress(const uint8_t public_key[33], char *address,
                     size_t address_len) {
  if (address_len < TRON_ADDRESS_MAX_LEN) {
    return false;
  }

  uint8_t uncompressed_pubkey[65];
  uint8_t hash[32];
  uint8_t addr_bytes[21];

  // Uncompress the public key
  ecdsa_uncompress_pubkey(&secp256k1, public_key, uncompressed_pubkey);

  // Keccak256 hash of uncompressed public key (skip first 0x04 byte)
  keccak_256(uncompressed_pubkey + 1, 64, hash);

  // Take last 20 bytes of hash and prepend TRON prefix byte
  addr_bytes[0] = TRON_ADDRESS_PREFIX;
  memcpy(addr_bytes + 1, hash + 12, 20);

  // Base58Check encode with double SHA256
  if (!base58_encode_check(addr_bytes, 21, HASHER_SHA2D, address,
                           address_len)) {
    return false;
  }

  // Clean up sensitive data
  memzero(uncompressed_pubkey, sizeof(uncompressed_pubkey));
  memzero(hash, sizeof(hash));

  return true;
}

/**
 * Format TRON amount (SUN) for display
 * 1 TRX = 1,000,000 SUN
 */
void tron_formatAmount(char *buf, size_t len, uint64_t amount) {
  bignum256 val;
  bn_read_uint64(amount, &val);
  bn_format(&val, NULL, " TRX", TRON_DECIMALS, 0, false, buf, len);
}

/**
 * Sign a TRON transaction with secp256k1
 */
void tron_signTx(const HDNode *node, const TronSignTx *msg,
                 TronSignedTx *resp) {
  if (!node || !msg || !resp) {
    return;
  }

  // Verify we have raw transaction data
  if (!msg->has_raw_data || msg->raw_data.size == 0) {
    return;
  }

  // Get the curve for secp256k1
  const curve_info *curve = get_curve_by_name(SECP256K1_NAME);
  if (!curve) {
    return;
  }

  // Hash the transaction with SHA256
  uint8_t hash[32];
  sha256_Raw(msg->raw_data.bytes, msg->raw_data.size, hash);

  // Sign with secp256k1 (recoverable signature: 65 bytes including recovery
  // ID)
  uint8_t sig[65];
  uint8_t pby;

  if (ecdsa_sign_digest(&secp256k1, node->private_key, hash, sig, &pby,
                        NULL) != 0) {
    memzero(hash, sizeof(hash));
    return;
  }

  // Convert to recoverable signature format (r + s + recovery_id)
  // The recovery ID allows recovering the public key from the signature
  sig[64] = pby;

  // Copy signature to response (65 bytes)
  resp->has_signature = true;
  resp->signature.size = 65;
  memcpy(resp->signature.bytes, sig, 65);

  // Clean up sensitive data
  memzero(hash, sizeof(hash));
  memzero(sig, sizeof(sig));
}
