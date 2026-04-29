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
bool tron_getAddress(const uint8_t public_key[33], char* address,
                     size_t address_len) {
  if (address_len < TRON_ADDRESS_MAX_LEN) {
    return false;
  }

  uint8_t uncompressed_pubkey[65];
  uint8_t hash[32];
  uint8_t addr_bytes[21];

  // Uncompress the public key
  if (!ecdsa_uncompress_pubkey(&secp256k1, public_key, uncompressed_pubkey)) {
    return false;
  }

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
void tron_formatAmount(char* buf, size_t len, uint64_t amount) {
  bignum256 val;
  bn_read_uint64(amount, &val);
  bn_format(&val, NULL, " TRX", TRON_DECIMALS, 0, false, buf, len);
}

/**
 * Sign a TRON transaction with secp256k1
 */
bool tron_signTx(const HDNode* node, const TronSignTx* msg,
                 TronSignedTx* resp) {
  if (!node || !msg || !resp) {
    return false;
  }

  // Verify we have raw transaction data
  if (!msg->has_raw_data || msg->raw_data.size == 0) {
    return false;
  }

  // Get the curve for secp256k1
  const curve_info* curve = get_curve_by_name(SECP256K1_NAME);
  if (!curve) {
    return false;
  }

  // Hash the transaction with SHA256
  uint8_t hash[32];
  sha256_Raw(msg->raw_data.bytes, msg->raw_data.size, hash);

  // Sign with secp256k1 (recoverable signature: 65 bytes including recovery
  // ID)
  uint8_t sig[65];
  uint8_t pby;

  if (ecdsa_sign_digest(&secp256k1, node->private_key, hash, sig, &pby, NULL) !=
      0) {
    memzero(hash, sizeof(hash));
    return false;
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

  return true;
}

static int tron_is_canonic_typed(uint8_t v, uint8_t signature[64]) {
  // Mirror ethereum_is_canonic: accept recovery IDs 0/1, reject 2/3.
  // Returning non-zero = "canonical, accept"; zero = "retry".
  (void)signature;
  return (v & 2) == 0;
}

/**
 * Compute the TIP-712 typed-data digest:
 *   keccak256("\x19\x01" || domain_separator_hash || message_hash)
 *
 * If the typed-data primaryType is the EIP712Domain itself, message_hash
 * is empty/absent and the digest folds in only the domain separator.
 *
 * Mirrors ethereum_typed_hash() — TIP-712 uses the same '\x19\x01' prefix
 * as EIP-712.
 */
static void tron_typed_hash(const uint8_t domain_separator_hash[32],
                            const uint8_t message_hash[32],
                            bool has_message_hash, uint8_t hash[32]) {
  struct SHA3_CTX ctx = {0};
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, (const uint8_t*)"\x19\x01", 2);
  sha3_Update(&ctx, domain_separator_hash, 32);
  if (has_message_hash) {
    sha3_Update(&ctx, message_hash, 32);
  }
  keccak_Final(&ctx, hash);
}

/**
 * Sign a TIP-712 typed-data digest. Host pre-computes the domain
 * separator hash and message hash per the TIP-712 spec; the device just
 * signs the assembled digest with secp256k1 + recovery id.
 *
 * Caller must have populated node->public_key (hdnode_fill_public_key).
 */
bool tron_typed_hash_sign(const HDNode* node, const TronSignTypedHash* msg,
                          TronTypedDataSignature* resp) {
  if (!node || !msg || !resp) {
    return false;
  }
  if (msg->domain_separator_hash.size != 32 ||
      (msg->has_message_hash && msg->message_hash.size != 32)) {
    return false;
  }

  char address[TRON_ADDRESS_MAX_LEN];
  if (!tron_getAddress(node->public_key, address, sizeof(address))) {
    return false;
  }

  uint8_t hash[32] = {0};
  tron_typed_hash(msg->domain_separator_hash.bytes, msg->message_hash.bytes,
                  msg->has_message_hash, hash);

  uint8_t v = 0;
  if (ecdsa_sign_digest(&secp256k1, node->private_key, hash,
                        resp->signature.bytes, &v,
                        tron_is_canonic_typed) != 0) {
    memzero(hash, sizeof(hash));
    return false;
  }

  resp->signature.bytes[64] = 27 + v;
  resp->signature.size = 65;
  strlcpy(resp->address, address, sizeof(resp->address));

  memzero(hash, sizeof(hash));
  return true;
}
