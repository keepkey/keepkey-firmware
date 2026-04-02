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

#include "keepkey/firmware/solana.h"
#include "keepkey/firmware/solana_tx.h"
#include "keepkey/firmware/fsm.h"
#include "trezor/crypto/ed25519-donna/ed25519.h"
#include "trezor/crypto/base58.h"
#include "trezor/crypto/memzero.h"

#include <string.h>

/*
 * Convert Ed25519 public key to Solana Base58 address
 *
 * Solana addresses are simply the Base58-encoded Ed25519 public key (32 bytes)
 */
bool solana_publicKeyToAddress(const uint8_t public_key[32], char *address,
                                size_t address_size) {
  if (!public_key || !address || address_size < SOLANA_ADDRESS_SIZE) {
    return false;
  }

  // Solana uses plain Base58 encoding (NO checksum) for addresses
  // The public key is 32 bytes, which encodes to ~43-44 Base58 characters
  size_t len = address_size;
  if (!b58enc(address, &len, public_key, 32)) {
    return false;
  }

  return len > 0;
}

/*
 * Sign Solana transaction
 *
 * Signs the MESSAGE portion of the raw transaction bytes with Ed25519.
 * Solana transaction wire format: [sig_count (compact-u16)][sig_count × 64-byte signatures][message]
 * Only the message portion is signed — the signature envelope is NOT part of the signed data.
 */
bool solana_signTx(const HDNode *node, const SolanaSignTx *msg,
                   SolanaSignedTx *resp) {
  if (!node || !msg || !resp) {
    return false;
  }

  // Validate we have transaction data
  if (!msg->has_raw_tx || msg->raw_tx.size == 0) {
    return false;
  }

  // Extract message bytes by skipping the signature envelope.
  const uint8_t *data = msg->raw_tx.bytes;
  size_t remaining = msg->raw_tx.size;

  // Read num_signatures (compact-u16)
  uint16_t num_sigs;
  if (!read_compact_u16(&data, &remaining, &num_sigs)) return false;

  // Skip past the dummy signatures (64 bytes each)
  size_t sigs_size = (size_t)num_sigs * 64;
  if (remaining < sigs_size) return false;
  data += sigs_size;
  remaining -= sigs_size;

  // 'data' now points to the message, 'remaining' is the message length

  // Get Ed25519 public key
  uint8_t public_key[32];
  ed25519_publickey(node->private_key, public_key);

  // Allocate buffer for signature (64 bytes for Ed25519)
  uint8_t signature[SOLANA_SIGNATURE_SIZE];

  // Sign ONLY the message bytes (not the signature envelope)
  ed25519_sign(data, remaining, node->private_key, public_key, signature);

  // Copy signature to response
  resp->has_signature = true;
  resp->signature.size = SOLANA_SIGNATURE_SIZE;
  memcpy(resp->signature.bytes, signature, SOLANA_SIGNATURE_SIZE);

  // Clean up sensitive data
  memzero(public_key, sizeof(public_key));
  memzero(signature, sizeof(signature));
  return true;
}
