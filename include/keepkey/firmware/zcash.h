/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2025 KeepKey
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

#ifndef KEEPKEY_FIRMWARE_ZCASH_H
#define KEEPKEY_FIRMWARE_ZCASH_H

#include <stdbool.h>
#include <stdint.h>

/* Orchard spending keys derived via ZIP-32.
 * cppcheck doesn't see these used because the consumers live in
 * fsm_msg_zcash.h which is #include'd into fsm.c rather than compiled
 * separately, so the struct members appear "unused" in this TU. */
typedef struct {
  // cppcheck-suppress unusedStructMember
  uint8_t sk[32]; /* Spending key (master secret at this level) */
  // cppcheck-suppress unusedStructMember
  uint8_t ask[32]; /* Spend authorizing key (scalar) */
  // cppcheck-suppress unusedStructMember
  uint8_t nk[32]; /* Nullifier deriving key */
  // cppcheck-suppress unusedStructMember
  uint8_t rivk[32]; /* Commitment randomness key */
} ZcashOrchardKeys;

/**
 * Derive Orchard spending keys from the device seed via ZIP-32.
 * Path: m_orchard / 32' / 133' / account'
 *
 * Uses BLAKE2b with personalization "ZcashIP32Orchard" for key derivation.
 *
 * @param seed       BIP-39 master seed
 * @param seed_len   Seed length (typically 64 bytes)
 * @param account    Account index (0-based, will be hardened)
 * @param keys       Output: derived Orchard keys
 * @return true on success
 */
bool zcash_derive_orchard_keys(const uint8_t* seed, uint32_t seed_len,
                               uint32_t account, ZcashOrchardKeys* keys);

/**
 * Compute the ZIP 244 shielded sighash for Orchard spend authorization.
 *
 * For shielded-only transactions, transparent_sig_digest uses the "no inputs"
 * form. For mixed transactions, transparent data must be provided separately.
 *
 * @param header_digest     32-byte pre-computed header digest
 * @param transparent_digest 32-byte transparent sig digest (or empty hash)
 * @param sapling_digest    32-byte sapling digest (or empty hash)
 * @param orchard_digest    32-byte orchard digest
 * @param branch_id         Consensus branch ID (LE)
 * @param sighash_out       32-byte output sighash
 * @return true on success
 */
bool zcash_compute_shielded_sighash(const uint8_t header_digest[32],
                                    const uint8_t transparent_digest[32],
                                    const uint8_t sapling_digest[32],
                                    const uint8_t orchard_digest[32],
                                    uint32_t branch_id,
                                    uint8_t sighash_out[32]);

/**
 * Compute the ZIP-32 §6.1 seed fingerprint.
 *
 *   SeedFingerprint := BLAKE2b-256(
 *     "Zcash_HD_Seed_FP", I2LEBSP_8(len(seed)) || seed)
 *
 * The 1-byte length prefix domain-separates seeds of different lengths that
 * happen to share a prefix.
 *
 * 32-byte stable identifier of a seed. Used by host wallets and PCZTs
 * (zip32_derivation.seed_fingerprint) to confirm which device seed produced
 * a given key, address, or signature. Trivial seeds (all-zero, all-0xFF)
 * and seeds outside [32, 252] bytes are rejected per ZIP-32 §6.1.
 *
 * @param seed              Seed bytes (BIP-39 seed or BIP-32 master seed)
 * @param seed_len          Seed length, must be in [32, 252]
 * @param fingerprint_out   32-byte output fingerprint
 * @return true on success, false if seed is invalid
 */
bool zcash_calculate_seed_fingerprint(const uint8_t* seed, uint32_t seed_len,
                                      uint8_t fingerprint_out[32]);

#endif
