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

/* Orchard spending keys derived via ZIP-32 */
typedef struct {
  uint8_t sk[32];    /* Spending key (master secret at this level) */
  uint8_t ask[32];   /* Spend authorizing key (scalar) */
  uint8_t nk[32];    /* Nullifier deriving key */
  uint8_t rivk[32];  /* Commitment randomness key */
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
bool zcash_derive_orchard_keys(const uint8_t *seed, uint32_t seed_len,
                               uint32_t account, ZcashOrchardKeys *keys);

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

#endif
