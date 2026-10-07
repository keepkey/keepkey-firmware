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
#include <stddef.h>
#include <stdint.h>

/* Orchard spending keys derived via ZIP-32. Consumers live in
 * fsm_msg_zcash.h (#included into fsm.c), hence the cppcheck suppressions. */
typedef struct {
  // cppcheck-suppress unusedStructMember
  uint8_t sk[32]; /* Spending key (master secret at this level) */
  // cppcheck-suppress unusedStructMember
  uint8_t ask[32]; /* Spend authorizing key (scalar) */
  // cppcheck-suppress unusedStructMember
  uint8_t ak[32]; /* Public spend validating key (compressed, even y) */
  // cppcheck-suppress unusedStructMember
  uint8_t nk[32]; /* Nullifier deriving key */
  // cppcheck-suppress unusedStructMember
  uint8_t rivk[32]; /* Commitment randomness key */
  // cppcheck-suppress unusedStructMember
  uint8_t dk[32]; /* Diversifier key */
} ZcashOrchardKeys;

typedef void (*ZcashOrchardProgressCallback)(uint32_t completed, uint32_t total,
                                             void* context);

typedef struct {
  bool has_header_digest;
  size_t header_digest_size;
  bool has_transparent_digest;
  size_t transparent_digest_size;
  bool has_sapling_digest;
  size_t sapling_digest_size;
  bool has_orchard_digest;
  size_t orchard_digest_size;
  bool is_ironwood;
  bool has_ironwood_digest;
  size_t ironwood_digest_size;
  bool has_orchard_flags;
  uint32_t orchard_flags;
  bool has_orchard_value_balance;
  bool has_orchard_anchor;
  size_t orchard_anchor_size;
  bool has_header_fields;
  uint32_t n_transparent_inputs;
  uint32_t n_transparent_outputs;
} ZcashPCZTSigningRequestMeta;

typedef enum {
  ZCASH_PCZT_SIGNING_REQUEST_OK = 0,
  ZCASH_PCZT_SIGNING_REQUEST_MISSING_TX_DIGESTS,
  ZCASH_PCZT_SIGNING_REQUEST_INVALID_DIGEST_SIZE,
  ZCASH_PCZT_SIGNING_REQUEST_MISSING_HEADER_FIELDS,
  ZCASH_PCZT_SIGNING_REQUEST_UNSUPPORTED_SAPLING_COMPONENT,
  ZCASH_PCZT_SIGNING_REQUEST_MISSING_ORCHARD_METADATA,
  ZCASH_PCZT_SIGNING_REQUEST_MISSING_TRANSPARENT_DIGEST,
} ZcashPCZTSigningRequestStatus;

typedef struct {
  const uint8_t* prevout_txid;
  uint32_t prevout_index;
  uint32_t sequence;
  uint64_t value;
  const uint8_t* script_pubkey;
  size_t script_pubkey_size;
} ZcashTransparentInputDigestInfo;

typedef struct {
  uint64_t value;
  const uint8_t* script_pubkey;
  size_t script_pubkey_size;
} ZcashTransparentOutputDigestInfo;

#define ZCASH_ORCHARD_RAW_RECEIVER_SIZE 43
#define ZCASH_ORCHARD_UNIFIED_ADDRESS_SIZE 128

/* Validates the initial ZcashSignPCZT metadata: digest presence and sizes,
 * header fields, transparent and Orchard metadata, and no Sapling component.
 * Per-action sighashes are refused later, in fsm_msgZcashPCZTAction(). */
ZcashPCZTSigningRequestStatus zcash_pczt_signing_request_status(
    const ZcashPCZTSigningRequestMeta* meta);

/* ZIP-32 Orchard keys at m_orchard/32'/133'/account'. account must be
 * < 0x80000000; returns false (keys untouched) on NULL args or bad account. */
bool zcash_derive_orchard_keys(const uint8_t* seed, uint32_t seed_len,
                               uint32_t account, ZcashOrchardKeys* keys);

/* Progress follows the fixed public scalar-mult schedule, not the secret. */
bool zcash_derive_orchard_keys_with_progress(
    const uint8_t* seed, uint32_t seed_len, uint32_t account,
    ZcashOrchardKeys* keys, ZcashOrchardProgressCallback progress,
    void* progress_context);

/* ZIP-244 shielded sighash for Orchard spend auth. Digests are 32 bytes;
 * absent components pass their empty hash. branch_id is LE. */
bool zcash_compute_shielded_sighash(const uint8_t header_digest[32],
                                    const uint8_t transparent_digest[32],
                                    const uint8_t sapling_digest[32],
                                    const uint8_t orchard_digest[32],
                                    uint32_t branch_id,
                                    uint8_t sighash_out[32]);

/** Compute the five-component ZIP-229 transaction-v6 sighash. */
bool zcash_compute_v6_shielded_sighash(const uint8_t header_digest[32],
                                       const uint8_t transparent_digest[32],
                                       const uint8_t sapling_digest[32],
                                       const uint8_t orchard_digest[32],
                                       const uint8_t ironwood_digest[32],
                                       uint32_t branch_id,
                                       uint8_t sighash_out[32]);

/* Only v5 (ZIP-225) and v6 pairs; digest selection keys off version, so any
 * other pair must be refused before confirmation. */
bool zcash_tx_version_supported(uint32_t version, uint32_t version_group_id);

/* Orchard v6 binds the empty Ironwood digest; a host digest is accepted only
 * if it equals that, else the device would sign a different sighash. */
bool zcash_v6_orchard_ironwood_digest_valid(bool present, size_t size,
                                            const uint8_t* digest);

/* True when script has the P2PKH shape (OP_DUP OP_HASH160 <20> ...). */
bool zcash_script_is_p2pkh(const uint8_t* script, size_t script_size);

/* True when script is P2PKH paying HASH160(public_key). */
bool zcash_p2pkh_script_matches_pubkey(const uint8_t* script,
                                       size_t script_size,
                                       const uint8_t public_key[33]);

/* ZIP-244 T.1 header_digest from plaintext header fields. */
bool zcash_compute_header_digest(uint32_t version, uint32_t version_group_id,
                                 uint32_t branch_id, uint32_t lock_time,
                                 uint32_t expiry_height,
                                 uint8_t digest_out[32]);

/* ZIP-244 T.2 transparent_digest; not the per-input signature digest. */
bool zcash_compute_transparent_digest(
    const ZcashTransparentInputDigestInfo* inputs, size_t n_inputs,
    const ZcashTransparentOutputDigestInfo* outputs, size_t n_outputs,
    uint8_t digest_out[32]);

/* ZIP-244 §4.9 transparent_sig_digest as consensus verifies Orchard sigs:
 * S.2 with EMPTY txin_sig_digest if n_inputs > 0, else T.1. */
bool zcash_compute_orchard_transparent_sig_digest(
    const ZcashTransparentInputDigestInfo* inputs, size_t n_inputs,
    const ZcashTransparentOutputDigestInfo* outputs, size_t n_outputs,
    uint8_t digest_out[32]);

/* ZIP-244 S.2 per-input transparent sig digest; SIGHASH_ALL only. */
bool zcash_compute_transparent_sighash_digest(
    const ZcashTransparentInputDigestInfo* inputs, size_t n_inputs,
    const ZcashTransparentOutputDigestInfo* outputs, size_t n_outputs,
    uint32_t signable_input_index, uint8_t sighash_type,
    uint8_t digest_out[32]);

/* Encode receiver (d || pk_d) as a ZIP-316 UA for display only; proves no
 * ownership. */
bool zcash_orchard_receiver_to_unified_address(
    const uint8_t receiver[ZCASH_ORCHARD_RAW_RECEIVER_SIZE], const char* hrp,
    char* address_out, size_t address_out_len);

/** ZIP-2005 V3 note commitment used by the Ironwood pool. */
bool zcash_ironwood_compute_cmx_with_progress(
    const uint8_t receiver[ZCASH_ORCHARD_RAW_RECEIVER_SIZE], uint64_t value,
    const uint8_t rho[32], const uint8_t rseed[32], uint8_t cmx_out[32],
    ZcashOrchardProgressCallback progress, void* progress_context);

/* cmx = Extract_P(NoteCommit(g_d, pk_d, v, rho, psi)); rho is the action
 * nullifier. Binds displayed receiver/value to the action before signing.
 * Callback (may be NULL) exposes only the public Sinsemilla word index and
 * count. */
bool zcash_orchard_compute_cmx_with_progress(
    const uint8_t receiver[ZCASH_ORCHARD_RAW_RECEIVER_SIZE], uint64_t value,
    const uint8_t rho[32], const uint8_t rseed[32], uint8_t cmx_out[32],
    ZcashOrchardProgressCallback progress, void* progress_context);

/* d_j = FF1-AES256.Encrypt(dk, "", I2LEBSP_88(j)); index and output are
 * 11-byte LEBS2OSP encodings. */
bool zcash_orchard_derive_diversifier(const uint8_t dk[32],
                                      const uint8_t index_le[11],
                                      uint8_t diversifier_out[11]);

/* g_d = GroupHash^Pallas("z.cash:Orchard-gd", d); on identity, hashes the
 * empty message under the same domain. */
bool zcash_orchard_diversify_hash(const uint8_t diversifier[11],
                                  uint8_t gd_out[32]);

/* pk_d = [ivk] DiversifyHash(d); ivk must be nonzero, gd_out may be NULL. */
bool zcash_orchard_derive_transmission_key(const uint8_t ivk[32],
                                           const uint8_t diversifier[11],
                                           uint8_t gd_out[32],
                                           uint8_t pkd_out[32]);

/* ivk = Commit^ivk(ExtractP(ak), nk, rivk); ak sign bit clear, ivk nonzero. */
bool zcash_orchard_derive_ivk(const uint8_t ak[32], const uint8_t nk[32],
                              const uint8_t rivk[32], uint8_t ivk_out[32]);

/* Raw external receiver d_j || pk_dj (43 bytes) from FVK parts and index. */
bool zcash_orchard_derive_receiver(const uint8_t ak[32], const uint8_t nk[32],
                                   const uint8_t rivk[32], const uint8_t dk[32],
                                   const uint8_t index_le[11],
                                   uint8_t receiver_out[43]);

/* Orchard-only ZIP-316 UA: Bech32m(hrp, F4Jumble(d_j || pk_dj)). */
bool zcash_orchard_derive_unified_address(const ZcashOrchardKeys* keys,
                                          const uint8_t index_le[11],
                                          const char* hrp, char* address_out,
                                          size_t address_out_len);

/* ZIP-32 §6.1: BLAKE2b-256("Zcash_HD_Seed_FP", I2LEBSP_8(len) || seed).
 * Rejects trivial (all-0x00/0xFF) seeds and lengths outside [32, 252]. */
bool zcash_calculate_seed_fingerprint(const uint8_t* seed, uint32_t seed_len,
                                      uint8_t fingerprint_out[32]);

/* Optional asserted fingerprint: absent, or exactly 32 bytes. */
bool zcash_seed_fingerprint_request_valid(bool present, size_t size);

/* An Orchard nullifier (rho) is a Pallas base-field element: its 32-byte
 * little-endian encoding is canonical only below the field modulus. */
bool zcash_orchard_nullifier_canonical(const uint8_t nullifier[32]);

/* Storage-scoped wrappers (in storage.c) are the only sanctioned production
 * path to seed-derived Zcash material: the raw seed never leaves storage.c.
 * The bare derivations above are for unit-test vectors. */
bool storage_zcashOrchardKeys(uint32_t account, bool usePassphrase,
                              ZcashOrchardKeys* keys_out);

bool storage_zcashSeedFingerprint(bool usePassphrase,
                                  uint8_t fingerprint_out[32]);

/* Wipes all signing state (keys, sigs, digests) so a host cannot resume an
 * approved session after Initialize/Cancel/ClearSession. */
void zcash_signing_abort(void);
bool zcash_signing_is_active(void);

#endif
