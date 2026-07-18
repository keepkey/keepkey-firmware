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
  // cppcheck-suppress unusedStructMember
  uint8_t dk[32]; /* Diversifier key */
} ZcashOrchardKeys;

typedef struct {
  bool has_header_digest;
  size_t header_digest_size;
  bool has_transparent_digest;
  size_t transparent_digest_size;
  bool has_sapling_digest;
  size_t sapling_digest_size;
  bool has_orchard_digest;
  size_t orchard_digest_size;
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

/**
 * Validate the clear-signing metadata required before Orchard signatures.
 *
 * This rejects the legacy flow where the host supplied only a per-action
 * sighash. The firmware must assemble the ZIP-244 sighash from transaction
 * component digests and verify the Orchard digest against streamed action data
 * before returning signatures.
 */
ZcashPCZTSigningRequestStatus zcash_pczt_signing_request_status(
    const ZcashPCZTSigningRequestMeta* meta);

bool zcash_pczt_signing_request_is_clear(
    const ZcashPCZTSigningRequestMeta* meta);

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
 * Compute ZIP-244 T.1 header_digest from plaintext transaction header fields.
 */
bool zcash_compute_header_digest(uint32_t version, uint32_t version_group_id,
                                 uint32_t branch_id, uint32_t lock_time,
                                 uint32_t expiry_height,
                                 uint8_t digest_out[32]);

/**
 * Compute ZIP-244 T.2 transparent_digest from plaintext transparent data.
 *
 * This is the digest mixed into the Orchard/Sapling signing commitment. It is
 * not the same as the per-input transparent signature digest.
 */
bool zcash_compute_transparent_digest(
    const ZcashTransparentInputDigestInfo* inputs, size_t n_inputs,
    const ZcashTransparentOutputDigestInfo* outputs, size_t n_outputs,
    uint8_t digest_out[32]);

/**
 * Compute ZIP-244 §4.9 transparent_sig_digest for Orchard spend authorization.
 *
 * Uses the S.2 form with EMPTY txin_sig_digest when n_inputs > 0 (shield txs),
 * or falls back to T.1 when n_inputs == 0 (deshield / private-send). This is
 * what the Zcash consensus node uses to verify Orchard spend auth sigs and the
 * binding signature in a hybrid (transparent + Orchard) transaction.
 */
bool zcash_compute_orchard_transparent_sig_digest(
    const ZcashTransparentInputDigestInfo* inputs, size_t n_inputs,
    const ZcashTransparentOutputDigestInfo* outputs, size_t n_outputs,
    uint8_t digest_out[32]);

/**
 * Compute ZIP-244 S.2 per-input transparent signature digest.
 *
 * This currently accepts SIGHASH_ALL only, matching the existing transparent
 * signing flow.
 */
bool zcash_compute_transparent_sighash_digest(
    const ZcashTransparentInputDigestInfo* inputs, size_t n_inputs,
    const ZcashTransparentOutputDigestInfo* outputs, size_t n_outputs,
    uint32_t signable_input_index, uint8_t sighash_type,
    uint8_t digest_out[32]);

/**
 * Encode a raw Orchard receiver (d || pk_d) as an Orchard-only ZIP-316 Unified
 * Address for display. This is for recipient review; it does not derive or
 * prove ownership of the receiver.
 */
bool zcash_orchard_receiver_to_unified_address(
    const uint8_t receiver[ZCASH_ORCHARD_RAW_RECEIVER_SIZE], const char* hrp,
    char* address_out, size_t address_out_len);

/**
 * Recompute an Orchard output note commitment x-coordinate (cmx).
 *
 * cmx = Extract_P(NoteCommit_rcm^Orchard(g_d, pk_d, v, rho, psi))
 * where receiver = d || pk_d, rho is the action nullifier, and rseed is the
 * output note seed. This binds the user-displayed receiver/value to the action
 * commitment before any authorization signature is emitted.
 */
bool zcash_orchard_compute_cmx(
    const uint8_t receiver[ZCASH_ORCHARD_RAW_RECEIVER_SIZE], uint64_t value,
    const uint8_t rho[32], const uint8_t rseed[32], uint8_t cmx_out[32]);

/**
 * Derive an Orchard diversifier from a diversifier key and 88-bit index.
 *
 * ZIP-32 defines Orchard diversifiers as:
 *   d_j = FF1-AES256.Encrypt(dk, "", I2LEBSP_88(j))
 *
 * Both index_le and diversifier_out are 11-byte LEBS2OSP encodings of the
 * 88-bit bitstrings.
 *
 * @param dk              32-byte Orchard diversifier key
 * @param index_le        11-byte little-endian diversifier index bitstring
 * @param diversifier_out 11-byte output diversifier
 * @return true on success
 */
bool zcash_orchard_derive_diversifier(const uint8_t dk[32],
                                      const uint8_t index_le[11],
                                      uint8_t diversifier_out[11]);

/**
 * Compute DiversifyHash^Orchard(d) as a serialized Pallas point.
 *
 *   g_d = GroupHash^Pallas("z.cash:Orchard-gd", d)
 *
 * If the group hash ever returns the identity, Orchard falls back to hashing
 * the empty message under the same domain.
 *
 * @param diversifier 11-byte Orchard diversifier
 * @param gd_out      32-byte compressed Pallas point
 * @return true on success
 */
bool zcash_orchard_diversify_hash(const uint8_t diversifier[11],
                                  uint8_t gd_out[32]);

/**
 * Derive an Orchard diversified transmission key.
 *
 *   g_d  = DiversifyHash^Orchard(d)
 *   pk_d = KA^Orchard.DerivePublic(ivk, g_d) = [ivk] g_d
 *
 * @param ivk         32-byte nonzero Orchard incoming viewing key encoding
 * @param diversifier 11-byte Orchard diversifier
 * @param gd_out      optional 32-byte compressed g_d output, may be NULL
 * @param pkd_out     32-byte compressed diversified transmission key
 * @return true on success
 */
bool zcash_orchard_derive_transmission_key(const uint8_t ivk[32],
                                           const uint8_t diversifier[11],
                                           uint8_t gd_out[32],
                                           uint8_t pkd_out[32]);

/**
 * Derive the external Orchard incoming viewing key from FVK components.
 *
 *   ivk = Commit^ivk.Output(ExtractP(ak), nk, rivk)
 *
 * @param ak      32-byte Orchard spend validating key encoding, sign bit clear
 * @param nk      32-byte Orchard nullifier deriving key
 * @param rivk    32-byte Orchard IVK commitment randomness
 * @param ivk_out 32-byte nonzero Orchard incoming viewing key
 * @return true on success
 */
bool zcash_orchard_derive_ivk(const uint8_t ak[32], const uint8_t nk[32],
                              const uint8_t rivk[32], uint8_t ivk_out[32]);

/**
 * Derive a raw Orchard receiver from external FVK components and index.
 *
 *   d_j   = DiversifierKey(dk).get(j)
 *   ivk   = Commit^ivk.Output(ExtractP(ak), nk, rivk)
 *   pk_dj = KA^Orchard.DerivePublic(ivk, DiversifyHash(d_j))
 *
 * @param ak           32-byte Orchard spend validating key encoding
 * @param nk           32-byte Orchard nullifier deriving key
 * @param rivk         32-byte Orchard IVK commitment randomness
 * @param dk           32-byte Orchard diversifier key
 * @param index_le     11-byte little-endian diversifier index bitstring
 * @param receiver_out 43-byte raw receiver: d_j || pk_dj
 * @return true on success
 */
bool zcash_orchard_derive_receiver(const uint8_t ak[32], const uint8_t nk[32],
                                   const uint8_t rivk[32], const uint8_t dk[32],
                                   const uint8_t index_le[11],
                                   uint8_t receiver_out[43]);

/**
 * Derive an Orchard-only ZIP-316 Unified Address from derived Orchard keys.
 *
 *   ak       = [ask] G_spendauth
 *   receiver = d_j || pk_dj
 *   address  = Bech32m(HRP, F4Jumble(Orchard receiver payload))
 *
 * @param keys            ZIP-32-derived Orchard key material
 * @param index_le        11-byte little-endian diversifier index bitstring
 * @param hrp             ZIP-316 HRP ("u" for mainnet, "utest" for testnet)
 * @param address_out     NUL-terminated output address
 * @param address_out_len Size of address_out
 * @return true on success
 */
bool zcash_orchard_derive_unified_address(const ZcashOrchardKeys* keys,
                                          const uint8_t index_le[11],
                                          const char* hrp, char* address_out,
                                          size_t address_out_len);

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

/**
 * Validate the wire shape of an optional asserted seed fingerprint. Omission is
 * valid; a present assertion must be exactly 32 bytes.
 */
bool zcash_seed_fingerprint_request_valid(bool present, size_t size);

/* ── Storage-scoped wrappers ───────────────────────────────────────────
 *
 * The two functions below own the seed access. Implementations live in
 * lib/firmware/storage.c so the raw 64-byte BIP-39 seed never escapes
 * that translation unit. Callers (FSM handlers) get only the derived
 * material — Orchard keys or the 32-byte fingerprint — never a pointer
 * to the seed itself. This is the only sanctioned way for production
 * firmware code to consume seed-derived Zcash material.
 *
 * The bare zcash_derive_orchard_keys() / zcash_calculate_seed_fingerprint()
 * functions above remain in the header for unit tests, which feed them
 * known test vectors directly.
 */

/**
 * Derive Orchard keys for an account using the device's session seed.
 *
 * @param account       Account index (0-based, will be hardened)
 * @param usePassphrase Whether to apply the passphrase (prompts if needed)
 * @param keys_out      Output: derived Orchard keys
 * @return true on success, false if seed unavailable or derivation fails
 */
bool storage_zcashOrchardKeys(uint32_t account, bool usePassphrase,
                              ZcashOrchardKeys* keys_out);

/**
 * Compute the ZIP-32 §6.1 seed fingerprint for the device's session seed.
 *
 * @param usePassphrase    Whether to apply the passphrase (prompts if needed)
 * @param fingerprint_out  32-byte output fingerprint
 * @return true on success, false if seed unavailable
 */
bool storage_zcashSeedFingerprint(bool usePassphrase,
                                  uint8_t fingerprint_out[32]);

/**
 * Tear down any in-progress Zcash signing session.
 *
 * Wipes the static signing state (active flag, derived Orchard keys,
 * accumulated signatures, sub-digest contexts, transparent-input
 * counters) so a host cannot resume streaming PCZTAction or
 * TransparentInput messages against a previously-approved session
 * after Initialize, Cancel, or ClearSession. Safe to call when no
 * session is active.
 */
void zcash_signing_abort(void);

#endif
