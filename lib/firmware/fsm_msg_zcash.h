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

/* Zcash-specific headers — included here because fsm_msg_zcash.h
 * is #include'd inside fsm.c, not compiled separately. */
#include "keepkey/firmware/zcash.h"
#include "trezor/crypto/blake2b.h"
#include "trezor/crypto/pallas.h"
#include "trezor/crypto/redpallas.h"
#include "trezor/crypto/memzero.h"

/* Precomputed empty digest constants for shielded-only transactions.
 * These are BLAKE2b-256 with the respective personalizations over empty input.
 * Verified against Keystone3 test vectors. */
static const uint8_t EMPTY_TRANSPARENT_DIGEST[32] = {
  0xc3, 0x3f, 0x2e, 0x95, 0x70, 0x5f, 0xaa, 0xb3,
  0x5f, 0x8d, 0x53, 0x3f, 0xa6, 0x1e, 0x95, 0xc3,
  0xb7, 0xaa, 0xba, 0x07, 0x76, 0xb8, 0x74, 0xa9,
  0xf7, 0x4f, 0xc1, 0x27, 0x84, 0x37, 0x6a, 0x59
};

static const uint8_t EMPTY_SAPLING_DIGEST[32] = {
  0x6f, 0x2f, 0xc8, 0xf9, 0x8f, 0xea, 0xfd, 0x94,
  0xe7, 0x4a, 0x0d, 0xf4, 0xbe, 0xd7, 0x43, 0x91,
  0xee, 0x0b, 0x5a, 0x69, 0x94, 0x5e, 0x4c, 0xed,
  0x8c, 0xa8, 0xa0, 0x95, 0x20, 0x6f, 0x00, 0xae
};

/* Zcash shielded signing state */
static struct {
  bool active;
  uint32_t account;
  uint32_t n_actions;
  uint32_t current_action;
  uint64_t total_amount;
  uint64_t fee;
  uint32_t branch_id;
  ZcashOrchardKeys keys;
  uint8_t sighash[32];
  /* Phase 2a: on-device sighash computation */
  bool has_device_sighash;
  /* Phase 2b: incremental orchard digest verification */
  bool verify_orchard_digest;
  uint8_t expected_orchard_digest[32];
  BLAKE2B_CTX compact_ctx;
  BLAKE2B_CTX memos_ctx;
  BLAKE2B_CTX noncompact_ctx;
  uint8_t orchard_flags;
  int64_t orchard_value_balance;
  uint8_t orchard_anchor[32];
  /* Signatures buffer: up to 16 actions (64 bytes each) */
  uint8_t signatures[16][64];
  /* Phase 3: transparent shielding state */
  uint32_t n_transparent_inputs;
  uint32_t current_transparent_input;
} zcash_signing;

#define ZCASH_MAX_ACTIONS 16
#define ZCASH_MAX_TRANSPARENT_INPUTS 8

void fsm_msgZcashSignPCZT(const ZcashSignPCZT *msg) {
  RESP_INIT(ZcashPCZTActionAck);

  CHECK_INITIALIZED

  CHECK_PIN

  /* Validate parameters */
  if (!msg->has_n_actions || msg->n_actions == 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("No actions specified"));
    layoutHome();
    return;
  }

  if (msg->n_actions > ZCASH_MAX_ACTIONS) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Too many Orchard actions"));
    layoutHome();
    return;
  }

  /* Determine account from path or explicit account field */
  uint32_t account = 0;
  if (msg->has_account) {
    account = msg->account;
  } else if (msg->address_n_count >= 3) {
    /* Extract account from path: m/32'/133'/account' */
    account = msg->address_n[2] & 0x7FFFFFFF;  /* Strip hardened bit */
  }

  /* Confirm with user */
  char amount_str[32];
  char fee_str[32];
  uint64_t total = msg->has_total_amount ? msg->total_amount : 0;
  uint64_t fee = msg->has_fee ? msg->fee : 0;

  /* Format amounts (1 ZEC = 100,000,000 zatoshis) */
  snprintf(amount_str, sizeof(amount_str), "%llu.%08llu ZEC",
           (unsigned long long)(total / 100000000ULL),
           (unsigned long long)(total % 100000000ULL));
  snprintf(fee_str, sizeof(fee_str), "%llu.%08llu ZEC",
           (unsigned long long)(fee / 100000000ULL),
           (unsigned long long)(fee % 100000000ULL));

  /* Display confirmation — different text for shielded-only vs hybrid */
  uint32_t n_tinputs = msg->has_n_transparent_inputs ? msg->n_transparent_inputs : 0;
  if (n_tinputs > 0) {
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx,
                 "Zcash Shield", "Shield transparent ZEC to Orchard?\n"
                 "Amount: %s\nFee: %s\nInputs: %lu\nActions: %lu",
                 amount_str, fee_str,
                 (unsigned long)n_tinputs,
                 (unsigned long)msg->n_actions)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  } else {
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx,
                 "Zcash Shielded", "Sign shielded transaction?\n"
                 "Amount: %s\nFee: %s\nActions: %lu",
                 amount_str, fee_str, (unsigned long)msg->n_actions)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  }

  /* Get the real BIP-39 seed for ZIP-32 Orchard derivation.
   * storage_getSeed() returns the 64-byte mnemonic-derived seed,
   * handling passphrase entry if needed. This is NOT the BIP-32
   * root key — ZIP-32 Orchard uses a completely separate derivation
   * tree rooted at the raw seed. */
  const uint8_t *seed = storage_getRawSeed(true);
  if (!seed) {
    fsm_sendFailure(FailureType_Failure_NotInitialized,
                    _("Device not initialized or seed unavailable"));
    layoutHome();
    return;
  }

  if (!zcash_derive_orchard_keys(seed, 64, account,
                                 &zcash_signing.keys)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Orchard key derivation failed"));
    layoutHome();
    return;
  }

  /* Initialize signing state */
  zcash_signing.active = true;
  zcash_signing.account = account;
  zcash_signing.n_actions = msg->n_actions;
  zcash_signing.current_action = 0;
  zcash_signing.total_amount = total;
  zcash_signing.fee = fee;
  zcash_signing.branch_id = msg->has_branch_id ? msg->branch_id : 0x37519621;
  zcash_signing.has_device_sighash = false;
  zcash_signing.verify_orchard_digest = false;
  zcash_signing.n_transparent_inputs =
      msg->has_n_transparent_inputs ? msg->n_transparent_inputs : 0;
  zcash_signing.current_transparent_input = 0;

  if (zcash_signing.n_transparent_inputs > ZCASH_MAX_TRANSPARENT_INPUTS) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Too many transparent inputs"));
    zcash_signing.active = false;
    layoutHome();
    return;
  }

  /* Phase 2a: Compute sighash on-device if sub-digests are provided.
   *
   * TRUST MODEL:
   *
   * What the device verifies:
   *   - Orchard digest: recomputed from streamed action data (Phase 2b)
   *     covering nullifiers, commitments, ephemeral keys, ciphertexts,
   *     value commitments, randomized keys, flags, value balance, anchor.
   *   - Sighash: assembled on-device from the 4 sub-digests.
   *
   * What the device trusts from the host:
   *   - header_digest, transparent_digest, sapling_digest: accepted
   *     without verification. The device cannot recompute these without
   *     the full transaction data, which exceeds memory constraints.
   *   - Displayed amounts (total_amount, fee): these are for user
   *     confirmation only. Orchard values are hidden by Pedersen
   *     commitments (cv_net) — the device cannot extract plaintext
   *     amounts from the verified digest. This is inherent to the
   *     Zcash shielded protocol, not a firmware limitation.
   *
   * For shielded-only transactions (no transparent inputs):
   *   transparent_digest defaults to the well-known empty hash,
   *   so no trust assumption is needed for that component.
   *
   * For mixed transactions:
   *   The host is trusted for non-Orchard components. This matches
   *   the trust model of other Zcash hardware wallet implementations
   *   (Keystone, Trezor) for the streaming PCZT protocol. */
  if (msg->has_header_digest && msg->header_digest.size == 32 &&
      msg->has_orchard_digest && msg->orchard_digest.size == 32) {

    uint8_t t_digest[32], s_digest[32];

    /* Use provided transparent digest, or default to empty */
    if (msg->has_transparent_digest && msg->transparent_digest.size == 32) {
      memcpy(t_digest, msg->transparent_digest.bytes, 32);
    } else {
      memcpy(t_digest, EMPTY_TRANSPARENT_DIGEST, 32);
    }

    /* Use provided sapling digest, or default to empty */
    if (msg->has_sapling_digest && msg->sapling_digest.size == 32) {
      memcpy(s_digest, msg->sapling_digest.bytes, 32);
    } else {
      memcpy(s_digest, EMPTY_SAPLING_DIGEST, 32);
    }

    zcash_compute_shielded_sighash(
        msg->header_digest.bytes, t_digest, s_digest,
        msg->orchard_digest.bytes,
        zcash_signing.branch_id,
        zcash_signing.sighash);
    zcash_signing.has_device_sighash = true;

    /* Phase 2b: Initialize orchard digest verification if bundle metadata
     * is provided (orchard_flags, orchard_value_balance, orchard_anchor).
     * The device will incrementally hash each action's data and verify
     * the computed orchard_digest matches the one used for sighash. */
    if (msg->has_orchard_flags && msg->has_orchard_value_balance &&
        msg->has_orchard_anchor && msg->orchard_anchor.size == 32) {

      memcpy(zcash_signing.expected_orchard_digest,
             msg->orchard_digest.bytes, 32);
      zcash_signing.orchard_flags = (uint8_t)msg->orchard_flags;
      zcash_signing.orchard_value_balance = msg->orchard_value_balance;
      memcpy(zcash_signing.orchard_anchor, msg->orchard_anchor.bytes, 32);

      /* Initialize BLAKE2b streaming contexts for the 3 sub-hashes */
      blake2b_InitPersonal(&zcash_signing.compact_ctx, 32,
                           "ZTxIdOrcActCHash", 16);
      blake2b_InitPersonal(&zcash_signing.memos_ctx, 32,
                           "ZTxIdOrcActMHash", 16);
      blake2b_InitPersonal(&zcash_signing.noncompact_ctx, 32,
                           "ZTxIdOrcActNHash", 16);
      zcash_signing.verify_orchard_digest = true;
    }
  }

  /* Request first action data */
  resp->has_next_index = true;
  resp->next_index = 0;
  msg_write(MessageType_MessageType_ZcashPCZTActionAck, resp);
  layoutProgress(_("Signing Zcash"), 0);
}

void fsm_msgZcashGetOrchardFVK(const ZcashGetOrchardFVK *msg) {
  RESP_INIT(ZcashOrchardFVK);

  CHECK_INITIALIZED

  CHECK_PIN

  /* Determine account from path or explicit account field */
  uint32_t account = 0;
  if (msg->has_account) {
    account = msg->account;
  } else if (msg->address_n_count >= 3) {
    account = msg->address_n[2] & 0x7FFFFFFF;
  }

  /* Get the real BIP-39 seed for ZIP-32 Orchard derivation */
  const uint8_t *seed = storage_getRawSeed(true);
  if (!seed) {
    fsm_sendFailure(FailureType_Failure_NotInitialized,
                    _("Device not initialized or seed unavailable"));
    layoutHome();
    return;
  }

  ZcashOrchardKeys keys;
  if (!zcash_derive_orchard_keys(seed, 64, account, &keys)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Orchard key derivation failed"));
    layoutHome();
    return;
  }

  /* Compute ak = [ask]G_spendauth on Pallas curve (SpendAuth basepoint) */
  bignum256 ask_scalar;
  bn_read_le(keys.ask, &ask_scalar);
  curve_point ak_point;
  redpallas_scalar_mult_spendauth_G(&ask_scalar, &ak_point);

  /* Serialize ak as Pallas point (LE x-coord, sign bit in high byte) */
  uint8_t ak_bytes[32];
  bignum256 x_copy;
  bn_copy(&ak_point.x, &x_copy);
  bn_write_le(&x_copy, ak_bytes);
  if (bn_is_odd(&ak_point.y)) {
    ak_bytes[31] |= 0x80;
  }

  /* Build response */
  resp->has_ak = true;
  resp->ak.size = 32;
  memcpy(resp->ak.bytes, ak_bytes, 32);

  resp->has_nk = true;
  resp->nk.size = 32;
  memcpy(resp->nk.bytes, keys.nk, 32);

  resp->has_rivk = true;
  resp->rivk.size = 32;
  memcpy(resp->rivk.bytes, keys.rivk, 32);

  /* Clean up sensitive data */
  memzero(&ask_scalar, sizeof(ask_scalar));
  memzero(&keys, sizeof(keys));

  msg_write(MessageType_MessageType_ZcashOrchardFVK, resp);
  layoutHome();
}

void fsm_msgZcashPCZTAction(const ZcashPCZTAction *msg) {
  if (!zcash_signing.active) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Not in Zcash signing mode"));
    layoutHome();
    return;
  }

  /* Enforce transparent phase completion: if the session declared
   * transparent inputs, ALL must be signed before Orchard actions.
   * This prevents a malicious host from skipping transparent-input
   * confirmations and jumping straight to Orchard signing. */
  if (zcash_signing.current_transparent_input <
      zcash_signing.n_transparent_inputs) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Transparent inputs not yet complete"));
    zcash_signing.active = false;
    memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
    layoutHome();
    return;
  }

  /* Validate action index */
  if (!msg->has_index || msg->index != zcash_signing.current_action) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Unexpected action index"));
    zcash_signing.active = false;
    memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
    layoutHome();
    return;
  }

  /* Validate required fields */
  if (!msg->has_alpha || msg->alpha.size != 32) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Missing or invalid alpha randomizer"));
    zcash_signing.active = false;
    memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
    layoutHome();
    return;
  }

  /* Phase 2a: require sighash only in legacy mode */
  if (!zcash_signing.has_device_sighash) {
    if (!msg->has_sighash || msg->sighash.size != 32) {
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Missing or invalid sighash"));
      zcash_signing.active = false;
      memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
      layoutHome();
      return;
    }
  }

  /* Phase 2b: feed action data into incremental BLAKE2b contexts */
  if (zcash_signing.verify_orchard_digest &&
      msg->has_nullifier && msg->nullifier.size == 32 &&
      msg->has_cmx && msg->cmx.size == 32 &&
      msg->has_epk && msg->epk.size == 32 &&
      msg->has_enc_compact && msg->enc_compact.size == 52 &&
      msg->has_enc_memo && msg->enc_memo.size == 512 &&
      msg->has_enc_noncompact && msg->enc_noncompact.size > 0 &&
      msg->has_cv_net && msg->cv_net.size == 32 &&
      msg->has_rk && msg->rk.size == 32 &&
      msg->has_out_ciphertext && msg->out_ciphertext.size == 80) {

    /* Compact: nf || cmx || epk || enc[0..52] */
    blake2b_Update(&zcash_signing.compact_ctx, msg->nullifier.bytes, 32);
    blake2b_Update(&zcash_signing.compact_ctx, msg->cmx.bytes, 32);
    blake2b_Update(&zcash_signing.compact_ctx, msg->epk.bytes, 32);
    blake2b_Update(&zcash_signing.compact_ctx, msg->enc_compact.bytes, 52);

    /* Memos: enc[52..564] */
    blake2b_Update(&zcash_signing.memos_ctx, msg->enc_memo.bytes, 512);

    /* Noncompact: cv_net || rk || enc[564..] || out_ciphertext */
    blake2b_Update(&zcash_signing.noncompact_ctx, msg->cv_net.bytes, 32);
    blake2b_Update(&zcash_signing.noncompact_ctx, msg->rk.bytes, 32);
    blake2b_Update(&zcash_signing.noncompact_ctx,
                   msg->enc_noncompact.bytes, msg->enc_noncompact.size);
    blake2b_Update(&zcash_signing.noncompact_ctx,
                   msg->out_ciphertext.bytes, 80);
  }

  /* Use device-computed sighash if available, otherwise legacy host sighash */
  const uint8_t *sighash = zcash_signing.has_device_sighash
      ? zcash_signing.sighash
      : msg->sighash.bytes;

  /* Sign this action with RedPallas:
   * sig = RedPallas.sign(ask, alpha, sighash) */
  if (redpallas_sign_digest(zcash_signing.keys.ask,
                            msg->alpha.bytes,
                            sighash,
                            zcash_signing.signatures[msg->index]) != 0) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("RedPallas signing failed"));
    zcash_signing.active = false;
    memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
    layoutHome();
    return;
  }

  zcash_signing.current_action++;

  /* Update progress */
  uint32_t progress = (zcash_signing.current_action * 1000) /
                      zcash_signing.n_actions;
  layoutProgress(_("Signing Zcash"), progress);

  /* Check if all actions are signed */
  if (zcash_signing.current_action >= zcash_signing.n_actions) {

    /* Phase 2b: verify orchard digest before returning signatures */
    if (zcash_signing.verify_orchard_digest) {
      uint8_t compact_hash[32], memos_hash[32], noncompact_hash[32];

      blake2b_Final(&zcash_signing.compact_ctx, compact_hash, 32);
      blake2b_Final(&zcash_signing.memos_ctx, memos_hash, 32);
      blake2b_Final(&zcash_signing.noncompact_ctx, noncompact_hash, 32);

      /* Compute orchard_digest = BLAKE2b("ZTxIdOrchardHash",
       *   compact_hash || memos_hash || noncompact_hash ||
       *   flags(1) || value_balance(8) || anchor(32)) */
      BLAKE2B_CTX orchard_ctx;
      blake2b_InitPersonal(&orchard_ctx, 32, "ZTxIdOrchardHash", 16);
      blake2b_Update(&orchard_ctx, compact_hash, 32);
      blake2b_Update(&orchard_ctx, memos_hash, 32);
      blake2b_Update(&orchard_ctx, noncompact_hash, 32);
      blake2b_Update(&orchard_ctx, &zcash_signing.orchard_flags, 1);
      blake2b_Update(&orchard_ctx,
                     (const uint8_t *)&zcash_signing.orchard_value_balance, 8);
      blake2b_Update(&orchard_ctx, zcash_signing.orchard_anchor, 32);

      uint8_t computed_orchard_digest[32];
      blake2b_Final(&orchard_ctx, computed_orchard_digest, 32);

      /* Verify computed matches expected */
      if (memcmp(computed_orchard_digest,
                 zcash_signing.expected_orchard_digest, 32) != 0) {
        fsm_sendFailure(FailureType_Failure_Other,
                        _("Orchard digest mismatch: transaction data "
                          "does not match sighash"));
        zcash_signing.active = false;
        memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
        memzero(zcash_signing.signatures, sizeof(zcash_signing.signatures));
        layoutHome();
        return;
      }
    }

    /* All done - send the collected signatures */
    ZcashSignedPCZT *resp_signed = (ZcashSignedPCZT *)msg_resp;
    memset(resp_signed, 0, sizeof(ZcashSignedPCZT));

    resp_signed->signatures_count = zcash_signing.n_actions;
    for (uint32_t i = 0; i < zcash_signing.n_actions; i++) {
      resp_signed->signatures[i].size = 64;
      memcpy(resp_signed->signatures[i].bytes, zcash_signing.signatures[i], 64);
    }

    /* Clean up */
    zcash_signing.active = false;
    memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
    memzero(zcash_signing.signatures, sizeof(zcash_signing.signatures));

    msg_write(MessageType_MessageType_ZcashSignedPCZT, resp_signed);
    layoutHome();
  } else {
    /* Request next action */
    ZcashPCZTActionAck *resp_ack = (ZcashPCZTActionAck *)msg_resp;
    memset(resp_ack, 0, sizeof(ZcashPCZTActionAck));
    resp_ack->has_next_index = true;
    resp_ack->next_index = zcash_signing.current_action;
    msg_write(MessageType_MessageType_ZcashPCZTActionAck, resp_ack);
  }
}

/* Phase 3: Transparent input signing for hybrid shielding transactions.
 *
 * The host sends one ZcashTransparentInput per transparent input after
 * the initial ZcashSignPCZT. The device derives the secp256k1 key at
 * the provided BIP44 path, ECDSA-signs the per-input sighash, and
 * returns a DER signature.
 *
 * After all transparent inputs, the device transitions to the Orchard
 * action phase (ZcashPCZTAction streaming). */
void fsm_msgZcashTransparentInput(const ZcashTransparentInput *msg) {
  RESP_INIT(ZcashTransparentSig);

  if (!zcash_signing.active) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Not in Zcash signing mode"));
    layoutHome();
    return;
  }

  if (zcash_signing.n_transparent_inputs == 0) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("No transparent inputs expected"));
    zcash_signing.active = false;
    memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
    layoutHome();
    return;
  }

  if (msg->index != zcash_signing.current_transparent_input) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Unexpected transparent input index"));
    zcash_signing.active = false;
    memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
    layoutHome();
    return;
  }

  if (msg->sighash.size != 32) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid sighash size"));
    zcash_signing.active = false;
    memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
    layoutHome();
    return;
  }

  /* PATH ENFORCEMENT: transparent inputs must use exactly
   * m/44'/133'/account'/change/index where:
   *   - account' is hardened and matches the session account
   *   - change is 0 (external) or 1 (internal)
   *   - index is unhardened
   *
   * This prevents a compromised host from pivoting a shielding approval
   * into signing with arbitrary secp256k1 keys on the device. */
  if (msg->address_n_count != 5) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Path must be m/44'/133'/account'/change/index"));
    zcash_signing.active = false;
    memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
    layoutHome();
    return;
  }

  if (msg->address_n[0] != (0x80000000 | 44) ||
      msg->address_n[1] != (0x80000000 | 133)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Path must start with m/44'/133'"));
    zcash_signing.active = false;
    memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
    layoutHome();
    return;
  }

  /* Account must be hardened and match the approved session */
  if (!(msg->address_n[2] & 0x80000000)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Account must be hardened"));
    zcash_signing.active = false;
    memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
    layoutHome();
    return;
  }

  uint32_t path_account = msg->address_n[2] & 0x7FFFFFFF;
  if (path_account != zcash_signing.account) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Account does not match approved session"));
    zcash_signing.active = false;
    memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
    layoutHome();
    return;
  }

  /* Change must be 0 (external) or 1 (internal), unhardened */
  if (msg->address_n[3] > 1) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Change must be 0 or 1"));
    zcash_signing.active = false;
    memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
    layoutHome();
    return;
  }

  /* Index must be unhardened */
  if (msg->address_n[4] & 0x80000000) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Index must not be hardened"));
    zcash_signing.active = false;
    memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
    layoutHome();
    return;
  }

  /* Per-input confirmation: show the user what's being signed */
  {
    char input_str[64];
    uint64_t amt = msg->has_amount ? msg->amount : 0;
    snprintf(input_str, sizeof(input_str), "Input %lu: %llu.%08llu ZEC",
             (unsigned long)(msg->index + 1),
             (unsigned long long)(amt / 100000000ULL),
             (unsigned long long)(amt % 100000000ULL));
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx,
                 "Sign Input", "Sign transparent input?\n%s",
                 input_str)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      zcash_signing.active = false;
      memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
      layoutHome();
      return;
    }
  }

  /* Derive the secp256k1 key at the validated Zcash BIP44 path */
  const CoinType *coin = fsm_getCoin(true, "Zcash");
  if (!coin) {
    fsm_sendFailure(FailureType_Failure_Other, _("Unknown coin: Zcash"));
    zcash_signing.active = false;
    memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
    layoutHome();
    return;
  }

  HDNode *node = fsm_getDerivedNode(coin->curve_name, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) {
    zcash_signing.active = false;
    memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
    layoutHome();
    return;
  }

  hdnode_fill_public_key(node);

  /* ECDSA sign the per-input sighash */
  uint8_t sig[64];
  if (hdnode_sign_digest(node, msg->sighash.bytes, sig, NULL, NULL) != 0) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("ECDSA signing failed"));
    memzero(node, sizeof(*node));
    zcash_signing.active = false;
    memzero(&zcash_signing.keys, sizeof(zcash_signing.keys));
    layoutHome();
    return;
  }

  /* DER encode the signature */
  uint8_t der_sig[73];
  int der_len = ecdsa_sig_to_der(sig, der_sig);

  /* Build response — signature is a required field (no has_ prefix in nanopb) */
  resp->signature.size = der_len;
  memcpy(resp->signature.bytes, der_sig, der_len);

  zcash_signing.current_transparent_input++;
  resp->has_next_index = true;

  if (zcash_signing.current_transparent_input >=
      zcash_signing.n_transparent_inputs) {
    resp->next_index = 0xFF;
  } else {
    resp->next_index = zcash_signing.current_transparent_input;
  }

  memzero(node, sizeof(*node));
  memzero(sig, sizeof(sig));

  msg_write(MessageType_MessageType_ZcashTransparentSig, resp);
  layoutProgress(_("Signing Zcash"), 0);
}
