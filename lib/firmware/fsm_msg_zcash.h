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
#include <limits.h>

#include "keepkey/firmware/zcash.h"
#include "trezor/crypto/blake2b.h"
#include "trezor/crypto/pallas.h"
#include "trezor/crypto/redpallas.h"
#include "trezor/crypto/memzero.h"

/* Precomputed empty digest constants for shielded-only transactions.
 * These are BLAKE2b-256 with the respective personalizations over empty input.
 * Verified against Keystone3 test vectors. */
static const uint8_t EMPTY_TRANSPARENT_DIGEST[32] = {
    0xc3, 0x3f, 0x2e, 0x95, 0x70, 0x5f, 0xaa, 0xb3, 0x5f, 0x8d, 0x53,
    0x3f, 0xa6, 0x1e, 0x95, 0xc3, 0xb7, 0xaa, 0xba, 0x07, 0x76, 0xb8,
    0x74, 0xa9, 0xf7, 0x4f, 0xc1, 0x27, 0x84, 0x37, 0x6a, 0x59};

static const uint8_t EMPTY_SAPLING_DIGEST[32] = {
    0x6f, 0x2f, 0xc8, 0xf9, 0x8f, 0xea, 0xfd, 0x94, 0xe7, 0x4a, 0x0d,
    0xf4, 0xbe, 0xd7, 0x43, 0x91, 0xee, 0x0b, 0x5a, 0x69, 0x94, 0x5e,
    0x4c, 0xed, 0x8c, 0xa8, 0xa0, 0x95, 0x20, 0x6f, 0x00, 0xae};

#define ZCASH_MAX_ACTIONS 16
#define ZCASH_MAX_TRANSPARENT_INPUTS 8
#define ZCASH_MAX_TRANSPARENT_OUTPUTS 8
#define ZCASH_MAX_TRANSPARENT_SCRIPT_PUBKEY 128

typedef struct {
  bool received;
  uint8_t prevout_txid[32];
  uint32_t prevout_index;
  uint32_t sequence;
  uint64_t amount;
  uint8_t script_pubkey[ZCASH_MAX_TRANSPARENT_SCRIPT_PUBKEY];
  size_t script_pubkey_size;
  uint32_t address_n[8];
  uint32_t address_n_count;
} ZcashTransparentInputState;

typedef struct {
  bool received;
  uint64_t amount;
  uint8_t script_pubkey[ZCASH_MAX_TRANSPARENT_SCRIPT_PUBKEY];
  size_t script_pubkey_size;
} ZcashTransparentOutputState;

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
  uint8_t header_digest[32];
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
  /* Signatures buffer: one 64-byte sig per action */
  uint8_t signatures[ZCASH_MAX_ACTIONS][64];
  /* Phase 3: transparent shielding state */
  bool has_expected_transparent_digest;
  uint8_t expected_transparent_digest[32];
  bool transparent_digest_verified;
  uint32_t n_transparent_outputs;
  uint32_t current_transparent_output;
  uint32_t n_transparent_inputs;
  uint32_t current_transparent_input;
  ZcashTransparentOutputState
      transparent_outputs[ZCASH_MAX_TRANSPARENT_OUTPUTS];
  ZcashTransparentInputState transparent_inputs[ZCASH_MAX_TRANSPARENT_INPUTS];
  /* Deferred transparent ECDSA sigs — buffered until Orchard/fee final gate */
  bool has_pending_transparent;
  ZcashTransparentSigned pending_transparent;
} zcash_signing;

/* Public API; declared in keepkey/firmware/zcash.h. */
void zcash_signing_abort(void) {
  /* Centralized cleanup: stop the trickle progress animation here so every
   * abort path (Cancel, ClearSession, failures) kills it even when the caller
   * does not go through layoutHome()/layout_clear_animations(). */
  layoutProgressTrickleStop();
  memzero(&zcash_signing, sizeof(zcash_signing));
}

static bool zcash_script_is_p2pkh(const uint8_t* script, size_t script_size) {
  return script && script_size == 25 && script[0] == 0x76 &&
         script[1] == 0xa9 && script[2] == 0x14 && script[23] == 0x88 &&
         script[24] == 0xac;
}

static bool zcash_script_is_p2sh(const uint8_t* script, size_t script_size) {
  return script && script_size == 23 && script[0] == 0xa9 &&
         script[1] == 0x14 && script[22] == 0x87;
}

static bool zcash_script_is_standard_transparent(const uint8_t* script,
                                                 size_t script_size) {
  return zcash_script_is_p2pkh(script, script_size) ||
         zcash_script_is_p2sh(script, script_size);
}

static bool zcash_transparent_script_to_address(const uint8_t* script,
                                                size_t script_size, char* out,
                                                size_t out_size) {
  if (!script || !out || out_size == 0) return false;

  const CoinType* coin = fsm_getCoin(true, "Zcash");
  if (!coin) return false;

  uint32_t address_type;
  const uint8_t* hash160;
  if (zcash_script_is_p2pkh(script, script_size)) {
    if (!coin->has_address_type) return false;
    address_type = coin->address_type;
    hash160 = script + 3;
  } else if (zcash_script_is_p2sh(script, script_size)) {
    if (!coin->has_address_type_p2sh) return false;
    address_type = coin->address_type_p2sh;
    hash160 = script + 2;
  } else {
    return false;
  }

  uint8_t raw[4 + 20] = {0};
  size_t prefix_len = address_prefix_bytes_len(address_type);
  if (prefix_len == 0 || prefix_len + 20 > sizeof(raw)) return false;
  address_write_prefix_bytes(address_type, raw);
  memcpy(raw + prefix_len, hash160, 20);
  return base58_encode_check(raw, (int)(prefix_len + 20), HASHER_SHA2D, out,
                             (int)out_size) != 0;
}

static void zcash_format_amount(uint64_t amount, char* out, size_t out_size) {
  snprintf(out, out_size, "%llu.%08llu ZEC",
           (unsigned long long)(amount / 100000000ULL),
           (unsigned long long)(amount % 100000000ULL));
}

/* Determine account — require explicit account or strict ZIP-32 path
 * m/32'/133'/account' (all hardened, exactly 3 elements). Shared by
 * ZcashSignPCZT / ZcashGetOrchardFVK / ZcashDisplayAddress so a malformed
 * host path cannot silently resolve to an unintended account. */
static bool zcash_resolve_account(bool has_account, uint32_t account_field,
                                  const uint32_t* address_n,
                                  uint32_t address_n_count,
                                  uint32_t* account_out) {
  if (has_account) {
    *account_out = account_field;
    return true;
  }
  if (address_n_count == 3 && address_n[0] == (0x80000000 | 32) &&
      address_n[1] == (0x80000000 | 133) && (address_n[2] & 0x80000000)) {
    *account_out = address_n[2] & 0x7FFFFFFF;
    return true;
  }
  fsm_sendFailure(
      FailureType_Failure_SyntaxError,
      _("Require account field or ZIP-32 path m/32'/133'/account'"));
  return false;
}

/* Optional seed_fingerprint binding (ZIP-32 §6.1). If the host asserts a
 * seed identity, verify it matches this device's seed before proceeding.
 * Catches "wrong device" attacks where the host accidentally targets a
 * different seed than the one it built the request against. */
static bool zcash_check_seed_fingerprint(bool has_expected,
                                         const uint8_t* expected,
                                         size_t expected_size) {
  if (!zcash_seed_fingerprint_request_valid(has_expected, expected_size)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Seed fingerprint must be 32 bytes"));
    return false;
  }
  if (!has_expected) return true;

  uint8_t actual_fp[32];
  if (!storage_zcashSeedFingerprint(true, actual_fp)) {
    fsm_sendFailure(FailureType_Failure_NotInitialized,
                    _("Device not initialized or seed unavailable"));
    return false;
  }
  bool match = memcmp(actual_fp, expected, 32) == 0;
  memzero(actual_fp, sizeof(actual_fp));
  if (!match) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Seed fingerprint mismatch — wrong device"));
    return false;
  }
  return true;
}

static bool zcash_verify_and_confirm_orchard_output(
    const ZcashPCZTAction* msg) {
  if (!msg->has_value || !msg->has_recipient ||
      msg->recipient.size != ZCASH_ORCHARD_RAW_RECEIVER_SIZE ||
      !msg->has_rseed || msg->rseed.size != 32) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Missing Orchard output metadata"));
    return false;
  }

  uint8_t computed_cmx[32];
  if (!zcash_orchard_compute_cmx(msg->recipient.bytes, msg->value,
                                 msg->nullifier.bytes, msg->rseed.bytes,
                                 computed_cmx) ||
      memcmp(computed_cmx, msg->cmx.bytes, 32) != 0) {
    memzero(computed_cmx, sizeof(computed_cmx));
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Orchard note commitment mismatch"));
    return false;
  }
  memzero(computed_cmx, sizeof(computed_cmx));

  char address[ZCASH_ORCHARD_UNIFIED_ADDRESS_SIZE];
  if (!zcash_orchard_receiver_to_unified_address(msg->recipient.bytes, "u",
                                                 address, sizeof(address))) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid Orchard recipient"));
    return false;
  }

  char amount_str[32];
  zcash_format_amount(msg->value, amount_str, sizeof(amount_str));
  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Zcash Output",
               "Send shielded ZEC?\n%s\nAmount: %s", address, amount_str)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Signing cancelled"));
    memzero(address, sizeof(address));
    return false;
  }

  memzero(address, sizeof(address));
  return true;
}

static bool zcash_compute_verified_fee(uint64_t* fee_out) {
  if (!fee_out) return false;

  int64_t net_transparent = 0;
  for (uint32_t i = 0; i < zcash_signing.n_transparent_inputs; i++) {
    const uint64_t amount = zcash_signing.transparent_inputs[i].amount;
    if (amount > (uint64_t)INT64_MAX ||
        net_transparent > INT64_MAX - (int64_t)amount) {
      return false;
    }
    net_transparent += (int64_t)amount;
  }

  for (uint32_t i = 0; i < zcash_signing.n_transparent_outputs; i++) {
    const uint64_t amount = zcash_signing.transparent_outputs[i].amount;
    if (amount > (uint64_t)INT64_MAX ||
        net_transparent < INT64_MIN + (int64_t)amount) {
      return false;
    }
    net_transparent -= (int64_t)amount;
  }

  const int64_t value_balance = zcash_signing.orchard_value_balance;
  if ((value_balance > 0 && net_transparent > INT64_MAX - value_balance) ||
      (value_balance < 0 && net_transparent < INT64_MIN - value_balance)) {
    return false;
  }

  const int64_t signed_fee = net_transparent + value_balance;
  if (signed_fee < 0) return false;

  *fee_out = (uint64_t)signed_fee;
  return true;
}

static bool zcash_verify_and_confirm_fee(void) {
  uint64_t verified_fee = 0;
  if (!zcash_compute_verified_fee(&verified_fee)) {
    fsm_sendFailure(FailureType_Failure_Other, _("Invalid transaction fee"));
    return false;
  }

  if (verified_fee != zcash_signing.fee) {
    fsm_sendFailure(FailureType_Failure_Other, _("Fee mismatch"));
    return false;
  }

  char fee_str[32];
  zcash_format_amount(verified_fee, fee_str, sizeof(fee_str));
  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Zcash Fee",
               "Confirm transaction fee?\n%s", fee_str)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Signing cancelled"));
    return false;
  }

  return true;
}

static void zcash_send_action_ack(uint32_t next_index) {
  ZcashPCZTActionAck* resp_ack = (ZcashPCZTActionAck*)msg_resp;
  memset(resp_ack, 0, sizeof(ZcashPCZTActionAck));
  resp_ack->has_next_index = true;
  resp_ack->next_index = next_index;
  msg_write(MessageType_MessageType_ZcashPCZTActionAck, resp_ack);

  /* The device now blocks until the host generates the (slow) Orchard proof for
   * this action. Ease the progress bar from the milestone already reached
   * toward the one this action will complete, so the screen keeps moving
   * instead of looking stuck at a frozen value. Stopped again when the action
   * arrives. */
  uint32_t n = zcash_signing.n_actions;
  if (n > 0) {
    int base = (int)((next_index * 1000) / n);
    int target = (int)(((next_index + 1) * 1000) / n);
    layoutProgressTrickle(_("Signing Zcash"), base, target);
  }
}

static void zcash_send_transparent_output_ack(uint32_t next_index) {
  ZcashTransparentAck* resp = (ZcashTransparentAck*)msg_resp;
  memset(resp, 0, sizeof(ZcashTransparentAck));
  resp->has_next_output_index = true;
  resp->next_output_index = next_index;
  msg_write(MessageType_MessageType_ZcashTransparentAck, resp);
}

static void zcash_send_transparent_input_ack(uint32_t next_index) {
  ZcashTransparentAck* resp = (ZcashTransparentAck*)msg_resp;
  memset(resp, 0, sizeof(ZcashTransparentAck));
  resp->has_next_input_index = true;
  resp->next_input_index = next_index;
  msg_write(MessageType_MessageType_ZcashTransparentAck, resp);
}

static bool zcash_build_transparent_digest_info(
    ZcashTransparentInputDigestInfo inputs[ZCASH_MAX_TRANSPARENT_INPUTS],
    ZcashTransparentOutputDigestInfo outputs[ZCASH_MAX_TRANSPARENT_OUTPUTS]) {
  for (uint32_t i = 0; i < zcash_signing.n_transparent_inputs; i++) {
    const ZcashTransparentInputState* stored =
        &zcash_signing.transparent_inputs[i];
    if (!stored->received) return false;
    inputs[i].prevout_txid = stored->prevout_txid;
    inputs[i].prevout_index = stored->prevout_index;
    inputs[i].sequence = stored->sequence;
    inputs[i].value = stored->amount;
    inputs[i].script_pubkey = stored->script_pubkey;
    inputs[i].script_pubkey_size = stored->script_pubkey_size;
  }

  for (uint32_t i = 0; i < zcash_signing.n_transparent_outputs; i++) {
    const ZcashTransparentOutputState* stored =
        &zcash_signing.transparent_outputs[i];
    if (!stored->received) return false;
    outputs[i].value = stored->amount;
    outputs[i].script_pubkey = stored->script_pubkey;
    outputs[i].script_pubkey_size = stored->script_pubkey_size;
  }

  return true;
}

static bool zcash_finalize_transparent_digest(void) {
  if (!zcash_signing.has_expected_transparent_digest) return false;

  ZcashTransparentInputDigestInfo inputs[ZCASH_MAX_TRANSPARENT_INPUTS] = {0};
  ZcashTransparentOutputDigestInfo outputs[ZCASH_MAX_TRANSPARENT_OUTPUTS] = {0};
  uint8_t transparent_digest[32] = {0};

  if (!zcash_build_transparent_digest_info(inputs, outputs) ||
      !zcash_compute_orchard_transparent_sig_digest(
          inputs, zcash_signing.n_transparent_inputs, outputs,
          zcash_signing.n_transparent_outputs, transparent_digest)) {
    memzero(transparent_digest, sizeof(transparent_digest));
    memzero(inputs, sizeof(inputs));
    memzero(outputs, sizeof(outputs));
    return false;
  }

  if (memcmp(transparent_digest, zcash_signing.expected_transparent_digest,
             32) != 0) {
    memzero(transparent_digest, sizeof(transparent_digest));
    memzero(inputs, sizeof(inputs));
    memzero(outputs, sizeof(outputs));
    return false;
  }

  zcash_compute_shielded_sighash(
      zcash_signing.header_digest, transparent_digest, EMPTY_SAPLING_DIGEST,
      zcash_signing.expected_orchard_digest, zcash_signing.branch_id,
      zcash_signing.sighash);
  zcash_signing.has_device_sighash = true;
  zcash_signing.transparent_digest_verified = true;

  memzero(transparent_digest, sizeof(transparent_digest));
  memzero(inputs, sizeof(inputs));
  memzero(outputs, sizeof(outputs));
  return true;
}

static bool zcash_sign_transparent_inputs(bool* cancelled) {
  if (!zcash_signing.transparent_digest_verified) return false;
  if (cancelled) *cancelled = false;

  bool ok = false;
  ZcashTransparentInputDigestInfo inputs[ZCASH_MAX_TRANSPARENT_INPUTS] = {0};
  ZcashTransparentOutputDigestInfo outputs[ZCASH_MAX_TRANSPARENT_OUTPUTS] = {0};
  if (!zcash_build_transparent_digest_info(inputs, outputs)) goto cleanup;

  const CoinType* coin = fsm_getCoin(true, "Zcash");
  if (!coin) goto cleanup;

  memset(&zcash_signing.pending_transparent, 0, sizeof(ZcashTransparentSigned));
  zcash_signing.pending_transparent.signatures_count =
      zcash_signing.n_transparent_inputs;

  for (uint32_t i = 0; i < zcash_signing.n_transparent_inputs; i++) {
    const ZcashTransparentInputState* stored =
        &zcash_signing.transparent_inputs[i];

    char input_str[64];
    char amount_str[32];
    zcash_format_amount(stored->amount, amount_str, sizeof(amount_str));
    snprintf(input_str, sizeof(input_str), "Input %lu: %s",
             (unsigned long)(i + 1), amount_str);
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Sign Input",
                 "Sign transparent input?\n%s", input_str)) {
      if (cancelled) *cancelled = true;
      goto cleanup;
    }

    HDNode* node = fsm_getDerivedNode(coin->curve_name, stored->address_n,
                                      stored->address_n_count, NULL);
    if (!node) goto cleanup;

    /* ZIP-244 §4.4: signature_digest = ZcashTxHash_(
     *   header_digest || transparent_sig_digest || sapling_digest ||
     * orchard_digest) Binding the transparent ECDSA sig to all four components
     * ensures it cannot be replayed in a transaction with different
     * Orchard/header data. */
    uint8_t t_sig_digest[32] = {0};
    uint8_t full_sighash[32] = {0};
    uint8_t sig[64] = {0};
    uint8_t der_sig[73] = {0};

    bool sign_ok =
        zcash_compute_transparent_sighash_digest(
            inputs, zcash_signing.n_transparent_inputs, outputs,
            zcash_signing.n_transparent_outputs, i, 0x01, t_sig_digest) &&
        zcash_compute_shielded_sighash(zcash_signing.header_digest,
                                       t_sig_digest, EMPTY_SAPLING_DIGEST,
                                       zcash_signing.expected_orchard_digest,
                                       zcash_signing.branch_id, full_sighash) &&
        hdnode_sign_digest(node, full_sighash, sig, NULL, NULL) == 0;

    memzero(node, sizeof(*node));
    memzero(t_sig_digest, sizeof(t_sig_digest));
    memzero(full_sighash, sizeof(full_sighash));

    if (!sign_ok) {
      memzero(sig, sizeof(sig));
      goto cleanup;
    }

    int der_len = ecdsa_sig_to_der(sig, der_sig);
    zcash_signing.pending_transparent.signatures[i].size = der_len;
    memcpy(zcash_signing.pending_transparent.signatures[i].bytes, der_sig,
           der_len);

    memzero(sig, sizeof(sig));
    memzero(der_sig, sizeof(der_sig));
  }

  zcash_signing.has_pending_transparent = true;
  ok = true;

cleanup:
  memzero(inputs, sizeof(inputs));
  memzero(outputs, sizeof(outputs));
  return ok;
}

void fsm_msgZcashSignPCZT(const ZcashSignPCZT* msg) {
  RESP_INIT(ZcashPCZTActionAck);

  CHECK_INITIALIZED

  CHECK_PIN

  /* Validate parameters */
  if (!msg->has_n_actions || msg->n_actions == 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("No actions specified"));
    layoutHome();
    return;
  }

  if (msg->n_actions > ZCASH_MAX_ACTIONS) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Too many Orchard actions"));
    layoutHome();
    return;
  }

  uint32_t account;
  if (!zcash_resolve_account(msg->has_account, msg->account, msg->address_n,
                             msg->address_n_count, &account)) {
    layoutHome();
    return;
  }

  uint32_t n_tinputs =
      msg->has_n_transparent_inputs ? msg->n_transparent_inputs : 0;
  if (n_tinputs > ZCASH_MAX_TRANSPARENT_INPUTS) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Too many transparent inputs"));
    layoutHome();
    return;
  }

  uint32_t n_toutputs =
      msg->has_n_transparent_outputs ? msg->n_transparent_outputs : 0;
  if (n_toutputs > ZCASH_MAX_TRANSPARENT_OUTPUTS) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Too many transparent outputs"));
    layoutHome();
    return;
  }

  uint32_t branch_id = msg->has_branch_id ? msg->branch_id : 0;

  ZcashPCZTSigningRequestMeta signing_meta = {0};
  signing_meta.has_header_digest = msg->has_header_digest;
  signing_meta.header_digest_size = msg->header_digest.size;
  signing_meta.has_transparent_digest = msg->has_transparent_digest;
  signing_meta.transparent_digest_size = msg->transparent_digest.size;
  signing_meta.has_sapling_digest = msg->has_sapling_digest;
  signing_meta.sapling_digest_size = msg->sapling_digest.size;
  signing_meta.has_orchard_digest = msg->has_orchard_digest;
  signing_meta.orchard_digest_size = msg->orchard_digest.size;
  signing_meta.has_orchard_flags = msg->has_orchard_flags;
  signing_meta.orchard_flags = msg->orchard_flags;
  signing_meta.has_orchard_value_balance = msg->has_orchard_value_balance;
  signing_meta.has_orchard_anchor = msg->has_orchard_anchor;
  signing_meta.orchard_anchor_size = msg->orchard_anchor.size;
  signing_meta.has_header_fields =
      msg->has_tx_version && msg->has_version_group_id && msg->has_branch_id &&
      msg->has_lock_time && msg->has_expiry_height;
  signing_meta.n_transparent_inputs = n_tinputs;
  signing_meta.n_transparent_outputs = n_toutputs;

  const ZcashPCZTSigningRequestStatus status =
      zcash_pczt_signing_request_status(&signing_meta);
  if (status != ZCASH_PCZT_SIGNING_REQUEST_OK) {
    static const char* const status_msgs[] = {
        [ZCASH_PCZT_SIGNING_REQUEST_MISSING_TX_DIGESTS] =
            "Missing transaction digests",
        [ZCASH_PCZT_SIGNING_REQUEST_INVALID_DIGEST_SIZE] =
            "Invalid transaction digest",
        [ZCASH_PCZT_SIGNING_REQUEST_MISSING_HEADER_FIELDS] =
            "Missing transaction header",
        [ZCASH_PCZT_SIGNING_REQUEST_UNSUPPORTED_SAPLING_COMPONENT] =
            "Sapling not supported",
        [ZCASH_PCZT_SIGNING_REQUEST_MISSING_TRANSPARENT_DIGEST] =
            "Missing transparent digest",
        [ZCASH_PCZT_SIGNING_REQUEST_MISSING_ORCHARD_METADATA] =
            "Missing Orchard metadata",
    };
    const char* status_msg =
        ((size_t)status < sizeof(status_msgs) / sizeof(status_msgs[0]) &&
         status_msgs[status])
            ? status_msgs[status]
            : "Missing Orchard metadata";
    fsm_sendFailure(FailureType_Failure_SyntaxError, _(status_msg));
    layoutHome();
    return;
  }

  uint8_t header_digest[32];
  if (!zcash_compute_header_digest(msg->tx_version, msg->version_group_id,
                                   branch_id, msg->lock_time,
                                   msg->expiry_height, header_digest) ||
      memcmp(header_digest, msg->header_digest.bytes, 32) != 0) {
    fsm_sendFailure(FailureType_Failure_Other, _("Header digest mismatch"));
    layoutHome();
    return;
  }

  /* Confirm with user */
  char amount_str[32];
  char fee_str[32];
  uint64_t total = msg->has_total_amount ? msg->total_amount : 0;
  uint64_t fee = msg->has_fee ? msg->fee : 0;

  /* Format amounts (1 ZEC = 100,000,000 zatoshis) */
  zcash_format_amount(total, amount_str, sizeof(amount_str));
  zcash_format_amount(fee, fee_str, sizeof(fee_str));

  /* Display confirmation — different text for shielded-only vs hybrid */
  if (n_tinputs > 0) {
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Zcash Shield",
                 "Shield transparent ZEC to Orchard?\n"
                 "Amount: %s\nFee: %s\nInputs: %lu\nOutputs: %lu\nActions: %lu",
                 amount_str, fee_str, (unsigned long)n_tinputs,
                 (unsigned long)n_toutputs, (unsigned long)msg->n_actions)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  } else if (n_toutputs > 0) {
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Zcash Shielded",
                 "Sign transaction with transparent outputs?\n"
                 "Amount: %s\nFee: %s\nOutputs: %lu\nActions: %lu",
                 amount_str, fee_str, (unsigned long)n_toutputs,
                 (unsigned long)msg->n_actions)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  } else {
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Zcash Shielded",
                 "Sign shielded transaction?\n"
                 "Amount: %s\nFee: %s\nActions: %lu",
                 amount_str, fee_str, (unsigned long)msg->n_actions)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  }

  /* Approved — show the signing screen before Orchard key derivation, which
   * is seconds of Pallas math with nothing else drawing. */
  layoutProgress(_("Signing Zcash"), 0);

  if (!zcash_check_seed_fingerprint(msg->has_expected_seed_fingerprint,
                                    msg->expected_seed_fingerprint.bytes,
                                    msg->expected_seed_fingerprint.size)) {
    layoutHome();
    return;
  }

  /* Clear any stale state from a prior (possibly abandoned) session before
   * starting a new one, so buffered transparent signatures or Orchard state
   * from an earlier PCZT can never leak into this transaction. */
  zcash_signing_abort();

  /* Derive Orchard keys via storage; the seed never leaves storage.c. */
  if (!storage_zcashOrchardKeys(account, true, &zcash_signing.keys)) {
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
  zcash_signing.branch_id = branch_id;
  memcpy(zcash_signing.header_digest, header_digest, 32);
  zcash_signing.has_device_sighash = false;
  zcash_signing.verify_orchard_digest = false;
  zcash_signing.n_transparent_outputs =
      msg->has_n_transparent_outputs ? msg->n_transparent_outputs : 0;
  zcash_signing.current_transparent_output = 0;
  zcash_signing.n_transparent_inputs =
      msg->has_n_transparent_inputs ? msg->n_transparent_inputs : 0;
  zcash_signing.current_transparent_input = 0;
  zcash_signing.has_expected_transparent_digest = false;
  zcash_signing.transparent_digest_verified = false;

  /* Phase 2a: Compute sighash on-device from validated sub-digests.
   *
   * TRUST MODEL:
   *
   * What the device verifies:
   *   - Orchard digest: recomputed from streamed action data (Phase 2b)
   *     covering nullifiers, commitments, ephemeral keys, ciphertexts,
   *     value commitments, randomized keys, flags, value balance, anchor.
   *   - Orchard outputs: each displayed receiver/value is bound to cmx by
   *     recomputing the note commitment from recipient/value/rseed/rho before
   *     any authorization signature is emitted.
   *   - Transaction fee: computed from streamed transparent totals plus
   *     orchard_value_balance and compared to the requested fee before final
   *     user confirmation.
   *   - Sighash: assembled on-device from the 4 sub-digests.
   *   - transparent_digest: recomputed from streamed transparent outputs and
   *     inputs before any transparent or Orchard signature is emitted.
   *   - header_digest: recomputed from plaintext transaction header fields
   *     and compared to the supplied component digest.
   *   - Sapling: explicitly unsupported in this signing path. The device
   *     always uses the ZIP-244 empty Sapling digest and rejects any
   *     host-provided Sapling component.
   *
   * total_amount is a summary prompt. Transparent recipients, Orchard output
   * recipients, Orchard output values, and the transaction fee all have their
   * own verification gates before signatures are released.
   *
   * For shielded-only transactions (no transparent inputs):
   *   transparent_digest defaults to the well-known empty hash,
   *   so no trust assumption is needed for that component.
   *
   * For mixed transactions:
   *   transparent_digest is mandatory and verified against plaintext
   *   transparent metadata before local sighash derivation. */
  uint8_t t_digest[32], s_digest[32];

  if (n_tinputs == 0 && n_toutputs == 0) {
    memcpy(t_digest, EMPTY_TRANSPARENT_DIGEST, 32);
    memcpy(s_digest, EMPTY_SAPLING_DIGEST, 32);

    zcash_compute_shielded_sighash(
        header_digest, t_digest, s_digest, msg->orchard_digest.bytes,
        zcash_signing.branch_id, zcash_signing.sighash);
    zcash_signing.has_device_sighash = true;
    zcash_signing.transparent_digest_verified = true;
  } else {
    memcpy(zcash_signing.expected_transparent_digest,
           msg->transparent_digest.bytes, 32);
    zcash_signing.has_expected_transparent_digest = true;
  }
  memzero(t_digest, sizeof(t_digest));
  memzero(s_digest, sizeof(s_digest));

  /* Phase 2b: Orchard digest verification is mandatory for signing.
   * The device incrementally hashes each action's data and verifies the
   * computed orchard_digest matches the one used for sighash. */
  memcpy(zcash_signing.expected_orchard_digest, msg->orchard_digest.bytes, 32);
  zcash_signing.orchard_flags = (uint8_t)msg->orchard_flags;
  zcash_signing.orchard_value_balance = msg->orchard_value_balance;
  memcpy(zcash_signing.orchard_anchor, msg->orchard_anchor.bytes, 32);

  blake2b_InitPersonal(&zcash_signing.compact_ctx, 32, "ZTxIdOrcActCHash", 16);
  blake2b_InitPersonal(&zcash_signing.memos_ctx, 32, "ZTxIdOrcActMHash", 16);
  blake2b_InitPersonal(&zcash_signing.noncompact_ctx, 32, "ZTxIdOrcActNHash",
                       16);
  zcash_signing.verify_orchard_digest = true;

  /* Draw the initial static progress BEFORE requesting the first component:
   * for the actions-only path zcash_send_action_ack() arms the trickle, and a
   * layoutProgress() after it would clear the animation queue and freeze it. */
  layoutProgress(_("Signing Zcash"), 0);

  /* Request the first plaintext component. Transparent outputs are reviewed
   * before any transparent input or Orchard signature can be emitted. */
  if (zcash_signing.n_transparent_outputs > 0) {
    zcash_send_transparent_output_ack(0);
  } else if (zcash_signing.n_transparent_inputs > 0) {
    zcash_send_transparent_input_ack(0);
  } else {
    zcash_send_action_ack(0);
  }
}

void fsm_msgZcashGetOrchardFVK(const ZcashGetOrchardFVK* msg) {
  RESP_INIT(ZcashOrchardFVK);

  CHECK_INITIALIZED

  CHECK_PIN

  uint32_t account;
  if (!zcash_resolve_account(msg->has_account, msg->account, msg->address_n,
                             msg->address_n_count, &account)) {
    layoutHome();
    return;
  }

  if (msg->has_show_display && msg->show_display &&
      !confirm(ButtonRequestType_ButtonRequest_ProtectCall,
               "Export Zcash View Key",
               "Export Orchard viewing key for account %u?\nReveals Zcash "
               "activity.",
               (unsigned)account)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, _("Cancelled"));
    layoutHome();
    return;
  }

  /* Derive Orchard keys via storage; the seed never leaves storage.c. */
  layoutProgress(_("Deriving Zcash"), 0);
  ZcashOrchardKeys keys;
  if (!storage_zcashOrchardKeys(account, true, &keys)) {
    fsm_sendFailure(FailureType_Failure_NotInitialized,
                    _("Orchard key derivation failed (seed unavailable?)"));
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

  /* Seed identity (ZIP-32 §6.1). Lets the host pin this FVK to a
   * specific device-seed identity for later signing/display flows. */
  uint8_t fp[32];
  if (storage_zcashSeedFingerprint(true, fp)) {
    resp->has_seed_fingerprint = true;
    resp->seed_fingerprint.size = 32;
    memcpy(resp->seed_fingerprint.bytes, fp, 32);
    memzero(fp, sizeof(fp));
  }

  /* Clean up sensitive data */
  memzero(&ask_scalar, sizeof(ask_scalar));
  memzero(&keys, sizeof(keys));

  msg_write(MessageType_MessageType_ZcashOrchardFVK, resp);
  layoutHome();
}

void fsm_msgZcashDisplayAddress(const ZcashDisplayAddress* msg) {
  RESP_INIT(ZcashAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  uint32_t account;
  if (!zcash_resolve_account(msg->has_account, msg->account, msg->address_n,
                             msg->address_n_count, &account)) {
    layoutHome();
    return;
  }

  if (!zcash_check_seed_fingerprint(msg->has_expected_seed_fingerprint,
                                    msg->expected_seed_fingerprint.bytes,
                                    msg->expected_seed_fingerprint.size)) {
    layoutHome();
    return;
  }

  /* Derive Orchard keys via storage; the seed never leaves storage.c. */
  layoutProgress(_("Deriving Zcash"), 0);
  ZcashOrchardKeys keys;
  if (!storage_zcashOrchardKeys(account, true, &keys)) {
    fsm_sendFailure(FailureType_Failure_NotInitialized,
                    _("Orchard key derivation failed (seed unavailable?)"));
    layoutHome();
    return;
  }

  layoutProgress(_("Deriving address"), 650);
  char derived_address[sizeof(resp->address)];
  const uint8_t default_receiver_index[11] = {0};
  if (!zcash_orchard_derive_unified_address(&keys, default_receiver_index, "u",
                                            derived_address,
                                            sizeof(derived_address))) {
    memzero(&keys, sizeof(keys));
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Orchard address derivation failed"));
    layoutHome();
    return;
  }

  /* Clean up sensitive key material BEFORE display prompt. */
  memzero(&keys, sizeof(keys));

  layoutProgress(_("Loading address"), 1000);

  char desc[48];
  snprintf(desc, sizeof(desc), "Zcash #%lu Orchard", (unsigned long)account);
  if (!confirm_zcash_address(desc, derived_address)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Address display cancelled"));
    layoutHome();
    return;
  }

  /* User confirmed — return the address bound to this device's seed. */
  resp->has_address = true;
  strlcpy(resp->address, derived_address, sizeof(resp->address));

  /* Seed identity (ZIP-32 §6.1) — pin the attestation to this device. */
  uint8_t fp[32];
  if (storage_zcashSeedFingerprint(true, fp)) {
    resp->has_seed_fingerprint = true;
    resp->seed_fingerprint.size = 32;
    memcpy(resp->seed_fingerprint.bytes, fp, 32);
    memzero(fp, sizeof(fp));
  }

  msg_write(MessageType_MessageType_ZcashAddress, resp);
  layoutHome();
}

void fsm_msgZcashPCZTAction(const ZcashPCZTAction* msg) {
  if (!zcash_signing.active) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Not in Zcash signing mode"));
    layoutHome();
    return;
  }

  /* An action arrived: stop the trickle so the exact per-action milestone (and
   * the fee confirm reached at completion) draws cleanly. Re-armed by the next
   * zcash_send_action_ack() if more actions remain. */
  layoutProgressTrickleStop();

  /* Enforce transparent phase completion: if the session declared any
   * transparent data, all plaintext must be streamed and verified before
   * Orchard actions.
   * This prevents a malicious host from skipping transparent-input
   * confirmations and jumping straight to Orchard signing. */
  if (zcash_signing.current_transparent_output <
          zcash_signing.n_transparent_outputs ||
      zcash_signing.current_transparent_input <
          zcash_signing.n_transparent_inputs ||
      ((zcash_signing.n_transparent_outputs > 0 ||
        zcash_signing.n_transparent_inputs > 0) &&
       !zcash_signing.transparent_digest_verified)) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Transparent data not yet complete"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  /* Validate action index */
  if (!msg->has_index || msg->index != zcash_signing.current_action) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Unexpected action index"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  /* Validate required fields */
  if (!msg->has_alpha || msg->alpha.size != 32) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Missing or invalid alpha randomizer"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  /* Phase 2a: a device-computed sighash is mandatory. */
  if (!zcash_signing.has_device_sighash) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Missing transaction digests"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  const bool has_orchard_action_data =
      zcash_signing.verify_orchard_digest && msg->has_nullifier &&
      msg->nullifier.size == 32 && msg->has_cmx && msg->cmx.size == 32 &&
      msg->has_epk && msg->epk.size == 32 && msg->has_enc_compact &&
      msg->enc_compact.size == 52 && msg->has_enc_memo &&
      msg->enc_memo.size == 512 && msg->has_enc_noncompact &&
      /* 580-byte enc_ciphertext = compact(52) + memo(512) + noncompact(16);
       * pin the exact size like every sibling field so a host serializer bug
       * fails fast per-action instead of as an end-of-flow digest mismatch. */
      msg->enc_noncompact.size == 16 && msg->has_cv_net &&
      msg->cv_net.size == 32 && msg->has_rk && msg->rk.size == 32 &&
      msg->has_out_ciphertext && msg->out_ciphertext.size == 80;

  if (!has_orchard_action_data) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Missing Orchard action data"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  if (!zcash_verify_and_confirm_orchard_output(msg)) {
    zcash_signing_abort();
    layoutHome();
    return;
  }

  /* The user just approved — switch to the signing screen NOW. RedPallas
   * signing below is many seconds of pure device-side math, and without
   * this draw the dismissed dialog would sit on screen the whole time. */
  layoutProgress(_("Signing Zcash"), (zcash_signing.current_action * 1000) /
                                         zcash_signing.n_actions);

  /* Phase 2b: feed action data into incremental BLAKE2b contexts */
  blake2b_Update(&zcash_signing.compact_ctx, msg->nullifier.bytes, 32);
  blake2b_Update(&zcash_signing.compact_ctx, msg->cmx.bytes, 32);
  blake2b_Update(&zcash_signing.compact_ctx, msg->epk.bytes, 32);
  blake2b_Update(&zcash_signing.compact_ctx, msg->enc_compact.bytes, 52);

  blake2b_Update(&zcash_signing.memos_ctx, msg->enc_memo.bytes, 512);

  blake2b_Update(&zcash_signing.noncompact_ctx, msg->cv_net.bytes, 32);
  blake2b_Update(&zcash_signing.noncompact_ctx, msg->rk.bytes, 32);
  blake2b_Update(&zcash_signing.noncompact_ctx, msg->enc_noncompact.bytes,
                 msg->enc_noncompact.size);
  blake2b_Update(&zcash_signing.noncompact_ctx, msg->out_ciphertext.bytes, 80);

  const uint8_t* sighash = zcash_signing.sighash;

  /* Sign this action with RedPallas:
   * sig = RedPallas.sign(ask, alpha, sighash) */
  if (redpallas_sign_digest(zcash_signing.keys.ask, msg->alpha.bytes, sighash,
                            zcash_signing.signatures[msg->index]) != 0) {
    fsm_sendFailure(FailureType_Failure_Other, _("RedPallas signing failed"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  zcash_signing.current_action++;

  /* Update progress */
  uint32_t progress =
      (zcash_signing.current_action * 1000) / zcash_signing.n_actions;
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
                     (const uint8_t*)&zcash_signing.orchard_value_balance, 8);
      blake2b_Update(&orchard_ctx, zcash_signing.orchard_anchor, 32);

      uint8_t computed_orchard_digest[32];
      blake2b_Final(&orchard_ctx, computed_orchard_digest, 32);

      /* Verify computed matches expected */
      if (memcmp(computed_orchard_digest, zcash_signing.expected_orchard_digest,
                 32) != 0) {
        fsm_sendFailure(FailureType_Failure_Other,
                        _("Orchard digest mismatch: transaction data "
                          "does not match sighash"));
        zcash_signing_abort();
        layoutHome();
        return;
      }
    }

    if (!zcash_verify_and_confirm_fee()) {
      zcash_signing_abort();
      layoutHome();
      return;
    }

    /* Release deferred transparent ECDSA sigs at the same gate as Orchard sigs
     * — both are sent only after Orchard digest verification and fee
     * confirmation. */
    if (zcash_signing.has_pending_transparent) {
      ZcashTransparentSigned* t_resp = (ZcashTransparentSigned*)msg_resp;
      memcpy(t_resp, &zcash_signing.pending_transparent,
             sizeof(ZcashTransparentSigned));
      msg_write(MessageType_MessageType_ZcashTransparentSigned, t_resp);
    }

    /* All done - send the collected Orchard signatures */
    ZcashSignedPCZT* resp_signed = (ZcashSignedPCZT*)msg_resp;
    memset(resp_signed, 0, sizeof(ZcashSignedPCZT));

    resp_signed->signatures_count = zcash_signing.n_actions;
    for (uint32_t i = 0; i < zcash_signing.n_actions; i++) {
      resp_signed->signatures[i].size = 64;
      memcpy(resp_signed->signatures[i].bytes, zcash_signing.signatures[i], 64);
    }

    /* Clean up */
    zcash_signing_abort();

    msg_write(MessageType_MessageType_ZcashSignedPCZT, resp_signed);
    layoutHome();
  } else {
    /* Request next action */
    zcash_send_action_ack(zcash_signing.current_action);
  }
}

void fsm_msgZcashTransparentOutput(const ZcashTransparentOutput* msg) {
  if (!zcash_signing.active) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Not in Zcash signing mode"));
    layoutHome();
    return;
  }

  if (zcash_signing.n_transparent_outputs == 0) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("No transparent outputs expected"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  if (zcash_signing.current_transparent_input != 0) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Transparent outputs must come first"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  if (msg->index != zcash_signing.current_transparent_output) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Unexpected transparent output index"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  if (!msg->has_amount || !msg->has_script_pubkey ||
      msg->script_pubkey.size == 0 ||
      msg->script_pubkey.size > ZCASH_MAX_TRANSPARENT_SCRIPT_PUBKEY) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid transparent output script"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  char address[64];
  if (!zcash_transparent_script_to_address(msg->script_pubkey.bytes,
                                           msg->script_pubkey.size, address,
                                           sizeof(address))) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Unsupported transparent output script"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  char amount_str[32];
  zcash_format_amount(msg->amount, amount_str, sizeof(amount_str));
  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Zcash Output",
               "Send transparent ZEC?\n%s\nAmount: %s", address, amount_str)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Signing cancelled"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  ZcashTransparentOutputState* stored =
      &zcash_signing.transparent_outputs[msg->index];
  stored->received = true;
  stored->amount = msg->amount;
  stored->script_pubkey_size = msg->script_pubkey.size;
  memcpy(stored->script_pubkey, msg->script_pubkey.bytes,
         msg->script_pubkey.size);

  zcash_signing.current_transparent_output++;

  /* Static draw before the dispatch: the actions transition below arms the
   * trickle, and a layoutProgress() after it would clear and freeze it. */
  layoutProgress(_("Signing Zcash"), 0);

  if (zcash_signing.current_transparent_output <
      zcash_signing.n_transparent_outputs) {
    zcash_send_transparent_output_ack(zcash_signing.current_transparent_output);
  } else if (zcash_signing.n_transparent_inputs > 0) {
    zcash_send_transparent_input_ack(0);
  } else {
    if (!zcash_finalize_transparent_digest()) {
      fsm_sendFailure(FailureType_Failure_Other,
                      _("Transparent digest mismatch"));
      zcash_signing_abort();
      layoutHome();
      return;
    }
    zcash_send_action_ack(0);
  }
}

/* Phase 3: Transparent plaintext streaming for hybrid shielding
 * transactions. The host streams all outputs first, then all inputs. Only after
 * the firmware verifies transparent_digest from the streamed plaintext does it
 * derive per-input ZIP-244 sighashes and emit ECDSA signatures. */
void fsm_msgZcashTransparentInput(const ZcashTransparentInput* msg) {
  if (!zcash_signing.active) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Not in Zcash signing mode"));
    layoutHome();
    return;
  }

  if (zcash_signing.n_transparent_inputs == 0) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("No transparent inputs expected"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  if (zcash_signing.current_transparent_output <
      zcash_signing.n_transparent_outputs) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Transparent outputs not yet complete"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  if (msg->index != zcash_signing.current_transparent_input) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Unexpected transparent input index"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  if (msg->has_sighash) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Host transparent sighash rejected"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  if (!msg->has_amount || !msg->has_prevout_txid ||
      msg->prevout_txid.size != 32 || !msg->has_prevout_index ||
      !msg->has_sequence || !msg->has_script_pubkey ||
      msg->script_pubkey.size == 0 ||
      msg->script_pubkey.size > ZCASH_MAX_TRANSPARENT_SCRIPT_PUBKEY) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid transparent input data"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  if (!zcash_script_is_standard_transparent(msg->script_pubkey.bytes,
                                            msg->script_pubkey.size)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Unsupported transparent input script"));
    zcash_signing_abort();
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
    zcash_signing_abort();
    layoutHome();
    return;
  }

  if (msg->address_n[0] != (0x80000000 | 44) ||
      msg->address_n[1] != (0x80000000 | 133)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Path must start with m/44'/133'"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  /* Account must be hardened and match the approved session */
  if (!(msg->address_n[2] & 0x80000000)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Account must be hardened"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  uint32_t path_account = msg->address_n[2] & 0x7FFFFFFF;
  if (path_account != zcash_signing.account) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Account does not match approved session"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  /* Change must be 0 (external) or 1 (internal), unhardened */
  if (msg->address_n[3] > 1) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Change must be 0 or 1"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  /* Index must be unhardened */
  if (msg->address_n[4] & 0x80000000) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Index must not be hardened"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  ZcashTransparentInputState* stored =
      &zcash_signing.transparent_inputs[msg->index];
  stored->received = true;
  stored->amount = msg->amount;
  memcpy(stored->prevout_txid, msg->prevout_txid.bytes, 32);
  stored->prevout_index = msg->prevout_index;
  stored->sequence = msg->sequence;
  stored->script_pubkey_size = msg->script_pubkey.size;
  memcpy(stored->script_pubkey, msg->script_pubkey.bytes,
         msg->script_pubkey.size);
  stored->address_n_count = msg->address_n_count;
  memcpy(stored->address_n, msg->address_n,
         msg->address_n_count * sizeof(msg->address_n[0]));

  zcash_signing.current_transparent_input++;

  if (zcash_signing.current_transparent_input <
      zcash_signing.n_transparent_inputs) {
    zcash_send_transparent_input_ack(zcash_signing.current_transparent_input);
    layoutProgress(_("Signing Zcash"), 0);
    return;
  }

  if (!zcash_finalize_transparent_digest()) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Transparent digest mismatch"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  bool cancelled = false;
  if (!zcash_sign_transparent_inputs(&cancelled)) {
    fsm_sendFailure(cancelled ? FailureType_Failure_ActionCancelled
                              : FailureType_Failure_Other,
                    cancelled ? _("Signing cancelled")
                              : _("Transparent input signing failed"));
    zcash_signing_abort();
    layoutHome();
    return;
  }

  /* Transparent ECDSA sigs are buffered in zcash_signing.pending_transparent.
   * They are released at the same final gate as Orchard sigs, after Orchard
   * digest verification and fee confirmation. */
  /* Static draw before arming: zcash_send_action_ack() arms the trickle, so a
   * layoutProgress() after it would clear the animation queue and freeze it. */
  layoutProgress(_("Signing Zcash"), 0);
  zcash_send_action_ack(0);
}
