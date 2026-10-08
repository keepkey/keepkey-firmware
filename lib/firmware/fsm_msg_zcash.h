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

/* Included here: this file is #include'd inside fsm.c. */
#include "trezor/crypto/blake2b.h"
#include "trezor/crypto/redpallas.h"
#include "trezor/crypto/memzero.h"

/* Empty-component digests: BLAKE2b-256 of empty input under each
 * personalization (verified against Keystone3 vectors). */
static const uint8_t EMPTY_TRANSPARENT_DIGEST[32] = {
    0xc3, 0x3f, 0x2e, 0x95, 0x70, 0x5f, 0xaa, 0xb3, 0x5f, 0x8d, 0x53,
    0x3f, 0xa6, 0x1e, 0x95, 0xc3, 0xb7, 0xaa, 0xba, 0x07, 0x76, 0xb8,
    0x74, 0xa9, 0xf7, 0x4f, 0xc1, 0x27, 0x84, 0x37, 0x6a, 0x59};

static const uint8_t EMPTY_SAPLING_DIGEST[32] = {
    0x6f, 0x2f, 0xc8, 0xf9, 0x8f, 0xea, 0xfd, 0x94, 0xe7, 0x4a, 0x0d,
    0xf4, 0xbe, 0xd7, 0x43, 0x91, 0xee, 0x0b, 0x5a, 0x69, 0x94, 0x5e,
    0x4c, 0xed, 0x8c, 0xa8, 0xa0, 0x95, 0x20, 0x6f, 0x00, 0xae};

/* ZIP-229 v6 Orchard-protocol personalizations; Sapling's is unchanged. */
static const uint8_t EMPTY_ORCHARD_DIGEST_V6[32] = {
    0xa3, 0x36, 0x7d, 0x2f, 0xde, 0xa2, 0x91, 0x01, 0x59, 0xfc, 0x50,
    0x26, 0xe9, 0xbf, 0x1f, 0xcc, 0xd3, 0xe2, 0x8c, 0xe5, 0xe6, 0xde,
    0x46, 0xbf, 0xb7, 0x15, 0x87, 0x23, 0x0e, 0xea, 0x95, 0x15};

static const uint8_t EMPTY_IRONWOOD_DIGEST_V6[32] = {
    0xb9, 0xcf, 0xe6, 0x43, 0xce, 0x45, 0xb2, 0x8c, 0x33, 0x19, 0x0f,
    0x0d, 0x52, 0x23, 0xe4, 0x75, 0x97, 0x2f, 0x2a, 0x14, 0x9d, 0xc5,
    0x44, 0x04, 0xfd, 0x83, 0x65, 0x52, 0x1f, 0x84, 0x16, 0xc5};

/* The empty Orchard bundle digest: ZIP-244 for v5, ZIP-229 for v6. */
static void zcash_empty_orchard_digest(bool transaction_v6, uint8_t out[32]) {
  if (transaction_v6) {
    memcpy(out, EMPTY_ORCHARD_DIGEST_V6, 32);
    return;
  }
  BLAKE2B_CTX ctx;
  blake2b_InitPersonal(&ctx, 32, "ZTxIdOrchardHash", 16);
  blake2b_Final(&ctx, out, 32);
}

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
static CONFIDENTIAL struct {
  bool active;
  uint32_t account;
  uint32_t n_actions;
  uint32_t current_action;
  uint64_t fee;
  uint32_t branch_id;
  ZcashOrchardKeys keys;
  /* The account's internal-scope (change) ivk, and the value of the outputs
   * proven to pay it: shown once, at the final gate. */
  uint8_t ivk_internal[32];
  uint64_t change_value;
  uint8_t header_digest[32];
  uint8_t sighash[32];
  bool transaction_v6;
  /* The pool of the actions being streamed. A crossing transaction (ZIP 318)
   * streams n_orchard_actions Orchard actions, then the Ironwood ones. */
  bool is_ironwood;
  uint32_t n_orchard_actions;
  uint8_t orchard_component_digest[32];
  uint8_t ironwood_component_digest[32];
  /* Set only at the final gate, from device-computed digests. */
  bool has_device_sighash;
  /* Phase 2b: incremental orchard digest verification */
  bool verify_orchard_digest;
  BLAKE2B_CTX compact_ctx;
  BLAKE2B_CTX memos_ctx;
  BLAKE2B_CTX noncompact_ctx;
  /* Per bundle, indexed by pool (0 Orchard, 1 Ironwood). */
  uint8_t expected_bundle_digest[2][32];
  uint8_t bundle_flags[2];
  int64_t bundle_value_balance[2];
  uint8_t orchard_anchor[32];
  /* One slot per REAL spend; dummies are never signed here. While streaming a
   * slot holds alpha || rk, at the final gate the 64-byte signature. */
  uint8_t signatures[ZCASH_MAX_ACTIONS][64];
  uint32_t signature_count;
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
  /* Every abort path must stop the trickle animation. */
  layoutProgressTrickleStop();
  memzero(&zcash_signing, sizeof(zcash_signing));
}

bool zcash_signing_is_active(void) { return zcash_signing.active; }

#if DEBUG_LINK
static uint32_t zcash_test_sign_operations;
uint32_t zcash_test_signOperations(void) { return zcash_test_sign_operations; }
void zcash_test_clearSignOperations(void) { zcash_test_sign_operations = 0; }
#define ZCASH_TEST_COUNT_SIGN() (zcash_test_sign_operations++)
#else
#define ZCASH_TEST_COUNT_SIGN() ((void)0)
#endif

/* Every mid-session failure reports, wipes the session, then returns home. */
static void zcash_fail(FailureType code, const char* text) {
  fsm_sendFailure(code, text);
  zcash_signing_abort();
  layoutHome();
}

static bool zcash_script_is_p2sh(const uint8_t* script, size_t script_size) {
  return script && script_size == 23 && script[0] == 0xa9 &&
         script[1] == 0x14 && script[22] == 0x87;
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

/* m/44'/133'/account'/change/index for the session account, unhardened
 * change and index. change is 0 (external), 1 (internal) or 2, the ZIP 320
 * ephemeral scope (TransparentKeyScope::EPHEMERAL). NULL when valid. */
static const char* zcash_transparent_path_error(const uint32_t* address_n,
                                                uint32_t count) {
  if (count != 5) return "Path must be m/44'/133'/account'/change/index";
  if (address_n[0] != (0x80000000 | 44) || address_n[1] != (0x80000000 | 133))
    return "Path must start with m/44'/133'";
  if (!(address_n[2] & 0x80000000)) return "Account must be hardened";
  if ((address_n[2] & 0x7FFFFFFF) != zcash_signing.account)
    return "Account does not match approved session";
  if (address_n[3] > 2) return "Change must be 0, 1 or 2";
  if (address_n[4] & 0x80000000) return "Index must not be hardened";
  return NULL;
}

/* Whether script is P2PKH paying the key at address_n. *reported is set when
 * a helper (fsm_getCoin/fsm_getDerivedNode) has already sent the Failure. */
static bool zcash_script_pays_path(const uint32_t* address_n, uint32_t count,
                                   const uint8_t* script, size_t script_size,
                                   bool* reported) {
  *reported = false;
  const CoinType* coin = fsm_getCoin(true, "Zcash");
  HDNode* node =
      coin ? fsm_getDerivedNode(coin->curve_name, address_n, count, NULL)
           : NULL;
  if (!node) {
    *reported = true;
    return false;
  }
  hdnode_fill_public_key(node);
  const bool matches =
      zcash_p2pkh_script_matches_pubkey(script, script_size, node->public_key);
  memzero(node, sizeof(*node));
  return matches;
}

static void zcash_format_amount(uint64_t amount, char* out, size_t out_size) {
  snprintf(out, out_size, "%llu.%08llu ZEC",
           (unsigned long long)(amount / 100000000ULL),
           (unsigned long long)(amount % 100000000ULL));
}

/* Account from an explicit field or strict m/32'/133'/account' (all
 * hardened), so a malformed path cannot resolve to an unintended account. */
static bool zcash_resolve_account(bool has_account, uint32_t account_field,
                                  const uint32_t* address_n,
                                  uint32_t address_n_count,
                                  uint32_t* account_out) {
  if (has_account) {
    /* ZIP-32 hardens this index; accepting the high bit aliases account zero.
     */
    if (account_field & 0x80000000u) {
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Zcash account must be below 0x80000000"));
      return false;
    }
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

/* Optional seed_fingerprint (ZIP-32 §6.1): refuse a request built for a
 * different seed. */
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
    const ZcashPCZTAction* msg, ZcashOrchardProgressCallback progress,
    void* progress_context) {
  /* value is a uint64, recipient a 43-byte raw receiver, and rseed, nullifier
   * and cmx 32 bytes each. All five are required: nanopb zero-fills an omitted
   * field, so e.g. a dropped nullifier would mean an implicit rho of zero. */
  if (!msg->has_value || !msg->has_recipient ||
      msg->recipient.size != ZCASH_ORCHARD_RAW_RECEIVER_SIZE ||
      !msg->has_rseed || msg->rseed.size != 32 || !msg->has_nullifier ||
      msg->nullifier.size != 32 || !msg->has_cmx || msg->cmx.size != 32) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Missing Orchard output metadata"));
    return false;
  }

  /* rho is a base-field element: reject a non-canonical encoding rather than
   * reduce it, or two wire values would map to one commitment. */
  if (!zcash_orchard_nullifier_canonical(msg->nullifier.bytes)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Orchard nullifier is not canonical"));
    return false;
  }

  uint8_t computed_cmx[32];
  bool cmx_ok =
      zcash_signing.is_ironwood
          ? zcash_ironwood_compute_cmx_with_progress(
                msg->recipient.bytes, msg->value, msg->nullifier.bytes,
                msg->rseed.bytes, computed_cmx, progress, progress_context)
          : zcash_orchard_compute_cmx_with_progress(
                msg->recipient.bytes, msg->value, msg->nullifier.bytes,
                msg->rseed.bytes, computed_cmx, progress, progress_context);
  if (!cmx_ok || memcmp(computed_cmx, msg->cmx.bytes, 32) != 0) {
    memzero(computed_cmx, sizeof(computed_cmx));
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Shielded note commitment mismatch"));
    return false;
  }
  memzero(computed_cmx, sizeof(computed_cmx));

  /* The cmx checked above binds value 0, so this output pays no one: padding
   * dummies (protocol spec 4.8.3) and, from NU6.3, the fabricated output paired
   * with each spend (ZIP 326), whose ciphertext may be random bytes. Without a
   * user_address it is accepted unshown whether or not it decrypts, as
   * Keystone does. With one it is a deliberate send, e.g. memo-only, and is
   * checked and shown like any other. */
  if (msg->value == 0 && !msg->has_user_address) return true;

  /* cmx alone does not reach the recipient: a corrupted epk or ciphertext
   * leaves a valid note that normal wallet scanning can never find. */
  if (!zcash_orchard_note_ciphertext_valid(
          msg->recipient.bytes, msg->value, msg->nullifier.bytes,
          msg->rseed.bytes, zcash_signing.is_ironwood, msg->epk.bytes,
          msg->enc_compact.bytes, msg->enc_memo.bytes,
          msg->enc_noncompact.bytes)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Shielded note ciphertext mismatch"));
    return false;
  }

  /* ZIP 374: show the address the user entered only once it is proven to
   * hold this output's Orchard receiver; any doubt refuses the transaction. */
  char address[ZCASH_ORCHARD_UNIFIED_ADDRESS_SIZE];
  const char* shown = address;
  const char* title = "Orchard address";
  if (msg->has_user_address) {
    switch (zcash_user_address_check(msg->user_address, msg->recipient.bytes)) {
      case ZCASH_USER_ADDRESS_MATCH:
        break;
      case ZCASH_USER_ADDRESS_NOT_MAINNET:
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Recipient address is not mainnet"));
        return false;
      case ZCASH_USER_ADDRESS_UNSUPPORTED:
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Recipient address metadata unsupported"));
        return false;
      case ZCASH_USER_ADDRESS_MISMATCH:
        fsm_sendFailure(FailureType_Failure_Other,
                        _("Recipient address does not match output"));
        return false;
      default:
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Invalid recipient address"));
        return false;
    }
    /* The check refused mixed case, so this only turns an all-uppercase
     * address (a QR scan) into the lowercase form wallets show. msg lives in
     * the writable decode buffer. */
    for (char* c = (char*)msg->user_address; *c; c++)
      if (*c >= 'A' && *c <= 'Z') *c = (char)(*c + ('a' - 'A'));
    shown = msg->user_address;
    title = "Shielded recipient";
  }

  /* Change, as Ledger finds it: the recipient is proven to be this account's
   * internal-scope address, pk_d = [ivk_internal] g_d, so the note returns to
   * the key that signs. Its value is shown once, as a total, at the final
   * gate. An output to any other address, the account's external ones
   * included, is shown on its own. */
  if (msg->value > 0 && zcash_orchard_receiver_matches_ivk(
                            zcash_signing.ivk_internal, msg->recipient.bytes)) {
    if (zcash_signing.change_value > UINT64_MAX - msg->value) {
      fsm_sendFailure(FailureType_Failure_Other, _("Invalid change value"));
      return false;
    }
    zcash_signing.change_value += msg->value;
    return true;
  }

  /* Without a user_address, show the Orchard-only address rebuilt from the
   * receiver. */
  if (!msg->has_user_address &&
      !zcash_orchard_receiver_to_unified_address(msg->recipient.bytes, "u",
                                                 address, sizeof(address))) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid Orchard recipient"));
    return false;
  }

  char amount_str[32];
  zcash_format_amount(msg->value, amount_str, sizeof(amount_str));

  /* Two screens: a 106-char UA fills the 3-row body and draw_string silently
   * truncates, which would drop the amount -- the only place the user verifies
   * the Orchard output value. Amount first, then the address via confirm(),
   * which paginates. */
  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Zcash Output",
               "Send shielded ZEC?\nAmount: %s", amount_str)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Signing cancelled"));
    memzero(address, sizeof(address));
    return false;
  }

  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title, "%s",
               shown)) {
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

  int64_t signed_fee = net_transparent;
  for (int pool = 0; pool < 2; pool++) {
    const int64_t value_balance = zcash_signing.bundle_value_balance[pool];
    if ((value_balance > 0 && signed_fee > INT64_MAX - value_balance) ||
        (value_balance < 0 && signed_fee < INT64_MIN - value_balance)) {
      return false;
    }
    signed_fee += value_balance;
  }
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

typedef struct {
  uint32_t base;
  uint32_t span;
  uint32_t last;
} ZcashActionProgress;

static void zcash_action_progress(uint32_t completed, uint32_t total,
                                  void* context) {
  ZcashActionProgress* progress = (ZcashActionProgress*)context;
  if (!progress || total == 0) return;

  /* completed/total is a public schedule, never dependent on ask, the nonce
   * or secret bits (no timing side channel). Redraw only on permil change. */
  uint32_t permil = progress->base + (progress->span * completed) / total;
  if (permil != progress->last) {
    progress->last = permil;
    layoutProgress(_("Signing Zcash"), (int)permil);
  }
}

static void zcash_send_action_ack(uint32_t next_index) {
  note_workflow_progress();
  ZcashPCZTActionAck* resp_ack = (ZcashPCZTActionAck*)msg_resp;
  memset(resp_ack, 0, sizeof(ZcashPCZTActionAck));
  resp_ack->has_next_index = true;
  resp_ack->next_index = next_index;
  msg_write(MessageType_MessageType_ZcashPCZTActionAck, resp_ack);

  /* Trickle the bar while the host builds the slow Orchard proof. */
  uint32_t n = zcash_signing.n_actions;
  if (n > 0) {
    int base = (int)((next_index * 1000) / n);
    int target = (int)(((next_index + 1) * 1000) / n);
    layoutProgressTrickle(_("Signing Zcash"), base, target);
  }
}

static void zcash_send_transparent_ack(bool output, uint32_t next_index) {
  note_workflow_progress();
  ZcashTransparentAck* resp = (ZcashTransparentAck*)msg_resp;
  memset(resp, 0, sizeof(ZcashTransparentAck));
  if (output) {
    resp->has_next_output_index = true;
    resp->next_output_index = next_index;
  } else {
    resp->has_next_input_index = true;
    resp->next_input_index = next_index;
  }
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

static bool zcash_compute_active_sighash(const uint8_t transparent_digest[32],
                                         uint8_t sighash[32]) {
  if (zcash_signing.transaction_v6) {
    return zcash_compute_v6_shielded_sighash(
        zcash_signing.header_digest, transparent_digest, EMPTY_SAPLING_DIGEST,
        zcash_signing.orchard_component_digest,
        zcash_signing.ironwood_component_digest, zcash_signing.branch_id,
        sighash);
  }
  return zcash_compute_shielded_sighash(
      zcash_signing.header_digest, transparent_digest, EMPTY_SAPLING_DIGEST,
      zcash_signing.orchard_component_digest, zcash_signing.branch_id, sighash);
}

/* The transparent component digest from the device-held plaintext; the empty
 * digest for a shielded-only transaction. */
static bool zcash_device_transparent_digest(uint8_t transparent_digest[32]) {
  if (zcash_signing.n_transparent_inputs == 0 &&
      zcash_signing.n_transparent_outputs == 0) {
    memcpy(transparent_digest, EMPTY_TRANSPARENT_DIGEST, 32);
    return true;
  }

  ZcashTransparentInputDigestInfo inputs[ZCASH_MAX_TRANSPARENT_INPUTS] = {0};
  ZcashTransparentOutputDigestInfo outputs[ZCASH_MAX_TRANSPARENT_OUTPUTS] = {0};
  const bool ok = zcash_build_transparent_digest_info(inputs, outputs) &&
                  zcash_compute_orchard_transparent_sig_digest(
                      inputs, zcash_signing.n_transparent_inputs, outputs,
                      zcash_signing.n_transparent_outputs, transparent_digest);
  memzero(inputs, sizeof(inputs));
  memzero(outputs, sizeof(outputs));
  return ok;
}

/* Early, friendly check of the host's transparent digest claim. The sighash
 * is computed only at the final gate, from the device digest. */
static bool zcash_finalize_transparent_digest(void) {
  if (!zcash_signing.has_expected_transparent_digest) return false;

  uint8_t transparent_digest[32] = {0};
  const bool ok = zcash_device_transparent_digest(transparent_digest) &&
                  memcmp(transparent_digest,
                         zcash_signing.expected_transparent_digest, 32) == 0;
  memzero(transparent_digest, sizeof(transparent_digest));
  if (ok) zcash_signing.transparent_digest_verified = true;
  return ok;
}

/* *reported is set when a helper (fsm_getCoin/fsm_getDerivedNode) has already
 * sent the terminal Failure, so the caller must not send another. */
static bool zcash_sign_transparent_inputs(bool* cancelled, bool* reported) {
  if (cancelled) *cancelled = false;
  if (reported) *reported = false;
  if (!zcash_signing.has_device_sighash) return false;

  bool ok = false;
  ZcashTransparentInputDigestInfo inputs[ZCASH_MAX_TRANSPARENT_INPUTS] = {0};
  ZcashTransparentOutputDigestInfo outputs[ZCASH_MAX_TRANSPARENT_OUTPUTS] = {0};
  if (!zcash_build_transparent_digest_info(inputs, outputs)) goto cleanup;

  const CoinType* coin = fsm_getCoin(true, "Zcash");
  if (!coin) {
    if (reported) *reported = true;
    goto cleanup;
  }

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
    if (!node) {
      if (reported) *reported = true;
      goto cleanup;
    }

    /* ZIP-244/229: bind the transparent ECDSA signature to every transaction
     * component, including Ironwood for transaction v6. */
    uint8_t t_sig_digest[32] = {0};
    uint8_t full_sighash[32] = {0};
    uint8_t sig[64] = {0};
    uint8_t der_sig[73] = {0};

    bool sign_ok = zcash_compute_transparent_sighash_digest(
        inputs, zcash_signing.n_transparent_inputs, outputs,
        zcash_signing.n_transparent_outputs, i, 0x01, t_sig_digest);
    if (sign_ok) {
      sign_ok = zcash_compute_active_sighash(t_sig_digest, full_sighash);
    }
    if (sign_ok) ZCASH_TEST_COUNT_SIGN();
    sign_ok =
        sign_ok && hdnode_sign_digest(node, full_sighash, sig, NULL, NULL) == 0;

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

/* RedPallas-signs every buffered spend, in action order, over the final
 * device sighash. Sends the Failure itself. */
static bool zcash_sign_orchard_spends(void) {
  const uint32_t count = zcash_signing.signature_count;
  for (uint32_t i = 0; i < count; i++) {
    uint8_t* slot = zcash_signing.signatures[i];
    uint8_t alpha[32], rk[32];
    memcpy(alpha, slot, 32);
    memcpy(rk, slot + 32, 32);

    /* T must be unpredictable: rk and M are public, so a guessable T makes
     * r = H*(T || rk || M) computable and one signature discloses ask. Draw it
     * from the checked RNG and refuse on a failed verdict. 80 bytes per the
     * Zcash spec so H* is uniform over the scalar field; the signer also
     * refuses an all-zero T. */
    uint8_t zcash_T[80];
    if (!rng_health_check() ||
        !random_buffer_checked(zcash_T, sizeof(zcash_T))) {
      memzero(zcash_T, sizeof(zcash_T));
      memzero(alpha, sizeof(alpha));
      memzero(rk, sizeof(rk));
      zcash_fail(FailureType_Failure_Other,
                 _("RNG health check failed; refusing to sign"));
      return false;
    }

    const uint32_t base = (i * 1000) / count;
    ZcashActionProgress progress = {base, ((i + 1) * 1000) / count - base,
                                    base};
    /* _with_ak, never _for_rk: rk is re-derived from the device's OWN ak and
     * alpha, so the device cannot sign under a key that is not its own. */
    ZCASH_TEST_COUNT_SIGN();
    int sign_rc = redpallas_sign_digest_with_ak(
        zcash_signing.keys.ask, zcash_signing.keys.ak, alpha, rk,
        zcash_signing.sighash, zcash_T, slot, zcash_action_progress, &progress);
    memzero(zcash_T, sizeof(zcash_T));
    memzero(alpha, sizeof(alpha));
    memzero(rk, sizeof(rk));
    if (sign_rc != 0) {
      zcash_fail(FailureType_Failure_Other,
                 _("Orchard spend authorization failed"));
      return false;
    }
  }
  return true;
}

static void zcash_start_bundle(bool is_ironwood) {
  zcash_signing.is_ironwood = is_ironwood;
  blake2b_InitPersonal(&zcash_signing.compact_ctx, 32,
                       is_ironwood ? "ZTxIdIrnActCH_v6" : "ZTxIdOrcActCHash",
                       16);
  blake2b_InitPersonal(&zcash_signing.memos_ctx, 32,
                       is_ironwood ? "ZTxIdIrnActMH_v6" : "ZTxIdOrcActMHash",
                       16);
  blake2b_InitPersonal(&zcash_signing.noncompact_ctx, 32,
                       is_ironwood ? "ZTxIdIrnActNH_v6" : "ZTxIdOrcActNHash",
                       16);
}

/* Finalize the streamed bundle's digest into its sighash component. The
 * device digest is what gets signed; the host claim is compared only to fail
 * early with a clear error. */
static bool zcash_finish_bundle(void) {
  const int pool = zcash_signing.is_ironwood ? 1 : 0;
  uint8_t compact_hash[32], memos_hash[32], noncompact_hash[32];

  blake2b_Final(&zcash_signing.compact_ctx, compact_hash, 32);
  blake2b_Final(&zcash_signing.memos_ctx, memos_hash, 32);
  blake2b_Final(&zcash_signing.noncompact_ctx, noncompact_hash, 32);

  /* Every v6 bundle digest, Orchard or Ironwood, omits the anchor: v6 moves
   * it to the auth digest. The action digests keep their v5 personalizations
   * for the Orchard pool (ZIP-229). */
  BLAKE2B_CTX bundle_ctx;
  blake2b_InitPersonal(
      &bundle_ctx, 32,
      pool ? "ZTxIdIronwd_H_v6"
           : (zcash_signing.transaction_v6 ? "ZTxIdOrchardH_v6"
                                           : "ZTxIdOrchardHash"),
      16);
  blake2b_Update(&bundle_ctx, compact_hash, 32);
  blake2b_Update(&bundle_ctx, memos_hash, 32);
  blake2b_Update(&bundle_ctx, noncompact_hash, 32);
  blake2b_Update(&bundle_ctx, &zcash_signing.bundle_flags[pool], 1);
  blake2b_Update(&bundle_ctx,
                 (const uint8_t*)&zcash_signing.bundle_value_balance[pool], 8);
  if (!zcash_signing.transaction_v6) {
    blake2b_Update(&bundle_ctx, zcash_signing.orchard_anchor, 32);
  }

  uint8_t* bundle_digest = pool ? zcash_signing.ironwood_component_digest
                                : zcash_signing.orchard_component_digest;
  blake2b_Final(&bundle_ctx, bundle_digest, 32);

  if (memcmp(bundle_digest, zcash_signing.expected_bundle_digest[pool], 32) !=
      0) {
    zcash_fail(FailureType_Failure_Other,
               _("Shielded digest mismatch: transaction data "
                 "does not match sighash"));
    return false;
  }
  return true;
}

/* Final gate: verify everything, then sign over device digests only. Reached
 * after the last action, or after the last transparent input when there are
 * no actions. Ends the session either way. */
static void zcash_final_gate(void) {
  if (zcash_signing.n_actions > 0) {
    if (!zcash_finish_bundle()) return;
  } else {
    /* Transparent-only: both bundles are empty, by the device's constants. */
    zcash_empty_orchard_digest(zcash_signing.transaction_v6,
                               zcash_signing.orchard_component_digest);
    memcpy(zcash_signing.ironwood_component_digest, EMPTY_IRONWOOD_DIGEST_V6,
           32);
  }

  uint8_t t_digest[32];
  const bool sighash_ok =
      zcash_signing.transparent_digest_verified &&
      zcash_device_transparent_digest(t_digest) &&
      zcash_compute_active_sighash(t_digest, zcash_signing.sighash);
  memzero(t_digest, sizeof(t_digest));
  if (!sighash_ok) {
    zcash_fail(FailureType_Failure_Other, _("Sighash computation failed"));
    return;
  }
  zcash_signing.has_device_sighash = true;

  if (zcash_signing.change_value > 0) {
    char change_str[32];
    zcash_format_amount(zcash_signing.change_value, change_str,
                        sizeof(change_str));
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Zcash Change",
                 "Change back to your wallet:\n%s", change_str)) {
      zcash_fail(FailureType_Failure_ActionCancelled, _("Signing cancelled"));
      return;
    }
  }

  if (!zcash_verify_and_confirm_fee()) {
    zcash_signing_abort();
    layoutHome();
    return;
  }

  if (zcash_signing.n_transparent_inputs > 0) {
    bool cancelled = false;
    bool reported = false;
    if (!zcash_sign_transparent_inputs(&cancelled, &reported)) {
      if (reported) {
        zcash_signing_abort();  // the helper already answered the host
        return;
      }
      zcash_fail(cancelled ? FailureType_Failure_ActionCancelled
                           : FailureType_Failure_Other,
                 cancelled ? _("Signing cancelled")
                           : _("Transparent input signing failed"));
      return;
    }
  }

  layoutProgress(_("Signing Zcash"), 0);
  if (!zcash_sign_orchard_spends()) return;

  /* Transparent sigs are released only at this final gate. */
  if (zcash_signing.has_pending_transparent) {
    ZcashTransparentSigned* t_resp = (ZcashTransparentSigned*)msg_resp;
    memcpy(t_resp, &zcash_signing.pending_transparent,
           sizeof(ZcashTransparentSigned));
    msg_write(MessageType_MessageType_ZcashTransparentSigned, t_resp);
  }

  ZcashSignedPCZT* resp_signed = (ZcashSignedPCZT*)msg_resp;
  memset(resp_signed, 0, sizeof(ZcashSignedPCZT));

  resp_signed->signatures_count = zcash_signing.signature_count;
  for (uint32_t i = 0; i < zcash_signing.signature_count; i++) {
    resp_signed->signatures[i].size = 64;
    memcpy(resp_signed->signatures[i].bytes, zcash_signing.signatures[i], 64);
  }

  zcash_signing_abort();

  msg_write(MessageType_MessageType_ZcashSignedPCZT, resp_signed);
  layoutHome();
}

void fsm_msgZcashSignPCZT(const ZcashSignPCZT* msg) {
  RESP_INIT(ZcashPCZTActionAck);

  CHECK_INITIALIZED

  CHECK_PIN

  const uint32_t n_ironwood_actions =
      msg->has_n_ironwood_actions ? msg->n_ironwood_actions : 0;
  /* No shielded action is a transparent-only transaction (ZIP 320: a TEX
   * payment's second step), which needs a transparent input to sign. */
  const bool transparent_only = msg->has_n_actions && msg->n_actions == 0;
  if (!msg->has_n_actions ||
      (transparent_only &&
       (n_ironwood_actions > 0 || !msg->has_n_transparent_inputs ||
        msg->n_transparent_inputs == 0))) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("No actions specified"));
    layoutHome();
    return;
  }
  if (msg->n_actions > ZCASH_MAX_ACTIONS ||
      n_ironwood_actions > ZCASH_MAX_ACTIONS - msg->n_actions) {
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
  bool is_ironwood =
      msg->has_shielded_pool &&
      msg->shielded_pool == ZcashShieldedPool_ZCASH_SHIELDED_POOL_IRONWOOD;
  if (msg->has_shielded_pool &&
      msg->shielded_pool != ZcashShieldedPool_ZCASH_SHIELDED_POOL_ORCHARD &&
      msg->shielded_pool != ZcashShieldedPool_ZCASH_SHIELDED_POOL_IRONWOOD) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Unknown shielded pool"));
    layoutHome();
    return;
  }
  /* Every personalization keys off tx_version: reject unknown pairs. */
  if (msg->has_tx_version && msg->has_version_group_id &&
      !zcash_tx_version_supported(msg->tx_version, msg->version_group_id)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Unsupported transaction version"));
    layoutHome();
    return;
  }
  if (is_ironwood &&
      (!msg->has_tx_version || msg->tx_version != 6 ||
       !msg->has_version_group_id || msg->version_group_id != 0xD884B698 ||
       branch_id != 0x37A5165B)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid Ironwood transaction"));
    layoutHome();
    return;
  }

  /* ZIP 318 pool crossing: an Orchard bundle and an Ironwood bundle in one
   * NU6.3 v6 transaction. Both are streamed and verified. */
  const bool crossing = n_ironwood_actions > 0;
  if (crossing &&
      (is_ironwood || msg->tx_version != 6 || branch_id != 0x37A5165B ||
       !msg->has_ironwood_digest || msg->ironwood_digest.size != 32 ||
       !msg->has_ironwood_flags || msg->ironwood_flags > 0xff ||
       !msg->has_ironwood_value_balance)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid pool-crossing transaction"));
    layoutHome();
    return;
  }

  /* Otherwise only one pool is verified, so the other pool's digest must be
   * the empty one, never host-attested; else the device would sign over an
   * unseen bundle. */
  if (is_ironwood &&
      memcmp(msg->orchard_digest.bytes, EMPTY_ORCHARD_DIGEST_V6, 32) != 0) {
    fsm_sendFailure(
        FailureType_Failure_SyntaxError,
        _("Ironwood transaction must have an empty Orchard bundle"));
    layoutHome();
    return;
  }
  /* Reciprocal: refuse, not replace, a supplied Ironwood digest. */
  if (!is_ironwood && !crossing && msg->tx_version == 6 &&
      !zcash_v6_orchard_ironwood_digest_valid(msg->has_ironwood_digest,
                                              msg->ironwood_digest.size,
                                              msg->ironwood_digest.bytes)) {
    fsm_sendFailure(
        FailureType_Failure_SyntaxError,
        _("Orchard transaction must have an empty Ironwood bundle"));
    layoutHome();
    return;
  }

  /* Before v6 there is no Ironwood component in the sighash: refuse, never
   * silently drop, a supplied digest. */
  if (msg->has_ironwood_digest && msg->tx_version != 6) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Ironwood digest requires a v6 transaction"));
    layoutHome();
    return;
  }

  ZcashPCZTSigningRequestMeta signing_meta = {0};
  signing_meta.has_header_digest = msg->has_header_digest;
  signing_meta.header_digest_size = msg->header_digest.size;
  signing_meta.has_transparent_digest = msg->has_transparent_digest;
  signing_meta.transparent_digest_size = msg->transparent_digest.size;
  signing_meta.has_sapling_digest = msg->has_sapling_digest;
  signing_meta.sapling_digest_size = msg->sapling_digest.size;
  signing_meta.sapling_digest = msg->sapling_digest.bytes;
  signing_meta.has_orchard_digest = msg->has_orchard_digest;
  signing_meta.orchard_digest_size = msg->orchard_digest.size;
  signing_meta.is_ironwood = is_ironwood;
  signing_meta.has_ironwood_digest = msg->has_ironwood_digest;
  signing_meta.ironwood_digest_size = msg->ironwood_digest.size;
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

  /* Transparent-only: the sighash commits to the empty bundle digests, which
   * the device supplies itself. Refuse, never replace, a host claim of any
   * other bundle. */
  if (transparent_only) {
    uint8_t empty_orchard[32];
    zcash_empty_orchard_digest(msg->tx_version == 6, empty_orchard);
    if (memcmp(msg->orchard_digest.bytes, empty_orchard, 32) != 0 ||
        msg->orchard_value_balance != 0 ||
        (msg->has_ironwood_digest &&
         memcmp(msg->ironwood_digest.bytes, EMPTY_IRONWOOD_DIGEST_V6, 32) !=
             0) ||
        (msg->has_ironwood_value_balance && msg->ironwood_value_balance != 0)) {
      fsm_sendFailure(
          FailureType_Failure_SyntaxError,
          _("Transparent transaction must have empty shielded bundles"));
      layoutHome();
      return;
    }
  }

  /* Consensus (ZIP 229, ZIP 258): reserved flag bits are zero, Orchard bit 2
   * included, and from NU6.3 no value may enter the Orchard pool. Such a
   * transaction can never be mined; refuse it before any screen. */
  if ((msg->orchard_flags & (is_ironwood ? 0xF8u : 0xFCu)) != 0 ||
      (crossing && (msg->ironwood_flags & 0xF8u) != 0)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid shielded bundle flags"));
    layoutHome();
    return;
  }
  if (!is_ironwood && branch_id == 0x37A5165B &&
      msg->orchard_value_balance < 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Value cannot enter the Orchard pool"));
    layoutHome();
    return;
  }

  /* Shielded-only: the transparent component is the empty one. Refuse, not
   * replace, a different supplied digest, as for the inactive pool above. */
  if (n_tinputs == 0 && n_toutputs == 0 && msg->has_transparent_digest &&
      memcmp(msg->transparent_digest.bytes, EMPTY_TRANSPARENT_DIGEST, 32) !=
          0) {
    fsm_sendFailure(
        FailureType_Failure_SyntaxError,
        _("Shielded transaction must have an empty transparent bundle"));
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

  /* The summary shows no amount. total_amount is host-supplied and nothing
   * the device signs commits to it, so it must never be displayed as a fact;
   * every value that is signed is shown on a verified screen (Orchard
   * outputs, proven change as one total, transparent outputs). The fee shown
   * here is the host's claim and is checked against the device-computed fee,
   * then confirmed again, before any signature is released. */
  char fee_str[32];
  uint64_t fee = msg->has_fee ? msg->fee : 0;

  /* 1 ZEC = 100,000,000 zatoshis */
  zcash_format_amount(fee, fee_str, sizeof(fee_str));

  if (transparent_only) {
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Zcash Transparent",
                 "Send transparent ZEC?\n"
                 "Fee: %s\nInputs: %lu\nOutputs: %lu",
                 fee_str, (unsigned long)n_tinputs,
                 (unsigned long)n_toutputs)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  } else if (n_tinputs > 0) {
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Zcash Shield",
                 "Shield transparent ZEC?\n"
                 "Fee: %s\nInputs: %lu\nOutputs: %lu\nActions: %lu",
                 fee_str, (unsigned long)n_tinputs, (unsigned long)n_toutputs,
                 (unsigned long)(msg->n_actions + n_ironwood_actions))) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  } else if (n_toutputs > 0) {
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Zcash Shielded",
                 "Sign transaction with transparent outputs?\n"
                 "Fee: %s\nOutputs: %lu\nActions: %lu",
                 fee_str, (unsigned long)n_toutputs,
                 (unsigned long)(msg->n_actions + n_ironwood_actions))) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  } else {
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Zcash Shielded",
                 "Sign shielded transaction?\n"
                 "Fee: %s\nActions: %lu",
                 fee_str,
                 (unsigned long)(msg->n_actions + n_ironwood_actions))) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  }

  /* Draw before seconds of Orchard key derivation. */
  layoutProgress(_("Signing Zcash"), 0);

  if (!zcash_check_seed_fingerprint(msg->has_expected_seed_fingerprint,
                                    msg->expected_seed_fingerprint.bytes,
                                    msg->expected_seed_fingerprint.size)) {
    layoutHome();
    return;
  }

  /* No state from an abandoned session may leak into this one. */
  zcash_signing_abort();

  /* Derive Orchard keys via storage; the seed never leaves storage.c. */
  if (!storage_zcashOrchardKeys(account, true, &zcash_signing.keys)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Orchard key derivation failed"));
    layoutHome();
    return;
  }
  /* Change is recognised by the internal-scope ivk, derived once here. */
  if (!zcash_orchard_derive_internal_ivk(
          zcash_signing.keys.ak, zcash_signing.keys.nk, zcash_signing.keys.rivk,
          zcash_signing.ivk_internal)) {
    zcash_signing_abort();
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Orchard key derivation failed"));
    layoutHome();
    return;
  }
  /* The session signs with ask/ak only; do not keep sk, nk, rivk, dk. */
  memzero(zcash_signing.keys.sk, sizeof(zcash_signing.keys.sk));
  memzero(zcash_signing.keys.nk, sizeof(zcash_signing.keys.nk));
  memzero(zcash_signing.keys.rivk, sizeof(zcash_signing.keys.rivk));
  memzero(zcash_signing.keys.dk, sizeof(zcash_signing.keys.dk));

  zcash_signing.active = true;
  zcash_signing.account = account;
  zcash_signing.n_actions = msg->n_actions + n_ironwood_actions;
  zcash_signing.n_orchard_actions = is_ironwood ? 0 : msg->n_actions;
  zcash_signing.current_action = 0;
  zcash_signing.fee = fee;
  zcash_signing.branch_id = branch_id;
  zcash_signing.transaction_v6 = msg->tx_version == 6;
  zcash_signing.is_ironwood = is_ironwood;
  memcpy(zcash_signing.header_digest, header_digest, 32);
  /* The active pool's component digest is set only at the final gate, from
   * the device-computed bundle digest; the inactive one is the empty digest
   * (Ironwood's empty Orchard digest was checked above). */
  if (is_ironwood) {
    memcpy(zcash_signing.orchard_component_digest, EMPTY_ORCHARD_DIGEST_V6, 32);
  } else if (zcash_signing.transaction_v6) {
    /* Orchard-v6: bind the canonical empty Ironwood component. */
    memcpy(zcash_signing.ironwood_component_digest, EMPTY_IRONWOOD_DIGEST_V6,
           32);
  }
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

  /* TRUST MODEL -- verify, then sign. Nothing is signed while streaming. At
   * the final gate the device finalizes the active-pool digest from the
   * streamed actions (each output's cmx and ciphertext checked, each spend's
   * rk derived from its own ak), computes the sighash from its OWN digests
   * (header, transparent, active pool; Sapling unsupported, always empty),
   * checks and confirms the fee, and only then signs. Host digest claims are
   * compared only for an early, friendly error. */
  if (n_tinputs == 0 && n_toutputs == 0) {
    zcash_signing.transparent_digest_verified = true;
  } else {
    memcpy(zcash_signing.expected_transparent_digest,
           msg->transparent_digest.bytes, 32);
    zcash_signing.has_expected_transparent_digest = true;
  }

  /* Phase 2b: every streamed bundle's digest is recomputed. An Ironwood-only
   * request describes its bundle with the orchard_* fields. */
  const int first_pool = is_ironwood ? 1 : 0;
  memcpy(zcash_signing.expected_bundle_digest[first_pool],
         is_ironwood ? msg->ironwood_digest.bytes : msg->orchard_digest.bytes,
         32);
  zcash_signing.bundle_flags[first_pool] = (uint8_t)msg->orchard_flags;
  zcash_signing.bundle_value_balance[first_pool] = msg->orchard_value_balance;
  if (crossing) {
    memcpy(zcash_signing.expected_bundle_digest[1], msg->ironwood_digest.bytes,
           32);
    zcash_signing.bundle_flags[1] = (uint8_t)msg->ironwood_flags;
    zcash_signing.bundle_value_balance[1] = msg->ironwood_value_balance;
  }
  memcpy(zcash_signing.orchard_anchor, msg->orchard_anchor.bytes, 32);

  zcash_start_bundle(is_ironwood);
  zcash_signing.verify_orchard_digest = true;

  /* Static draw first: layoutProgress() after arming freezes the trickle. */
  layoutProgress(_("Signing Zcash"), 0);

  /* Transparent outputs are reviewed before any signature is emitted. */
  if (zcash_signing.n_transparent_outputs > 0) {
    zcash_send_transparent_ack(true, 0);
  } else if (zcash_signing.n_transparent_inputs > 0) {
    zcash_send_transparent_ack(false, 0);
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

  /* Viewing keys disclose wallet activity; the host cannot waive consent. */
  if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall,
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

  resp->has_ak = true;
  resp->ak.size = 32;
  memcpy(resp->ak.bytes, keys.ak, 32);

  resp->has_nk = true;
  resp->nk.size = 32;
  memcpy(resp->nk.bytes, keys.nk, 32);

  resp->has_rivk = true;
  resp->rivk.size = 32;
  memcpy(resp->rivk.bytes, keys.rivk, 32);

  /* Seed identity (ZIP-32 §6.1) for later host pinning. */
  uint8_t fp[32];
  if (storage_zcashSeedFingerprint(true, fp)) {
    resp->has_seed_fingerprint = true;
    resp->seed_fingerprint.size = 32;
    memcpy(resp->seed_fingerprint.bytes, fp, 32);
    memzero(fp, sizeof(fp));
  }

  /* Clean up sensitive data */
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

  /* Stop the trickle; the next ack re-arms it. */
  layoutProgressTrickleStop();

  /* A transparent-only session ends at its last input. */
  if (zcash_signing.n_actions == 0) {
    zcash_fail(FailureType_Failure_UnexpectedMessage, _("No actions expected"));
    return;
  }

  /* Declared transparent data must be fully streamed and verified first, so a
   * host cannot skip transparent confirmations. */
  if (zcash_signing.current_transparent_output <
          zcash_signing.n_transparent_outputs ||
      zcash_signing.current_transparent_input <
          zcash_signing.n_transparent_inputs ||
      ((zcash_signing.n_transparent_outputs > 0 ||
        zcash_signing.n_transparent_inputs > 0) &&
       !zcash_signing.transparent_digest_verified)) {
    zcash_fail(FailureType_Failure_UnexpectedMessage,
               _("Transparent data not yet complete"));
    return;
  }

  if (!msg->has_index || msg->index != zcash_signing.current_action) {
    zcash_fail(FailureType_Failure_SyntaxError, _("Unexpected action index"));
    return;
  }

  /* The device signs only the sighash it assembles itself; refuse, never
   * ignore, a legacy host-supplied one (as for transparent inputs). */
  if (msg->has_sighash) {
    zcash_fail(FailureType_Failure_SyntaxError,
               _("Host action sighash rejected"));
    return;
  }

  if (!msg->has_alpha || msg->alpha.size != 32) {
    zcash_fail(FailureType_Failure_SyntaxError,
               _("Missing or invalid alpha randomizer"));
    return;
  }

  const bool has_orchard_action_data =
      zcash_signing.verify_orchard_digest && msg->has_is_spend &&
      msg->has_nullifier && msg->nullifier.size == 32 && msg->has_cmx &&
      msg->cmx.size == 32 && msg->has_epk && msg->epk.size == 32 &&
      msg->has_enc_compact && msg->enc_compact.size == 52 &&
      msg->has_enc_memo && msg->enc_memo.size == 512 &&
      msg->has_enc_noncompact &&
      /* 580 = compact(52) + memo(512) + noncompact(16). */
      msg->enc_noncompact.size == 16 && msg->has_cv_net &&
      msg->cv_net.size == 32 && msg->has_rk && msg->rk.size == 32 &&
      msg->has_out_ciphertext && msg->out_ciphertext.size == 80;

  if (!has_orchard_action_data) {
    zcash_fail(FailureType_Failure_SyntaxError,
               _("Missing Orchard action data"));
    return;
  }

  const uint32_t action_base =
      (zcash_signing.current_action * 1000) / zcash_signing.n_actions;
  const uint32_t action_target =
      ((zcash_signing.current_action + 1) * 1000) / zcash_signing.n_actions;
  ZcashActionProgress verification_progress = {
      action_base, action_target - action_base, action_base};

  /* 1086-bit note commitment = 109 public Sinsemilla rounds. */
  layoutProgress(_("Signing Zcash"), action_base);
  if (!zcash_verify_and_confirm_orchard_output(msg, zcash_action_progress,
                                               &verification_progress)) {
    zcash_signing_abort();
    layoutHome();
    return;
  }

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

  /* The host's PCZT IO finalizer already signed dummy spends with their
   * ephemeral keys; only real spends are signed, at the final gate. rk is
   * hashed into the bundle digest, so check here that it is the device's own
   * ak re-randomized by alpha, and keep alpha || rk for the signer. */
  if (msg->is_spend) {
    uint8_t* slot = zcash_signing.signatures[zcash_signing.signature_count];
    if (redpallas_derive_rk_from_ak(zcash_signing.keys.ak, msg->alpha.bytes,
                                    slot + 32) != 0 ||
        memcmp(slot + 32, msg->rk.bytes, 32) != 0) {
      zcash_fail(FailureType_Failure_Other,
                 _("Orchard spend authorization failed"));
      return;
    }
    memcpy(slot, msg->alpha.bytes, 32);
    zcash_signing.signature_count++;
  }

  zcash_signing.current_action++;

  uint32_t progress =
      (zcash_signing.current_action * 1000) / zcash_signing.n_actions;
  layoutProgress(_("Signing Zcash"), progress);

  /* The last Orchard action of a crossing transaction closes the Orchard
   * bundle; the Ironwood actions follow. */
  if (!zcash_signing.is_ironwood &&
      zcash_signing.current_action == zcash_signing.n_orchard_actions &&
      zcash_signing.current_action < zcash_signing.n_actions) {
    if (!zcash_finish_bundle()) return;
    zcash_start_bundle(true);
  }

  if (zcash_signing.current_action >= zcash_signing.n_actions) {
    zcash_final_gate();
  } else {
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
    zcash_fail(FailureType_Failure_UnexpectedMessage,
               _("No transparent outputs expected"));
    return;
  }

  if (zcash_signing.current_transparent_input != 0) {
    zcash_fail(FailureType_Failure_UnexpectedMessage,
               _("Transparent outputs must come first"));
    return;
  }

  /* Bound the free-running counter: a host can keep sending outputs past the
   * declared count, which would write past transparent_outputs[8]. */
  if (msg->index >= zcash_signing.n_transparent_outputs ||
      msg->index >= ZCASH_MAX_TRANSPARENT_OUTPUTS ||
      zcash_signing.current_transparent_output >=
          zcash_signing.n_transparent_outputs) {
    zcash_fail(FailureType_Failure_SyntaxError,
               _("Transparent output index out of range"));
    return;
  }

  if (msg->index != zcash_signing.current_transparent_output) {
    zcash_fail(FailureType_Failure_SyntaxError,
               _("Unexpected transparent output index"));
    return;
  }

  if (!msg->has_amount || !msg->has_script_pubkey ||
      msg->script_pubkey.size == 0 ||
      msg->script_pubkey.size > ZCASH_MAX_TRANSPARENT_SCRIPT_PUBKEY) {
    zcash_fail(FailureType_Failure_SyntaxError,
               _("Invalid transparent output script"));
    return;
  }

  /* An output with a path pays the account's own ZIP 320 one-time
   * (ephemeral) address, the first step of a TEX payment from shielded funds.
   * It is shown as such only once the script is proven to pay that key. */
  const bool own = msg->address_n_count > 0;
  const bool tex = msg->has_is_tex && msg->is_tex;
  if (own) {
    const char* path_error =
        zcash_transparent_path_error(msg->address_n, msg->address_n_count);
    if (!path_error && msg->address_n[3] != 2)
      path_error = "Output path must be a one-time address";
    if (!path_error && tex) path_error = "A one-time address is not a TEX";
    if (path_error) {
      zcash_fail(FailureType_Failure_SyntaxError, _(path_error));
      return;
    }
    bool reported;
    if (!zcash_script_pays_path(msg->address_n, msg->address_n_count,
                                msg->script_pubkey.bytes,
                                msg->script_pubkey.size, &reported)) {
      if (reported) {
        zcash_signing_abort();
        return;
      }
      zcash_fail(FailureType_Failure_SyntaxError,
                 _("Transparent output script does not match path"));
      return;
    }
  }

  /* is_tex is a host hint the chain cannot show: a TEX address (ZIP 320) is
   * the same P2PKH key hash, so the destination shown is the same either
   * way. */
  char address[64];
  const bool show_tex = tex && zcash_script_is_p2pkh(msg->script_pubkey.bytes,
                                                     msg->script_pubkey.size);
  if (!(show_tex ? zcash_tex_address(msg->script_pubkey.bytes + 3, address,
                                     sizeof(address))
                 : zcash_transparent_script_to_address(
                       msg->script_pubkey.bytes, msg->script_pubkey.size,
                       address, sizeof(address)))) {
    zcash_fail(FailureType_Failure_SyntaxError,
               _("Unsupported transparent output script"));
    return;
  }

  char amount_str[32];
  zcash_format_amount(msg->amount, amount_str, sizeof(amount_str));
  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Zcash Output",
               own        ? "To your one-time address:\n%s\nAmount: %s"
               : show_tex ? "Send to TEX address?\n%s\nAmount: %s"
                          : "Send transparent ZEC?\n%s\nAmount: %s",
               address, amount_str)) {
    zcash_fail(FailureType_Failure_ActionCancelled, _("Signing cancelled"));
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

  /* Static draw before the dispatch arms the trickle. */
  layoutProgress(_("Signing Zcash"), 0);

  if (zcash_signing.current_transparent_output <
      zcash_signing.n_transparent_outputs) {
    zcash_send_transparent_ack(true, zcash_signing.current_transparent_output);
  } else if (zcash_signing.n_transparent_inputs > 0) {
    zcash_send_transparent_ack(false, 0);
  } else {
    if (!zcash_finalize_transparent_digest()) {
      zcash_fail(FailureType_Failure_Other, _("Transparent digest mismatch"));
      return;
    }
    zcash_send_action_ack(0);
  }
}

/* Phase 3: transparent outputs then inputs are streamed and checked; ECDSA
 * signing waits for the final gate. */
void fsm_msgZcashTransparentInput(const ZcashTransparentInput* msg) {
  if (!zcash_signing.active) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Not in Zcash signing mode"));
    layoutHome();
    return;
  }

  if (zcash_signing.n_transparent_inputs == 0) {
    zcash_fail(FailureType_Failure_UnexpectedMessage,
               _("No transparent inputs expected"));
    return;
  }

  if (zcash_signing.current_transparent_output <
      zcash_signing.n_transparent_outputs) {
    zcash_fail(FailureType_Failure_UnexpectedMessage,
               _("Transparent outputs not yet complete"));
    return;
  }

  /* Bound the index before use: a host can keep sending inputs past the
   * declared count, which would write past the 8-element array. */
  if (msg->index >= zcash_signing.n_transparent_inputs ||
      msg->index >= ZCASH_MAX_TRANSPARENT_INPUTS ||
      zcash_signing.current_transparent_input >=
          zcash_signing.n_transparent_inputs) {
    zcash_fail(FailureType_Failure_SyntaxError,
               _("Transparent input index out of range"));
    return;
  }

  if (msg->index != zcash_signing.current_transparent_input) {
    zcash_fail(FailureType_Failure_SyntaxError,
               _("Unexpected transparent input index"));
    return;
  }

  if (msg->has_sighash) {
    zcash_fail(FailureType_Failure_SyntaxError,
               _("Host transparent sighash rejected"));
    return;
  }

  if (!msg->has_amount || !msg->has_prevout_txid ||
      msg->prevout_txid.size != 32 || !msg->has_prevout_index ||
      !msg->has_sequence || !msg->has_script_pubkey ||
      msg->script_pubkey.size == 0 ||
      msg->script_pubkey.size > ZCASH_MAX_TRANSPARENT_SCRIPT_PUBKEY) {
    zcash_fail(FailureType_Failure_SyntaxError,
               _("Invalid transparent input data"));
    return;
  }

  /* Inputs are P2PKH only: the scriptPubKey is used as scriptCode, which is
   * wrong for P2SH (outputs may still be P2SH). */
  if (!zcash_script_is_p2pkh(msg->script_pubkey.bytes,
                             msg->script_pubkey.size)) {
    zcash_fail(FailureType_Failure_SyntaxError,
               _("Transparent inputs must be P2PKH"));
    return;
  }

  /* The path is the session account's, so a shielding approval cannot sign
   * with arbitrary secp256k1 keys, and the scriptPubKey is the sighash
   * scriptCode: it must pay the key that address_n will sign with. */
  const char* path_error =
      zcash_transparent_path_error(msg->address_n, msg->address_n_count);
  if (path_error) {
    zcash_fail(FailureType_Failure_SyntaxError, _(path_error));
    return;
  }
  bool reported;
  if (!zcash_script_pays_path(msg->address_n, msg->address_n_count,
                              msg->script_pubkey.bytes, msg->script_pubkey.size,
                              &reported)) {
    if (reported) {
      zcash_signing_abort();
      return;
    }
    zcash_fail(FailureType_Failure_SyntaxError,
               _("Transparent input script does not match path"));
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
    zcash_send_transparent_ack(false, zcash_signing.current_transparent_input);
    layoutProgress(_("Signing Zcash"), 0);
    return;
  }

  if (!zcash_finalize_transparent_digest()) {
    zcash_fail(FailureType_Failure_Other, _("Transparent digest mismatch"));
    return;
  }

  /* Inputs are confirmed and signed only at the final gate, reached here
   * when there are no shielded actions. Static draw before arming. */
  if (zcash_signing.n_actions == 0) {
    zcash_final_gate();
    return;
  }
  layoutProgress(_("Signing Zcash"), 0);
  zcash_send_action_ack(0);
}
