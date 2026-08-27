/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "keepkey/firmware/hive.h"

#include "trezor/crypto/base58.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"

#include <string.h>
#include <stdint.h>

// ── STM public key encoding ───────────────────────────────────────────────

bool hive_getPublicKey(const uint8_t public_key[33], char* out,
                       size_t out_len) {
  const size_t prefix_len = strlen(HIVE_PUBKEY_PREFIX);
  if (out_len < prefix_len + 1) return false;
  strlcpy(out, HIVE_PUBKEY_PREFIX, out_len);
  // Graphene uses RIPEMD checksum (not SHA256d) for public key encoding
  return base58_encode_check(public_key, 33, HASHER_RIPEMD, out + prefix_len,
                             out_len - prefix_len);
}

// ── Single-role key derivation to raw 33 bytes ────────────────────────────
// Path: m/48'/13'/role_hardened/account_index_hardened/0'
// hdnode_private_ckd() returns 1 on success, 0 on failure.

static bool hive_role_valid(uint32_t role) {
  return role == HIVE_ROLE_OWNER || role == HIVE_ROLE_ACTIVE ||
         role == HIVE_ROLE_MEMO || role == HIVE_ROLE_POSTING;
}

bool hive_slip48_path_valid(const uint32_t* address_n, size_t count) {
  if (!address_n || count != 5) return false;
  if (address_n[0] != HIVE_SLIP48_PURPOSE) return false;
  if (address_n[1] != HIVE_SLIP48_NETWORK) return false;
  if (!hive_role_valid(address_n[2])) return false;
  if ((address_n[3] & 0x80000000u) == 0) return false;
  if (address_n[4] != 0x80000000u) return false;
  return true;
}

bool hive_slip48_path_valid_for_role(const uint32_t* address_n, size_t count,
                                     uint32_t required_role) {
  return hive_role_valid(required_role) &&
         hive_slip48_path_valid(address_n, count) &&
         address_n[2] == required_role;
}

bool hive_deriveRawKey(const HDNode* root, uint32_t role_hardened,
                       uint32_t account_index_hardened, uint8_t out[33]) {
  HDNode node;
  memcpy(&node, root, sizeof(HDNode));
  if (!hdnode_private_ckd(&node, HIVE_SLIP48_PURPOSE)) goto fail;
  if (!hdnode_private_ckd(&node, HIVE_SLIP48_NETWORK)) goto fail;
  if (!hdnode_private_ckd(&node, role_hardened)) goto fail;
  if (!hdnode_private_ckd(&node, account_index_hardened)) goto fail;
  if (!hdnode_private_ckd(&node, 0x80000000u)) goto fail;
  hdnode_fill_public_key(&node);
  memcpy(out, node.public_key, 33);
  memzero(&node, sizeof(node));
  return true;
fail:
  memzero(&node, sizeof(node));
  return false;
}

// ── SLIP-0048 multi-role key derivation ───────────────────────────────────

bool hive_getPublicKeys(const HDNode* root, uint32_t account_index,
                        char* owner_out, size_t owner_len, char* active_out,
                        size_t active_len, char* memo_out, size_t memo_len,
                        char* posting_out, size_t posting_len) {
  const uint32_t roles[4] = {
      HIVE_ROLE_OWNER,
      HIVE_ROLE_ACTIVE,
      HIVE_ROLE_MEMO,
      HIVE_ROLE_POSTING,
  };
  char* outs[4] = {owner_out, active_out, memo_out, posting_out};
  const size_t lens[4] = {owner_len, active_len, memo_len, posting_len};

  uint32_t account_hardened = account_index | 0x80000000u;

  for (int i = 0; i < 4; i++) {
    uint8_t raw[33];
    if (!hive_deriveRawKey(root, roles[i], account_hardened, raw)) return false;
    if (!hive_getPublicKey(raw, outs[i], lens[i])) {
      memzero(raw, sizeof(raw));
      return false;
    }
    memzero(raw, sizeof(raw));
  }
  return true;
}

// ── Graphene binary serialization helpers ─────────────────────────────────

static void append_u8(uint8_t** buf, const uint8_t* end, uint8_t v) {
  if (*buf < end) {
    **buf = v;
    (*buf)++;
  }
}

static void append_u16_le(uint8_t** buf, const uint8_t* end, uint16_t v) {
  append_u8(buf, end, v & 0xFF);
  append_u8(buf, end, (v >> 8) & 0xFF);
}

static void append_u32_le(uint8_t** buf, const uint8_t* end, uint32_t v) {
  append_u8(buf, end, v & 0xFF);
  append_u8(buf, end, (v >> 8) & 0xFF);
  append_u8(buf, end, (v >> 16) & 0xFF);
  append_u8(buf, end, (v >> 24) & 0xFF);
}

static void append_u64_le(uint8_t** buf, const uint8_t* end, uint64_t v) {
  for (int i = 0; i < 8; i++) {
    append_u8(buf, end, v & 0xFF);
    v >>= 8;
  }
}

static void append_varint(uint8_t** buf, const uint8_t* end, uint64_t v) {
  do {
    uint8_t b = v & 0x7F;
    v >>= 7;
    if (v) b |= 0x80;
    append_u8(buf, end, b);
  } while (v);
}

static void append_string(uint8_t** buf, const uint8_t* end, const char* s) {
  size_t len = s ? strlen(s) : 0;
  append_varint(buf, end, len);
  for (size_t i = 0; i < len && *buf < end; i++)
    append_u8(buf, end, (uint8_t)s[i]);
}

/*
 * Graphene asset encoding: int64 LE amount + uint8 precision + 7-byte symbol
 */
static void append_asset(uint8_t** buf, const uint8_t* end, uint64_t amount,
                         uint8_t precision, const char* symbol) {
  append_u64_le(buf, end, amount);
  append_u8(buf, end, precision);
  char sym[7] = {0};
  if (symbol) strncpy(sym, symbol, 6);
  for (int i = 0; i < 7 && *buf < end; i++)
    append_u8(buf, end, (uint8_t)sym[i]);
}

/*
 * Graphene authority structure (Hive wire format):
 *   weight_threshold (uint32 LE) = 1
 *   num_account_auths (varint)   = 0
 *   num_key_auths (varint)       = 1
 *     compressed public key      (33 bytes, no type prefix)
 *     weight (uint16 LE)         = 1
 *
 * Note: Hive does NOT use a key-type prefix byte before the 33 raw bytes.
 */
static void append_authority(uint8_t** buf, const uint8_t* end,
                             const uint8_t pubkey[33]) {
  append_u32_le(buf, end, 1);  // weight_threshold = 1
  append_varint(buf, end, 0);  // 0 account auths
  append_varint(buf, end, 1);  // 1 key auth
  for (int i = 0; i < 33 && *buf < end; i++) append_u8(buf, end, pubkey[i]);
  append_u16_le(buf, end, 1);  // weight = 1
}

/*
 * Common transaction header: ref_block_num, ref_block_prefix, expiration,
 * then a varint op count = 1, then the op type varint.
 */
static void append_tx_header(uint8_t** buf, const uint8_t* end,
                             uint16_t ref_block_num, uint32_t ref_block_prefix,
                             uint32_t expiration, uint32_t op_type) {
  append_u16_le(buf, end, ref_block_num);
  append_u32_le(buf, end, ref_block_prefix);
  append_u32_le(buf, end, expiration);
  append_varint(buf, end, 1);  // 1 operation
  append_varint(buf, end, op_type);
}

static void append_tx_footer(uint8_t** buf, const uint8_t* end) {
  append_varint(buf, end, 0);  // 0 extensions
}

/*
 * Graphene legacy canonical-signature rule (identical to EOS/Steem): high bit
 * of both r and s must be clear — same predicate as eos_is_canonic. Modern
 * hived (post-HF28) actually enforces only BIP-0062 low-S (fc is_canonical ->
 * is_bip_0062_canonical), which trezor-crypto's low-S normalization already
 * guarantees; keeping the stricter legacy rule costs an occasional extra
 * RFC6979 iteration and stays compatible with every historical verifier.
 */
static int hive_is_canonic(uint8_t v, uint8_t signature[64]) {
  (void)v;
  return !(signature[0] & 0x80) &&
         !(signature[0] == 0 && !(signature[1] & 0x80)) &&
         !(signature[32] & 0x80) &&
         !(signature[32] == 0 && !(signature[33] & 0x80));
}

/*
 * Core sign helper over an already-computed 32-byte digest → 65-byte
 * compact recoverable sig: header (27 + recovery_id + 4 compressed-key
 * flag), then r(32) ‖ s(32).
 */
static bool hive_sign_raw_digest(const HDNode* node, const uint8_t digest[32],
                                 uint8_t sig[65]) {
  uint8_t pby;
  if (ecdsa_sign_digest(&secp256k1, node->private_key, digest, sig + 1, &pby,
                        hive_is_canonic) != 0) {
    return false;
  }
  // Compact signature header: 27 + recovery_id + 4 (compressed key flag)
  sig[0] = 27 + pby + 4;
  return true;
}

/*
 * Transaction sign helper: SHA256(chain_id || serialized_tx) → compact sig.
 * Writes 65 bytes into sig[]. Returns true on success.
 */
static bool hive_sign_digest(const HDNode* node, const uint8_t* chain_id,
                             const uint8_t* tx_buf, size_t tx_len,
                             uint8_t sig[65]) {
  SHA256_CTX sha;
  sha256_Init(&sha);
  sha256_Update(&sha, chain_id, HIVE_CHAIN_ID_LEN);
  sha256_Update(&sha, tx_buf, tx_len);
  uint8_t digest[32];
  sha256_Final(&sha, digest);

  bool ok = hive_sign_raw_digest(node, digest, sig);
  memzero(digest, sizeof(digest));
  return ok;
}

/*
 * Chain-id select (host-supplied 32-byte chain_id or mainnet default) +
 * hive_sign_digest, writing the 65-byte compact signature into sig[].
 */
static bool hive_sign_tx_sig(const HDNode* node, bool has_chain_id,
                             const uint8_t* chain_id_bytes,
                             size_t chain_id_size, const uint8_t* tx_buf,
                             size_t tx_len, uint8_t sig[65]) {
  const uint8_t default_chain_id[32] = HIVE_CHAIN_ID;
  /* Pin to Hive mainnet. A host-supplied chain_id is accepted only if it equals
   * mainnet; any other value is refused rather than signed under an undisclosed
   * network domain (the confirmations just say "Hive"). This also keeps the tx
   * digest domain singular — SHA256(mainnet_chain_id || tx) — so the
   * message-signing guard that rejects messages beginning with the mainnet
   * chain id fully closes the tx/message signature collision. */
  if (has_chain_id) {
    if (chain_id_size != HIVE_CHAIN_ID_LEN ||
        memcmp(chain_id_bytes, default_chain_id, HIVE_CHAIN_ID_LEN) != 0) {
      return false;
    }
  }
  return hive_sign_digest(node, default_chain_id, tx_buf, tx_len, sig);
}

// ── Parsed operation signing (HiveSignOperations) ─────────────────────────
//
// The host serializes the transaction; firmware re-derives everything it
// displays from the bytes and refuses anything outside the phase-1 op table.
// Digest/signature are identical to HiveSignTx: SHA256(chain_id || tx).

typedef struct {
  const uint8_t* p;
  const uint8_t* end;
} HiveCur;

/*
 * Bounded unsigned LEB128: at most 5 bytes, must fit uint32, overlong
 * encodings rejected (an unbounded shift is a classic overflow hole).
 */
static bool cur_varint(HiveCur* c, uint32_t* out) {
  uint32_t v = 0;
  for (int shift = 0; shift <= 28; shift += 7) {
    if (c->p >= c->end) return false;
    uint8_t b = *c->p++;
    if (shift == 28 && (b & 0xF0)) return false;  // overflow or 6th byte
    v |= (uint32_t)(b & 0x7F) << shift;
    if (!(b & 0x80)) {
      // A multi-byte LEB128 whose final group is zero has a shorter encoding.
      // hived re-serializes values canonically when checking a signature, so
      // accepting an overlong form would make the device sign bytes the chain
      // interprets and hashes differently.
      if (shift > 0 && (b & 0x7F) == 0) return false;
      *out = v;
      return true;
    }
  }
  return false;
}

/* varint length + bytes, bounds-checked against the buffer AND field caps. */
static bool cur_string(HiveCur* c, const uint8_t** s, uint16_t* slen,
                       uint32_t min_len, uint32_t max_len) {
  uint32_t n;
  if (!cur_varint(c, &n)) return false;
  if (n < min_len || n > max_len) return false;
  if ((size_t)(c->end - c->p) < n) return false;
  *s = c->p;
  *slen = (uint16_t)n;
  c->p += n;
  return true;
}

/*
 * Hive account names are rendered in compact multi-field confirmation screens,
 * so they must be valid protocol names rather than arbitrary byte strings.
 * This rejects embedded NUL/newline/control bytes that would truncate or
 * reshape the OLED while later bytes remained covered by the signature.
 */
static bool hive_account_name_valid(const uint8_t* s, uint16_t len,
                                    bool allow_empty) {
  if (len == 0) return allow_empty;
  if (len < 3 || len > 16) return false;

  bool at_segment_start = true;
  bool previous_hyphen = false;
  for (uint16_t i = 0; i < len; i++) {
    uint8_t ch = s[i];
    if (at_segment_start) {
      if (ch < 'a' || ch > 'z') return false;
      at_segment_start = false;
      previous_hyphen = false;
    } else if (ch == '.') {
      if (previous_hyphen || i + 1 == len) return false;
      at_segment_start = true;
    } else if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')) {
      previous_hyphen = false;
    } else if (ch == '-') {
      previous_hyphen = true;
    } else {
      return false;
    }
  }
  return !at_segment_start && !previous_hyphen;
}

static bool cur_account(HiveCur* c, const uint8_t** s, uint16_t* slen,
                        bool allow_empty) {
  if (!cur_string(c, s, slen, allow_empty ? 0 : 1, 16)) return false;
  return hive_account_name_valid(*s, *slen, allow_empty);
}

static int hive_slice_cmp(const uint8_t* a, uint16_t a_len, const uint8_t* b,
                          uint16_t b_len) {
  uint16_t min_len = a_len < b_len ? a_len : b_len;
  int cmp = memcmp(a, b, min_len);
  if (cmp != 0) return cmp;
  return (a_len > b_len) - (a_len < b_len);
}

/* Fixed-width little-endian readers, bounds-checked against the buffer. */
static bool cur_u16(HiveCur* c, uint16_t* out) {
  if ((size_t)(c->end - c->p) < 2) return false;
  *out = (uint16_t)((uint16_t)c->p[0] | ((uint16_t)c->p[1] << 8));
  c->p += 2;
  return true;
}

static bool cur_u32(HiveCur* c, uint32_t* out) {
  if ((size_t)(c->end - c->p) < 4) return false;
  *out = (uint32_t)c->p[0] | ((uint32_t)c->p[1] << 8) |
         ((uint32_t)c->p[2] << 16) | ((uint32_t)c->p[3] << 24);
  c->p += 4;
  return true;
}

/*
 * Graphene serializes bool as one byte. Anything other than 0/1 is a host
 * serializer bug, not a truthy value — reject rather than normalize, so a
 * malformed fill_or_kill or allow_votes can never be silently coerced.
 */
static bool cur_bool(HiveCur* c, bool* out) {
  if (c->p >= c->end) return false;
  uint8_t b = *c->p++;
  if (b > 1) return false;
  *out = (b == 1);
  return true;
}

uint64_t hive_assetAmount(const uint8_t* asset) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; i--) v = (v << 8) | asset[i];
  return v;
}

uint8_t hive_assetPrecision(const uint8_t* asset) { return asset[8]; }

// Wire symbol → display symbol. The chain serializes the pre-rebrand names;
// the user knows the post-rebrand ones. cur_asset() has already validated the
// symbol and its NUL padding, so the compares below are exact.
const char* hive_assetSymbol(const uint8_t* asset) {
  const char* sym = (const char*)(asset + 9);
  if (memcmp(sym, "STEEM", 6) == 0) return "HIVE";
  if (memcmp(sym, "SBD", 4) == 0) return "HBD";
  return sym;
}

/*
 * One 16-byte Graphene asset: int64 LE amount, uint8 precision, 7-byte
 * NUL-padded symbol.
 *
 * The symbol must be in `allowed` and carry its protocol-fixed precision.
 * Both checks are load-bearing for display integrity: an unexpected symbol
 * lets a host swap VESTS for HIVE (a ~2000x difference in real value behind
 * an identical-looking number), and a wrong precision moves the decimal
 * point on the confirmation screen relative to what the chain applies.
 */
static bool cur_asset(HiveCur* c, const uint8_t** out, uint32_t allowed) {
  if ((size_t)(c->end - c->p) < HIVE_ASSET_LEN) return false;
  const uint8_t* a = c->p;
  const uint8_t* sym = a + 9;

  uint32_t bit;
  uint8_t want_precision;
  size_t sym_len;
  // WIRE symbols, not display symbols: the 2020 rebrand renamed the tokens but
  // NOT their on-chain serialization, so hived still encodes HIVE as "STEEM"
  // and HBD as "SBD". Accepting the display spellings would let us sign bytes
  // hived can never validate — its signature check re-serializes the operation
  // and recovers a key from different bytes, surfacing as the misleading
  // "missing required active authority". hive_assetSymbol() maps back for the
  // OLED so the user still reads HIVE/HBD.
  if (memcmp(sym, "STEEM", 5) == 0) {
    bit = HIVE_SYM_HIVE;
    want_precision = 3;
    sym_len = 5;
  } else if (memcmp(sym, "SBD", 3) == 0) {
    bit = HIVE_SYM_HBD;
    want_precision = 3;
    sym_len = 3;
  } else if (memcmp(sym, "VESTS", 5) == 0) {
    bit = HIVE_SYM_VESTS;
    want_precision = 6;
    sym_len = 5;
  } else {
    return false;
  }
  // The prefix compares above would also accept a longer symbol sharing the
  // prefix ("HBDX"); the padding check is what makes them exact, and it also
  // guarantees hive_assetSymbol() returns a NUL-terminated C string.
  for (size_t i = sym_len; i < 7; i++) {
    if (sym[i] != 0) return false;
  }
  if (!(bit & allowed)) return false;
  if (a[8] != want_precision) return false;
  // Every asset field in this table is a quantity. A negative int64 would
  // render as an enormous positive number through the unsigned formatter.
  if (a[7] & 0x80) return false;

  *out = a;
  c->p += HIVE_ASSET_LEN;
  return true;
}

/*
 * Shared rejection reasons.
 *
 * These are diagnostics, not security surface: the protection is that the
 * device REFUSES, and the host already knows which operation it sent. One
 * bespoke sentence per failure site cost ~1.8KB of rodata on a part with
 * single-digit KB of flash left, so failures are grouped by reason instead.
 * The three that carry a distinct security meaning — an authority rotation,
 * a detached comment_options, a wrong-tier request — stay separate so they
 * are never confused with an ordinary parse failure in a bug report.
 */
static const char E_MALFORMED[] = "Hive tx: malformed operation";
static const char E_RANGE[] = "Hive tx: value out of range";
static const char E_AMOUNT[] = "Hive tx: amount must be greater than zero";
static const char E_NOOP[] = "Hive tx: operation has no effect";
static const char E_EXTENSIONS[] = "Hive tx: extensions must be empty";
static const char E_BENEFICIARIES[] = "Hive tx: invalid beneficiaries";
static const char E_SYMBOLS[] = "Hive tx: order symbols must differ";
static const char E_AUTHORITY[] = "Hive tx: authority changes not supported";
static const char E_BINDING[] =
    "Hive tx: comment_options must follow its comment";
static const char E_MIXED_TIER[] = "Hive tx: mixed posting/active ops";

const char* hive_parseOperations(const uint8_t* tx, size_t len,
                                 HiveParsedTx* out) {
  memzero(out, sizeof(*out));
  // 10-byte header + op_count varint + extensions varint is the structural
  // minimum; op bodies are bounds-checked as they parse.
  if (len < 12) return "Hive tx too short";
  if (len > HIVE_MAX_OPS_TX_LEN) return "Hive tx too long";  // = proto cap

  // Header (ref_block_num u16, ref_block_prefix u32, expiration u32) is
  // covered by the signature but carries nothing to confirm on-device.
  HiveCur c = {tx + 10, tx + len};

  uint32_t op_count;
  if (!cur_varint(&c, &op_count)) return E_MALFORMED;
  if (op_count < 1 || op_count > HIVE_MAX_TX_OPS)
    return "Hive tx: op count must be 1-4";
  out->num_ops = (uint8_t)op_count;

  bool any_posting = false, any_active = false;

  for (uint32_t i = 0; i < op_count; i++) {
    HiveTxOp* op = &out->ops[i];
    uint32_t op_type;
    if (!cur_varint(&c, &op_type)) return E_MALFORMED;
    op->op_type = op_type;

    switch (op_type) {
      case HIVE_OP_VOTE: {  // posting authority
        if (!cur_account(&c, &op->acct, &op->acct_len, false) ||
            !cur_account(&c, &op->target, &op->target_len, false) ||
            !cur_string(&c, &op->detail, &op->detail_len, 1, 256))
          return E_MALFORMED;
        if ((size_t)(c.end - c.p) < 2) return E_MALFORMED;
        int16_t w = (int16_t)((uint16_t)c.p[0] | ((uint16_t)c.p[1] << 8));
        c.p += 2;
        if (w < -10000 || w > 10000) return E_RANGE;
        op->weight = w;
        any_posting = true;
        break;
      }
      case HIVE_OP_COMMENT: {  // posting authority
        const uint8_t *pa, *ppl, *permlink, *jm;
        uint16_t pa_len, ppl_len, permlink_len, jm_len;
        if (!cur_account(&c, &pa, &pa_len, true) ||
            !cur_string(&c, &ppl, &ppl_len, 1, 256) ||
            !cur_account(&c, &op->acct, &op->acct_len, false) ||
            !cur_string(&c, &permlink, &permlink_len, 1, 256) ||
            !cur_string(&c, &op->target, &op->target_len, 0, 256) ||
            !cur_string(&c, &op->detail, &op->detail_len, 1,
                        HIVE_MAX_OPS_TX_LEN) ||
            !cur_string(&c, &jm, &jm_len, 0, HIVE_MAX_OPS_TX_LEN))
          return E_MALFORMED;
        op->parent_author = pa;
        op->parent_author_len = pa_len;
        op->parent_permlink = ppl;
        op->parent_permlink_len = ppl_len;
        op->permlink = permlink;
        op->permlink_len = permlink_len;
        op->json_metadata = jm;
        op->json_metadata_len = jm_len;
        op->is_top_level = (pa_len == 0);
        any_posting = true;
        break;
      }
      case HIVE_OP_CUSTOM_JSON: {  // posting OR active authority
        uint32_t n_active, n_posting;
        if (!cur_varint(&c, &n_active)) return E_MALFORMED;
        if (n_active > HIVE_MAX_CUSTOM_JSON_AUTHS) return E_RANGE;
        const uint8_t* previous_auth = NULL;
        uint16_t previous_auth_len = 0;
        for (uint32_t k = 0; k < n_active; k++) {
          const uint8_t* s;
          uint16_t sl;
          if (!cur_account(&c, &s, &sl, false)) return E_MALFORMED;
          if (previous_auth &&
              hive_slice_cmp(previous_auth, previous_auth_len, s, sl) >= 0)
            return E_MALFORMED;
          op->auth_acct[op->n_auths] = s;
          op->auth_acct_len[op->n_auths++] = sl;
          previous_auth = s;
          previous_auth_len = sl;
          if (!op->acct) {
            op->acct = s;
            op->acct_len = sl;
          }
        }
        if (!cur_varint(&c, &n_posting)) return E_MALFORMED;
        if (n_posting > HIVE_MAX_CUSTOM_JSON_AUTHS - n_active) return E_RANGE;
        previous_auth = NULL;
        previous_auth_len = 0;
        for (uint32_t k = 0; k < n_posting; k++) {
          const uint8_t* s;
          uint16_t sl;
          if (!cur_account(&c, &s, &sl, false)) return E_MALFORMED;
          if (previous_auth &&
              hive_slice_cmp(previous_auth, previous_auth_len, s, sl) >= 0)
            return E_MALFORMED;
          op->auth_acct[op->n_auths] = s;
          op->auth_acct_len[op->n_auths++] = sl;
          previous_auth = s;
          previous_auth_len = sl;
          if (!op->acct) {
            op->acct = s;
            op->acct_len = sl;
          }
        }
        if (n_active + n_posting == 0) return E_MALFORMED;
        // Both tiers on one op can never be satisfied by a single signature
        // (post-HF28 hived requires the exact authority) — malformed input.
        if (n_active > 0 && n_posting > 0) return E_MIXED_TIER;
        if (!cur_string(&c, &op->target, &op->target_len, 1, 32) ||
            !cur_string(&c, &op->detail, &op->detail_len, 1,
                        HIVE_MAX_OPS_TX_LEN))
          return E_MALFORMED;
        op->needs_active = (n_active > 0);
        if (op->needs_active)
          any_active = true;
        else
          any_posting = true;
        break;
      }
      case HIVE_OP_TRANSFER_TO_VESTING: {  // active authority
        // `to` may be empty — hived reads that as "power up to self".
        if (!cur_account(&c, &op->acct, &op->acct_len, false) ||
            !cur_account(&c, &op->target, &op->target_len, true) ||
            !cur_asset(&c, &op->assets[0], HIVE_SYM_HIVE))
          return E_MALFORMED;
        if (hive_assetAmount(op->assets[0]) == 0) return E_AMOUNT;
        op->n_assets = 1;
        any_active = true;
        break;
      }
      case HIVE_OP_WITHDRAW_VESTING: {  // active authority
        // 0.000000 VESTS is meaningful here: it cancels an in-progress
        // power-down, so zero must NOT be rejected.
        if (!cur_account(&c, &op->acct, &op->acct_len, false) ||
            !cur_asset(&c, &op->assets[0], HIVE_SYM_VESTS))
          return E_MALFORMED;
        op->n_assets = 1;
        any_active = true;
        break;
      }
      case HIVE_OP_LIMIT_ORDER_CREATE: {  // active authority
        if (!cur_account(&c, &op->acct, &op->acct_len, false) ||
            !cur_u32(&c, &op->req_id) ||
            !cur_asset(&c, &op->assets[0], HIVE_SYM_HIVE | HIVE_SYM_HBD) ||
            !cur_asset(&c, &op->assets[1], HIVE_SYM_HIVE | HIVE_SYM_HBD) ||
            !cur_bool(&c, &op->flag) || !cur_u32(&c, &op->expiration))
          return E_MALFORMED;
        if (hive_assetAmount(op->assets[0]) == 0 ||
            hive_assetAmount(op->assets[1]) == 0)
          return E_AMOUNT;
        // The internal market only pairs HIVE against HBD. A same-symbol
        // order is rejected on-chain anyway, and on the OLED it would read
        // as a harmless self-trade while burning the fill.
        if (memcmp(op->assets[0] + 9, op->assets[1] + 9, 7) == 0)
          return E_SYMBOLS;
        op->n_assets = 2;
        any_active = true;
        break;
      }
      case HIVE_OP_LIMIT_ORDER_CANCEL: {  // active authority
        if (!cur_account(&c, &op->acct, &op->acct_len, false) ||
            !cur_u32(&c, &op->req_id))
          return E_MALFORMED;
        any_active = true;
        break;
      }
      case HIVE_OP_CONVERT: {  // active authority
        if (!cur_account(&c, &op->acct, &op->acct_len, false) ||
            !cur_u32(&c, &op->req_id) ||
            !cur_asset(&c, &op->assets[0], HIVE_SYM_HBD))
          return E_MALFORMED;
        if (hive_assetAmount(op->assets[0]) == 0) return E_AMOUNT;
        op->n_assets = 1;
        any_active = true;
        break;
      }
      case HIVE_OP_COMMENT_OPTIONS: {  // posting authority
        uint16_t percent_hbd;
        if (!cur_account(&c, &op->acct, &op->acct_len, false) ||
            !cur_string(&c, &op->permlink, &op->permlink_len, 1, 256) ||
            !cur_asset(&c, &op->assets[0], HIVE_SYM_HBD) ||
            !cur_u16(&c, &percent_hbd) || !cur_bool(&c, &op->flag) ||
            !cur_bool(&c, &op->flag2))
          return E_MALFORMED;
        if (percent_hbd > 10000) return E_RANGE;
        op->weight = (int16_t)percent_hbd;
        op->n_assets = 1;

        // SECURITY: this op redirects a post's payout. It binds to exactly
        // one post, so it is accepted ONLY immediately after a comment op
        // with the same author and permlink. Standing alone it could attach
        // beneficiaries to a post the user published earlier and is not
        // reviewing on this screen.
        if (i == 0 || out->ops[i - 1].op_type != HIVE_OP_COMMENT)
          return E_BINDING;
        const HiveTxOp* prev = &out->ops[i - 1];
        if (prev->acct_len != op->acct_len ||
            memcmp(prev->acct, op->acct, op->acct_len) != 0 ||
            prev->permlink_len != op->permlink_len ||
            memcmp(prev->permlink, op->permlink, op->permlink_len) != 0)
          return E_BINDING;

        uint32_t ext_n;
        if (!cur_varint(&c, &ext_n)) return E_MALFORMED;
        // hived permits only one comment_payout_beneficiaries extension;
        // two would let a host split 16 beneficiaries past a per-extension
        // bound check.
        if (ext_n > 1) return E_BENEFICIARIES;
        if (ext_n == 1) {
          uint32_t tag, n_benef;
          if (!cur_varint(&c, &tag) || tag != 0) return E_BENEFICIARIES;
          if (!cur_varint(&c, &n_benef) || n_benef < 1 ||
              n_benef > HIVE_MAX_BENEFICIARIES)
            return E_BENEFICIARIES;
          uint32_t weight_sum = 0;
          const uint8_t* prev_acct = NULL;
          uint16_t prev_acct_len = 0;
          for (uint32_t k = 0; k < n_benef; k++) {
            if (!cur_account(&c, &op->benef_acct[k], &op->benef_acct_len[k],
                             false) ||
                !cur_u16(&c, &op->benef_weight[k]))
              return E_MALFORMED;
            if (op->benef_weight[k] > 10000) return E_RANGE;
            // hived requires strictly ascending account names, which also
            // enforces uniqueness. An unsorted list is rejected on-chain, so
            // signing it would only waste a device confirmation.
            if (prev_acct) {
              if (hive_slice_cmp(prev_acct, prev_acct_len, op->benef_acct[k],
                                 op->benef_acct_len[k]) >= 0)
                return E_BENEFICIARIES;
            }
            prev_acct = op->benef_acct[k];
            prev_acct_len = op->benef_acct_len[k];
            weight_sum += op->benef_weight[k];
          }
          if (weight_sum > 10000) return E_BENEFICIARIES;
          op->n_benef = (uint8_t)n_benef;
        }
        any_posting = true;
        break;
      }
      case HIVE_OP_TRANSFER_TO_SAVINGS: {  // active authority
        if (!cur_account(&c, &op->acct, &op->acct_len, false) ||
            !cur_account(&c, &op->target, &op->target_len, false) ||
            !cur_asset(&c, &op->assets[0], HIVE_SYM_HIVE | HIVE_SYM_HBD) ||
            !cur_string(&c, &op->detail, &op->detail_len, 0, HIVE_MAX_MEMO_LEN))
          return E_MALFORMED;
        if (hive_assetAmount(op->assets[0]) == 0) return E_AMOUNT;
        op->n_assets = 1;
        any_active = true;
        break;
      }
      case HIVE_OP_TRANSFER_FROM_SAVINGS: {  // active authority
        if (!cur_account(&c, &op->acct, &op->acct_len, false) ||
            !cur_u32(&c, &op->req_id) ||
            !cur_account(&c, &op->target, &op->target_len, false) ||
            !cur_asset(&c, &op->assets[0], HIVE_SYM_HIVE | HIVE_SYM_HBD) ||
            !cur_string(&c, &op->detail, &op->detail_len, 0, HIVE_MAX_MEMO_LEN))
          return E_MALFORMED;
        if (hive_assetAmount(op->assets[0]) == 0) return E_AMOUNT;
        op->n_assets = 1;
        any_active = true;
        break;
      }
      case HIVE_OP_CLAIM_REWARD_BALANCE: {  // posting authority
        if (!cur_account(&c, &op->acct, &op->acct_len, false) ||
            !cur_asset(&c, &op->assets[0], HIVE_SYM_HIVE) ||
            !cur_asset(&c, &op->assets[1], HIVE_SYM_HBD) ||
            !cur_asset(&c, &op->assets[2], HIVE_SYM_VESTS))
          return E_MALFORMED;
        if (hive_assetAmount(op->assets[0]) == 0 &&
            hive_assetAmount(op->assets[1]) == 0 &&
            hive_assetAmount(op->assets[2]) == 0)
          return E_NOOP;
        op->n_assets = 3;
        any_posting = true;
        break;
      }
      case HIVE_OP_DELEGATE_VESTING_SHARES: {  // active authority
        // 0.000000 VESTS is meaningful: it removes an existing delegation.
        if (!cur_account(&c, &op->acct, &op->acct_len, false) ||
            !cur_account(&c, &op->target, &op->target_len, false) ||
            !cur_asset(&c, &op->assets[0], HIVE_SYM_VESTS))
          return E_MALFORMED;
        op->n_assets = 1;
        any_active = true;
        break;
      }
      case HIVE_OP_ACCOUNT_UPDATE2: {  // active or posting authority
        uint32_t ext_n;
        if (!cur_account(&c, &op->acct, &op->acct_len, false))
          return E_MALFORMED;
        // SECURITY: account_update2 can rotate owner/active/posting/memo
        // keys. Only the profile-metadata form is in the table — this is the
        // op-9/10 device-derived-keys invariant applied field-level. Any
        // authority field present is a hard reject; do NOT soften this
        // without the authority-management design review.
        for (int k = 0; k < 4; k++) {
          bool present;
          if (!cur_bool(&c, &present)) return E_MALFORMED;
          if (present) return E_AUTHORITY;
        }
        if (!cur_string(&c, &op->detail, &op->detail_len, 0,
                        HIVE_MAX_OPS_TX_LEN) ||
            !cur_string(&c, &op->json_metadata, &op->json_metadata_len, 0,
                        HIVE_MAX_OPS_TX_LEN))
          return E_MALFORMED;
        if (op->detail_len == 0 && op->json_metadata_len == 0) return E_NOOP;
        if (!cur_varint(&c, &ext_n)) return E_MALFORMED;
        if (ext_n != 0) return E_EXTENSIONS;
        // json_metadata is an active-key field; a posting_json_metadata-only
        // update is a posting-tier profile change.
        op->needs_active = (op->detail_len > 0);
        if (op->needs_active)
          any_active = true;
        else
          any_posting = true;
        break;
      }
      case HIVE_OP_TRANSFER:
      case HIVE_OP_ACCOUNT_CREATE:
      case HIVE_OP_ACCOUNT_UPDATE:
        // PERMANENTLY excluded from this table: transfer keeps the stronger
        // dedicated HiveSignTx display path; the account ops keep the
        // device-derived-keys-only invariant (a generic raw-bytes path
        // would let a host slip third-party authorities into an
        // account_update). Never add these here.
        return "Hive tx: op requires its dedicated message type";
      default:
        return "Hive tx: unsupported operation type";
    }
  }

  uint32_t ext_count;
  if (!cur_varint(&c, &ext_count)) return E_MALFORMED;
  if (ext_count != 0) return E_EXTENSIONS;
  if (c.p != c.end) return "Hive tx: trailing bytes";

  // One signature cannot satisfy posting- and active-tier ops at once.
  if (any_posting && any_active) return E_MIXED_TIER;
  out->needs_active = any_active;
  return NULL;
}

void hive_signOperations(const HDNode* node, const HiveSignOperations* msg,
                         HiveSignedOperations* resp) {
  if (!msg->has_serialized_tx || msg->serialized_tx.size == 0 ||
      msg->serialized_tx.size > HIVE_MAX_OPS_TX_LEN)
    return;

  // Hash straight from the decoded message — no stack copy of the 2KB tx.
  if (!hive_sign_tx_sig(node, msg->has_chain_id, msg->chain_id.bytes,
                        msg->chain_id.size, msg->serialized_tx.bytes,
                        msg->serialized_tx.size, resp->signature.bytes)) {
    return;
  }

  resp->has_signature = true;
  resp->signature.size = 65;
}

// ── Message signing (Keychain signBuffer contract) ────────────────────────
// Digest is SHA256(message bytes) ONLY: no chain_id prepend (unlike
// transactions) and no Bitcoin/Solana-style message prefix. hive-js
// Signature.signBuffer — which every Hive dApp verifies against — hashes
// the raw bytes exactly once; any added prefix silently breaks all dApp
// verification.

bool hive_message_is_printable(const uint8_t* message, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (message[i] < 0x20 || message[i] > 0x7e) return false;
  }
  return true;
}

void hive_signMessage(const HDNode* node, const HiveSignMessage* msg,
                      HiveSignedMessage* resp) {
  if (!msg->has_message || msg->message.size > HIVE_MAX_MESSAGE_LEN) return;

  uint8_t digest[32];
  sha256_Raw(msg->message.bytes, msg->message.size, digest);

  uint8_t sig[65];
  if (!hive_sign_raw_digest(node, digest, sig)) {
    memzero(digest, sizeof(digest));
    memzero(sig, sizeof(sig));
    return;
  }

  resp->has_signature = true;
  resp->signature.size = 65;
  memcpy(resp->signature.bytes, sig, 65);

  // Caller must have run hdnode_fill_public_key(node). Returned so the host
  // can build Keychain's publicKey response field without a second call.
  resp->has_public_key = true;
  resp->public_key.size = 33;
  memcpy(resp->public_key.bytes, node->public_key, 33);

  memzero(digest, sizeof(digest));
  memzero(sig, sizeof(sig));
}

// ── Transfer (op type 2) ──────────────────────────────────────────────────

static size_t hive_serialize_transfer(const HiveSignTx* msg, uint8_t* buf,
                                      size_t buf_len) {
  uint8_t* p = buf;
  const uint8_t* end = buf + buf_len;

  append_tx_header(&p, end, (uint16_t)(msg->ref_block_num & 0xFFFF),
                   msg->ref_block_prefix, msg->expiration, HIVE_OP_TRANSFER);

  append_string(&p, end, msg->has_from ? msg->from : "");
  append_string(&p, end, msg->has_to ? msg->to : "");

  const char* sym = msg->has_asset_symbol ? msg->asset_symbol : "HIVE";
  uint8_t prec = (uint8_t)(msg->has_decimals ? msg->decimals : HIVE_DECIMALS);
  append_asset(&p, end, msg->amount, prec, sym);

  append_string(&p, end, msg->has_memo ? msg->memo : "");
  append_tx_footer(&p, end);
  return (size_t)(p - buf);
}

void hive_signTx(const HDNode* node, const HiveSignTx* msg,
                 HiveSignedTx* resp) {
  // Reject memos that would overflow the fixed-size tx_buf.
  if (msg->has_memo && strlen(msg->memo) > HIVE_MAX_MEMO_LEN) return;

  uint8_t tx_buf[512];
  size_t tx_len = hive_serialize_transfer(msg, tx_buf, sizeof(tx_buf));

  if (!hive_sign_tx_sig(node, msg->has_chain_id, msg->chain_id.bytes,
                        msg->chain_id.size, tx_buf, tx_len,
                        resp->signature.bytes)) {
    return;
  }

  resp->has_signature = true;
  resp->signature.size = 65;

  resp->has_serialized_tx = true;
  resp->serialized_tx.size = tx_len;
  memcpy(resp->serialized_tx.bytes, tx_buf, tx_len);

  memzero(tx_buf, tx_len);
}

// ── Account create (op type 9) ────────────────────────────────────────────
//
// All four role keys are device-derived by the caller (FSM handler) and
// passed as raw 33-byte compressed public keys. The firmware never uses
// host-supplied key strings for the actual transaction.

static size_t hive_serialize_account_create(const HiveSignAccountCreate* msg,
                                            const uint8_t owner_raw[33],
                                            const uint8_t active_raw[33],
                                            const uint8_t posting_raw[33],
                                            const uint8_t memo_raw[33],
                                            uint8_t* buf, size_t buf_len) {
  uint8_t* p = buf;
  const uint8_t* end = buf + buf_len;

  append_tx_header(&p, end, (uint16_t)(msg->ref_block_num & 0xFFFF),
                   msg->ref_block_prefix, msg->expiration,
                   HIVE_OP_ACCOUNT_CREATE);

  // fee (asset)
  uint64_t fee = msg->has_fee_amount ? msg->fee_amount : 3000;
  append_asset(&p, end, fee, HIVE_DECIMALS, "HIVE");

  // creator
  append_string(&p, end, msg->has_creator ? msg->creator : "");

  // new_account_name
  append_string(&p, end,
                msg->has_new_account_name ? msg->new_account_name : "");

  // authority fields use device-derived raw bytes (no host trust, no type
  // prefix)
  append_authority(&p, end, owner_raw);
  append_authority(&p, end, active_raw);
  append_authority(&p, end, posting_raw);

  // memo_key: 33 raw bytes, no authority wrapper, no type prefix byte
  for (int i = 0; i < 33 && p < end; i++) append_u8(&p, end, memo_raw[i]);

  // json_metadata (empty)
  append_string(&p, end, "");
  append_tx_footer(&p, end);

  return (size_t)(p - buf);
}

void hive_signAccountCreate(const HDNode* signing_node,
                            const HiveSignAccountCreate* msg,
                            const uint8_t owner_raw[33],
                            const uint8_t active_raw[33],
                            const uint8_t posting_raw[33],
                            const uint8_t memo_raw[33],
                            HiveSignedAccountCreate* resp) {
  uint8_t tx_buf[512];
  size_t tx_len =
      hive_serialize_account_create(msg, owner_raw, active_raw, posting_raw,
                                    memo_raw, tx_buf, sizeof(tx_buf));

  if (!hive_sign_tx_sig(signing_node, msg->has_chain_id, msg->chain_id.bytes,
                        msg->chain_id.size, tx_buf, tx_len,
                        resp->signature.bytes)) {
    memzero(tx_buf, sizeof(tx_buf));
    return;
  }

  resp->has_signature = true;
  resp->signature.size = 65;

  resp->has_serialized_tx = true;
  resp->serialized_tx.size = tx_len;
  memcpy(resp->serialized_tx.bytes, tx_buf, tx_len);

  memzero(tx_buf, tx_len);
}

// ── Account update (op type 10) ───────────────────────────────────────────
//
// All four new role keys are device-derived by the caller (FSM handler).
// The host-supplied new_*_key fields in the message are not used for signing.

static size_t hive_serialize_account_update(const HiveSignAccountUpdate* msg,
                                            const uint8_t owner_raw[33],
                                            const uint8_t active_raw[33],
                                            const uint8_t posting_raw[33],
                                            const uint8_t memo_raw[33],
                                            uint8_t* buf, size_t buf_len) {
  uint8_t* p = buf;
  const uint8_t* end = buf + buf_len;

  append_tx_header(&p, end, (uint16_t)(msg->ref_block_num & 0xFFFF),
                   msg->ref_block_prefix, msg->expiration,
                   HIVE_OP_ACCOUNT_UPDATE);

  // account name
  append_string(&p, end, msg->has_account ? msg->account : "");

  /*
   * account_update optional authority fields use a Graphene "optional" wrapper:
   *   present: 0x01 + authority bytes
   *   absent:  0x00
   * We always include all four — this replaces all authorities.
   */
  append_u8(&p, end, 0x01);  // owner present
  append_authority(&p, end, owner_raw);
  append_u8(&p, end, 0x01);  // active present
  append_authority(&p, end, active_raw);
  append_u8(&p, end, 0x01);  // posting present
  append_authority(&p, end, posting_raw);

  // memo_key: 33 raw bytes, always present, no type prefix byte
  for (int i = 0; i < 33 && p < end; i++) append_u8(&p, end, memo_raw[i]);

  // json_metadata (empty)
  append_string(&p, end, "");
  append_tx_footer(&p, end);

  return (size_t)(p - buf);
}

void hive_signAccountUpdate(const HDNode* signing_node,
                            const HiveSignAccountUpdate* msg,
                            const uint8_t owner_raw[33],
                            const uint8_t active_raw[33],
                            const uint8_t posting_raw[33],
                            const uint8_t memo_raw[33],
                            HiveSignedAccountUpdate* resp) {
  uint8_t tx_buf[512];
  size_t tx_len =
      hive_serialize_account_update(msg, owner_raw, active_raw, posting_raw,
                                    memo_raw, tx_buf, sizeof(tx_buf));

  if (!hive_sign_tx_sig(signing_node, msg->has_chain_id, msg->chain_id.bytes,
                        msg->chain_id.size, tx_buf, tx_len,
                        resp->signature.bytes)) {
    memzero(tx_buf, sizeof(tx_buf));
    return;
  }

  resp->has_signature = true;
  resp->signature.size = 65;

  resp->has_serialized_tx = true;
  resp->serialized_tx.size = tx_len;
  memcpy(resp->serialized_tx.bytes, tx_buf, tx_len);

  memzero(tx_buf, tx_len);
}
