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

#include "keepkey/firmware/zcash.h"

#include <string.h>

#include "keepkey/firmware/crypto.h"
#include "trezor/crypto/aes/aes.h"
#include "trezor/crypto/bignum.h"
#include "trezor/crypto/blake2b.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/hasher.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/pallas.h"
#include "trezor/crypto/pallas_ct.h"
#include "trezor/crypto/pallas_sinsemilla.h"
#include "trezor/crypto/pallas_swu.h"
#include "trezor/crypto/redpallas.h"
#include "trezor/crypto/zcash_zip316.h"

/* ZIP-32 Orchard master key only; children use PRF^expand. */
static void zip32_orchard_master(const uint8_t* seed, size_t seed_len,
                                 uint8_t out[64]) {
  BLAKE2B_CTX ctx;
  blake2b_InitPersonal(&ctx, 64, "ZcashIP32Orchard", 16);
  blake2b_Update(&ctx, seed, seed_len);
  blake2b_Final(&ctx, out, 64);
  /* ctx still holds the master key (h) and the last seed block (buf). */
  memzero(&ctx, sizeof(ctx));
}

/* PRF^expand(sk, t) = BLAKE2b-512("Zcash_ExpandSeed", sk || t) */
static void prf_expand(const uint8_t sk[32], const uint8_t* t, size_t t_len,
                       uint8_t out[64]) {
  BLAKE2B_CTX ctx;
  blake2b_InitPersonal(&ctx, 64, "Zcash_ExpandSeed", 16);
  blake2b_Update(&ctx, sk, 32);
  blake2b_Update(&ctx, t, t_len);
  blake2b_Final(&ctx, out, 64);
  /* ctx still holds sk and the output. */
  memzero(&ctx, sizeof(ctx));
}

/* 2^256 mod q (Pallas scalar order), LE. Check: R + 3*q == 2^256. */
static const uint8_t two_256_mod_q[32] = {
    0xfd, 0xff, 0xff, 0xff, 0x9c, 0x3e, 0x2b, 0x5b, 0x67, 0x05, 0x42,
    0xe3, 0x0b, 0x35, 0x2c, 0x99, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
};

/* 2^256 mod p (Pallas base prime), LE. Check: R + 3*p == 2^256. */
static const uint8_t two_256_mod_p[32] = {
    0xfd, 0xff, 0xff, 0xff, 0x38, 0x6d, 0x78, 0x34, 0xad, 0x14, 0x19,
    0xe4, 0x0b, 0x35, 0x2c, 0x99, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
};

/* ToScalar: (lo + hi * 2^256) mod q over 64 LE bytes, matching the orchard
 * crate's from_uniform_bytes. */
static void to_scalar(const uint8_t input[64], uint8_t output[32]) {
  bignum256 lo, hi, t256, result;

  bn_read_le(input, &lo);
  pallas_ct_mod_q(&lo);

  bn_read_le(input + 32, &hi);
  pallas_ct_mod_q(&hi);

  bn_read_le(two_256_mod_q, &t256);

  bn_copy(&hi, &result);
  pallas_ct_mul_mod_q(&result, &t256);

  pallas_ct_add_mod_q(&result, &lo);

  bn_write_le(&result, output);

  memzero(&lo, sizeof(lo));
  memzero(&hi, sizeof(hi));
  memzero(&result, sizeof(result));
}

/* ToBase: (lo + hi * 2^256) mod p over 64 LE bytes. */
static void to_base(const uint8_t input[64], uint8_t output[32]) {
  bignum256 lo, hi, t256, result;

  bn_read_le(input, &lo);
  pallas_ct_mod_p(&lo);

  bn_read_le(input + 32, &hi);
  pallas_ct_mod_p(&hi);

  bn_read_le(two_256_mod_p, &t256);

  bn_copy(&hi, &result);
  pallas_ct_mul_mod_p(&result, &t256);

  bignum256 sum;
  pallas_ct_add_mod_p(&result, &lo, &sum);
  bn_copy(&sum, &result);
  memzero(&sum, sizeof(sum));

  bn_write_le(&result, output);

  memzero(&lo, sizeof(lo));
  memzero(&hi, sizeof(hi));
  memzero(&result, sizeof(result));
}

#define ZIP32_HARDENED 0x80000000

/* Diversifiers: FF1-AES256, radix 2, n = 88, empty tweak, 10 rounds. Bytes
 * are LEBS2OSP but FF1 NUM/STR use numeral order: keep the bit-order
 * conversion, or this silently becomes a different (radix-256) permutation. */
#define ZCASH_FF1_BITS 88
#define ZCASH_FF1_HALF_BITS 44
#define ZCASH_FF1_MASK44 ((UINT64_C(1) << ZCASH_FF1_HALF_BITS) - 1)

static uint8_t bit_get_le(const uint8_t* bytes, uint32_t bit) {
  return (bytes[bit >> 3] >> (bit & 7)) & 1;
}

static void bit_set_le(uint8_t* bytes, uint32_t bit, uint8_t value) {
  if (value) {
    bytes[bit >> 3] |= (uint8_t)(1u << (bit & 7));
  }
}

static uint64_t ff1_bits_to_num(const uint8_t bits[11], uint32_t offset,
                                uint32_t len) {
  uint64_t n = 0;
  for (uint32_t i = 0; i < len; i++) {
    n = (n << 1) | bit_get_le(bits, offset + i);
  }
  return n;
}

static void ff1_num_to_bits(uint64_t n, uint8_t bits[11], uint32_t offset,
                            uint32_t len) {
  for (uint32_t i = 0; i < len; i++) {
    uint32_t shift = len - 1 - i;
    bit_set_le(bits, offset + i, (uint8_t)((n >> shift) & 1));
  }
}

static void ff1_store_be48(uint64_t n, uint8_t out[6]) {
  for (int i = 5; i >= 0; i--) {
    out[i] = (uint8_t)(n & 0xff);
    n >>= 8;
  }
}

static bool aes256_encrypt_block(const aes_encrypt_ctx* ctx,
                                 const uint8_t in[16], uint8_t out[16]) {
  return aes_encrypt(in, out, ctx) == EXIT_SUCCESS;
}

static bool ff1_round_y_mod_2_44(const aes_encrypt_ctx* ctx, uint8_t round,
                                 uint64_t b, uint64_t* y_mod) {
  static const uint8_t P[16] = {
      0x01, 0x02, 0x01, 0x00, 0x00, 0x02, 0x0a, 0x2c,
      0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x00,
  };

  uint8_t q[16] = {0};
  uint8_t y[16];
  uint8_t block[16];
  uint8_t r[16];
  uint64_t low48 = 0;
  bool ok = false;

  /* Q = T || 0^9 || [i]_1 || [NUM(B)]_6  (t = 0, b = 6) */
  q[9] = round;
  ff1_store_be48(b, q + 10);

  /* PRF(P || Q) = CBC-MAC_AES(P || Q), IV = 0. */
  if (!aes256_encrypt_block(ctx, P, y)) goto cleanup;
  for (int i = 0; i < 16; i++) {
    block[i] = y[i] ^ q[i];
  }
  if (!aes256_encrypt_block(ctx, block, r)) goto cleanup;

  /* d = 12; only NUM(S) mod 2^44 is needed. */
  for (int i = 6; i < 12; i++) {
    low48 = (low48 << 8) | r[i];
  }
  *y_mod = low48 & ZCASH_FF1_MASK44;
  ok = true;

cleanup:
  memzero(q, sizeof(q));
  memzero(y, sizeof(y));
  memzero(block, sizeof(block));
  memzero(r, sizeof(r));
  memzero(&low48, sizeof(low48));
  return ok;
}

bool zcash_orchard_derive_diversifier(const uint8_t dk[32],
                                      const uint8_t index_le[11],
                                      uint8_t diversifier_out[11]) {
  if (!dk || !index_le || !diversifier_out) return false;

  aes_encrypt_ctx ctx;
  if (aes_encrypt_key256(dk, &ctx) != EXIT_SUCCESS) {
    memzero(&ctx, sizeof(ctx));
    return false;
  }

  uint64_t A =
      ff1_bits_to_num(index_le, 0, ZCASH_FF1_HALF_BITS) & ZCASH_FF1_MASK44;
  uint64_t B =
      ff1_bits_to_num(index_le, ZCASH_FF1_HALF_BITS, ZCASH_FF1_HALF_BITS) &
      ZCASH_FF1_MASK44;

  for (uint8_t round = 0; round < 10; round++) {
    uint64_t y;
    if (!ff1_round_y_mod_2_44(&ctx, round, B, &y)) {
      memzero(&ctx, sizeof(ctx));
      memzero(&A, sizeof(A));
      memzero(&B, sizeof(B));
      return false;
    }
    uint64_t C = (A + y) & ZCASH_FF1_MASK44;
    A = B;
    B = C;
  }

  memset(diversifier_out, 0, 11);
  ff1_num_to_bits(A, diversifier_out, 0, ZCASH_FF1_HALF_BITS);
  ff1_num_to_bits(B, diversifier_out, ZCASH_FF1_HALF_BITS, ZCASH_FF1_HALF_BITS);

  memzero(&ctx, sizeof(ctx));
  return true;
}

static bool orchard_diversify_point(const uint8_t diversifier[11],
                                    curve_point* gd) {
  if (!diversifier || !gd) return false;
  static const char domain[] = "z.cash:Orchard-gd";

  if (pallas_group_hash(domain, diversifier, 11, gd) != 0) {
    return false;
  }

  if (pallas_point_is_identity(gd)) {
    if (pallas_group_hash(domain, NULL, 0, gd) != 0 ||
        pallas_point_is_identity(gd)) {
      memzero(gd, sizeof(*gd));
      return false;
    }
  }

  return true;
}

bool zcash_orchard_diversify_hash(const uint8_t diversifier[11],
                                  uint8_t gd_out[32]) {
  if (!gd_out) return false;

  curve_point gd;
  if (!orchard_diversify_point(diversifier, &gd)) {
    return false;
  }

  pallas_point_encode(&gd, gd_out);
  memzero(&gd, sizeof(gd));
  return true;
}

bool zcash_orchard_derive_transmission_key(const uint8_t ivk[32],
                                           const uint8_t diversifier[11],
                                           uint8_t gd_out[32],
                                           uint8_t pkd_out[32]) {
  if (!ivk || !pkd_out) return false;

  bignum256 ivk_scalar;
  bn_read_le(ivk, &ivk_scalar);
  bn_normalize(&ivk_scalar);
  if (bn_is_zero(&ivk_scalar) || !bn_is_less(&ivk_scalar, &pallas_prime)) {
    memzero(&ivk_scalar, sizeof(ivk_scalar));
    return false;
  }

  curve_point gd;
  if (!orchard_diversify_point(diversifier, &gd)) {
    memzero(&ivk_scalar, sizeof(ivk_scalar));
    return false;
  }

  curve_point pkd;
  /* ivk is secret: constant-time multiply only. */
  pallas_ct_point_mult(&ivk_scalar, &gd, &pkd);
  if (pallas_point_is_identity(&pkd)) {
    memzero(&ivk_scalar, sizeof(ivk_scalar));
    memzero(&gd, sizeof(gd));
    memzero(&pkd, sizeof(pkd));
    return false;
  }

  if (gd_out) {
    pallas_point_encode(&gd, gd_out);
  }
  pallas_point_encode(&pkd, pkd_out);

  memzero(&ivk_scalar, sizeof(ivk_scalar));
  memzero(&gd, sizeof(gd));
  memzero(&pkd, sizeof(pkd));
  return true;
}

bool zcash_orchard_derive_ivk(const uint8_t ak[32], const uint8_t nk[32],
                              const uint8_t rivk[32], uint8_t ivk_out[32]) {
  if (!ak || !nk || !rivk || !ivk_out) return false;
  if ((ak[31] & 0x80) != 0) return false;

  if (pallas_sinsemilla_commit_ivk(ak, nk, rivk, ivk_out) != 0) {
    return false;
  }

  bignum256 ivk;
  bn_read_le(ivk_out, &ivk);
  bn_normalize(&ivk);
  bool ok = !bn_is_zero(&ivk) && bn_is_less(&ivk, &pallas_prime);
  memzero(&ivk, sizeof(ivk));
  if (!ok) {
    memzero(ivk_out, 32);
  }
  return ok;
}

bool zcash_orchard_derive_receiver(const uint8_t ak[32], const uint8_t nk[32],
                                   const uint8_t rivk[32], const uint8_t dk[32],
                                   const uint8_t index_le[11],
                                   uint8_t receiver_out[43]) {
  if (!receiver_out) return false;

  uint8_t diversifier[11];
  uint8_t ivk[32];
  uint8_t pkd[32];
  bool ok = zcash_orchard_derive_diversifier(dk, index_le, diversifier) &&
            zcash_orchard_derive_ivk(ak, nk, rivk, ivk) &&
            zcash_orchard_derive_transmission_key(ivk, diversifier, NULL, pkd);

  if (ok) {
    memcpy(receiver_out, diversifier, sizeof(diversifier));
    memcpy(receiver_out + sizeof(diversifier), pkd, sizeof(pkd));
  } else {
    memzero(receiver_out, 43);
  }

  memzero(diversifier, sizeof(diversifier));
  memzero(ivk, sizeof(ivk));
  memzero(pkd, sizeof(pkd));
  return ok;
}

bool zcash_orchard_derive_unified_address(const ZcashOrchardKeys* keys,
                                          const uint8_t index_le[11],
                                          const char* hrp, char* address_out,
                                          size_t address_out_len) {
  if (!keys || !index_le || !hrp || !address_out) return false;

  bignum256 ask_scalar;
  curve_point ak_point;
  bignum256 ak_x;
  uint8_t ak[32];
  uint8_t receiver[43];

  bn_read_le(keys->ask, &ask_scalar);
  redpallas_scalar_mult_spendauth_G_progress(&ask_scalar, &ak_point, NULL,
                                             NULL);
  bn_copy(&ak_point.x, &ak_x);
  bn_write_le(&ak_x, ak);

  bool ok = zcash_orchard_derive_receiver(ak, keys->nk, keys->rivk, keys->dk,
                                          index_le, receiver);
  if (ok) {
    ok = zcash_zip316_encode_orchard_unified_address(hrp, receiver, address_out,
                                                     address_out_len) == 0;
  }
  if (!ok && address_out_len > 0) {
    address_out[0] = '\0';
  }

  memzero(&ask_scalar, sizeof(ask_scalar));
  memzero(&ak_point, sizeof(ak_point));
  memzero(&ak_x, sizeof(ak_x));
  memzero(ak, sizeof(ak));
  memzero(receiver, sizeof(receiver));
  return ok;
}

bool zcash_orchard_receiver_to_unified_address(
    const uint8_t receiver[ZCASH_ORCHARD_RAW_RECEIVER_SIZE], const char* hrp,
    char* address_out, size_t address_out_len) {
  if (!receiver || !hrp || !address_out) return false;
  return zcash_zip316_encode_orchard_unified_address(hrp, receiver, address_out,
                                                     address_out_len) == 0;
}

static bool zcash_pack_orchard_note_commit_msg(const uint8_t receiver[43],
                                               uint64_t value,
                                               const uint8_t rho[32],
                                               const uint8_t psi[32],
                                               uint8_t msg[136]) {
  memset(msg, 0, 136);

  /* bits 0..255: repr_P(g_d) */
  curve_point gd;
  if (!orchard_diversify_point(receiver, &gd)) {
    memzero(&gd, sizeof(gd));
    return false;
  }
  pallas_point_encode(&gd, msg);
  memzero(&gd, sizeof(gd));

  /* bits 256..511: repr_P(pk_d) */
  memcpy(msg + 32, receiver + 11, 32);

  /* bits 512..575: I2LEBSP_64(value) */
  for (int i = 0; i < 8; i++) {
    msg[64 + i] = (uint8_t)((value >> (8 * i)) & 0xff);
  }

  /* bits 576..830: I2LEBSP_255(rho) */
  memcpy(msg + 72, rho, 31);
  msg[103] = rho[31] & 0x7f;

  /* bits 831..1085: I2LEBSP_255(psi), packed at bit offset 831. */
  uint8_t psi255[32];
  memcpy(psi255, psi, 32);
  psi255[31] &= 0x7f;
  for (int i = 0; i < 32; i++) {
    msg[103 + i] |= (uint8_t)(psi255[i] << 7);
    msg[104 + i] |= (uint8_t)(psi255[i] >> 1);
  }
  memzero(psi255, sizeof(psi255));
  return true;
}

static bool zcash_orchard_family_compute_cmx_with_progress(
    const uint8_t receiver[ZCASH_ORCHARD_RAW_RECEIVER_SIZE], uint64_t value,
    const uint8_t rho[32], const uint8_t rseed[32], uint8_t cmx_out[32],
    bool ironwood, ZcashOrchardProgressCallback progress,
    void* progress_context) {
  if (!receiver || !rho || !rseed || !cmx_out) return false;

  uint8_t msg[136];
  uint8_t prf_in[137];
  uint8_t prf_out[64];
  uint8_t rcm[32];
  uint8_t psi[32];
  curve_point gd, q, r;
  bool ok = false;

  /* psi is unchanged between V2 (Orchard) and V3 (Ironwood) notes. */
  memcpy(prf_in + 1, rho, 32);
  prf_in[0] = 0x09;
  prf_expand(rseed, prf_in, 33, prf_out);
  to_base(prf_out, psi);

  if (ironwood) {
    /* ZIP-2005 H_rcm binds V3 randomness to every note field. */
    if (!orchard_diversify_point(receiver, &gd)) goto cleanup;
    prf_in[0] = 0x0B;
    pallas_point_encode(&gd, prf_in + 1);
    memcpy(prf_in + 33, receiver + 11, 32);
    for (size_t i = 0; i < 8; i++) {
      prf_in[65 + i] = (uint8_t)((value >> (8 * i)) & 0xff);
    }
    memcpy(prf_in + 73, rho, 32);
    memcpy(prf_in + 105, psi, 32);
    prf_expand(rseed, prf_in, sizeof(prf_in), prf_out);
  } else {
    prf_in[0] = 0x05;
    prf_expand(rseed, prf_in, 33, prf_out);
  }
  to_scalar(prf_out, rcm);

  ok = zcash_pack_orchard_note_commit_msg(receiver, value, rho, psi, msg) &&
       pallas_group_hash("z.cash:SinsemillaQ",
                         (const uint8_t*)"z.cash:Orchard-NoteCommit-M",
                         strlen("z.cash:Orchard-NoteCommit-M"), &q) == 0 &&
       pallas_group_hash("z.cash:Orchard-NoteCommit-r", NULL, 0, &r) == 0 &&
       pallas_sinsemilla_short_commit_progress(&q, &r, msg, 1086, rcm, cmx_out,
                                               progress, progress_context) == 0;

cleanup:
  if (!ok) memzero(cmx_out, 32);
  memzero(msg, sizeof(msg));
  memzero(prf_in, sizeof(prf_in));
  memzero(prf_out, sizeof(prf_out));
  memzero(rcm, sizeof(rcm));
  memzero(psi, sizeof(psi));
  memzero(&gd, sizeof(gd));
  memzero(&q, sizeof(q));
  memzero(&r, sizeof(r));
  return ok;
}

bool zcash_orchard_compute_cmx_with_progress(
    const uint8_t receiver[ZCASH_ORCHARD_RAW_RECEIVER_SIZE], uint64_t value,
    const uint8_t rho[32], const uint8_t rseed[32], uint8_t cmx_out[32],
    ZcashOrchardProgressCallback progress, void* progress_context) {
  return zcash_orchard_family_compute_cmx_with_progress(
      receiver, value, rho, rseed, cmx_out, false, progress, progress_context);
}

bool zcash_ironwood_compute_cmx_with_progress(
    const uint8_t receiver[ZCASH_ORCHARD_RAW_RECEIVER_SIZE], uint64_t value,
    const uint8_t rho[32], const uint8_t rseed[32], uint8_t cmx_out[32],
    ZcashOrchardProgressCallback progress, void* progress_context) {
  return zcash_orchard_family_compute_cmx_with_progress(
      receiver, value, rho, rseed, cmx_out, true, progress, progress_context);
}

bool zcash_derive_orchard_keys_with_progress(
    const uint8_t* seed, uint32_t seed_len, uint32_t account,
    ZcashOrchardKeys* keys, ZcashOrchardProgressCallback progress,
    void* progress_context) {
  /* A caller-set hardened bit would alias another account. */
  if (!seed || !keys || (account & ZIP32_HARDENED)) return false;
  if (seed_len < 32 || seed_len > 252) return false;

  uint8_t I[64];
  uint8_t sk[32], chain_code[32];

  zip32_orchard_master(seed, seed_len, I);
  memcpy(sk, I, 32);
  memcpy(chain_code, I + 32, 32);

  /* m / 32' / 133' / account':
   * I = PRF^expand(chain_code, [0x81] || sk || I2LEOSP32(index)) */
  const uint32_t path[3] = {
      32 | ZIP32_HARDENED,     /* Purpose (Orchard) */
      133 | ZIP32_HARDENED,    /* Coin type (Zcash) */
      account | ZIP32_HARDENED /* Account */
  };

  for (int i = 0; i < 3; i++) {
    uint8_t child_input[1 + 32 + 4];
    child_input[0] = 0x81; /* ORCHARD_ZIP32_CHILD domain separator */
    memcpy(child_input + 1, sk, 32);
    uint32_t idx = path[i];
    child_input[33] = idx & 0xff;
    child_input[34] = (idx >> 8) & 0xff;
    child_input[35] = (idx >> 16) & 0xff;
    child_input[36] = (idx >> 24) & 0xff;

    prf_expand(chain_code, child_input, sizeof(child_input), I);
    memcpy(sk, I, 32);
    memcpy(chain_code, I + 32, 32);

    memzero(child_input, sizeof(child_input));
  }

  memcpy(keys->sk, sk, 32);

  uint8_t expanded[64];

  /* ask = ToScalar(PRF^expand(sk, [0x06])) */
  uint8_t t_ask = 0x06;
  prf_expand(sk, &t_ask, 1, expanded);
  to_scalar(expanded, keys->ask);
  uint8_t ak_bytes[32];

  /* Spec 4.2.3: negate ask if [ask]G_spendauth has odd y. */
  {
    bignum256 ask_test;
    bn_read_le(keys->ask, &ask_test);
    curve_point ak_test;
    redpallas_scalar_mult_spendauth_G_progress(&ask_test, &ak_test, progress,
                                               progress_context);
    bignum256 ak_x;
    bn_copy(&ak_test.x, &ak_x);
    bn_write_le(&ak_x, ak_bytes);
    if (bn_is_odd(&ak_test.y)) {
      bignum256 ask_val, neg_ask;
      bn_read_le(keys->ask, &ask_val);
      bn_subtract(&pallas_order, &ask_val, &neg_ask);
      bn_write_le(&neg_ask, keys->ask);
      memzero(&neg_ask, sizeof(neg_ask));
      memzero(&ask_val, sizeof(ask_val));
    }
    memzero(&ask_test, sizeof(ask_test));
    memzero(&ak_test, sizeof(ak_test));
    memzero(&ak_x, sizeof(ak_x));
  }
  /* Cache ak: avoids repeating the secret-scalar multiply. */
  memcpy(keys->ak, ak_bytes, sizeof(keys->ak));

  /* nk = ToBase(PRF^expand(sk, [0x07])) */
  uint8_t t_nk = 0x07;
  prf_expand(sk, &t_nk, 1, expanded);
  to_base(expanded, keys->nk);

  /* rivk = ToScalar(PRF^expand(sk, [0x08])) */
  uint8_t t_rivk = 0x08;
  prf_expand(sk, &t_rivk, 1, expanded);
  to_scalar(expanded, keys->rivk);

  /* dk = truncate_32(PRF^expand(rivk, [0x82] || ak || nk)) */
  uint8_t dk_input[1 + 32 + 32];
  dk_input[0] = 0x82;
  memcpy(dk_input + 1, ak_bytes, 32);
  memcpy(dk_input + 33, keys->nk, 32);
  prf_expand(keys->rivk, dk_input, sizeof(dk_input), expanded);
  memcpy(keys->dk, expanded, 32);

  memzero(I, sizeof(I));
  memzero(sk, sizeof(sk));
  memzero(chain_code, sizeof(chain_code));
  memzero(expanded, sizeof(expanded));
  memzero(ak_bytes, sizeof(ak_bytes));
  memzero(dk_input, sizeof(dk_input));

  return true;
}

bool zcash_derive_orchard_keys(const uint8_t* seed, uint32_t seed_len,
                               uint32_t account, ZcashOrchardKeys* keys) {
  return zcash_derive_orchard_keys_with_progress(seed, seed_len, account, keys,
                                                 NULL, NULL);
}

static bool zcash_compute_shielded_sighash_inner(
    const uint8_t header_digest[32], const uint8_t transparent_digest[32],
    const uint8_t sapling_digest[32], const uint8_t orchard_digest[32],
    const uint8_t* ironwood_digest, uint32_t branch_id,
    uint8_t sighash_out[32]) {
  if (!header_digest || !transparent_digest || !sapling_digest ||
      !orchard_digest || !sighash_out) {
    return false;
  }
  Hasher h;
  uint8_t personal[16];

  memcpy(personal, "ZcashTxHash_", 12);
  memcpy(personal + 12, &branch_id, 4);

  hasher_InitParam(&h, HASHER_BLAKE2B_PERSONAL, personal, 16);
  hasher_Update(&h, header_digest, 32);
  hasher_Update(&h, transparent_digest, 32);
  hasher_Update(&h, sapling_digest, 32);
  hasher_Update(&h, orchard_digest, 32);
  if (ironwood_digest) hasher_Update(&h, ironwood_digest, 32);
  hasher_Final(&h, sighash_out);
  memzero(personal, sizeof(personal));
  return true;
}

bool zcash_compute_shielded_sighash(const uint8_t header_digest[32],
                                    const uint8_t transparent_digest[32],
                                    const uint8_t sapling_digest[32],
                                    const uint8_t orchard_digest[32],
                                    uint32_t branch_id,
                                    uint8_t sighash_out[32]) {
  return zcash_compute_shielded_sighash_inner(header_digest, transparent_digest,
                                              sapling_digest, orchard_digest,
                                              NULL, branch_id, sighash_out);
}

bool zcash_compute_v6_shielded_sighash(const uint8_t header_digest[32],
                                       const uint8_t transparent_digest[32],
                                       const uint8_t sapling_digest[32],
                                       const uint8_t orchard_digest[32],
                                       const uint8_t ironwood_digest[32],
                                       uint32_t branch_id,
                                       uint8_t sighash_out[32]) {
  if (!ironwood_digest) return false;
  return zcash_compute_shielded_sighash_inner(
      header_digest, transparent_digest, sapling_digest, orchard_digest,
      ironwood_digest, branch_id, sighash_out);
}

static void zcash_write_u32_le(uint32_t value, uint8_t out[4]) {
  out[0] = (uint8_t)(value & 0xff);
  out[1] = (uint8_t)((value >> 8) & 0xff);
  out[2] = (uint8_t)((value >> 16) & 0xff);
  out[3] = (uint8_t)((value >> 24) & 0xff);
}

static void zcash_write_u64_le(uint64_t value, uint8_t out[8]) {
  for (size_t i = 0; i < 8; i++) {
    out[i] = (uint8_t)((value >> (8 * i)) & 0xff);
  }
}

static void zcash_blake2b_personal_256(const char personal[16],
                                       const uint8_t* data, size_t data_len,
                                       uint8_t digest_out[32]) {
  BLAKE2B_CTX ctx;
  blake2b_InitPersonal(&ctx, 32, personal, 16);
  if (data_len > 0) {
    blake2b_Update(&ctx, data, data_len);
  }
  blake2b_Final(&ctx, digest_out, 32);
}

bool zcash_tx_version_supported(uint32_t version, uint32_t version_group_id) {
  return (version == 5 && version_group_id == 0x26A7270A) ||
         (version == 6 && version_group_id == 0xD884B698);
}

bool zcash_v6_orchard_ironwood_digest_valid(bool present, size_t size,
                                            const uint8_t* digest) {
  if (!present) return true;
  if (size != 32 || !digest) return false;
  uint8_t empty[32];
  zcash_blake2b_personal_256("ZTxIdIronwd_H_v6", NULL, 0, empty);
  return memcmp(digest, empty, 32) == 0;
}

bool zcash_script_is_p2pkh(const uint8_t* script, size_t script_size) {
  return script && script_size == 25 && script[0] == 0x76 &&
         script[1] == 0xa9 && script[2] == 0x14 && script[23] == 0x88 &&
         script[24] == 0xac;
}

bool zcash_p2pkh_script_matches_pubkey(const uint8_t* script,
                                       size_t script_size,
                                       const uint8_t public_key[33]) {
  if (!public_key || !zcash_script_is_p2pkh(script, script_size)) {
    return false;
  }
  uint8_t hash160[20];
  ecdsa_get_pubkeyhash(public_key, HASHER_SHA2_RIPEMD, hash160);
  const bool match = memcmp(hash160, script + 3, sizeof(hash160)) == 0;
  memzero(hash160, sizeof(hash160));
  return match;
}

bool zcash_compute_header_digest(uint32_t version, uint32_t version_group_id,
                                 uint32_t branch_id, uint32_t lock_time,
                                 uint32_t expiry_height,
                                 uint8_t digest_out[32]) {
  if (!digest_out) return false;

  uint8_t header[20];
  zcash_write_u32_le(version | 0x80000000u, header);
  zcash_write_u32_le(version_group_id, header + 4);
  zcash_write_u32_le(branch_id, header + 8);
  zcash_write_u32_le(lock_time, header + 12);
  zcash_write_u32_le(expiry_height, header + 16);

  zcash_blake2b_personal_256("ZTxIdHeadersHash", header, sizeof(header),
                             digest_out);
  memzero(header, sizeof(header));
  return true;
}

static bool zcash_validate_transparent_digest_info(
    const ZcashTransparentInputDigestInfo* inputs, size_t n_inputs,
    const ZcashTransparentOutputDigestInfo* outputs, size_t n_outputs) {
  if (n_inputs > 0 && !inputs) return false;
  if (n_outputs > 0 && !outputs) return false;

  for (size_t i = 0; i < n_inputs; i++) {
    if (!inputs[i].prevout_txid ||
        (inputs[i].script_pubkey_size > 0 && !inputs[i].script_pubkey)) {
      return false;
    }
  }

  for (size_t i = 0; i < n_outputs; i++) {
    if (outputs[i].script_pubkey_size > 0 && !outputs[i].script_pubkey) {
      return false;
    }
  }

  return true;
}

static void zcash_hash_transparent_prevouts(
    const ZcashTransparentInputDigestInfo* inputs, size_t n_inputs,
    uint8_t digest_out[32]) {
  BLAKE2B_CTX ctx;
  uint8_t le[4];
  blake2b_InitPersonal(&ctx, 32, "ZTxIdPrevoutHash", 16);
  for (size_t i = 0; i < n_inputs; i++) {
    blake2b_Update(&ctx, inputs[i].prevout_txid, 32);
    zcash_write_u32_le(inputs[i].prevout_index, le);
    blake2b_Update(&ctx, le, sizeof(le));
  }
  blake2b_Final(&ctx, digest_out, 32);
  memzero(le, sizeof(le));
}

static void zcash_hash_transparent_sequences(
    const ZcashTransparentInputDigestInfo* inputs, size_t n_inputs,
    uint8_t digest_out[32]) {
  BLAKE2B_CTX ctx;
  uint8_t le[4];
  blake2b_InitPersonal(&ctx, 32, "ZTxIdSequencHash", 16);
  for (size_t i = 0; i < n_inputs; i++) {
    zcash_write_u32_le(inputs[i].sequence, le);
    blake2b_Update(&ctx, le, sizeof(le));
  }
  blake2b_Final(&ctx, digest_out, 32);
  memzero(le, sizeof(le));
}

static void zcash_hash_transparent_amounts(
    const ZcashTransparentInputDigestInfo* inputs, size_t n_inputs,
    uint8_t digest_out[32]) {
  BLAKE2B_CTX ctx;
  uint8_t le[8];
  blake2b_InitPersonal(&ctx, 32, "ZTxTrAmountsHash", 16);
  for (size_t i = 0; i < n_inputs; i++) {
    zcash_write_u64_le(inputs[i].value, le);
    blake2b_Update(&ctx, le, sizeof(le));
  }
  blake2b_Final(&ctx, digest_out, 32);
  memzero(le, sizeof(le));
}

static void zcash_hash_transparent_scripts(
    const ZcashTransparentInputDigestInfo* inputs, size_t n_inputs,
    uint8_t digest_out[32]) {
  BLAKE2B_CTX ctx;
  uint8_t compact_size[9];
  blake2b_InitPersonal(&ctx, 32, "ZTxTrScriptsHash", 16);
  for (size_t i = 0; i < n_inputs; i++) {
    size_t compact_size_len =
        ser_length(inputs[i].script_pubkey_size, compact_size);
    blake2b_Update(&ctx, compact_size, compact_size_len);
    if (inputs[i].script_pubkey_size > 0) {
      blake2b_Update(&ctx, inputs[i].script_pubkey,
                     inputs[i].script_pubkey_size);
    }
  }
  blake2b_Final(&ctx, digest_out, 32);
  memzero(compact_size, sizeof(compact_size));
}

static void zcash_hash_transparent_outputs(
    const ZcashTransparentOutputDigestInfo* outputs, size_t n_outputs,
    uint8_t digest_out[32]) {
  BLAKE2B_CTX ctx;
  uint8_t le[8];
  uint8_t compact_size[9];
  blake2b_InitPersonal(&ctx, 32, "ZTxIdOutputsHash", 16);
  for (size_t i = 0; i < n_outputs; i++) {
    zcash_write_u64_le(outputs[i].value, le);
    blake2b_Update(&ctx, le, sizeof(le));
    size_t compact_size_len =
        ser_length(outputs[i].script_pubkey_size, compact_size);
    blake2b_Update(&ctx, compact_size, compact_size_len);
    if (outputs[i].script_pubkey_size > 0) {
      blake2b_Update(&ctx, outputs[i].script_pubkey,
                     outputs[i].script_pubkey_size);
    }
  }
  blake2b_Final(&ctx, digest_out, 32);
  memzero(le, sizeof(le));
  memzero(compact_size, sizeof(compact_size));
}

static bool zcash_hash_transparent_input(
    const ZcashTransparentInputDigestInfo* input, uint8_t digest_out[32]) {
  if (!input) return false;

  BLAKE2B_CTX ctx;
  uint8_t le4[4];
  uint8_t le8[8];
  uint8_t compact_size[9];
  blake2b_InitPersonal(&ctx, 32, "Zcash___TxInHash", 16);
  blake2b_Update(&ctx, input->prevout_txid, 32);
  zcash_write_u32_le(input->prevout_index, le4);
  blake2b_Update(&ctx, le4, sizeof(le4));
  zcash_write_u64_le(input->value, le8);
  blake2b_Update(&ctx, le8, sizeof(le8));
  size_t compact_size_len = ser_length(input->script_pubkey_size, compact_size);
  blake2b_Update(&ctx, compact_size, compact_size_len);
  if (input->script_pubkey_size > 0) {
    blake2b_Update(&ctx, input->script_pubkey, input->script_pubkey_size);
  }
  zcash_write_u32_le(input->sequence, le4);
  blake2b_Update(&ctx, le4, sizeof(le4));
  blake2b_Final(&ctx, digest_out, 32);
  memzero(le4, sizeof(le4));
  memzero(le8, sizeof(le8));
  memzero(compact_size, sizeof(compact_size));
  return true;
}

bool zcash_compute_transparent_digest(
    const ZcashTransparentInputDigestInfo* inputs, size_t n_inputs,
    const ZcashTransparentOutputDigestInfo* outputs, size_t n_outputs,
    uint8_t digest_out[32]) {
  if (!digest_out || !zcash_validate_transparent_digest_info(
                         inputs, n_inputs, outputs, n_outputs)) {
    return false;
  }

  if (n_inputs == 0 && n_outputs == 0) {
    zcash_blake2b_personal_256("ZTxIdTranspaHash", NULL, 0, digest_out);
    return true;
  }

  uint8_t prevouts_digest[32], sequence_digest[32], outputs_digest[32];
  zcash_hash_transparent_prevouts(inputs, n_inputs, prevouts_digest);
  zcash_hash_transparent_sequences(inputs, n_inputs, sequence_digest);
  zcash_hash_transparent_outputs(outputs, n_outputs, outputs_digest);

  BLAKE2B_CTX ctx;
  blake2b_InitPersonal(&ctx, 32, "ZTxIdTranspaHash", 16);
  blake2b_Update(&ctx, prevouts_digest, 32);
  blake2b_Update(&ctx, sequence_digest, 32);
  blake2b_Update(&ctx, outputs_digest, 32);
  blake2b_Final(&ctx, digest_out, 32);

  memzero(prevouts_digest, sizeof(prevouts_digest));
  memzero(sequence_digest, sizeof(sequence_digest));
  memzero(outputs_digest, sizeof(outputs_digest));
  return true;
}

/* ZIP-244 transparent_sig_digest for Orchard spend auth: S.2 form with an
 * EMPTY txin_sig_digest when n_inputs > 0, else T.1 (txid) form. */
bool zcash_compute_orchard_transparent_sig_digest(
    const ZcashTransparentInputDigestInfo* inputs, size_t n_inputs,
    const ZcashTransparentOutputDigestInfo* outputs, size_t n_outputs,
    uint8_t digest_out[32]) {
  if (!digest_out || !zcash_validate_transparent_digest_info(
                         inputs, n_inputs, outputs, n_outputs)) {
    return false;
  }

  if (n_inputs == 0) {
    return zcash_compute_transparent_digest(inputs, n_inputs, outputs,
                                            n_outputs, digest_out);
  }

  const uint8_t sighash_type = 0x01; /* SIGHASH_ALL */
  uint8_t prevouts_digest[32], amounts_digest[32], scripts_digest[32];
  uint8_t sequence_digest[32], outputs_digest[32], empty_txin_digest[32];

  zcash_hash_transparent_prevouts(inputs, n_inputs, prevouts_digest);
  zcash_hash_transparent_amounts(inputs, n_inputs, amounts_digest);
  zcash_hash_transparent_scripts(inputs, n_inputs, scripts_digest);
  zcash_hash_transparent_sequences(inputs, n_inputs, sequence_digest);
  zcash_hash_transparent_outputs(outputs, n_outputs, outputs_digest);

  zcash_blake2b_personal_256("Zcash___TxInHash", NULL, 0, empty_txin_digest);

  BLAKE2B_CTX ctx;
  blake2b_InitPersonal(&ctx, 32, "ZTxIdTranspaHash", 16);
  blake2b_Update(&ctx, &sighash_type, 1);
  blake2b_Update(&ctx, prevouts_digest, 32);
  blake2b_Update(&ctx, amounts_digest, 32);
  blake2b_Update(&ctx, scripts_digest, 32);
  blake2b_Update(&ctx, sequence_digest, 32);
  blake2b_Update(&ctx, outputs_digest, 32);
  blake2b_Update(&ctx, empty_txin_digest, 32);
  blake2b_Final(&ctx, digest_out, 32);

  memzero(prevouts_digest, sizeof(prevouts_digest));
  memzero(amounts_digest, sizeof(amounts_digest));
  memzero(scripts_digest, sizeof(scripts_digest));
  memzero(sequence_digest, sizeof(sequence_digest));
  memzero(outputs_digest, sizeof(outputs_digest));
  memzero(empty_txin_digest, sizeof(empty_txin_digest));
  return true;
}

bool zcash_compute_transparent_sighash_digest(
    const ZcashTransparentInputDigestInfo* inputs, size_t n_inputs,
    const ZcashTransparentOutputDigestInfo* outputs, size_t n_outputs,
    uint32_t signable_input_index, uint8_t sighash_type,
    uint8_t digest_out[32]) {
  if (!digest_out || !zcash_validate_transparent_digest_info(
                         inputs, n_inputs, outputs, n_outputs)) {
    return false;
  }

  if (sighash_type != 0x01 || signable_input_index >= n_inputs) {
    return false;
  }

  uint8_t prevouts_digest[32], amounts_digest[32], scripts_digest[32];
  uint8_t sequence_digest[32], outputs_digest[32], txin_sig_digest[32];
  zcash_hash_transparent_prevouts(inputs, n_inputs, prevouts_digest);
  zcash_hash_transparent_amounts(inputs, n_inputs, amounts_digest);
  zcash_hash_transparent_scripts(inputs, n_inputs, scripts_digest);
  zcash_hash_transparent_sequences(inputs, n_inputs, sequence_digest);
  zcash_hash_transparent_outputs(outputs, n_outputs, outputs_digest);

  zcash_hash_transparent_input(&inputs[signable_input_index], txin_sig_digest);

  BLAKE2B_CTX ctx;
  blake2b_InitPersonal(&ctx, 32, "ZTxIdTranspaHash", 16);
  blake2b_Update(&ctx, &sighash_type, 1);
  blake2b_Update(&ctx, prevouts_digest, 32);
  blake2b_Update(&ctx, amounts_digest, 32);
  blake2b_Update(&ctx, scripts_digest, 32);
  blake2b_Update(&ctx, sequence_digest, 32);
  blake2b_Update(&ctx, outputs_digest, 32);
  blake2b_Update(&ctx, txin_sig_digest, 32);
  blake2b_Final(&ctx, digest_out, 32);

  memzero(prevouts_digest, sizeof(prevouts_digest));
  memzero(amounts_digest, sizeof(amounts_digest));
  memzero(scripts_digest, sizeof(scripts_digest));
  memzero(sequence_digest, sizeof(sequence_digest));
  memzero(outputs_digest, sizeof(outputs_digest));
  memzero(txin_sig_digest, sizeof(txin_sig_digest));
  return true;
}

ZcashPCZTSigningRequestStatus zcash_pczt_signing_request_status(
    const ZcashPCZTSigningRequestMeta* meta) {
  if (!meta || !meta->has_header_digest || !meta->has_orchard_digest) {
    return ZCASH_PCZT_SIGNING_REQUEST_MISSING_TX_DIGESTS;
  }

  if (meta->header_digest_size != 32 || meta->orchard_digest_size != 32) {
    return ZCASH_PCZT_SIGNING_REQUEST_INVALID_DIGEST_SIZE;
  }

  if (meta->is_ironwood &&
      (!meta->has_ironwood_digest || meta->ironwood_digest_size != 32)) {
    return ZCASH_PCZT_SIGNING_REQUEST_MISSING_TX_DIGESTS;
  }

  if (meta->has_transparent_digest && meta->transparent_digest_size != 32) {
    return ZCASH_PCZT_SIGNING_REQUEST_INVALID_DIGEST_SIZE;
  }

  (void)meta->sapling_digest_size;
  if (meta->has_sapling_digest) {
    return ZCASH_PCZT_SIGNING_REQUEST_UNSUPPORTED_SAPLING_COMPONENT;
  }

  if (!meta->has_header_fields) {
    return ZCASH_PCZT_SIGNING_REQUEST_MISSING_HEADER_FIELDS;
  }

  if ((meta->n_transparent_inputs > 0 || meta->n_transparent_outputs > 0) &&
      (!meta->has_transparent_digest || meta->transparent_digest_size != 32)) {
    return ZCASH_PCZT_SIGNING_REQUEST_MISSING_TRANSPARENT_DIGEST;
  }

  if (!meta->has_orchard_flags || meta->orchard_flags > 0xff ||
      !meta->has_orchard_value_balance || !meta->has_orchard_anchor ||
      meta->orchard_anchor_size != 32) {
    return ZCASH_PCZT_SIGNING_REQUEST_MISSING_ORCHARD_METADATA;
  }

  return ZCASH_PCZT_SIGNING_REQUEST_OK;
}

bool zcash_orchard_nullifier_canonical(const uint8_t nullifier[32]) {
  bignum256 value;
  bn_read_le(nullifier, &value);
  bool canonical = bn_is_less(&value, &pallas_prime);
  memzero(&value, sizeof(value));
  return canonical;
}

/* An optional requested seed fingerprint must be exactly 32 bytes. */
bool zcash_seed_fingerprint_request_valid(bool present, size_t size) {
  return !present || size == 32;
}

/* ZIP-32 6.1 seed fingerprint. Rejects trivial (all-0x00/0xFF) seeds and
 * lengths outside [32, 252]. */
bool zcash_calculate_seed_fingerprint(const uint8_t* seed, uint32_t seed_len,
                                      uint8_t fingerprint_out[32]) {
  if (!seed || !fingerprint_out) return false;
  if (seed_len < 32 || seed_len > 252) return false;

  bool all_zero = true;
  bool all_ff = true;
  for (uint32_t i = 0; i < seed_len; i++) {
    if (seed[i] != 0x00) all_zero = false;
    if (seed[i] != 0xFF) all_ff = false;
    if (!all_zero && !all_ff) break;
  }
  if (all_zero || all_ff) return false;

  BLAKE2B_CTX ctx;
  if (blake2b_InitPersonal(&ctx, 32, "Zcash_HD_Seed_FP", 16) != 0) {
    return false;
  }
  uint8_t len_byte = (uint8_t)seed_len;
  blake2b_Update(&ctx, &len_byte, 1);
  blake2b_Update(&ctx, seed, seed_len);
  if (blake2b_Final(&ctx, fingerprint_out, 32) != 0) {
    memzero(&ctx, sizeof(ctx));
    return false;
  }

  memzero(&ctx, sizeof(ctx));
  return true;
}
