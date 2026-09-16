/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
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

#include "trezor/crypto/sha2.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/memzero.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/signatures.h"
#include "keepkey/board/pubkeys.h"

#include <stdint.h>
#include <stddef.h>

volatile const uint8_t valid_pubkey[PUBKEYS] = {
    0xff, 0xff, 0xff, 0xff, 0xff,
};

/* Signature verification runs before entropy collection and DRBG setup.
 * Keep this comparison deterministic: memcmp_s() deliberately randomizes its
 * access order and is only valid after those services are initialized. */
static int boot_constant_time_mismatch(const uint8_t* lhs, const uint8_t* rhs,
                                       size_t len) {
  volatile uint8_t diff = 0;
  for (size_t i = 0; i < len; ++i) diff |= lhs[i] ^ rhs[i];
  return diff != 0;
}

int signatures_ok(void) {
  uint32_t codelen = *((uint32_t*)FLASH_META_CODELEN);
  uint8_t sigindex1, sigindex2, sigindex3, firmware_fingerprint[32];

  sigindex1 = *((uint8_t*)FLASH_META_SIGINDEX1);
  sigindex2 = *((uint8_t*)FLASH_META_SIGINDEX2);
  sigindex3 = *((uint8_t*)FLASH_META_SIGINDEX3);

  if (sigindex1 < 1 || sigindex1 > PUBKEYS) {
    return SIG_FAIL;
  } /* Invalid index */
  if (sigindex2 < 1 || sigindex2 > PUBKEYS) {
    return SIG_FAIL;
  } /* Invalid index */
  if (sigindex3 < 1 || sigindex3 > PUBKEYS) {
    return SIG_FAIL;
  } /* Invalid index */

  if (sigindex1 == sigindex2) {
    return SIG_FAIL;
  } /* Duplicate use */
  if (sigindex1 == sigindex3) {
    return SIG_FAIL;
  } /* Duplicate use */
  if (sigindex2 == sigindex3) {
    return SIG_FAIL;
  } /* Duplicate use */

  if (0xff != valid_pubkey[sigindex1 - 1]) {
    return KEY_EXPIRED;
  } /* Expired signing key */
  if (0xff != valid_pubkey[sigindex2 - 1]) {
    return KEY_EXPIRED;
  } /* Expired signing key */
  if (0xff != valid_pubkey[sigindex3 - 1]) {
    return KEY_EXPIRED;
  } /* Expired signing key */

  /* F3 hardening: double-compute SHA-256, compare in constant time */
  uint8_t firmware_fingerprint2[32];
  sha256_Raw((uint8_t*)FLASH_APP_START, codelen, firmware_fingerprint);
  asm volatile("" ::: "memory");
  sha256_Raw((uint8_t*)FLASH_APP_START, codelen, firmware_fingerprint2);

  if (boot_constant_time_mismatch(firmware_fingerprint, firmware_fingerprint2,
                                  32)) {
    memzero(firmware_fingerprint, sizeof(firmware_fingerprint));
    memzero(firmware_fingerprint2, sizeof(firmware_fingerprint2));
    return SIG_FAIL;
  }
  memzero(firmware_fingerprint2, sizeof(firmware_fingerprint2));

  /* F3 hardening: infective aggregation — accumulate all three ECDSA
   * results instead of early-returning on each. Forces attacker to
   * corrupt all three verify calls, not just skip one branch. */
  volatile int verify_acc = 0;
  volatile int verify_sentinel = 0;

  verify_acc |=
      ecdsa_verify_digest(&secp256k1, pubkey[sigindex1 - 1],
                          (uint8_t*)FLASH_META_SIG1, firmware_fingerprint);
  verify_sentinel++;
  asm volatile("" ::: "memory");

  verify_acc |=
      ecdsa_verify_digest(&secp256k1, pubkey[sigindex2 - 1],
                          (uint8_t*)FLASH_META_SIG2, firmware_fingerprint);
  verify_sentinel++;
  asm volatile("" ::: "memory");

  verify_acc |=
      ecdsa_verify_digest(&secp256k1, pubkey[sigindex3 - 1],
                          (uint8_t*)FLASH_META_SIG3, firmware_fingerprint);
  verify_sentinel++;
  asm volatile("" ::: "memory");

  memzero(firmware_fingerprint, sizeof(firmware_fingerprint));

  /* All three verifies must have executed and all must have passed */
  if (verify_sentinel != 3) {
    return SIG_FAIL;
  }

  if (verify_acc != 0) {
    return SIG_FAIL;
  }

  return SIG_OK;
}
