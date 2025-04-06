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

#include "hwcrypto/crypto/sha2.h"
#include "hwcrypto/crypto/ecdsa.h"
#include "hwcrypto/crypto/secp256k1.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/signatures.h"
#include "keepkey/board/pubkeys.h"

#include <stdint.h>

volatile const uint8_t valid_pubkey[PUBKEYS] = {
    0xff, 0xff, 0xff, 0xff, 0xff,
};

int signatures_ok(void) {
  uint32_t codelen = *((uint32_t *)FLASH_META_CODELEN);
  uint8_t sigindex1, sigindex2, sigindex3, firmware_fingerprint[32];

  sigindex1 = *((uint8_t *)FLASH_META_SIGINDEX1);
  sigindex2 = *((uint8_t *)FLASH_META_SIGINDEX2);
  sigindex3 = *((uint8_t *)FLASH_META_SIGINDEX3);

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

  sha256_Raw((uint8_t *)FLASH_APP_START, codelen, firmware_fingerprint);

  if (ecdsa_verify_digest(&secp256k1, pubkey[sigindex1 - 1],
                          (uint8_t *)FLASH_META_SIG1,
                          firmware_fingerprint) != 0) { /* Failure */
    return SIG_FAIL;
  }

  if (ecdsa_verify_digest(&secp256k1, pubkey[sigindex2 - 1],
                          (uint8_t *)FLASH_META_SIG2,
                          firmware_fingerprint) != 0) { /* Failure */
    return SIG_FAIL;
  }

  if (ecdsa_verify_digest(&secp256k1, pubkey[sigindex3 - 1],
                          (uint8_t *)FLASH_META_SIG3,
                          firmware_fingerprint) != 0) { /* Failure */
    return SIG_FAIL;
  }

  return SIG_OK;
}
