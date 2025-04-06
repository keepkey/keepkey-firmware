/*
 * This file is part of the KEEPKEY project.
 *
 * Copyright (C) 2020 Shapeshift
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

#include <stdlib.h>
#include <string.h>

#include "keepkey/board/layout.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/txin_check.h"
#include "hwcrypto/crypto/memzero.h"
#include "hwcrypto/crypto/sha2.h"

static uint8_t
    txin_current_digest[SHA256_DIGEST_LENGTH]; /* current tx txins digest */

// these values help give a hint if malware is changing segwit txids in an
// attempt to create false txs
static uint8_t txin_last_digest[SHA256_DIGEST_LENGTH]; /* last tx digest */
static char last_amount_str[AMT_STR_LEN]; /* spend value of last tx */
static char last_addr_str[ADDR_STR_LEN];  /* last spend-to address */
static SHA256_CTX txin_hash_ctx;

// initialize the txin digest machine
void txin_dgst_initialize(void) {
  memzero(txin_current_digest, SHA256_DIGEST_LENGTH);
  memzero(txin_last_digest, SHA256_DIGEST_LENGTH);
  memzero(last_amount_str, AMT_STR_LEN);
  memzero(last_addr_str, ADDR_STR_LEN);
  sha256_Init(&txin_hash_ctx);
  return;
}

// hash in a txin
void txin_dgst_addto(const uint8_t *data, size_t len) {
  sha256_Update(&txin_hash_ctx, data, len);
  return;
}

// finalize txin digest
void txin_dgst_final(void) {
  sha256_Final(&txin_hash_ctx, txin_current_digest);
  return;
}

// compare dgst, amt, addr
// returns True if warning condition met
bool txin_dgst_compare(const char *amt_str, const char *addr_str) {
  // if amt and addr are same AND digest is different, then warn
  if ((strncmp(amt_str, last_amount_str, AMT_STR_LEN) == 0) &&
      (strncmp(addr_str, last_addr_str, ADDR_STR_LEN) == 0)) {
    if ((memcmp(txin_current_digest, txin_last_digest, SHA256_DIGEST_LENGTH) !=
         0)) {
      return (true);
    }
  }
  return (false);
}

// return string pointers to digests
void txin_dgst_getstrs(char *prev, char *cur, size_t len) {
  if (len != DIGEST_STR_LEN) {
    return;
  }
  data2hex(txin_current_digest, SHA256_DIGEST_LENGTH, cur);
  kk_strlwr(cur);
  data2hex(txin_last_digest, SHA256_DIGEST_LENGTH, prev);
  kk_strlwr(prev);
  return;
}

// save last state and reset for next tx request
void txin_dgst_save_and_reset(char *amt_str, char *addr_str) {
  memcpy(txin_last_digest, txin_current_digest, SHA256_DIGEST_LENGTH);
  memcpy(last_amount_str, amt_str, AMT_STR_LEN);
  memcpy(last_addr_str, addr_str, ADDR_STR_LEN);
  memzero(txin_current_digest, SHA256_DIGEST_LENGTH);
  sha256_Init(&txin_hash_ctx);
  return;
}
