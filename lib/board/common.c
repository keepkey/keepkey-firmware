/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "keepkey/board/common.h"

#include "keepkey/board/otp.h"
#include "keepkey/rand/rng.h"
#include "trezor/crypto/hmac_drbg.h"
#include "trezor/crypto/rand.h"

#ifndef EMULATOR
#  include <libopencm3/stm32/desig.h>
#endif

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

static HMAC_DRBG_CTX drbg_ctx;

void drbg_init() {
  uint8_t entropy[48] = {0};
  random_buffer(entropy, sizeof(entropy));
  hmac_drbg_init(&drbg_ctx, entropy, sizeof(entropy), NULL, 0);
}

void drbg_reseed(const uint8_t *entropy, size_t len) {
  hmac_drbg_reseed(&drbg_ctx, entropy, len, NULL, 0);
}

void drbg_generate(uint8_t *buf, size_t len) {
  hmac_drbg_generate(&drbg_ctx, buf, len);
}

uint32_t drbg_random32(void) {
  uint32_t value = 0;
  drbg_generate((uint8_t *)&value, sizeof(value));
  return value;
}
