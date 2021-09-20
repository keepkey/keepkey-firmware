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

#include "keepkey/rand/rng.h"

#include <libopencm3/cm3/common.h>
#include <libopencm3/stm32/memorymap.h>
#include <libopencm3/stm32/f2/rng.h>

void reset_rng(void) {
  /* disable RNG */
  RNG_CR &= ~(RNG_CR_IE | RNG_CR_RNGEN);
  /* reset Seed/Clock/ error status */
  RNG_SR &= ~(RNG_SR_SEIS | RNG_SR_CEIS);
  /* reenable RNG */
  RNG_CR |= RNG_CR_IE | RNG_CR_RNGEN;
  /* this delay is required before rng data can be read */
  {
    uint32_t cnt = 5 /* microseconds */ * 20;
    while (cnt--) {
      __asm__("nop");
    }
  }

  // to be extra careful and heed the STM32F205xx Reference manual,
  // Section 20.3.1 we don't use the first random number generated after setting
  // the RNGEN bit in setup
  random32();
}

uint32_t random32(void) {
  uint32_t rng_samples = 0, rng_sr_img;
  static uint32_t last = 0, new = 0;

  while (new == last) {
    /* Capture the RNG status register */
    rng_sr_img = RNG_SR;
    if ((rng_sr_img & (RNG_SR_SEIS | RNG_SR_CEIS)) == 0) {
      if (rng_sr_img & RNG_SR_DRDY) {
        new = RNG_DR;
      }
    } else if ((rng_sr_img & (RNG_SR_SECS | RNG_SR_CECS)) == 0) {
      /* Reset RNG interrupt status bits (SECS, CECS errors no longer exist) */
      RNG_SR &= ~(RNG_SR_SEIS | RNG_SR_CEIS);
    } else {
      /* RNG is not ready.  Allow few more samples for RNG to come back alive
       * before resetting */
      if (++rng_samples >= 100) {
        /* RNG in hang state.  Reset RNG */
        reset_rng();
        rng_samples = 0;
      }
    }
  }
  last = new;
  return new;
}

void random_buffer(uint8_t *buf, size_t len) {
  uint32_t r = 0;
  for (size_t i = 0; i < len; i++) {
    if (i % 4 == 0) {
      r = random32();
    }
    buf[i] = (r >> ((i % 4) * 8)) & 0xFF;
  }
}
