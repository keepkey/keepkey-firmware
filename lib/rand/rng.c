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

#include "trezor/crypto/rand.h"

#ifdef EMULATOR
#include "keepkey/emulator/emulator.h"
#endif

#ifndef EMULATOR
#include <libopencm3/cm3/common.h>
#include <libopencm3/stm32/memorymap.h>
#include <libopencm3/stm32/f2/rng.h>
#endif

/* EMULATOR is a definedness switch throughout this firmware.  Reject it on an
 * ARM target regardless of its value, so -DEMULATOR=0 cannot silently select a
 * hosted RNG in production firmware. */
#if defined(EMULATOR) && defined(__arm__)
#error \
    "EMULATOR selects the host CSPRNG; ARM firmware must use the STM32 hardware RNG"
#endif

/* trezor-crypto's crypto/rand.c contains a zero-seeded test LCG under
 * #ifndef RAND_PLATFORM_INDEPENDENT.  Production supplies random32() here, so
 * make removal of that provider declaration a compile failure rather than
 * relying on today's duplicate-symbol link failure. */
#ifndef RAND_PLATFORM_INDEPENDENT
#error \
    "RAND_PLATFORM_INDEPENDENT must be defined; otherwise trezor-crypto compiles its insecure test LCG"
#endif

/* Software mirror of the hardware's sticky seed/clock error.
 *
 * RNG_SR_SEIS latches in hardware, but only until someone clears it -- and both
 * random32() below and reset_rng() do, as they must to keep drawing. random32()
 * runs constantly, so by the time a self-test reads RNG_SR the evidence of a
 * transient fault is usually gone, and rng_source_live() was documented as
 * catching exactly that case. Record it here instead, where it cannot be
 * cleared by the recovery path that observed it.
 *
 * Boot-lifetime and one-way on purpose: a noise source that failed its own
 * continuous test once is not trusted again until the device is power-cycled.
 */
static volatile bool rng_seed_error_seen = false;
#ifndef EMULATOR
static volatile bool rng_discard_next = false;
#endif
static uint32_t rng_last_word = 0;

/* Preserve the STM32 continuous random-number generator test across every
 * production draw path. A repeated 32-bit word must be discarded before it
 * can reach the byte-level RCT/APT; a short seed buffer can otherwise return
 * several copies of a stuck non-uniform word before the APT window trips. */
static bool rng_word_is_fresh(uint32_t sample) {
  if (sample == rng_last_word) return false;
  rng_last_word = sample;
  return true;
}

bool rng_seed_error_latched(void) { return rng_seed_error_seen; }

#ifdef EMULATOR
static void rng_latch_seed_error(void) { rng_seed_error_seen = true; }
static bool rng_test_bounded_failure = false;

void rng_test_power_on_reset(void) {
  rng_seed_error_seen = false;
  rng_test_bounded_failure = false;
  rng_last_word = 0;
}
void rng_test_observe_transient_error(void) { rng_latch_seed_error(); }
void rng_test_observe_persistent_error(void) {
  rng_latch_seed_error();
  reset_rng();
}
void rng_test_force_bounded_failure(bool fail) {
  rng_test_bounded_failure = fail;
}
#endif

bool rng_persistent_error_step(uint32_t* samples) {
  if (samples == NULL) return false;
  if (++(*samples) < 100) return false;

  /* reset_rng() clears SEIS/CEIS. Preserve the fault before the caller takes
   * that recovery action, exactly as the transient-error branch does. */
  rng_seed_error_seen = true;
  *samples = 0;
  return true;
}

void reset_rng(void) {
#ifndef EMULATOR
  /* disable RNG */
  RNG_CR &= ~(RNG_CR_IE | RNG_CR_RNGEN);
  /* reset Seed/Clock/ error status */
  RNG_SR &= ~(RNG_SR_SEIS | RNG_SR_CEIS);
  /* reenable RNG */
  RNG_CR |= RNG_CR_IE | RNG_CR_RNGEN;
  rng_discard_next = true;
  /* this delay is required before rng data can be read */
  {
    uint32_t cnt = 5 /* microseconds */ * 20;
    while (cnt--) {
      __asm__("nop");
    }
  }

#endif
}

bool random32_bounded(uint32_t* out, uint32_t max_polls) {
  if (out == NULL || max_polls == 0) return false;
#ifndef EMULATOR
  for (uint32_t poll = 0; poll < max_polls; poll++) {
    if ((RNG_CR & RNG_CR_RNGEN) == 0) return false;
    const uint32_t status = RNG_SR;
    if (status & (RNG_SR_SEIS | RNG_SR_CEIS | RNG_SR_SECS | RNG_SR_CECS)) {
      rng_seed_error_seen = true;
      return false;
    }
    if (status & RNG_SR_DRDY) {
      const uint32_t sample = RNG_DR;
      if (rng_discard_next) {
        rng_discard_next = false;
        continue;
      }
      if (rng_word_is_fresh(sample)) {
        *out = sample;
        return true;
      }
    }
  }
  return false;
#else
  (void)max_polls;
  if (rng_test_bounded_failure) return false;
  const uint32_t sample = random32();
  if (!rng_word_is_fresh(sample)) return false;
  *out = sample;
  return true;
#endif
}

uint32_t random32(void) {
#ifndef EMULATOR
  uint32_t rng_samples = 0, rng_sr_img;

  for (;;) {
    /* Capture the RNG status register */
    rng_sr_img = RNG_SR;
    if ((rng_sr_img & (RNG_SR_SEIS | RNG_SR_CEIS)) == 0) {
      if (rng_sr_img & RNG_SR_DRDY) {
        const uint32_t sample = RNG_DR;
        /* STM32F205 section 20.3.1 requires discarding the first sample after
         * enabling RNGEN. Do it in this loop so reset_rng() never recurses
         * through random32() when the peripheral remains unavailable. */
        if (rng_discard_next) {
          rng_discard_next = false;
          continue;
        }
        if (rng_word_is_fresh(sample)) return sample;
      }
    } else if ((rng_sr_img & (RNG_SR_SECS | RNG_SR_CECS)) == 0) {
      /* Reset RNG interrupt status bits (SECS, CECS errors no longer
       * exist). Record it FIRST: clearing the hardware latch is exactly
       * what makes this fault invisible to a later self-test. */
      rng_seed_error_seen = true;
      RNG_SR &= ~(RNG_SR_SEIS | RNG_SR_CEIS);
    } else {
      /* RNG is not ready.  Allow few more samples for RNG to come back alive
       * before resetting */
      if (rng_persistent_error_step(&rng_samples)) {
        /* RNG in hang state.  Reset RNG */
        reset_rng();
      }
    }
  }
#else
  /* Emulator cryptography uses the existing host OS CSPRNG implementation,
   * which reads /dev/urandom and aborts on failure. */
  uint32_t value = 0;
  emulatorRandom(&value, sizeof(value));
  return value;
#endif
}

#if defined(EMULATOR) && !defined(__APPLE__)
/* trezor-crypto declares random_buffer() as a weak symbol so platforms can
 * supply their own. GNU/MinGW ld will NOT extract a weak definition from a
 * static archive to satisfy a strong reference (fsm.c/reset.c/storage.c),
 * which breaks the Linux .so and Windows .dll links. Provide a strong
 * definition here — identical to trezor-crypto's, built on our random32().
 * macOS ld64 resolves the weak one fine, so it's left untouched there. */
void random_buffer(uint8_t* buf, size_t len) {
  uint32_t r = 0;
  for (size_t i = 0; i < len; i++) {
    if (i % 4 == 0) r = random32();
    buf[i] = (r >> ((i % 4) * 8)) & 0xff;
  }
}
#endif

// I miss C++ templates sooo bad.
#define RANDOM_PERMUTE(BUFF, COUNT)             \
  do {                                          \
    for (size_t i = (COUNT) - 1; i >= 1; i--) { \
      size_t j = random_uniform(i + 1);         \
      typeof(*(BUFF)) t = (BUFF)[j];            \
      (BUFF)[j] = (BUFF)[i];                    \
      (BUFF)[i] = t;                            \
    }                                           \
  } while (0)

void random_permute_char(char* str, size_t len) { RANDOM_PERMUTE(str, len); }

void random_permute_u16(uint16_t* buf, size_t count) {
  RANDOM_PERMUTE(buf, count);
}

#undef RANDOM_PERMUTE
