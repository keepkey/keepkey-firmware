/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
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

/* Seed-time RNG self-test.
 *
 * WHAT THIS CATCHES, AND WHAT IT DOES NOT. Two different failures, two
 * different checks, and the difference matters enough to state up front:
 *
 *   rng_source_live()     -- the generator is the STM32 hardware peripheral
 *                            and that peripheral is enabled and producing.
 *   rng_health_analyze()  -- the output is not stuck or degenerate.
 *
 * Neither one detects a *healthy-looking generator with a tiny seed*. That
 * was the July 2026 COLDCARD failure: a board config left the hardware-RNG
 * macro defined-but-zero, a software PRNG was substituted, and it passed
 * every statistical test because that is what a CSPRNG does -- it was simply
 * seeded with ~40 bits. Recovering a 40-bit seed pool from output requires
 * searching it; by collision that is ~2^20 independent seedings. No amount of
 * sampling substitutes.
 *
 * What stops that failure here is upstream, in rng.c: two #error guards that
 * fail the *build* when the RNG source selection is wrong. rng_source_live()
 * is the runtime backstop for a future configuration that gets past them --
 * on a build where the hardware path was never enabled, RNG_CR_RNGEN reads
 * back clear and this refuses to produce a seed.
 *
 * The #ifndef EMULATOR below is not the kind of config macro this file exists
 * to distrust. rng.c asserts `#if defined(EMULATOR) && defined(__arm__)` is a
 * compile error, and __arm__ comes from the compiler's own target definition,
 * so ARM firmware always compiles the register path. There is no build of the
 * shipping firmware in which these checks are absent.
 */

#include "keepkey/rand/rng_health.h"

#include <string.h>

#include "trezor/crypto/memzero.h"
#include "trezor/crypto/rand.h"

#ifndef EMULATOR
#include <libopencm3/cm3/common.h>
#include <libopencm3/stm32/memorymap.h>
#include <libopencm3/stm32/f2/rng.h>
#endif

bool rng_source_live(void) {
#ifndef EMULATOR
  /* The peripheral clock being off reads back as a clear RNGEN, so this one
   * test covers both "never enabled" and "enabled then lost its clock". */
  if ((RNG_CR & RNG_CR_RNGEN) == 0) {
    return false;
  }

  /* Sticky seed/clock error. RNG_SR_SEIS means the noise source failed its
   * own continuous test; SEIS latches, so a transient fault is still visible
   * here even if the current sample looks fine. */
  if (RNG_SR & (RNG_SR_SEIS | RNG_SR_CEIS)) {
    return false;
  }

  /* Fresh data, bounded wait. random32() spins forever by design; a self-test
   * must be able to conclude "dead" rather than hang the device before the
   * user has been told anything.
   *
   * SEIS/CEIS is re-read on every iteration, not just once before the loop: a
   * seed or clock fault can latch while we are sampling, and a sample drawn
   * after the fault must not be accepted merely because the register was clean
   * when we started. */
  uint32_t first = 0;
  bool have_first = false;
  for (uint32_t tries = 0; tries < 100000; tries++) {
    const uint32_t sr = RNG_SR;
    if (sr & (RNG_SR_SEIS | RNG_SR_CEIS)) return false;
    if (sr & RNG_SR_DRDY) {
      uint32_t sample = RNG_DR;
      if (!have_first) {
        first = sample;
        have_first = true;
      } else if (sample != first) {
        return true;
      }
    }
  }
  return false;
#else
  /* Returning a bare `true` here made every caller's check a constant-folded
   * always-false branch, which static analysis correctly flags. Draw from the
   * same source the emulator actually uses and require it to vary:
   * emulatorRandom() aborts on failure, so this is cheap, but it is a real
   * check rather than an assertion, and it keeps the caller's branch meaningful
   * in both builds. */
  uint32_t a = 0, b = 0;
  random_buffer((uint8_t*)&a, sizeof(a));
  random_buffer((uint8_t*)&b, sizeof(b));
  return a != b;
#endif
}

/* SP 800-90B 4.4.1, repetition count.
 *
 * Cutoff C = 1 + ceil(-log2(alpha) / H). With H = 8 bits per byte and
 * alpha = 2^-30: 1 + ceil(30/8) = 5. Fail on five identical consecutive bytes.
 *
 * False positives on a good source: about len * 2^-32 for a run of five, i.e.
 * ~2.4e-7 over a 1024-byte sample. This gate blocks wallet creation, so alpha
 * sits at the strict end of NIST's 2^-20..2^-40 range: a spurious block is a
 * support ticket and must stay rare enough never to become one.
 *
 * SP 800-90B 4.4.2, adaptive proportion.
 *
 * NIST's counter is initialised to 1 because it INCLUDES the window's
 * reference sample. This implementation counts only the W-1 samples that
 * FOLLOW the reference, so its cutoff is NIST's minus one, and the two must
 * not be conflated -- an earlier revision of this file initialised the counter
 * to 1 while using the following-matches cutoff, which failed a window at 15
 * following matches instead of 16 and gave alpha = 3.227e-9, roughly 3.5x
 * looser than the 2^-30 it claimed.
 *
 * Exact tail, X ~ Binomial(W-1 = 511, p = 1/256):
 *
 *   P(X >= 15) = 3.227e-9      P(X >= 16) = 3.891e-10
 *   alpha = 2^-30              = 9.313e-10
 *
 * so 16 following matches is the smallest cutoff meeting alpha. (Do not cite a
 * cross-check against NIST's published table without restating the counter
 * convention: under NIST's inclusive counter the same derivation gives 17 at
 * alpha = 2^-30 and 14 at alpha = 2^-20.)
 *
 * Both tests run as STREAMING state so no sample buffer exists. The device has
 * a 16 KiB reserve gate and a history of boot faults from large automatic
 * buffers; a 1 KiB stack frame here is not worth a constant-space alternative.
 */

void rng_health_init(RngHealthCtx* ctx) {
  if (ctx == NULL) return;
  memzero(ctx, sizeof(*ctx));
  ctx->ok = true;
  ctx->rct_started = false;
  ctx->apt_started = false;
}

void rng_health_update(RngHealthCtx* ctx, const uint8_t* buf, size_t len) {
  if (ctx == NULL || buf == NULL || !ctx->ok) return;

  for (size_t i = 0; i < len; i++) {
    const uint8_t b = buf[i];
    ctx->total++;

    /* Repetition count: continuous over the whole stream, never reset by the
     * APT window. A run straddling a window boundary must still fail. */
    if (!ctx->rct_started) {
      ctx->rct_started = true;
      ctx->rct_prev = b;
      ctx->rct_run = 1;
    } else if (b == ctx->rct_prev) {
      if (++ctx->rct_run >= RNG_HEALTH_RCT_CUTOFF) {
        ctx->ok = false;
        return;
      }
    } else {
      ctx->rct_prev = b;
      ctx->rct_run = 1;
    }

    /* Adaptive proportion: windowed, counting only samples FOLLOWING the
     * window's reference sample. */
    if (!ctx->apt_started) {
      ctx->apt_started = true;
      ctx->apt_ref = b;
      ctx->apt_following = 0;
      ctx->apt_pos = 1; /* the reference occupies slot 0 of the window */
      continue;
    }

    if (b == ctx->apt_ref && ++ctx->apt_following >= RNG_HEALTH_APT_CUTOFF) {
      ctx->ok = false;
      return;
    }

    if (++ctx->apt_pos >= RNG_HEALTH_APT_WINDOW) {
      ctx->apt_started = false; /* next byte becomes a new window's reference */
    }
  }
}

bool rng_health_final(RngHealthCtx* ctx) {
  if (ctx == NULL) return false;
  const bool ok = ctx->ok && ctx->total > 0;
  memzero(ctx, sizeof(*ctx));
  return ok;
}

bool rng_health_analyze(const uint8_t* buf, size_t len) {
  if (buf == NULL || len == 0) return false;
  RngHealthCtx ctx;
  rng_health_init(&ctx);
  rng_health_update(&ctx, buf, len);
  return rng_health_final(&ctx);
}

static bool rng_health_gate(void) {
  if (!rng_source_live()) return false;

  /* Drawn in small chunks and folded immediately: no 1 KiB frame, no static
   * buffer, O(1) state regardless of RNG_HEALTH_SAMPLE_BYTES. */
  RngHealthCtx ctx;
  rng_health_init(&ctx);

  uint8_t chunk[32];
  for (size_t drawn = 0; drawn < RNG_HEALTH_SAMPLE_BYTES;
       drawn += sizeof(chunk)) {
    random_buffer(chunk, sizeof(chunk));
    rng_health_update(&ctx, chunk, sizeof(chunk));
  }
  memzero(chunk, sizeof(chunk));
  return rng_health_final(&ctx);
}

/* THE CENTRALISED VERDICT.
 *
 * The first version of this gate sat in one place -- the generate-mnemonic
 * path -- and every other producer of key material drew from random_buffer()
 * directly: recovery and import, LoadDevice, PIN and wipe-code changes, U2F key
 * handles, the OTP randomness block. So the check was real but its scope was
 * one code path, and the honest claim was never "this device will not create
 * key material on a broken generator".
 *
 * The verdict is therefore computed ONCE and latched, and every covered site
 * consumes it through random_buffer_checked() -- which avoids re-running a
 * 1 KiB sample per draw.
 *
 * COVERAGE IS OPT-IN, NOT INHERITED. Each call site opts in by name; the
 * complete list is in rng_health.h. Making coverage automatic -- inverting
 * random32() so that everything, including deps/, was gated by construction --
 * was built for 7.15 and descoped, so a new key-material draw added tomorrow
 * gets NO protection unless its author routes it here on purpose. Do not
 * describe this module as wallet-wide; two earlier revisions did, and both
 * claims were wrong.
 *
 * The latch is per boot and one-way. A generator that fails is not retried
 * until it passes -- retrying until success is how a marginal source talks its
 * way in. */
static enum { RNG_UNTESTED = 0, RNG_PASSED, RNG_FAILED } rng_verdict;

/* Continuous SP 800-90B state over every byte drawn through
 * random_buffer_checked() this boot -- which is not every byte of key material
 * in the device, only the opted-in sites listed in rng_health.h.
 * This is what the RCT and APT are actually specified for: they run on the
 * output as it is produced, not only on a one-time sample. Constant space --
 * the streaming context holds no buffer -- so covering every draw costs
 * nothing over covering one. */
static RngHealthCtx rng_continuous;

bool rng_health_check(void) {
  if (rng_verdict == RNG_UNTESTED) {
    if (rng_health_gate()) {
      rng_verdict = RNG_PASSED;
      rng_health_init(&rng_continuous);
    } else {
      rng_verdict = RNG_FAILED;
    }
  }
  return rng_verdict == RNG_PASSED && rng_continuous.ok;
}

bool random_buffer_checked(uint8_t* buf, size_t len) {
  if (buf == NULL) return false;

  if (!rng_health_check()) {
    memzero(buf, len);
    return false;
  }

  random_buffer(buf, len);

  /* Observe THESE bytes and refuse them if they are what tripped the test. The
   * triggering draw is part of the degenerate run, so returning it and failing
   * only on the next call would hand the caller exactly the output the test
   * just rejected. Wiping also means a caller that ignores the return value
   * still cannot walk away with key material from a failed source. */
  if (!rng_health_observe(buf, len)) {
    memzero(buf, len);
    return false;
  }
  return true;
}

bool rng_health_observe(const uint8_t* buf, size_t len) {
  if (rng_verdict != RNG_PASSED) return false;
  rng_health_update(&rng_continuous, buf, len);
  if (!rng_continuous.ok) {
    rng_verdict = RNG_FAILED;
    return false;
  }
  return true;
}

#ifdef EMULATOR
void rng_health_force_verdict(bool passed) {
  if (passed) {
    rng_verdict = RNG_PASSED;
    rng_health_init(&rng_continuous);
  } else {
    rng_verdict = RNG_FAILED;
    memzero(&rng_continuous, sizeof(rng_continuous));
  }
}
#endif
