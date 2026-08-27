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

#ifndef KEEPKEY_RAND_RNG_HEALTH_H
#define KEEPKEY_RAND_RNG_HEALTH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bytes drawn for the seed-time self-test: two full APT windows. */
#define RNG_HEALTH_SAMPLE_BYTES 1024

/* SP 800-90B continuous-test parameters, derived for H = 8 bits/byte and
 * alpha = 2^-30. Both derivations are spelled out in rng_health.c so a
 * reviewer can recompute them rather than trust a copied table. */
#define RNG_HEALTH_RCT_CUTOFF 5
#define RNG_HEALTH_APT_WINDOW 512
/* Counts samples FOLLOWING the window reference, so this is NIST's inclusive
 * cutoff minus one. Exact tail P(X >= 16) = 3.891e-10 <= 2^-30 for
 * X ~ Binomial(511, 1/256). See the derivation in rng_health.c. */
#define RNG_HEALTH_APT_CUTOFF 16

/* Streaming health-test state. Constant size: there is deliberately no sample
 * buffer anywhere in this module. */
typedef struct {
  uint8_t rct_prev;
  uint8_t apt_ref;
  uint32_t rct_run;
  uint32_t apt_following;
  uint32_t apt_pos;
  uint32_t total;
  /* RCT and APT keep INDEPENDENT initialisation state. Sharing one flag let
   * the APT window boundary reset the repetition counter, so a run straddling
   * byte 512 went undetected. RCT is continuous over the whole stream; only
   * APT is windowed. */
  bool rct_started;
  bool apt_started;
  bool ok;
} RngHealthCtx;

void rng_health_init(RngHealthCtx* ctx);
void rng_health_update(RngHealthCtx* ctx, const uint8_t* buf, size_t len);
/// Wipes ctx. Returns false if any window failed or no data was seen.
bool rng_health_final(RngHealthCtx* ctx);

/// Report which random32() implementation is actually running and whether it
/// is alive. On STM32 this reads the RNG peripheral's own control and status
/// registers; the answer does not depend on any build-configuration macro
/// having the value its name suggests. Returns false if the peripheral is
/// disabled, latching an error, or not producing fresh data.
///
/// SCOPE: detects an accidentally mis-built or dead generator. It is not an
/// attestation -- firmware that lies can return whatever it likes.
bool rng_source_live(void);

/// SP 800-90B repetition-count and adaptive-proportion tests over `buf`.
/// Pure function, no I/O: this is the unit-tested half.
///
/// SCOPE: catches a stuck or grossly degenerate source. A healthy-looking
/// generator with a tiny seed passes -- no output test detects that.
bool rng_health_analyze(const uint8_t* buf, size_t len);

/// The latched, boot-lifetime verdict on this device's generator.
///
/// The full gate -- rng_source_live() plus rng_health_analyze() over a freshly
/// drawn RNG_HEALTH_SAMPLE_BYTES sample -- runs ONCE, on first use, and the
/// answer is remembered. Every draw made through random_buffer_checked() is
/// folded into a continuous SP 800-90B test, and a failure there latches the
/// verdict to failed for the rest of the boot. Recovery is a reboot,
/// deliberately: a source that failed must not be retried until it passes.
///
/// SCOPE — OPT-IN, AND THIS IS THE COMPLETE LIST.
///
/// Covered, because each of these calls random_buffer_checked() by name:
///   - the device half of the seed        reset_init()
///   - the storage encryption key         storage_setPin_impl()
///   - the wipe-code key                  storage_setWipeCode_impl()
///   - the PIN-KDF salt                   storage_readStorageV1(), the V1
///                                        upgrade path that mints one
///   - the U2F key-handle derivation path generateKeyHandle()
///   - the one-shot OTP randomness block  flash_collectHWEntropy()
///   - the RedPallas spend-auth T          fsm_msg_zcash.h, the is_spend path
///
/// NOT covered: everything else in the tree and in deps/, because plain
/// random_buffer() and random32() are unchecked exactly as on develop.
///
/// Adding a new key-material draw does NOT inherit this gate. You must route
/// it through random_buffer_checked() deliberately. Inverting the default so
/// that coverage was automatic was built for 7.15 and descoped: it can hang
/// or brick the bootloader when the generator has failed and there is no
/// defined degraded-RNG recovery mode yet.
bool rng_health_check(void);

/// Fold \p len bytes of freshly drawn output into the boot-lifetime continuous
/// SP 800-90B state, latching the verdict to failed if the RCT or APT trips.
///
/// random_buffer_checked() calls this on every draw it makes. The initial 1 KiB
/// gate only says the source was healthy at boot; the continuous test is what
/// notices a source that degenerates afterwards.
///
/// Returns false if these very bytes tripped the test, so the caller can refuse
/// to return them. The triggering draw is part of the degenerate run -- handing
/// it back and aborting only on the NEXT call means a run that trips on the
/// last word of a buffer delivers that whole buffer first.
bool rng_health_observe(const uint8_t* buf, size_t len);

/// Draw \p len bytes and report failure instead of halting, for the paths that
/// have somewhere better to go: a host-visible error, or a one-shot write that
/// should simply be skipped and retried on a later healthy boot. Returns false
/// with \p buf zeroed.
///
/// THIS IS THE ONLY CHECKED DRAW. Plain random_buffer() and random32() are
/// NOT checked -- they behave exactly as on develop. A previous revision of
/// this branch inverted that and was descoped from 7.15, and this sentence
/// used to say the opposite; if you are reaching for entropy that must be
/// gated, you have to call this function by name.
bool random_buffer_checked(uint8_t* buf, size_t len);

#ifdef EMULATOR
/// Test-only: force the latched verdict. `false` stands in for a generator
/// that failed its self-test, which is otherwise unreachable from a host build;
/// `true` re-arms the continuous state.
void rng_health_force_verdict(bool passed);
#endif

#endif
