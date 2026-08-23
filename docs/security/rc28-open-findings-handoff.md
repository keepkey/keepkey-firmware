# RC28 handoff — open findings, owners, and order

Base: `develop` / RC27 `6ae3b964`. Written 2026-08-11 after three audit rounds,
then after a remediation pass, then after two external review rounds that
reopened findings from each.

| PR | Head | State |
|---|---|---|
| #366 RNG seed-time gate | `3246b5f1` | Inverted default; **link + continuous-test + bootloader defects fixed** after round 2 |
| #367 HASHES.txt labels | `fc092c8f` | Ordering, quorum gate, filename binding, truncation guard; wording narrowed |
| #368 storage V17 revert | `bee5b29d` | Substance approved; **ARM build fixed**, catalog repinned |
| #369 clear-sign roadmap | `53866b9c` | **10** blockers now: 4 resolved, 4 specified, 2 open decisions (5 custody, 10 work accounting) |

**RC28 is not merge-ready.** #369 is no longer the only reason it wasn't — for
a full round, #366 and #368 did not build.

## Post-7.15 security project: RNG coverage, RedPallas, degraded-RNG recovery

These three are one project, not three tickets, because each answer changes the
others. All were built during RC28 and deliberately descoped.

**1. Coverage is opt-in, and the list is short.** #366 ships six draws that
call `random_buffer_checked()` by name (see `rng_health.h`). Everything else,
including all of `deps/`, is unchecked exactly as on develop. A new key-material
draw inherits nothing.

**2. RedPallas is the reason that matters.** `redpallas.c:281` draws the Orchard
signing nonce with a bare `random_buffer()`, and `s = r + c*rsk` means two
signatures sharing `r` disclose the spend authorization key. Uncovered on
develop and uncovered in 7.15 — not a regression, but the highest-value gap.

**3. Inverting the default was built and rejected — read this before rebuilding
it.** Making `random32()` checked covers every dependency by construction, and
the attempt failed for reasons that are properties of the system, not of the
patch:

- ECDSA blinding runs on the VERIFY path. `curve_to_jacobian()` randomizes a Z
  coordinate on every point operation, so `ecdsa_verify_digest()` would abort on
  a failed verdict — and `keepkey_main.c:177` calls `signatures_ok()` before
  `kk_board_init()`. The firmware would not boot, with no message.
- Making blinding draw raw does NOT fix that. `generate_k_random()` loops
  `while (bn_is_zero(k) || !bn_is_less(k, prime))`, so a source stuck at zero
  hangs instead of aborting.
- The raw-blinding patch is only safe while `USE_RFC6979=1`. Under a different
  configuration the same switch controls the real ECDSA signing nonce. A
  comment is not a guard, and `rng_health.c` opens by warning against exactly
  this class of assumption.
- The bootloader reaches the same code through `signatures_ok()`, so any of
  this in a bootloader is a brick with no recovery path.

**The prerequisite is a defined degraded-RNG recovery mode** spanning firmware
and bootloader crypto: what a device does when its generator has failed, such
that it still boots, still verifies firmware, still signs with RFC6979 (which
needs no entropy) to move funds out, and still refuses to mint new key material.
Until that exists, inverting the default converts a degraded device into a dead
one.

**The rejected crypto branch has been deleted.** `BitHighlander/trezor-firmware`
carried `fix/blinding-draws-raw`, which made blinding draw raw behind a
`KK_BLINDING_RANDOM32` macro. It was removed rather than left unmerged so that
nobody repins to it later on the strength of its commit message, which argued a
case the loop condition above disproves. The approach is recorded here; the
branch is not.

---

## STOP — hard gate on the NEXT BOOTLOADER RELEASE

**Not an RC28 item. Do not fix it in an RC28 PR. Do not build and ship a
bootloader from this tree until it is fixed.**

`tools/bootloader/main.c` draws its stack canary through `random32()`, which
#366 made consult the RNG health verdict and `abort()`. The bootloader also
reaches nothing else through the gate — `signatures_ok()` was cleared by the
crypto-fork blinding patch — but that one call is enough:

> A device whose RNG has failed would abort inside the bootloader. It could not
> verify firmware, boot, or accept a replacement image. That is an
> unrecoverable brick, in the one component that exists to recover from
> everything else.

**Why it is not being fixed now.** A firmware release does not update anyone's
bootloader; devices keep the one they have. So this cannot reach an RC28 user,
and the fix would mean shipping bootloader changes reviewed under a firmware
deadline — landing in a bootloader release months later with the reasoning long
gone. Bootloader edits were reverted for exactly that reason;
`tools/bootloader/main.c` is byte-identical to develop.

**What to do when the bootloader is next cut.** Either give the canary
`random32_raw()` — it protects nothing an attacker can predict their way past —
or build kkrand for the bootloader with the gate compiled out so it cannot
return by someone adding a caller. Both were prototyped and reverted; see the
history of this branch. Then check the built ELF, because "nothing calls it" has
already failed twice in this module:

    arm-none-eabi-objdump -d bin/bootloader.elf > /tmp/bl.asm
    awk '/^[0-9a-f]+ </{fn=$2} /bl.*<random32>/{print fn}' /tmp/bl.asm | sort -u
    # must print nothing

---

## The pattern worth more than any single finding

Three rounds, and the same failure keeps recurring in different shapes: **work
that is correct as far as it goes, reported as if it went further.**

| Round | Claimed | Actually |
|---|---|---|
| 1 | "every key-material draw" is gated | a hand-written list; missed the RedPallas nonce in a submodule |
| 1 | certificate layout is "canonical" | every offset after 0x02 was still `*` |
| 2 | quorum gate verified on fixtures | `od` line-collapsing meant it passed unsigned images |
| 2 | "the bootloader gains no fatal path and no ROM" | memcmp_s's shuffle pulled the checked path in; +784 bytes |
| 2 | branches verified locally | **the emulator build passed; ARM was never compiled, and both branches were CI-red** |

The last one is the important one, and it has a mechanical fix rather than a
resolution to try harder: **an emulator build proves nothing about the shipping
firmware.** `_Alignas` compiles on clang and is rejected by the ARM toolchain.
A missing `random_uniform` link edge appears only when archives are ordered the
way the ARM target orders them. Neither is visible from `cmake -DKK_EMULATOR=ON`.

Cross-compile before claiming a branch is verified — the recipe is in §5, it
needs no toolchain install, and it takes about four minutes:

    docker run --rm --platform linux/amd64 -v "$PWD":/root/keepkey-firmware:z \
      kktech/firmware@sha256:7438e53933d47d53157ed6d96d864cb208597e62dce26235ace09d1063427fa2 \
      /bin/sh -c "mkdir -p /root/b && cd /root/b && \
        cmake -C /root/keepkey-firmware/cmake/caches/device.cmake \
              /root/keepkey-firmware -DCMAKE_BUILD_TYPE=MinSizeRel && \
        make -j4 && arm-none-eabi-size bin/*.elf"

Add `-DKK_BITCOIN_ONLY=ON` for the other variant. CI builds both; so should you.

## What the remediation pass changed

- **#368** — the emulator's `calc_crc32()` consumed `word_len` BYTES of a
  reflected zlib CRC-32 while hardware feeds `word_len` 32-bit WORDS to the
  STM32 peripheral. It now models CRC-32/MPEG-2 over words, with golden vectors
  independently checkable as the MPEG-2 CRC of each word's big-endian bytes, and
  a test that byte 2568 changes the 643-word CRC but not the 642-word one.
  `flash_temp` is explicitly `_Alignas(uint32_t)`. The audit's reboot regression
  is committed: `Storage.PinUnlocksAfterRebootUnderV17` reports `PIN_WRONG` when
  the hardcoded `PIN_KDF_V19` is put back, and the other 23 tests stay green
  under that same injection — which is the point.
- **#367** — rename now precedes hashing, and generation moved to
  `scripts/release/hash-manifest.sh` so key holders re-run the identical recipe
  over the signed binaries. It derives the device-image hash from `codelen`
  instead of assuming the file is `256+codelen` bytes, and reports the two
  separately when they differ.

  **The quorum gate as first written did not work.** `od` collapses repeated
  identical lines to `*` unless given `-v`, so a 192-byte all-zero signature
  area rendered as zeros plus `*`, the `*` survived `tr -d '0'`, and an unsigned
  image with its signer indices filled in passed. The self-test could not catch
  it because it wrote one byte into the first signature — the single input shape
  where the bug does not appear. Now: `-v` everywhere, each 64-byte signature
  region checked independently, signer slots required in 1..5, and
  `--require-signed` refuses a directory with no application image at all
  (it previously exited 0 on an empty directory, announcing success over
  nothing). The manifest says plainly that this is structural: it proves the
  unsigned binary was not published, not that the signatures verify.
- **#366** — **the default is inverted, and after round 2 it also links.**
  `random32()` consults the verdict and halts; trezor-crypto's `random_buffer()`, `random_uniform()` and everything
  built on them inherit it, so every cryptographic consumer inside `deps/` is
  covered without touching `deps/` at all. Link proof from the built binary:
  `redpallas.o`'s only undefined RNG symbol is `_random_buffer`, whose body is
  `bl _random32`, and `rng.c` references `_rng_health_require`.
  `random32_raw()` / `random_buffer_raw()` are the named opt-outs, each
  justified at its call site: the health gate itself (which would otherwise
  recurse), `GetEntropy` (the audit interface — gating it would block the
  measurement that finds a failing source), stack canaries in firmware and
  bootloader, timer jitter, U2F channel ids, compare decoys, and `drbg_init`'s
  seeding. The bootloader gains no fatal RNG path and no ROM.
  `random_buffer_or_die()` is gone — plain `random_buffer()` is now exactly
  that. `random_buffer_checked()` survives only for paths with somewhere better
  to go than a halt.

  Round 2 fixed three things the first attempt got wrong. `rng.c` no longer
  calls trezor-crypto's `random_uniform` (kkrand must depend on nothing, or
  single-pass archive ordering decides whether ARM links). `rng_health.c` no
  longer reaches up into kkboard for `layout_warning_static` — it halts with
  `abort()`, which is why `crypto-unit` links again. And `memcmp_s()` shuffles
  its decoys with `random_permute_char_raw()`; filling them raw and then
  shuffling them checked had pulled the fatal path back into the bootloader,
  which verifies signatures through `memcmp_s()`.

  **The continuous test now runs on the default path.** Previously only
  `random_buffer_checked()` folded bytes into the SP 800-90B state, so ordinary
  draws enforced the boot verdict and nothing more — and a source degenerating
  *after* the gate is precisely what the RCT and APT exist to catch.
  `random32()` calls `rng_health_observe()` on every checked draw.

  **Measured, not asserted:** bootloader text +784 bytes, firmware text +1408.
  The earlier "no ROM" claim was wrong. The bootloader's only edge into the
  health module is trezor-crypto's `generate_k_random` — an ECDSA *signing*
  nonce that `--gc-sections` keeps but the bootloader never calls, since it
  verifies rather than signs. No reachable fatal path there; real ROM cost.
- **#369** — §0 lists the blockers with severity, resolution location and
  status, and now says what Resolved and Specified each mean. Corrected on
  review: **both** roots need threshold custody, so Phase 1 is gated on the
  schema root's decision and Phase 2 on the delegation root's — a compromised
  schema root renders warning-free with no epoch and no expiry, making its only
  remedy a firmware release. Blocker 8 now carries a real byte layout (offsets,
  endianness, the exact signed transcript, the certificate hash) marked
  **proposed, not ratified**.

### Known, pre-existing, and NOT caused by this work

**`firmware-unit` cannot complete on a local macOS build.** Six suites hang
indefinitely, each spinning at 100% CPU on a test that drives the shared
`kkconfirm_preload` confirmation driver:

    Authenticator.WipeCancellationFailsClosed
    Ethereum.LiquidityCancellationFailsClosed
    Mayachain.MemoSwapFullFormShowsAffiliate
    Osmosis.MaxSwapAssetsAreRendererPagedCompletely
    Thorchain.MemoSwapFullFormShowsAffiliate
    Confirmation.ExactLengthPagerMeasuresRenderedRows

**Verified at the merge base.** `6ae3b9644` was checked out into the same
worktree, rebuilt, and all six hang identically there — none of this work is
involved. Excluding them, both branches are green and the whole suite takes
about eight seconds:

    firmware-unit  -Authenticator.*:Ethereum.*:Mayachain.*:Osmosis.*:Thorchain.*:Confirmation.*
      #368  327/327      #366  341/341
    board-unit
      #368  7/7 (includes the two new CRC tests)

Two things follow. **If CI for #366/#368 is red on a timeout, look here first**
rather than at the diffs. And *"the storage suite is 23/23"* was always a
filtered result — a full local `firmware-unit` run has never completed on this
platform, so treat any past claim of a clean full run with suspicion. CI builds
inside the emulator Docker image on Linux, which is presumably why #364 merged
green; whether that difference is the display stub, the button simulation or the
UDP transport has not been chased down, and is not this work's to chase.

---

## 1. Fixed this round (verify, do not re-litigate)

- **#368 wallet lockout.** `storage_setPin_impl` hardcoded `PIN_KDF_V19` and set
  `pin_kdf_v2 = true`. It creates the wrap and runs on wallet creation, every
  PIN change, and the V1 upgrade path; under a V17 record the flag cannot
  round-trip, so the next boot derived v15/v16 and every PIN failed. Both the
  derivation and the flag now follow `storage_rewrapPinKdfVersion()`.
- **#368 CRC tail.** `flash_temp[2570]` gave 642 words = 2568 bytes, leaving the
  V17 record's final byte outside the CRC on a path that reaches
  `storage_wipe()`. Now 2572 with static asserts.
- **#366 APT cutoff.** Counter initialised to 1 (NIST's inclusive convention)
  while using the following-matches cutoff: failed at 15 rather than 16, so
  shipped alpha was 3.227e-9, ~3.5x looser than the claimed 2^-30.
- **#366 RCT window reset.** One `started` flag initialised both tests, so a
  five-byte run straddling byte 512 was accepted. RCT and APT now keep
  independent state; two regressions added.
- **#366 compile.** `FailureType_Failure_ProcessError` does not exist.
- **#366 constant fold.** `rng_source_live()` returned bare `true` under
  EMULATOR, making callers' checks always-false branches. Now a real
  draw-twice-and-differ check.

---

## 2. Findings from the audit rounds

Each one is kept with its original text so it is not re-litigated; the
resolution follows it.

### 2.1 CLOSED (was High) — #366 did not establish wallet-wide RNG health

The gate sits only in the generate-mnemonic path. Recovery/import, `LoadDevice`,
PIN and wipe-code changes, upgrades and storage init all create or rewrap
storage encryption keys without passing it.

The narrow fix is sound; the *claim* is not. RC28 must not assert wallet-wide
RNG assurance.

**Design direction (do not scatter call-site checks):** maintain centralised
checked-RNG state and make every security-key draw consume it. One place that
knows the source passed, one place that fails closed, and every consumer routed
through it.

**Closed by inverting the default, on the second attempt.** The first attempt
did centralise the verdict but still routed consumers by hand, and review found
what a hand-written list always eventually misses: `redpallas.c:281` in the
pinned crypto submodule draws the Orchard signing nonce with a bare
`random_buffer()`, and `s = r + c*rsk` means two signatures sharing `r` give up
the spend authorization key. ECDSA blinding and SecAESSTM32 masking were in the
same position.

`random32()` is now the checked entry and the raw draw is the one you have to
ask for by name, so a dependency inherits the gate by linking rather than by
being remembered. **The claim this finding was about — that the device will not
create key material on a failed generator — is now supportable. It is still not
an unpredictability claim** (see the scope note atop `lib/rand/rng_health.c`),
and release notes must not upgrade it into one.

### 2.2 CLOSED (was High) — #367 left the published manifest stale and mislabeled

`release.yml` computes hashes **before** renaming (`:158-199`), then the
checklist (`:317-326`) tells key holders to replace the unsigned binary with the
3-of-5 signed one. Consequences:

- `HASHES.txt` names files that are never published;
- the full-image hash necessarily changes when descriptor signatures are
  inserted, and nothing regenerates it;
- **the published full hash therefore describes the unsigned draft, not the
  binary the device reports** — which is very likely the origin of the wrong
  `32155c11…` v7.14.1 pin found in Vault's table.

Also: the loop applies "compare with `Features.firmware_hash`" and "strip 256
bytes" to **every** `*.bin`, including `bootloader.bin`. Those instructions
describe application firmware only.

**Fix:** rename first, assemble the final signed artifacts, verify the 3-of-5
quorum, then generate both hashes from the final assets, with
artifact-type-specific instructions. #367's labels are correct and can merge;
they simply do not close this.

**Closed, after review found the quorum half of it inoperative** — `od` without
`-v`, one concatenated blob instead of three regions, signer slots unbounded,
and success on an empty directory. Details under *What the remediation pass
changed*. Worth internalising: the self-test passed throughout, because it
exercised the one input shape in which the bug is invisible. A green check on a
gate is evidence about the test, not about the gate.

### 2.3 CLOSED (was Medium) — #368's CRC correction was unprovable by the suite

Hardware `calc_crc32(data, word_len)` feeds `word_len` **32-bit words** to the
STM32 peripheral; the emulator implementation loops `word_len` **bytes**
(`lib/board/keepkey_board.c:133-153`). For the new 643-word buffer the emulator
covers 643 bytes, not 2572. The production fix is sound by inspection, but the
suite cannot demonstrate byte 2568 is covered.

**Fix:** correct the emulator to consume words, add a hardware-compatible golden
vector, and add a corruption test targeting byte 2568 specifically.

**Also:** make `flash_temp` explicitly `uint32_t`-aligned. The size assertion
does not guarantee alignment before the cast to `uint32_t *`.

### 2.4 CI — STILL OPEN

- **#366 / #368 were red for real reasons, now fixed.** #368 failed both ARM
  builds on `_Alignas` and then failed catalog validation on a stale test name;
  #366 failed every link on `random_uniform` and `layout_warning_static`. All
  four are addressed and the ARM builds were reproduced locally in CI's image.
  Separately, if a job ever times out rather than erroring, check the six
  confirm-driver suites first — those hangs reproduce at `6ae3b9644`, not on any
  branch.
- **Formatting — solved, and the earlier note was half wrong.** CI pins
  **clang-format-20**; the default on PATH here is 22.1.1, which is why
  `scripts/format-source-files.sh` rewrote 40+ untouched files including
  vendored `pb_*.c`. But a matching binary is already installed —
  `/opt/homebrew/opt/llvm@20/bin/clang-format` (20.1.8, brew `llvm@20`) — so the
  job is not unfixable locally, it was being run with the wrong compiler.

  Reproduce CI's check exactly, without touching anything else:

      CF=/opt/homebrew/opt/llvm@20/bin/clang-format
      for f in $(find include/keepkey lib/firmware lib/board lib/transport/src \
                 -name '*.c' -o -name '*.h' | grep -v generated | grep -v '.pb.'); do
        $CF --style=file --dry-run --Werror "$f" >/dev/null 2>&1 || echo "$f"
      done

  Fix a single hunk with `$CF --style=file --lines=A:B -i <file>` rather than
  reformatting whole files. `scripts/format-source-files.sh` still has no pinned
  version — **pin it to 20 before anyone runs it repo-wide.**

  Two violations were found this way and fixed: an 82-column comment in
  `storage.c` (red on #368 since `280f3b6f`, unrelated to the CRC work) and a
  pointer-alignment slip in `u2f.c`.

- **Static analysis — also runnable locally, and also red on #368 since
  `280f3b6f`.** cppcheck flagged
  `storage->pub.pin_kdf_v2 = (storage_rewrapPinKdfVersion() == PIN_KDF_V19)`
  as `knownConditionTrueFalse`, correctly: with `STORAGE_PIN_KDF_V19` at 0 the
  call returns `PIN_KDF_V16` unconditionally. Suppressed inline rather than
  simplified — writing `false` would make the persisted flag agree with the KDF
  by coincidence, so flipping the gate later would ship a v19 wrap described as
  v16, which is the lockout this branch exists to fix.

  CI's invocation is in `.github/workflows/ci.yml` under `static-analysis` and
  runs verbatim locally (`brew install cppcheck`); the findings land in
  `cppcheck_report.txt`, which the failing step never `cat`s because
  `--error-exitcode=1` kills it under `bash -e`. Either read the uploaded
  `cppcheck-report` artifact (`gh run download <run> -n cppcheck-report`) or
  just run it yourself. **Both of #368's Stage-1 failures were pre-existing**,
  and everything downstream was `SKIPPED` behind them — so the branch had never
  actually been built or tested by CI.

### 2.5 Release note, mandatory

**Installing RC28 on a device that ran RC27 wipes it.** RC27 wrote storage V19;
RC28 does not recognise it. That is the anti-rollback policy working as
designed, not a regression. Testers need their recovery phrase first.

### 2.6 CLOSED — the reboot regression is committed

The audit's end-to-end regression — create/reset, set PIN, serialize V17,
reload as after reboot, unlock, compare recovered key — passed and was never
committed. The existing 23 storage tests never cross the serialize/reboot
boundary, which is exactly where the lockout lived.

Now `Storage.PinUnlocksAfterRebootUnderV17`, extended to decrypt the secret
section as well as unwrap the key, and verified against a reintroduction of the
hardcoded `PIN_KDF_V19`: it reports `PIN_WRONG`, and the other 23 stay green
under the same injection.

---

## 3. Open — #369 architectural blockers

None are ROM questions. **"Only ROM remains open" is false**, and the roadmap
now says so in its own §0 rather than leaving it to this handoff.

Status after the remediation pass — the findings below are unchanged, and are
kept in full because they are what has to be answered:

| # | Where it stands |
|---|---|
| 1, 6 | **Resolved in the roadmap text.** Opaque cross-variant preservation; proof constraints read only from the verified certificate, with rate-limited advances. |
| 8 | **Conflict removed; layout proposed, not ratified.** The three-way field inconsistency is gone and the Phase 1/Phase 2 "anchor" contradiction is resolved by naming a schema root and a delegation root as separate keys. The byte layout — offsets, endianness, chain_scope ordering, the exact signed transcript, the certificate hash — is now written down but awaits sign-off. Do not build an issuer against it yet. |
| 2, 3, 7 | **Shape specified, decisions named.** The substrate's four parameters (rollback tolerance, checkpoint granularity, wear budget, power-loss state machine) still need an owner; so does the key/quorum inventory, and the choice between authenticated storage and a session-scoped policy. |
| 4 | **Three options written down**, one of which is to state the recovery-only interruption state honestly. Needs a decision, not more analysis. |
| 10 | **OPEN, and it is a decision not an analysis.** Per-certificate work thresholds versus one global committed height. Three options in the roadmap; also cap the committed height at the work-qualified checkpoint rather than crediting every accepted header. |
| 9 | **Resolved.** AUTHENTICATED vs AUTHORIZED certificates; without the split a factory-fresh device could never bootstrap freshness. |
| 5 | **Owner decision. Widened on review.** It gates Phase 1 **and** Phase 2, not just Phase 2: a compromised schema root also renders warning-free, and unlike a delegate it carries no epoch or expiry, so its only remedy is a firmware release. Both roots need threshold custody; only the parameters may differ. Start it in parallel — it is an operational programme, and it is the one item here that cannot be compressed by working harder. |

| # | Sev | Finding |
|---|---|---|
| 1 | High | Bitcoin-only says freshness may be "absent or inert". It must preserve the authenticated full-firmware freshness field **opaquely** — unable to advance or lower it — or full → btc-only → full resurrects expired delegates. Alternatively full firmware refuses clear-signing when the preserved state is missing, but the transition rule must be explicit. The doc's "shared substrate" and "absent or inert" statements contradict each other. |
| 2 | High | The four-field `SecurityRatchets` facility does not exist. The anti-rollback RFC defines a single 256-step OTP firmware floor. Authenticated flash prevents forgery, not restoration of an authenticated *old* snapshot; a unary OTP counter has 256 lifetime advances and cannot track header heights; committing on every `Finish` still wears flash, and a hostile host can replay ever-longer honest chains to force one advance per proof. Likely shape: OTP-backed coarse generation/checkpoint plus an authenticated journal, with explicit rollback tolerance, checkpoint granularity, wear budget and power-loss state machine. |
| 3 | High | "ROOT SIGNATURE" is an authority class, not a key. Name which root per ratchet. Separation must be cryptographic — distinct keys/quorums, domain-tagged signed transcripts, network/model/variant/format/purpose binding, and negative tests for cross-protocol replay and type confusion. The clear-sign root must never gain authority over firmware or storage epochs. |
| 4 | High | The anti-rollback RFC requires verifying the candidate before erase and old-or-new bootability after power loss. The bootloader erases sectors 7-11 before upload (`usb_flash.c:425-493`) with a single application slot. Needs staging/dual-slot, a signed-digest preflight with streamed verification, or a rewritten invariant that admits recovery-only interruption states. |
| 5 | High | Single-root custody. One dice-generated KeepKey root means one compromise yields globally warning-free false interpretations until firmware replacement. Needs N-of-M across independent devices/locations, plus rotation, backup, disaster recovery and overlapping-anchor transition. |
| 6 | High | `BitcoinFreshnessBegin` lists host-supplied anchor and thresholds. All proof constraints must come from an already-verified certificate; the host may only reference the certificate and stream headers. Also rate-limit persistent advances or require a meaningful checkpoint delta before committing. |
| 7 | High | Blind-sign policy is security-critical persistent state with no specified integrity protection. In unauthenticated public storage a physical attacker enables the downgrade policy directly. Specify authenticated storage or a session-scoped physical-confirmation model, plus behaviour after reset, variant change and corrupted policy. |
| 8 | Med | Certificate schemas conflict across the document: `btc_anchor_*`/`expiry_*` vs `bitcoin_not_before/not_after` vs `epoch` vs `epoch_min/epoch_max`. The acceptance rule checks an epoch "within" a range never defined. Phase 1 ships a built-in anchor while Phase 2 pins it. Needs one canonical signed byte layout, and either consolidated phases or separate schema-root vs production-delegation-root definitions. |

Plus the previously flagged, still-undecided: blind-sign policy stickiness.

---

## 4. Order — what is left

1. ~~**#368** — emulator CRC + alignment + commit the reboot regression.~~ Done,
   and approved on review; both pre-existing CI gates fixed alongside.
2. ~~**#367** — rename/sign/hash ordering, per-artifact instructions, and a
   quorum gate that works.~~ Done. Two things to carry forward: the checklist
   tells key holders to run `hash-manifest.sh --require-signed` over the signed
   binaries, and **the first real release is the test of that instruction**;
   and the gate remains **structural** — it proves the canonical unsigned draft
   was not published, and a signature region holding one non-zero byte passes
   it. Real verification is a separate piece of work nobody has started, but it
   is NOT blocked on obtaining keys: the five signing public keys are already in
   `include/keepkey/board/pubkeys.h`. What is missing is a host-side secp256k1
   verifier over sha256 of the image.
3. ~~**#366** — centralised checked-RNG state.~~ Done, by inversion, and the
   continuous test now runs on the default path. The remaining exposure is
   deliberate and listed: every `random32_raw()` / `random_buffer_raw()` call
   site. **Any new one is a security review item**, which is the property the
   naming exists to create.
4. **#369** — decide blockers 1-8 before any implementation. Suggested order:
   substrate (2) → authority model (3) → updater invariant (4) → certificate
   transcript (8) → cross-variant preservation (1) → proof-session inputs (6) →
   policy integrity (7) → custody (5). ROM measurement comes **after**, because
   every one of these changes what gets measured.

---

## 5. Build recipe (took three rounds to find; do not rediscover)

```
PATH=/tmp/kkshim:/tmp/nanopb-gen:$PATH        # `python` shim + "rU"-patched nanopb copy
cmake -B build -S . -DKK_EMULATOR=ON -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
      -DCMAKE_C_FLAGS=-DPB_NO_PACKED_STRUCTS=1 \
      -DCMAKE_CXX_FLAGS=-DPB_NO_PACKED_STRUCTS=1
cmake --build build --target firmware-unit -j8
./build/bin/firmware-unit --gtest_filter='Storage.*'
```

- nanopb 0.3.9.4's generator uses `open(..., "rU")`, removed in Python 3.11 —
  patch a **copy**, not the user's install.
- `protoc-gen-nanopb` needs `python` on PATH, not `python3`.
- Without `PB_NO_PACKED_STRUCTS=1` macOS ARM64 fails to link on unaligned nanopb
  field atoms.
- `deps/sca-hardening/SecAESSTM32` may not populate in a worktree; copy it from
  a populated checkout and delete the stray `.git` file it brings. Same for
  `deps/qrenc/QR-Code-generator`, without which cmake fails at configure time.
- **Do not run `git submodule update --init --recursive deps/crypto/trezor-
  firmware`** to get it. That pulls micropython, tinyusb and friends and takes
  longer than the rest of the build put together. Init the four direct
  submodules non-recursively, then `--recursive` only `deps/qrenc`.
- **Cross-compile before claiming anything about the shipping firmware.** The
  emulator build accepts C11 the ARM toolchain rejects and hides link-ordering
  faults. Recipe in the header; ~4 minutes per variant, no toolchain install.
- Run the suite as
  `--gtest_filter='-Authenticator.*:Ethereum.*:Mayachain.*:Osmosis.*:Thorchain.*:Confirmation.*'`
  or it will hang — see *Known, pre-existing* above. Filtered, it takes eight
  seconds; unfiltered it never finishes.
