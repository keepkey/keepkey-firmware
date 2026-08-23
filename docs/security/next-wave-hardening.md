# KeepKey next-wave security hardening

Status: proposed

Baseline: `BitHighlander/keepkey-firmware:develop` at `21d6a9d100b16566a1e48899abbbb7bab9366187`

Threat-model snapshot: 2026-08-03

## Objective

Reduce seed-exposure, rollback, entropy, and storage-at-rest risk without
combining unrelated security changes into one release candidate. Each code
change must be independently reviewable, revertible, and tied to a negative
control or a test that would fail if the security rule were removed.

This plan treats physical possession, a malicious host, fault injection, and a
previously valid signed image as in-scope. It does not claim that firmware can
substitute for a secure element.

## Gap register and disposition

| ID | Gap | Current disposition | Delivery vehicle |
|---|---|---|---|
| KK-HARD-001 | No secure element | Hardware revision | Board threat model and SE architecture |
| KK-HARD-002 | Production PIN KDF uses 10 PBKDF2 iterations | Firmware, migration-sensitive | Versioned KDF/storage PR after downgrade gate |
| KK-HARD-003 | Firmware-owned PIN attempt counter has no wipe ceiling | Firmware policy plus hardware limitation | Separate policy RFC and implementation |
| KK-HARD-004 | Single RNG source cannot fail closed | Firmware | Health-test API and seed-generation PR |
| KK-HARD-005 | Host can request display of internal seed entropy | Firmware, immediate | Remove display path while retaining wire compatibility |
| KK-HARD-006 | Valid signed firmware can be rolled back | Bootloader plus irreversible state | OTP security-epoch RFC, prototype, hardware campaign |
| KK-HARD-007 | No per-device supply-chain attestation | Hardware revision | SE-backed manufacturing and server protocol |
| KK-HARD-008 | Firmware measures the bootloader rather than the root measuring firmware | Hardware/boot architecture | Next-board measured-boot design |
| KK-HARD-009 | Large USB/WebUSB parser surface | Product architecture | Reachability inventory, parser fuzzing, pre-PIN minimization |
| KK-HARD-010 | Host receives bulk unconditioned RNG output | Firmware | Conditioned audit stream with compatibility analysis |
| KK-HARD-011 | No anti-klepto/anti-exfil signing | Protocol plus firmware | Research RFC; do not mix with transaction policy patches |

PR #333's Taproot change-output rule is a release blocker for Taproot-enabled
firmware, but remains outside this series so these branches stay based directly
on `develop`.

## Delivery waves

### Wave 0: remove direct secret exposure

1. Ignore the legacy `ResetDevice.display_random` wire field.
2. Remove the production OLED path that formats and confirms all 32 bytes of
   internal entropy.
3. Keep the protobuf field decodable so old hosts do not fail to communicate.
4. Confirm that debug-link-only entropy access remains excluded from production
   builds.

Merge gate: full firmware unit suite, release build, ROM delta, and a source
audit showing no production reference to `display_random` or the "Internal
Entropy" screen.

### Wave 1: establish downgrade-safe storage hardening

PIN KDF hardening and anti-rollback are coupled by migration safety. A new KDF
must carry an unambiguous, persisted selector so existing wallets can
be unwrapped with the legacy parameters exactly once and rewrapped after a
correct PIN. An older signed firmware must not silently clear or misinterpret
that selector.

Delivery order:

1. Approve the security-epoch format and identify an unused OTP block on every
   shipping hardware revision.
2. Ship a bootloader that understands epoch zero without burning an epoch.
3. Verify bootloader update and recovery on real hardware, including power loss
   at every flash/OTP boundary.
4. Introduce storage version 19 with an explicit KDF-v2 flag and legacy unwrap
   path.
5. Benchmark the production iteration count on the slowest supported device;
   record unlock latency and watchdog margin.
6. Only then advance the signed-image security epoch and make older images
   ineligible.

The KDF PR may be reviewed and tested before the bootloader work, but it must
remain draft until the downgrade/recovery gate is satisfied.

### Wave 2: make entropy fail closed and condition host output

Split this into two PRs:

- Change the RNG API to report failure and add repetition-count plus
  adaptive-proportion health tests. Seed creation must abort without committing
  storage if the source fails.
- Hash-condition the `GetEntropy` stream with domain separation and a counter.
  Re-evaluate or remove the 64 KiB confirmation-free budget after conditioning.

Required tests include constant, alternating, biased-window, reset, and normal
source fixtures. Emulator determinism is not evidence of MCU RNG health; the
release gate requires injected hardware failures or a test build with a
controlled RNG shim.

### Wave 3: reduce online and parser attack surface

- Decide an explicit PIN-attempt ceiling and recovery policy. A wipe ceiling is
  a product decision with irreversible user impact, not a drive-by constant.
- Inventory every message reachable before initialization and before PIN
  unlock. Remove unnecessary handlers from those states.
- Seed the protobuf/USB fuzz harness with every production message type and
  require sanitizer-clean parsing before adding new messages.
- Specify an anti-klepto protocol with host capability negotiation and test
  vectors before changing nonce generation.

### Hardware wave

The current MCU-only design cannot provide an independent PIN oracle,
monotonic attempt counter, device identity secret, or root-held firmware
measurement. The next board threat model must therefore cover:

- secure-element lifecycle, provisioning, and slot policy;
- seed release requiring both MCU-held and SE-held material;
- SE-backed PIN stretching and monotonic attempts;
- per-device supply-chain challenge/response;
- bootloader-to-firmware measured boot; and
- recovery behavior when either chip is unavailable.

These are architecture requirements, not open firmware bugs against the
current board.

## Common acceptance gates

Every hardening PR must provide:

- a branch based on the exact current `develop` head, with no release-branch
  merge commits;
- a precise security invariant and adversary capability;
- tests in both directions plus a recorded negative control where practical;
- regular and bitcoin-only builds, and privacy builds when touched code is
  shared;
- direct test-binary exit status rather than the current
  `docker compose run firmware-unit` wrapper exit status;
- format, static-analysis, ROM/RAM, and stack deltas;
- hardware test instructions and expected OLED/USB behavior;
- an explicit statement of downgrade and recovery consequences; and
- two human reviewers, including one reviewer who did not author the finding.

No release candidate advances to production signing while a release-reachable
critical/high finding lacks either a fix or a signed risk acceptance.

## Release evidence bundle

For each candidate, bind the following to the immutable tag and commit:

- signed tag verification and signer fingerprint;
- exact-head CI and release workflow URLs;
- firmware and payload SHA-256 manifests;
- unit, Python, emulator, and hardware result counts;
- disclosed skips with owners;
- bootloader version and security epoch;
- storage migration source/target versions; and
- reviewer approvals for every security PR in the composition.
