# SRS — KeepKey Firmware 7.15.0

Software Requirements Specification, IEEE 830 (concise form).
Status: **draft against `alpha`**. Baseline `dda531024`.

---

## 1. Introduction

### 1.1 Purpose
Defines what 7.15.0 must do, what it must NOT do, and how each requirement is
verified. Audience: firmware, host (Vault/SDK), and release review.

### 1.2 Scope
7.15.0 is the first release carrying the clear-signing *provider* tier. It adds
context to what the device already shows. **It never removes a screen.**

Two products ship:

| Product | Contents |
|---|---|
| Regular (`full`) | Every supported chain, including Zcash shielded/Orchard |
| Bitcoin-only | Bitcoin only; non-Bitcoin coins and Zcash privacy compiled out |

There is no separate `zcash-privacy` artifact.

### 1.3 Definitions
- **Clear-signing** — rendering a transaction's meaning (protocol, amounts,
  recipient) instead of raw calldata.
- **Provider** — a third-party identity supplying decode context. **Not**
  KeepKey attestation.
- **Runtime signer** — a provider identity loaded this session, RAM-only.
- **Pinned signer** — a verification key compiled into firmware. **None exists
  in 7.15** and none may.
- **Blind sign** — signing bytes the device cannot describe.
- **AdvancedMode** — session-scoped opt-in policy; never a flash bit.

### 1.4 References
- `docs/security/clearsign-provider-tier.md` — the tier's own scope rules,
  including the two-product decision and the Solana attestor's human-attestation gate
- `docs/security/clearsign-key-delegation-roadmap.md` — phases 0–3
- `deps/python-keepkey/scripts/generate-test-report.py` — the atlas (`SECTIONS`)

---

## 2. Overall Description

### 2.1 Product perspective
A signing device whose only real output is **what the user sees before they
press the button**. Every requirement below is ultimately about that screen.

### 2.2 User characteristics
Assume a user who reads the screen and does not read the host. The device may
never rely on the host to tell the truth, and may never rely on the user knowing
what a selector or an ABI offset is.

### 2.3 Constraints
- **C-1** STM32F205: ≥16 KiB SRAM reserve between `_ebss` and `_stack`, enforced
  by a linker `ASSERT` and `tools/check_sram_budget.py`.
- **C-2** No bootloader changes in this release.
- **C-3** The device's `snprintf` is integer-only; no float conversions.
- **C-4** `confirm()` paginates a body over `BODY_ROWS = 3`; bytes outside
  `0x21..0x7e` render as 4-glyph `\xNN` escapes.
- **C-5** Firmware SKIPS unknown protobuf fields — it does not reject them. A
  host on an older protocol degrades silently, so gating must be host-side and
  fail closed.

### 2.4 Assumptions
Hosts are untrusted. Providers are untrusted-but-named. The user is the only
authority.

---

## 3. Specific Requirements

### 3.1 Clear-signing is additive — THE release invariant

**R-1.1** After a successful clear-sign decode from a runtime-loaded provider,
the baseline raw/unverified review SHALL still run.
*Verify:* atlas F1/F2. Measured — Aave `supply()` baseline is 3 screens; a
VERIFIED v1 decode is 10 screens with those 3 **byte-identical at the tail**;
v2 static schema is 13 with the same tail.

**R-1.2** A payload whose signature fails verification SHALL fall back to the
ordinary unverified review — neither refusing nor showing partial decoded info.
*Verify:* F3. Measured: 3 frames byte-identical to baseline.

**R-1.3** No runtime signer SHALL reach the suppression branch.
*Verify:* F4/F5. All four slots produce VERIFIED decodes still followed by the
full baseline; no slot verifies without a runtime load.

**R-1.4** The firmware SHALL contain no pinned provider key.
*Verify:* zero key bytes in `signed_metadata.c`. **This single property is what
separates 7.15 from 7.16.**

> **What the user sees.** With a provider loaded and a matching signed payload:
> the provider's alias and fingerprint, then decoded screens naming the
> protocol, amounts and recipient — and then *the same raw-data review they
> would have seen with no provider at all*. Nothing is taken away.

### 3.2 Provider trust is opt-in and dies on its own

**R-2.1** AdvancedMode SHALL be session state, never a flash bit.
*Verify:* atlas I1; `storage.c` ignores legacy bit 12 at four sites.

**R-2.2** Loaded identities SHALL be RAM-only, cleared by reboot,
`ClearSession`, session teardown, and **disabling AdvancedMode**.
*Verify:* I3–I6.

**R-2.3** Loading a provider SHALL require an on-device confirm that cannot be
suppressed. *Verify:* V14; `signed_metadata_confirm_load`.

**R-2.4** The device SHALL never represent a provider as KeepKey-endorsed.
It renders the provider's own alias and fingerprint plus "NOT verified by
KeepKey".

**Deviation closed** (was: disable makes a signer inert but not erased).
`fsm_msgApplyPolicies` now calls `signed_metadata_clear_signers()` when
AdvancedMode is turned off. With the policy off the two behaviours were
indistinguishable — every consumer in `signed_metadata.c` already refuses a
runtime slot — so the bug was only visible on the way back: re-enabling
restored the provider to VERIFIED with no second trust screen, on a
confirmation that named the policy and never the signer. A user who disabled
AdvancedMode to drop a provider had not dropped it. I6 now asserts the signer
is gone, and its expected-response list (one ButtonRequest, one Success) proves
no trust screen appears on the way back.

### 3.3 Disclosure completeness

**R-3.1** Every byte covered by the signature SHALL be reachable on screen.
**R-3.2** A memo length that does not describe its own content SHALL be refused
(any NUL inside the declared length). *Verify:* Thorchain/Mayachain suites.
**R-3.3** An affiliate fee SHALL be displayed even when its affiliate slot is
empty. *Verify:* `MemoSwapFeeWithEmptyAffiliateIsStillShown` — 4 screens vs 3
without the fee.
**R-3.4** An amount SHALL never render as zero when non-zero, and never at the
wrong scale. *Verify:* `Solana.FormatTokenAmountNeverShowsZeroForNonzero`.
**R-3.5** A refused screen SHALL abort signing, never be re-asked differently.
*Verify:* `ThorchainMemoResult` CANCELLED vs UNPARSED.

### 3.4 Solana per-transaction context — IMPLEMENTED

**R-4.1** The device SHALL display provider-attested, transaction-bound context
for instructions whose accounts are not in the signed message (Address Lookup
Tables), behind AdvancedMode, additive.

**Status: implemented** (`KKSOLSW1`, firmware PR #500 — 146 added lines, no new
crypto primitive). Before it, `solana.c` skipped such instructions and rendered
**nothing**: the accounts an instruction would actually touch were invisible
while still being signed. That is the gap 7.15 closes, and closing it adds
screens.

The attestation binds to the transaction, not to the account list alone:

```
preimage = "KeepKeySolanaTxAccounts/1"
        || sha256(raw_tx)
        || count            (le32)
        || key[0..count-1]  (32 bytes each)
```

Verified through the existing chain-agnostic
`signed_metadata_verify_attestation()`. Three properties follow, each with a
test in section S of the atlas:

- `sha256(raw_tx)` in the preimage means an attestation harvested from one
  transaction cannot be replayed onto another — the same accounts under a
  different transaction do not verify;
- a bad signature degrades to today's flow rather than refusing, so a broken
  provider costs a user nothing but the extra screen;
- with no signer loaded the screens do not appear at all, which is the additive
  invariant (R-1.1) restated for this path.

The domain tag is versioned in the preimage itself, so a future account-context
format cannot be verified by a device that predates it.

### 3.5 Products

**R-5.1** Bitcoin-only SHALL compile out non-Bitcoin chains and Zcash privacy.
**R-5.2** The device SHALL report its product honestly in `firmware_variant`
(`KeepKeyBTC`/`EmulatorBTC`). *Verify:* atlas L; D-07.
**R-5.3** Non-Bitcoin paths SHALL refuse cleanly on bitcoin-only, not
half-render. *Verify:* atlas L.

### 3.6 Storage

**R-6.1** A signed UPGRADE SHALL never wipe. A DOWNGRADE wiping is expected.
**R-6.2** The committed record SHALL be recognisable on the next boot.
*Verify:* atlas U; D-02.
**R-6.3** Active flash format is V17. *Verify:* `test_active_flash_format_is_v17`.

### 3.7 Non-functional

**R-7.1** SRAM reserve ≥16,384 B, both products. *Currently:* full 18,172 B,
bitcoin-only 32,092 B.
**R-7.2** Both products build for ARM with `-Werror`.
**R-7.3** No CI job may silently skip. *Verify:* the aggregate `CI gate`.

---

## 4. Verification status

| | |
|---|---|
| `firmware-unit` (full) | 439/439 |
| `board-unit` | 12/12 |
| `firmware-unit` (bitcoin-only) | 63/63 |
| pyk suite (full emulator) | 620 passed, 33 skipped, 0 failed |
| pyk suite (bitcoin-only emulator) | 11/11 |
| ARM SRAM reserve | full **17,716 B** · btc-only **31,648 B** (budget ≥ 16,384 B, both PASS) |
| Token table applied | `ethereum_tokens: 350 of 1378 kept` · `uniswap_tokens: 150 of 568 kept` |
| Hardware (gate 3) | **NOT PERFORMED** |

Measured on the ARM cross-build of the KKSOLSW1 candidate, both variants. The
reserve is `_stack - _ebss` and the gate is enforced in CI, not read off a
build log.

The full-variant reserve fell 456 B from the previous line (18,172 B) and that
is KKSOLSW1: `fsm_msg_solana.h` flattens the nanopb array into a
`uint8_t lut_keys[SOL_MAX_LUT_ACCOUNTS][SOL_PUBKEY_SIZE]` so the attested keys
are contiguous for hashing. It is the honest cost of the feature and it is
recorded here rather than absorbed silently, because SRAM on this part is spent
once and an unexplained 456 B is the kind of thing that only becomes visible
when the next feature does not fit.

The token budget is what pays for it: 500 of 1,946 candidate entries, −23,104 B
of flash. The pinned data source has been stale since 2023-04-06, so the long
tail is not coverage of anything current.

---

## 5. Exit criteria

1. ~~R-4.1 implemented, or explicitly deferred~~ — **met.** KKSOLSW1 landed
   (firmware #500); §3.4.
2. Gate 3 OLED evidence per the human-attestation gate in
   `docs/security/clearsign-provider-tier.md`: a 44-character base58 program
   ID, an 8-byte discriminator on its own screen, all four argument types,
   16-character labels. **CI success alone does not prove this display
   boundary.**
3. The CI test report green with **nothing withheld**.
4. `solana-schemas-local.json` CI test key replaced or removed. **Host-side
   deliverable** — the file is not in this repository; it ships with the
   provider/Vault tooling. Listed here because a device cannot verify a
   schema signed with a test key, so it gates the release even though the
   fix lands elsewhere.
5. R-1.4 re-verified on the exact release candidate.
6. The D-01 sub-item (duplicate detector never observed firing correctly)
   resolved or accepted in writing.

---

## 6. Landing plan — alpha → fork `develop`

7.15 is cut from `alpha` into the fork's `develop`. `alpha` is *ahead* of 7.15:
it carries 7.16+ work, so the cut is a selection, not a fast-forward. What
follows is the selection.

### 6.1 What goes

| # | Change | Lines | Why it is in 7.15 |
|---|---|---|---|
| L1 | 7.14.2 security merge + the 10 defects it exposed | — | Three are shipping bugs. They go first because everything else rebases on them. |
| L2 | Clear-sign provider context, additive (§3.1–3.3) | — | The release's reason to exist. |
| L3 | KKSOLSW1 Solana account context (§3.4) | +146 | Last firmware build item. |
| L4 | Bitcoin-only variant (§3.5) | — | Second product, its own emulator leg. |
| L5 | Storage upgrade preservation (§3.6) | — | Proves a signed upgrade does not wipe. |
| L6 | Token table budget — 1,945 → 500 entries | −23,104 B flash | Pays for the above. |
| L7 | Test atlas sections F, I, L, U, J, Q, K, P + the report gates | — | The evidence. Without it none of the above is auditable. |

### 6.2 What does NOT go

Everything gated on a firmware-pinned provider key: the reductive branch, the
delegate certificate chain, expiry — that is 7.16+ scope. The release gate is
mechanical and checkable — **no pinned provider key bytes in the artifact** —
which is why 7.15 needs no custody programme.

### 6.3 Order

L1 → L6 → L2 → L3 → L4 → L5 → L7.

L6 goes early, directly after the defect fixes: it frees the flash the rest
spends, and a ROM overflow discovered after L2–L5 have landed is a bisect
through five features instead of one.

### 6.4 The gate on each PR

`ci-gate` green — not a green run summary. A failed Stage-1 gate marks the
whole downstream graph *skipped*, and a skipped required job is not a pass;
this has silently produced an all-green-looking run three times on this line.
`ci-gate` is the only check whose success means the entire graph ran.

### 6.5 What CI cannot close

Exit criterion 2. Every display bound in §3.1–3.4 is a claim about pixels, and
the emulator's framebuffer is not the OLED. Gate 3 is hardware, and it is
**still NOT PERFORMED** — it is the one item between a green `develop` and a
signable release candidate.
