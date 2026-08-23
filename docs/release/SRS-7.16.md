# SRS — KeepKey Firmware 7.16.0

Software Requirements Specification, IEEE 830 (concise form).
Status: **planned**. Depends on 7.15.0 shipping.

---

## 1. Introduction

### 1.1 Purpose
Defines the one capability 7.16 adds and the custody programme it requires.

### 1.2 Scope
7.16 crosses a single line: **KeepKey signs a provider's key**, and a
KeepKey-signed provider may render *without* the blind-sign review behind it.

That is the whole release. Everything else is consequence.

> **The 7.15/7.16 boundary is one branch.**
> ```c
> if (signed_metadata_from_loaded_signer()) {
>     needs_confirm = true;  data_needs_confirm = true;   // 7.15: additive
> } else {
>     needs_confirm = signed_metadata_schema_moves_value();
>     data_needs_confirm = false;                          // 7.16: may replace
> }
> ```
> The else-branch already exists and is **unreachable** because no pinned key
> exists. 7.16 is the release that makes it reachable — deliberately, once.

### 1.3 Definitions
Inherits SRS-7.15 §1.3, plus:
- **Root key** — the KeepKey key whose public half is compiled into firmware.
- **Delegate certificate** — a root-signed statement that a provider key may
  describe transactions.
- **Suppression** — omitting the raw-data review because a trusted describer
  already described it.

---

## 2. Overall Description

### 2.1 Why this needs its own release
In 7.15 a compromised provider can **mislabel** a transaction but cannot
**conceal** it: the raw review always follows and trust expires at reboot. That
bounded blast radius is why 7.15 needs no custody programme.

Suppression removes the bound. A compromised delegate key becomes able to hide
transaction bytes. So 7.16 cannot ship the branch without also shipping the key
management that makes the branch safe.

### 2.2 Constraints
Inherits SRS-7.15 §2.3. Additionally:
- **C-6** The root private key never exists on a device and never in CI.
- **C-7** Compiling a public key into firmware is irreversible in the field
  without a signed firmware update. It must be right the first time.
- **C-8** No bootloader changes.

---

## 3. Specific Requirements

### 3.1 Root of trust

**R-1.1** Firmware SHALL carry the KeepKey root PUBLIC key.
**R-1.2** The root private key SHALL be held offline under documented custody
(HSM or equivalent self-hosted; not a cloud KMS).
**R-1.3** Provisioning SHALL follow the runbook in
`7.15.0-rc21-clearsign-release-control.md` §"Production-key provisioning":
standard wallet, empty passphrase, derive twice, accept only on a byte-for-byte
match. **Never provision while a hidden wallet is active** — the attestor key
derives from the active seed/passphrase session, so a hidden wallet yields a
different identity.

### 3.2 Delegation

**R-2.1** A provider key SHALL be trusted only via a root-signed delegate
certificate.
**R-2.2** A certificate SHALL carry an expiry, and the device SHALL refuse an
expired one.
**R-2.3** Revocation SHALL be possible without a firmware update, or its absence
SHALL be stated as an accepted limitation with its blast radius.

### 3.3 Suppression — what actually changes on screen

**R-3.1** A KeepKey-signed provider MAY render without the raw-data review.
**R-3.2** A RUNTIME (self-service) provider SHALL remain additive, exactly as
7.15. The two tiers coexist; the tier is visible to the user.
**R-3.3** A suppressed render SHALL still show amount and recipient whenever the
schema cannot bind `msg->value` — a v2 schema describes calldata only.
**R-3.4** The screen SHALL distinguish the tiers. 7.15 shows "NOT verified by
KeepKey". 7.16's KeepKey-signed rendering must not merely drop that line;
**the user must be able to tell which tier described this transaction.**

> **Open decision, inherited from the roadmap and still unanswered.** Does a
> delegated render go fully warning-free, or keep a subtler marker such as
> *"described by KeepKey, 12 Aug"*? The roadmap asks this for delegated v1; the
> same question applies to Phase 0 and is not asked there. **Answer before
> building, not after.**

### 3.4 Structured EIP-712 — returns here

**R-4.1** Structured EIP-712 SHALL be re-enabled once canonical display
hardening lands. 7.14.2 disabled it — *"Structured EIP-712 disabled pending
canonical display hardening"* — because the device could not prove that what it
rendered was what it hashed.
**R-4.2** The x402 EIP-3009 `TransferWithAuthorization` vector SHALL sign again.
Its reference hashes are preserved in `test_sign_typed_data.py` for exactly this.

### 3.5 Carried from 7.15

~~**R-5.1** Resolve the AdvancedMode-disable deviation~~ — **closed in 7.15.**
`fsm_msgApplyPolicies` erases loaded signers on disable, which is what the tier
document already promised. Four lines. Nothing carried here.
**R-5.2** Resolve the duplicate-transaction detector question (D-01 sub-item):
either demonstrate a correct true-positive or simplify the check.

---

## 4. Verification

**V-1** A runtime provider still cannot suppress — the 7.15 atlas F section must
pass UNCHANGED against 7.16 firmware. This is the regression that matters most:
7.16 must not accidentally promote self-service providers.
**V-2** A delegated provider suppresses only where permitted, proven by screen
capture of both tiers side by side.
**V-3** An expired or revoked certificate falls back to additive rendering.
**V-4** Gate 3 OLED evidence for both tiers.

Implementation shape, open decisions and the custody argument are in
`../security/DESIGN-716-reductive.md`.

---

## 5. Explicitly NOT in 7.16

Quorum signing, multi-root delegation, provider reputation, fiat values, and any
context not derivable from the bytes — those are 7.17+ (SRS-7.17 §3.3).
