# SRS — KeepKey Firmware 7.17.0

Software Requirements Specification, IEEE 830 (concise form).
Status: **outline**. Third gate; contents may be re-scoped after 7.16 ships.

---

## 1. Introduction

### 1.1 Purpose
Defines the third gate: hardening the things 7.15 and 7.16 accepted as
limitations, and the classes of context that are not derivable from
transaction bytes.

### 1.2 Scope
7.15 added description. 7.16 added authority. **7.17 adds resilience** —
what happens when a key is lost, a describer lies, or the bytes simply do not
contain the answer.

---

## 2. Overall Description

### 2.1 Product perspective
By 7.17 the device describes most transactions and trusts a delegated describer.
The remaining risk concentrates in three places: key compromise recovery,
describers asserting facts the device cannot check, and chains where the signed
bytes are structurally insufficient.

### 2.2 Constraints
Inherits SRS-7.16 §2.2. Bootloader changes remain out of scope unless a
root-rotation requirement forces one — and if it does, **that is its own
release**, not a rider on this one.

---

## 3. Specific Requirements

### 3.1 Key lifecycle

**R-1.1** Root rotation SHALL be possible without bricking deployed devices.
**R-1.2** Quorum (k-of-n) delegate signing SHALL be supported if the custody
review requires it.
**R-1.3** Freshness: the device SHALL be able to reject a stale delegate
certificate, given it has no clock. **The mechanism is the open question** —
monotonic counters, host-supplied signed time, or explicit expiry only.

### 3.2 Context the bytes do not contain

**R-2.1** The device MAY display provider-attested context that is NOT derivable
from the signed bytes — recipient labels, reputation, fiat values.
**R-2.2** Such context SHALL be visually distinct from decoded fact.

> **This is the sharpest UX decision in the whole roadmap.** A decoded amount is
> something the device *computed from the bytes it is signing*. A fiat value or
> a recipient label is something *somebody told it*. If those render alike, the
> device teaches users to trust assertions as if they were derivations — and
> every guarantee below that point is theatre. **They must not look the same.**

### 3.3 Solana beyond ALT inlining

**R-3.1** If `KKSOLSW1` (SRS-7.15 §3.4) proves insufficient for lookup tables in
practice, the device SHALL either display a bounded attested account set or
refuse to clear-sign such instructions. **Rendering nothing while signing is the
outcome to eliminate.**

### 3.4 Debt from earlier gates

**R-4.1** Storage: `flash_erase_word()` is a no-op under EMULATOR, so
`storage_wipe()` erases nothing there and wear-levelling is untested. Either
emulate flash faithfully or state that wipe/wear is hardware-only evidence.
**R-4.2** `fsm_msgDebugLinkFlashDump()` is entirely `#ifndef EMULATOR`, so the
emulator cannot inspect flash or cross the boot boundary — which is *why* the
storage coverage gap existed. Fix the testability or accept it explicitly.
**R-4.3** The confirm-driver suite's harness race (fixed by a 200 ms drain grace
window) should be replaced by a deterministic handshake.
**R-4.4** The token table (`solana-schemas-local.json` and the compiled-in
ethereum/uniswap tables) should retire in favour of provider-signed schemas —
see `docs/security/token-table-retirement.md`.

---

## 4. Verification

**V-1** 7.15's additive invariant (atlas F) SHALL still pass, unchanged. It must
survive every gate; if it ever needs editing, the change is wrong.
**V-2** Rotation and revocation exercised end-to-end on hardware.
**V-3** Attested-context rendering distinguishable from derived fact in
screenshot evidence, judged by someone who did not write it.

---

## 5. Sequencing note

7.15 → 7.16 → 7.17 is **description → authority → resilience**. Each gate is
independently shippable and independently revertible. If 7.16's custody
programme is not ready, 7.15 ships and keeps shipping: additive clear-signing
has a bounded blast radius by construction and does not decay while it waits.
