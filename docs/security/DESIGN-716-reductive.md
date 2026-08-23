# 7.16 — the reductive path

Design note. Companion to `SRS-7.16.md`; this is the *how*, kept short
deliberately because the change itself is small.

---

## 1. What "reductive" means, exactly

7.15 is **additive**: a provider adds screens and the baseline raw review still
runs. 7.16 introduces the only case where a screen may be **removed** — a
describer KeepKey itself vouches for.

The whole difference is one branch that is already in the tree:

```c
/* lib/firmware/ethereum.c */
if (signed_metadata_from_loaded_signer()) {
    needs_confirm = true;  data_needs_confirm = true;   /* 7.15: additive */
} else {
    needs_confirm = signed_metadata_schema_moves_value();
    data_needs_confirm = false;                          /* 7.16: reductive */
}
```

The else-arm is **unreachable today**: it requires a signer that is not
runtime-loaded, and `signed_metadata.c` contains no compiled-in key. So:

> **The 7.15 → 7.16 delta is not new logic. It is a key, plus the rules for
> having one.**

That is why this document is short and why the LoC estimate below is small. If
an implementation of 7.16 is large, it has misunderstood the problem.

## 2. Where the gate sits

The user-visible rule, stated once:

| | inside AdvancedMode | outside AdvancedMode |
|---|---|---|
| **no provider** | raw review | refuse |
| **runtime provider** (7.15) | decoded screens **+ raw review** | refuse |
| **KeepKey-signed provider** (7.16) | decoded screens, raw review **may be omitted** | decoded screens, raw review may be omitted |

The second column is the point of 7.16. A KeepKey-signed describer is the only
thing that may render **outside** the Advanced gate, because it is the only
thing the device can attribute to KeepKey rather than to a stranger.

A runtime provider never moves out of column one. That is a regression test,
not a hope: the 7.15 atlas section F must pass **unchanged** against 7.16
firmware.

## 3. Minimal implementation

Four changes. Nothing else should be needed.

**3.1 A root public key in flash** — one array plus a slot marked built-in, so
`metadata_pubkey_for()` returns it with `is_loaded == false`. That single flag
is what makes the else-arm reachable, and it is already the branch condition.

**3.2 Delegate certificate verification** — a delegate cert is the existing
attestation shape with one more field: the root's signature over
(provider pubkey ‖ expiry). Verified with `signed_metadata_verify_attestation()`
against the built-in key, which is already chain-agnostic and already used by
EVM and Solana. **No new crypto primitive.**

**3.3 Expiry** — the device has no clock, so expiry is enforced against a
host-supplied signed time, or not at all. **This is the open decision**
(§5). Whatever is chosen, an expired certificate must degrade to the 7.15
additive path, never to a refusal: a stale cert is a describer we no longer
trust, and an undescribed transaction is exactly what 7.15 already handles
safely.

**3.4 One screen change** — a KeepKey-signed render must be distinguishable
from a runtime one. 7.15 shows the provider alias plus "NOT verified by
KeepKey". 7.16 must not merely delete that line; see §4.

Estimated diff: **under 150 lines of C**, most of it the key blob and its
comment. If it grows past that, the design has drifted.

## 4. What the user sees, and why it is the hard part

Removing a screen is easy. Making the removal legible is not.

The failure mode to design against is a user who cannot tell the two tiers
apart, because then the weaker tier inherits the stronger tier's credibility.
The device must answer, on the glass, "who is telling me this?" — and it has
exactly three states to distinguish:

1. **Nobody.** Raw review. The device shows bytes and says it cannot interpret
   them.
2. **A stranger** (runtime provider). Decoded screens, the provider's own alias
   and fingerprint, "NOT verified by KeepKey", and the raw review still follows.
3. **KeepKey** (delegate). Decoded screens; the raw review may be omitted.

State 3 must carry a positive marker rather than the absence of state 2's
warning. **An absence is not a signal** — a user who has never seen state 2
cannot notice that something is missing from state 3.

Concretely: state 3 should say who described it (e.g. *"described by KeepKey"*),
not merely stop saying "NOT verified". That is one string and one screen, and it
is the difference between a tier system and a trap.

## 5. Open decisions — answer before building

1. **Marker wording for state 3.** Fully warning-free, or a subtler
   *"described by KeepKey, 12 Aug"*? The roadmap asks this for delegated v1 and
   never answers it; it applies here.
2. **Freshness.** No clock. Expiry-only, host-supplied signed time, or a
   monotonic counter? Expiry-only is the smallest and is probably right for
   7.16, with the rest deferred to 7.17.
3. **Revocation without a firmware update.** If the answer is "not possible",
   that must be written down with its blast radius rather than left implicit.
4. **Carried from 7.15:** disabling AdvancedMode currently makes a loaded
   signer *inert but not erased*, so re-enabling it in the same session brings
   it back. `clearsign-provider-tier.md` says identities are cleared. Either
   erase on disable — which is what the document already promises — or correct
   the document. Measured behaviour is recorded in atlas section I6.

## 6. Custody — the reason this is its own release

In 7.15 a compromised provider can **mislabel** a transaction but cannot
**conceal** it: the raw review always follows and trust dies at reboot. That
bound is structural, which is why 7.15 needs no custody programme.

Suppression removes the bound. A compromised delegate key can then hide
transaction bytes. So the key and the rules for holding it are not adjacent
work to 7.16 — **they are 7.16**, and the code above is the small part.

Requirements are in `SRS-7.16.md` §3.1: root private key offline and
self-hosted, provisioning per the recorded runbook, and **never provisioned
while a hidden wallet is active** — the attestor key derives from the active
seed/passphrase session, so a hidden wallet yields a different identity
silently.

## 7. How 7.16 is verified

- **section F unchanged.** The 7.15 additive invariant must still pass, proving
  runtime providers were not promoted by accident. This is the single most
  important regression in the release.
- **Both tiers captured side by side** in the report, so a human can see the
  difference the design claims to make.
- **An expired or revoked certificate falls back to additive**, proven by
  screen capture, not by a wire assertion.
