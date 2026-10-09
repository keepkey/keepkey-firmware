# KeepKey dice vs ColdCard: what each one lets a user prove

Comparison as of 2026-09-09, against ColdCard Mk4/Mk5 5.6.2 and Q 1.5.2Q
(status page verified 2026-09-04) and KeepKey 7.14.3 / 7.15.

The question this answers is narrow and it is the only one that matters for an
advanced user: **can you prove to yourself that the device used your dice?**

Today, on KeepKey: **no.** On ColdCard: **yes, in both dice-only and mixed
modes.** The
gap is not the dice-entry UI, which is comparable. It is the derivation.

## Side by side

| | KeepKey 7.14.3 / 7.15 | ColdCard Mk4/Q |
| --- | --- | --- |
| Dice entered on-device | yes, single button, 7-cell 1-6+UNDO selector | yes, numeric keypad |
| Rolls ever cross a wire | no | no |
| Rolls required for a new seed | no, opt-in via `dice_entropy` | no; dice, coin flips, or timed key presses are required alternatives since 5.6.1 / 1.5.1Q |
| Roll count for 24 words | 99 | 99 |
| Roll count for 12 words | 50 | 50 |
| Bias rejection on rolls | none | rejects any face over 30% frequency |
| Digest shown while rolling | after entry, **first 8 bytes** | live, **full 32 bytes** |
| Digest is `SHA256(rolls)` | yes | yes |
| Host can contribute entropy | **yes — optional `EntropyAck.entropy`; omission contributes zero host bytes** | **no such command exists** |
| Device pre-mix entropy disclosed | no | yes, opt-in `View TRNG Words`, 24 BIP-39 words |
| Offline verifier published | no | yes, public-domain, stdlib-only |
| **User can verify the seed came from their rolls** | **no** | **yes** |

## Why ColdCard can show device entropy and we could not

This is the part that is easy to get backwards, and the reason the earlier
in-tree rationale here did not survive contact with the evidence.

ColdCard displays its own pre-mix TRNG value as 24 BIP-39 words and publishes a
verifier that recomputes the seed from it. That is safe **because the ckcc
protocol has no seed-creation or entropy command at all.** The complement of
the displayed value is dice the user holds and never transmits, so disclosure
costs nothing to anyone who is not already holding the roll sheet.

KeepKey's complement is optional `EntropyAck.entropy`, which the host may
supply; omission contributes zero host bytes. When supplied, our removed
`display_random` screen therefore disclosed the one half whose other half the
host itself chooses — and it was drawn *before* `EntropyRequest`, so a host
that observed the screen and knew its own `external_entropy` could compute the
resulting seed. Choosing an arbitrary target seed from a SHA-256 preimage is
not implied.

> The rule is about the complement, not about the act of showing.
> A value may be rendered on the OLED only if the host does not hold its
> complement.

By that same rule our roll digest is fine: it hashes the user's own input, and
dice fold in before `EntropyRequest`, so user entropy is committed before the
host contributes anything.

## The actual gap: the derivation

KeepKey today:

```
seed = SHA256( SHA256(int_entropy || rolls) || ext_entropy )
```

Three inputs. The user holds exactly one. `int_entropy` is the device RNG draw
and is never disclosed; `ext_entropy` comes from the host — and on our own stack
hdwallet generates it inside the transport with `crypto.getRandomValues` and
never surfaces it, so it is not recoverable even by a cooperating user.

So there is no computation a user can perform that confirms their rolls reached
the seed. What the digest proves is that the rolls were *captured*. Firmware
that displayed a correct digest and then ignored the rolls entirely would be
indistinguishable from outside.

ColdCard's Dice-Rolls-Only mode:

```
seed = SHA256(rolls)
```

One input, and the user holds it. They recompute the whole wallet offline and
compare the fingerprint. That is a proof without disclosing any device input. ColdCard's mixed mode
is independently verifiable too, using its disclosed TRNG input.

ColdCard's *mixed* mode is also verifiable:

```
user_entropy = SHA256(b'CC\x01' + method_id + rolls)
seed         = SHA256d(b'CC\x01SM' + method_id + base_seed + user_entropy)
```

because `base_seed` is exactly what `View TRNG Words` discloses. We cannot copy
that: our third input is host-held, so disclosing our `int_entropy` would hand
over a complete pre-image rather than completing a proof.

## Context worth knowing

In July 2026 ColdCard disclosed that a March 2021 change had routed seed
generation through MicroPython's Yasmarang PRNG for five years, reducing the
effective search space to roughly 72 bits on Mk4/Mk5/Q. The single mitigating
factor for affected users was **having rolled dice** — a user-supplied entropy
path that did not depend on the broken RNG.

That is the argument for dice-only mode in one sentence. Mixing protects you
when your dice are bad. Dice-only protects you when the *device* is bad, and
that is the failure that actually happened to a shipping vendor.

Both are defensible. They protect against opposite threats, which is why
ColdCard offers both and labels dice-only as advanced.

## What we should change

1. **Dice-only derivation**, `seed = SHA256(rolls)`, excluding both `int_entropy`
   and `ext_entropy` from the derivation. New `ResetDevice.dice_only = 11`
   (fields 1-10 are taken; `dice_entropy` is 10). Requires `dice_entropy`.
2. **Publish an offline verifier** — stdlib-only, no network, taking the roll
   string and word count and printing the mnemonic and fingerprint.
3. **Show the full 32-byte digest.** 64 bits already resists grinding, so this
   is parity rather than a fix, but it costs one line and removes an argument.
4. **Bias rejection on the roll distribution**, matching ColdCard's 30% rule.
   Cheap, and the only guard against a user whose die is visibly loaded.
5. **Never make dice-only the default.** It stakes the entire wallet on the
   user's dice and their privacy. It is the advanced option, and the warning
   screen has to say so.

Items 1 and 2 are what turn "trust us" into "check it yourself". Items 3-5 are
polish and guardrails around them.
