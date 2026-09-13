# KeepKey dice vs ColdCard: what each one lets a user prove

Comparison as of 2026-09-09, against ColdCard Mk4/Mk5 5.6.2 and Q 1.5.2Q
(status page verified 2026-09-04) and KeepKey 7.14.3 / 7.15.

The question this answers is narrow and it is the only one that matters for an
advanced user: **can you prove to yourself that the device used your dice?**

Before the verifiable-dice unit: KeepKey **no**, ColdCard **yes**. With it:
both **yes**, in each of two opt-in modes. The gap was never the dice-entry UI,
which is comparable. It was the derivation.

## Side by side

| | KeepKey 7.14.3 / 7.15 | ColdCard Mk4/Q |
| --- | --- | --- |
| Dice entered on-device | yes, single button, 7-cell 1-6+UNDO selector | yes, numeric keypad |
| Rolls ever cross a wire | no | no |
| Rolls required for a new seed | no, opt-in via `dice_entropy` | **yes, mandatory** since 5.6.1 / 1.5.1Q |
| Roll count for 24 words | 99 | 99 |
| Roll count for 12 words | 50 | 50 |
| Bias rejection on rolls | rejects any face over 30% frequency | rejects any face over 30% frequency |
| Digest shown | after entry, **full 32 bytes** | live, **full 32 bytes** |
| Digest is `SHA256(rolls)` | yes | yes |
| Host can contribute entropy | default (no-dice) mode only; **consumed and dropped** when dice are used | **no such command exists** |
| Device pre-mix entropy disclosed | yes, MIXED dice mode, 24 BIP-39 words shown **before** rolling | yes, opt-in `View TRNG Words`, 24 BIP-39 words |
| Offline verifier published | yes, `tools/verify_dice_seed.py`, stdlib-only | yes, public-domain, stdlib-only |
| **User can verify the seed came from their rolls** | **yes**, in either opt-in dice mode | **yes** |

## Why ColdCard can show device entropy and we could not

This is the part that is easy to get backwards, and the reason the earlier
in-tree rationale here did not survive contact with the evidence.

ColdCard displays its own pre-mix TRNG value as 24 BIP-39 words and publishes a
verifier that recomputes the seed from it. That is safe **because the ckcc
protocol has no seed-creation or entropy command at all.** The complement of
the displayed value is dice the user holds and never transmits, so disclosure
costs nothing to anyone who is not already holding the roll sheet.

KeepKey's complement is `ResetDevice.external_entropy`, which the host supplies
on every reset. Our removed `display_random` screen therefore disclosed the one
half whose other half the host itself chooses — and it was drawn *before*
`EntropyRequest`, so a host could read it and then pick `external_entropy` to
land on any seed it wanted.

> The rule is about the complement, not about the act of showing.
> A value may be rendered on the OLED only if the host does not hold its
> complement.

By that same rule our roll digest is fine: it hashes the user's own input, and
dice fold in before `EntropyRequest`, so user entropy is committed before the
host contributes anything.

## The gap this unit closes: the derivation

KeepKey's dice ceremony before this unit:

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
compare the fingerprint. That is a proof, and it is the only shape that yields
one.

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

## What changed

The host selects the mode before the ceremony starts — `dice_entropy` alone
is MIXED, `dice_entropy` with `dice_only` is DICE ONLY — so a wallet can
explain what is coming: 99 rolls, and for MIXED 24 words to copy down. The
device then shows a consent screen naming the mode it was asked for; holding
proceeds and the only "no" is cancelling the reset, which on a one-button
device is exactly the right answer to a mode the user did not choose. A host
cannot select dice-only silently.

**MIXED** (`dice_entropy` without `dice_only`):

```
user = SHA256("KK\x01D" || rolls)
seed = SHA256(SHA256("KK\x01SM" || device_draw || user))
```

The device shows its 32-byte draw as 24 BIP-39 words *before* the rolls are
entered, so it is committed before the device has seen them and cannot be
chosen to steer the result. Showing it is safe here for exactly the reason it
was unsafe under `display_random`: the other half is dice the host never sees.

**DICE ONLY**:

```
seed = SHA256(rolls)
```

Byte-identical to ColdCard's Dice-Rolls-Only. The device draw is discarded.

In both modes the host's `EntropyAck` is consumed and its bytes dropped, so
the wire flow and every existing host are unchanged; the full 32-byte digest
is shown; rolls with any face over 30% are refused before a digest is ever
drawn; and `tools/verify_dice_seed.py` recomputes the wallet offline from the
roll string (plus the 24 device words, for MIXED) with no secret from the
device and no network.

The default, no-dice reset is untouched: `SHA256(device_draw || host_entropy)`.
Host entropy stays there because it is the only backstop against a device RNG
that is broken but honest — ColdCard's July 2026 failure, which no on-device
health test catches — and it costs nothing there, since that path was never
verifiable anyway. It is removed exactly where it blocked verification.

What is still unmatched is hardware: no secure element, so the device draw is
weaker than ColdCard's three-source mix; one button, so 99 rolls is slower;
a smaller screen, so words and the digest page.
