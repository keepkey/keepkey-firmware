# Dice Entropy

On-device dice rolls, folded into the seed at creation time. Available from
firmware v7.14.3 (bitcoin-only line) and v7.15.0 (`ResetDevice.dice_entropy`).

## What happens

`reset.c:reset_init()`, when `dice_entropy` is set:

1. `dice_input_collect()` gathers rolls on the device's own button — short press
   selects 1-6, long press commits. 50 rolls for a 12-word seed, 75 for 18, 99
   for 24 (`dice_rolls_for_strength`). Rolls are stored as ASCII `'1'`-`'6'`,
   one byte each.
2. `dice_digest = SHA256(rolls)`. The first 8 bytes are shown on the OLED as 16
   hex characters, with the roll count, on a confirm screen.
3. `dice_mix(int_entropy, rolls, count)` replaces the internal entropy with
   `SHA256(int_entropy || rolls)` (`dice_input.c:138`).
4. Only then does the device send `EntropyRequest`, so the host's contribution
   arrives strictly after the device has committed to its own.

Cancelling at any point aborts the reset and zeroes the buffers. Nothing is
stored.

## What the digest proves

The digest is over the rolls, and nothing else. A user who wrote their rolls
down can recompute it:

```
printf '536142...' | shasum -a 256    # first 16 hex chars == displayed digest
```

A match proves the device recorded exactly that sequence, in that order, with
none dropped or substituted. That is the whole purpose of the digest, and it is
worth doing — it catches a device that quietly ignores button presses.

## What the digest does not prove

It does not prove the rolls reached the seed. `dice_mix()` is a separate step,
and neither `int_entropy` nor the mixed result is ever displayed. Firmware that
showed a correct digest and then skipped the mix would look identical from the
outside.

The seed is

```
seed = SHA256( SHA256(int_entropy || rolls) || ext_entropy )
```

Of those three inputs the user holds exactly one. `int_entropy` is the device
RNG draw and `ext_entropy` is supplied by the host, so there is no computation
the user can perform that confirms their rolls are in the result.

An earlier revision displayed `int_entropy` and described it as a verifiable
commitment. That was strictly worse, and not for the reason the old text here
gave: the screen was drawn *before* `EntropyRequest`, so it disclosed the exact
32 bytes whose complement the host itself chooses. Anyone who read the OLED and
knew `ext_entropy` computed the seed pre-image directly. (The old claim that the
displayed value was "post-mix" was wrong on every reachable path — dice and
`display_random` were mutually exclusive, so the value shown was the raw RNG
draw.) Trezor, whose `ResetDevice` this inherits, removed the identical feature
for the identical reason in PR #4119.

The roll digest is safe by contrast because it hashes the user's own input, not
seed material.

## How ColdCard does it, and what we owe them

ColdCard reaches a stronger position, and the difference is not the display —
it is *what the complement is*.

- ColdCard's USB protocol has **no seed-creation or entropy command at all**.
  The host cannot contribute entropy, so the complement of anything shown is
  dice the user holds and never transmits.
- Since 5.6.1 / 1.5.1Q user-supplied entropy is **mandatory** on every new
  seed; the user may choose 50 d6 rolls, 128 coin flips, or 65 timed key presses.
- The device shows the **full 32-byte** SHA-256 digest live while rolling, not a
  truncation.
- **Dice-Rolls-Only** mode derives `seed = SHA256(rolls)` and nothing else, so a
  user recomputes the whole wallet offline with a few lines of Python.
- Coinkite publishes a public-domain offline verifier for the mixed mode too,
  which works because they disclose the device's pre-mix TRNG value as 24
  BIP-39 words (`View TRNG Words`, 5.6.2 / 1.5.2Q).

That last point is the one to be careful with: ColdCard *does* display device
entropy. It is safe there precisely because no host holds the other half. Our
display was unsafe for the mirror-image reason. The rule is about the
complement, not about the act of showing.

Against that, our gap is specific and worth stating plainly: **a KeepKey user
cannot today prove their dice reached the seed.** They can prove the rolls were
captured, which is worth something and catches a device that drops presses. They
cannot prove the rolls were used.

## Closing the gap

Verifiability requires the user to know every derivation input, either from
their own choices or a safe disclosure. With KeepKey's host-supplied entropy
protocol, the practical path is a dice-only mode in which `seed = SHA256(rolls)`,
with the device RNG and the host's `ext_entropy` excluded from the derivation
rather than mixed in, and the full digest shown so the commitment is 256 bits
rather than 64. That mirrors ColdCard's Dice-Rolls-Only. ColdCard also verifies its mixed mode
by safely disclosing its device input; KeepKey cannot copy that disclosure
while a host supplies the other input.

It carries a real cost, which is why it must be an explicit advanced choice and
never a default: it stakes the wallet entirely on the quality and privacy of the
user's dice. A biased die, a short sequence, or a photographed roll sheet is the
whole seed. KeepKey's current mixed mode is safer for almost everyone but cannot be
independently verified; dice-only is verifiable and less forgiving. Both are defensible; silently
shipping the second as the default would not be.

## Why the current mode has no verifier

There is no host-side verifier for the mixing step as it stands, and adding one
would be a security regression rather than a feature.

Any such tool would need the device to disclose seed-derived material for the
host to check against — the exact disclosure removed above. A verifier that
instead reports "the device says it mixed" proves nothing: it relays a claim
from the component whose honesty is in question, and manufactures false
assurance. A user who trusts a green checkmark is worse off than one who knows
the mix is unverified.

Note the scope of that argument. It says the *mixed* derivation cannot be
verified without an unsafe disclosure. It does not say verification is
impossible — a derivation with no device-held or host-held inputs is verifiable
with no disclosure at all, which is what the dice-only mode above is for.

For the mixed mode the assurance chain is not a tool. It is:

1. **The digest** proves your rolls were captured.
2. **The published source** proves what the firmware does with them.
3. **The firmware hash** proves the binary you are running is that source.

Step 2 is the one that carries the weight, and it is not delegable — the user
verifies the code, or nobody does. Step 3 is what `Features.firmware_hash` and
the vault's `firmwareVerified` field exist for; unreleased RC builds report
`false` because their hashes are not in the shipped table.

## Scope

Dice cannot make the seed worse: the mix is a hash over both sources, so the
result is at least as unpredictable as the RNG alone. They are worth the effort
only if the RNG is what you distrust — and you are trusting the same firmware
either way.
