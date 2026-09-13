# Dice Entropy

On-device dice rolls as seed entropy, in two modes a user can verify offline.
Available from firmware v7.14.3 (bitcoin-only line) and v7.15.0
(`ResetDevice.dice_entropy`, `ResetDevice.dice_only`); a host must check
`Features.supports_dice_modes` before offering either, because older firmware
skips unknown fields silently rather than refusing them.

## What happens

`reset.c:reset_init()`, when `dice_entropy` is set:

1. A consent screen names the mode the host selected — "Dice + Device" or
   "Dice Only" — with the roll count. Holding proceeds; the only "no" is the
   host's Cancel, which aborts the reset. `no_backup` is refused with dice.
2. MIXED only: the device shows its own 32-byte RNG draw as 24 BIP-39 words,
   titled "Entropy N/M", and the consent screen has just said these are NOT a
   backup. The user copies them down. This happens before any roll is entered,
   so the draw is committed before the device has seen the rolls.
3. `dice_input_collect()` gathers rolls on the device's own button — short press
   selects 1-6, long press commits. 50 rolls for a 12-word seed, 75 for 18, 99
   for 24 (`dice_rolls_for_strength`). Rolls are stored as ASCII `'1'`-`'6'`,
   one byte each.
4. Rolls on which any face lands more than 30% of the time are refused with a
   `SyntaxError` before anything else is shown (`dice_rolls_look_biased`).
5. `dice_digest = SHA256(rolls)`. All 32 bytes are shown on the OLED as 64 hex
   characters, with the roll count, on a paged confirm screen.
6. The seed is derived per mode (`dice_derive_only` / `dice_derive_mixed`, in
   `dice_input.c`):
   - ONLY: `seed = SHA256(rolls)`
   - MIXED: `user = SHA256(TAG_USER || rolls)`;
     `seed = SHA256(SHA256(TAG_MIX || draw || user))`, where
     `TAG_USER` is the 4 bytes `4B 4B 01 44` and `TAG_MIX` the 5 bytes
     `4B 4B 01 53 4D`
7. The device sends `EntropyRequest` and consumes the host's `EntropyAck`, so
   the wire flow is unchanged, but the bytes are dropped: nothing enters the
   derivation that the user does not hold.
8. The backup words are shown and the seed is committed as usual.

Cancelling at any point aborts the reset and zeroes the buffers. Nothing is
stored.

## What the digest proves

The digest is over the rolls, and nothing else. A user who wrote their rolls
down can recompute it:

```
printf '536142...' | shasum -a 256    # all 64 hex chars == displayed digest
```

A match proves the device recorded exactly that sequence, in that order, with
none dropped or substituted. That is the whole purpose of the digest, and it is
worth doing — it catches a device that quietly ignores button presses.

## What the digest does not prove

On its own it does not prove the rolls reached the seed: a digest of the input
says nothing about what was done with it, and firmware that showed a correct
digest and then ignored the rolls would look identical from outside. That is
why the dice ceremony no longer offers an unverifiable derivation. Both modes
it offers (below) are built so the user can recompute the seed, and the digest
is the commitment that recomputation checks against.

Before this unit the dice derivation was
`SHA256(SHA256(int_entropy || rolls) || ext_entropy)` — three inputs, of which
the user held one, so no such recomputation existed.

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
- Since 5.6.1 / 1.5.1Q user entropy is **mandatory** on every new seed: 50 d6
  rolls, 128 coin flips, or 65 timed key presses.
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

## The two opt-in modes

Verifiability requires that the derivation contain nothing the user does not
hold. The host selects the mode in `ResetDevice` before the ceremony starts,
so the wallet can explain what is coming, and the device shows a consent
screen naming the mode it was asked for — holding proceeds, and the only "no"
is cancelling the reset, which is the right answer to a mode the user did not
choose. Two modes, both verifiable:

**MIXED** (`dice_entropy` alone). The device first shows its own 32-byte RNG draw
as 24 BIP-39 words, which the user copies down, and only then collects the
rolls. Because the draw is committed before the device has seen a roll, it
cannot be chosen to steer the result. Then

```
TAG_USER = 4B 4B 01 44          (the bytes 'K' 'K' 0x01 'D')
TAG_MIX  = 4B 4B 01 53 4D       (the bytes 'K' 'K' 0x01 'S' 'M')

user = SHA256(TAG_USER || rolls)
seed = SHA256(SHA256(TAG_MIX || device_draw || user))
```

The tags are written as bytes on purpose. As a C string literal,
`"KK\x01D"` is NOT those four bytes: C's `\x` escape is greedy and eats
`01D` as one hex number, giving `K K 0x1D` -- three bytes, a different
seed, and a verification that fails against an honest device. The firmware
spells them out as arrays (`dice_input.c`) for the same reason.

Showing the draw is safe here for the mirror-image reason it was unsafe under
`display_random`: the other half is dice the host never sees.

**DICE ONLY** (`dice_entropy` with `dice_only`). `seed = SHA256(rolls)`,
ColdCard's Dice-Rolls-Only byte for byte. The device draw is discarded, so the wallet rests entirely on the
quality and privacy of the rolls. A biased die, a short sequence, or a
photographed roll sheet is the whole seed. That is why it is an explicit
choice, never a default, and why the device refuses rolls where any face
exceeds 30% of the total before a digest is ever shown.

In both modes the host's `EntropyAck` is still consumed, so the wire flow and
every existing host are unchanged, but its bytes are dropped. The digest is
shown in full. `tools/verify_dice_seed.py` recomputes the wallet offline from
the roll string, plus the 24 device words for MIXED, with no secret from the
device and no network — compare its output with the backup words the device
showed, and the derivation has been checked by code the device did not write.

## Why the default, no-dice mode has no verifier

Without dice the seed is `SHA256(device_draw || ext_entropy)`. There is no
host-side verifier for that, and adding one would be a security regression
rather than a feature.

Any such tool would need the device to disclose seed-derived material for the
host to check against — the exact disclosure removed above. A verifier that
instead reports "the device says it mixed" proves nothing: it relays a claim
from the component whose honesty is in question, and manufactures false
assurance. A user who trusts a green checkmark is worse off than one who knows
the mix is unverified.

Note the scope of that argument. It says a derivation with a host-held input
cannot be verified without an unsafe disclosure. It does not say verification
is impossible — that is what the dice modes above are for: DICE ONLY has no
device- or host-held input at all, and MIXED discloses the device half only
where the other half is dice the host never sees. Host entropy stays in the
default mode because it is the one backstop against a device RNG that is
broken but honest, and it is removed exactly where it blocked verification.

For the default mode the assurance chain is not a tool. It is:

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
