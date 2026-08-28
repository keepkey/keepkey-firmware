# Dice Entropy

On-device dice rolls, folded into the seed at creation time. Available from
firmware v7.14.3 (bitcoin-only line) and v7.15.0 (`ResetDevice.dice_entropy`).

One difference from 7.15 in this line: the legacy `display_random` entropy
screen still exists here, because already-shipped 7.14 hosts request it. The
two are mutually exclusive — `ResetDevice` with both `display_random` and
`dice_entropy` set is refused with a SyntaxError, since the screen shows the
POST-mix internal entropy and honoring both would hand a host the seed
pre-image and make the dice fold-in worthless.

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

This is deliberate. An earlier revision displayed the mixed internal entropy and
described it as a verifiable commitment; that was strictly worse. A host that
supplies `ext_entropy` and reads that screen once computes
`SHA256(shown || ext_entropy)` — the seed pre-image. Dice change nothing about
that attack, because the displayed value is already post-mix. Unverifiable
mixing beats a verifiable seed pre-image. See the comment above the
`dice_entropy` block in `reset.c:reset_init()`.

The roll digest is safe by contrast because it hashes the user's own input, not
seed material.

## Why there is no tool for this

There cannot be a host-side verifier for the mixing step, and adding one would
be a security regression rather than a feature.

Any such tool would need the device to disclose seed-derived material for the
host to check against — which is the exact disclosure the design refuses. A
verifier that instead reports "the device says it mixed" proves nothing: it
relays a claim from the component whose honesty is in question. Worse, it
manufactures false assurance, and a user who trusts a green checkmark is in a
worse position than one who knows the mix is unverified.

So the assurance chain is not a tool. It is:

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
