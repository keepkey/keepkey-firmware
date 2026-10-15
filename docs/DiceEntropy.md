# Dice entropy: release-specific behavior

The 7.15 implementation in this branch differs from 7.14.3. In particular,
**the full dice digest is secret in 7.15: in dice-only mode it is the wallet's
BIP-39 entropy before truncation to the selected strength.** Do not publish the
roll sheet, digest, device entropy words, or final mnemonic.

## Setup and retry order

With PIN protection requested, both new-PIN entries must match before the dice
ceremony begins. The PIN stays staged until setup completes. A mismatch aborts
before dice; cancelling the ceremony clears staged settings, PIN, entropy,
digest and secret display state. Retrying starts a new ceremony.

The host selects `ResetDevice.dice_entropy`; `dice_only` additionally selects
rolls alone and requires `dice_entropy`. The device explicitly identifies the
selected mode for consent. Dice setup rejects `no_backup`.

## 7.15 derivation

Rolls are entered on the device button, using short presses to select a value
and a hold to commit it. There are 50 rolls for 12 words, 75 for 18, and 99 for
24. The hash input is the ASCII sequence of digits `1` through `6`, with no
spaces or newline. The firmware rejects unsupported counts or invalid digits,
and rejects any face occurring at least 25/50, 32/75 or 39/99 times. This check
catches gross repetition; it does not establish that the rolls are random.

For **Dice Only**:

```text
derived_entropy = SHA256(rolls)
```

For **Dice + Device**:

```text
user_entropy    = SHA256(bytes(4b 4b 01 44) || rolls)
derived_entropy = SHA256(SHA256(bytes(4b 4b 01 53 4d) || device_draw || user_entropy))
```

`device_draw` is exactly 32 bytes. The mixed ceremony shows it as 24 BIP-39
entropy words before dice collection. Those words encode the device input;
they are **not the final wallet backup**. The two tags above are literal bytes
(`KK`, byte `01`, then `D` or `SM`), with no trailing NUL.

Both modes show the complete `SHA256(rolls)` digest after collection and before
committing setup. BIP-39 encoding uses the first 16, 24 or 32 bytes of
`derived_entropy` for 12, 18 or 24 words respectively, with the normal BIP-39
checksum. This is mnemonic entropy, not the later BIP-39 passphrase-derived
512-bit seed.

The device still sends `EntropyRequest` and waits for `EntropyAck` to continue
the reset protocol, but **host entropy bytes are ignored in both dice modes**.
There is no additional host mixing or rehash at that step. Without dice,
normal setup retains `SHA256(device_draw || host_entropy)`.

Implementation: [reset.c](../lib/firmware/reset.c) (`reset_init`,
`reset_entropy`) and [dice_input.c](../lib/firmware/dice_input.c)
(`dice_derive_only`, `dice_derive_mixed`, `dice_rolls_look_biased`).

## What an offline check establishes

A digest match checks the recorded ASCII roll sequence. For dice-only, that
same digest also provides all mnemonic entropy. For mixed mode, the roll
sequence plus the decoded device entropy words provide every derivation input.
An independent offline computation can therefore compare the resulting
mnemonic with the final device backup. A digest match alone does not check the
mixed derivation.

This firmware repository does not include a standalone end-user verifier.
Native derivation vectors are in [dice.cpp](../unittests/firmware/dice.cpp).
Keep real ceremony inputs offline; a host or website given all inputs can
reconstruct the wallet. Neither a digest match nor a health-test pass proves
that firmware is trustworthy or that either entropy source is unpredictable.

Dice-only relies entirely on the quality and secrecy of the rolls. Mixed mode
adds the device draw, but independent checking still requires the private
inputs and an independently trusted computation.

## 7.14.3 distinction

7.14.3 supports mixed dice input with this derivation:

```text
derived_entropy = SHA256(SHA256(device_draw || rolls) || host_entropy)
```

It displays only the first eight bytes of `SHA256(rolls)` and does not disclose
the device draw. That receipt checks roll capture; it does not give the user
all inputs needed to recompute the final mnemonic. The 7.15 formulas, full
digest and dice-only option above must not be attributed to 7.14.3.

## Hardware RNG sampling before setup

On an uninitialized device without a storage compatibility lock, an approval
permits up to 8 MiB of consecutive `GetEntropy` output. The returned byte count
is charged. `GetFeatures` may interleave; other top-level operations, including
U2F PING/INIT, Initialize, Cancel, ClearSession and ResetDevice, revoke the
approved grant. Workflow abort, idle lock and reboot also revoke it. A zero-byte
request cannot open a grant. Initialized or compatibility-locked devices retain
per-request confirmation; an armed reset or recovery refuses sampling.

7.15 additionally has an initial 64 KiB allowance without approval, charged by
returned bytes. Initialize and session changes do not replenish it; a confirmed
factory wipe resets it, and a reboot starts a new in-memory allowance. The
8 MiB approval applies once that allowance is exhausted. 7.14.3 does not have
this initial allowance.

A host must handle short chunks, cancellation and incomplete audits. Sampling
can detect some broken RNG output; it does not measure secret entropy or prove
unpredictability. Dice entry is a separate physical operation after sampling.
