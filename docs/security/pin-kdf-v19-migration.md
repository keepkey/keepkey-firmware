# PIN KDF v19 migration

Status: draft implementation for review and hardware benchmarking

Baseline: `BitHighlander/keepkey-firmware` `develop` at
`21d6a9d100b16566a1e48899abbbb7bab9366187`

## Security goal

Storage v16 reduced the production PBKDF2 work factor used to wrap the storage
key from 100,000 iterations to 10. A flash image therefore leaves a short PIN
with almost no cryptographic work factor if readout protection is bypassed.

Storage v19 restores the production PIN work factor to 100,000 iterations. The
emulator and debug configurations use 1,000 iterations so the unit suite stays
practical. The change only covers the user PIN wrapping key; wipe-code and
authdata derivation remain on their existing parameters and need separate,
versioned migrations.

## Compatibility invariant

Existing wallets must always be unwrapped with the parameters that originally
wrapped them. The firmware must not rewrite a wallet until a correct PIN has
successfully authenticated the decrypted storage key.

V19 therefore adds an explicit `pin_kdf_v2` storage flag instead of changing
the meaning of the existing v15/v16 flag:

| Persistent state | KDF used to verify PIN | Action after correct PIN |
| --- | --- | --- |
| `pin_kdf_v2` | v19 | none |
| v16 transition flag only | v16 | rewrap with v19 and set `pin_kdf_v2` |
| neither flag | v15 | rewrap with v19 and set both transition flags |

An incorrect PIN never changes the wrapped key or migration flags. New PINs
are wrapped directly with the v19 parameters.

The v19 flag occupies bit 20 of the existing public-storage flags word. The
serialized byte length is unchanged. A v18 reader deliberately ignores this
bit; a v19 reader restores it.

## Release ordering

Do not ship this migration in a production release until the downgrade policy
is enforced. Older firmware does not understand storage version 19 or its KDF
flag. Allowing a device to boot an older signed image after migration risks a
wallet lockout, destructive recovery behavior, or accidental reinterpretation
of the storage record.

The intended order is:

1. Agree on and implement the anti-rollback security-epoch design in the
   bootloader.
2. Prove the bootloader update and interruption behavior on real devices.
3. Benchmark the 100,000-iteration PIN path on supported KeepKey hardware.
4. Exercise v15, v16, and v18 migrations through wrong PIN, correct PIN,
   interrupted commit, reboot, and recovery flows.
5. Enable v19 only in a release whose minimum security epoch rejects firmware
   that cannot read it.

## Required evidence

- Unit tests prove the production v16-to-v19 rewrap path and the v19 selector.
- A negative control that disables rewrapping makes the regression test fail.
- A wrong PIN leaves the wrapped key and all migration flags unchanged.
- V19 round-trips the new flag; the V18 reader ignores it.
- Full emulator unit suites pass from a clean build.
- Hardware timing includes minimum, median, and maximum unlock latency across
  supported board revisions and temperature/power conditions.
- Power-loss testing covers every write boundary during the rewrap commit.
- Downgrade attempts after migration fail closed without modifying storage.

## Non-goals

This change does not make short PINs equivalent to high-entropy secrets, add a
secure element, or prevent offline guessing after arbitrary flash extraction.
It restores a material software work factor while the hardware architecture
continues to rely on STM32 readout protection and write protection.
