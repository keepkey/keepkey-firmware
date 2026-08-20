# T1 — setup ceremony staged as a transaction (#429)

Device: 7.14.2, fw_hash fd7b3901…, variant KeepKey, device_id 39353036114736342A004600.
Vehicle: `ResetDevice` with an injected `RecoveryDevice`, per plan §2 T1.

## VERDICT: PASS

### Phase A — injection refused, nothing committed

| step | response |
|---|---|
| inject `RecoveryDevice` (label `pwned`, pin off, passphrase off) | `Failure code=1 'Device is in the middle of setup. Send Initialize or Cancel first.'` |
| `Cancel` | `Failure code=4 'Aborted'` |
| `EntropyAck` — **the exploit step** | `Failure code=1 'Not in Reset mode'` |
| end state | `initialized=False pin_protection=False passphrase_protection=False label=''` |

Tester confirmed: photos 3 and 4 were the plain home logo, no `RECOVERY` cipher
screen at any point, and **no hold was demanded anywhere after the two PIN
screens**.

This is the core of #429. On base `1af2ffe7de` the reset was still armed at the
`EntropyAck`, so it was consumed and committed a seed with the user's PIN and
passphrase silently stripped. `CHECK_NO_CEREMONY` (`fsm.c:118-125`) now refuses
before `recovery_cipher_init()` can write anything, and no screen is drawn — the
refusal is invisible to the user because nothing was ever staged.

Note the label: `''`, not `pwned`. The injected settings left no residue.

### Phase B — ceremony completes with the user's own settings

| step | response |
|---|---|
| inject `RecoveryDevice` again | `Failure code=1` |
| `EntropyAck`, ceremony proceeds | seed backup screens, holds taken |
| end state | `initialized=True pin_protection=True passphrase_protection=True label='ceremony-B'` |

## Photo 11 — resolved, was NOT a failure

During the run that set the PIN, `Ping(pin_protection=True)` returned `Success`
with **no** `PinMatrixRequest`. The plan lists that as a hard fail.

It is not, in this context. `Pin Caching` is an enabled policy and the PIN had
just been entered during the ceremony, so the session legitimately held it. On a
fresh session after a replug:

    initialized=True pin_protection=True passphrase_protection=True label='ceremony-B'
    -> PinMatrixRequest

**The plan's criterion needs qualifying:** `Ping(pin_protection=True)` returning
`Success` with no matrix is a hard fail only on a session that has not already
authenticated. Re-testing it inside the setup session tests the cache, not the gate.

## Method note

The photo-11 check in `gh429_setup_ceremony.py` printed PASS when the matrix never
appeared, because the assertion lived inside the `if PinMatrixRequest:` branch —
a check that cannot fail is not a check. Same shape as the T5 error. Verified
separately in `t1_pin_gate_check.py`, which asserts on the branch actually taken.

## Device left as

Initialised, random seed, PIN `789456`, passphrase ON, label `ceremony-B`.
T2 wipes this and loads `mnemonic12`.
