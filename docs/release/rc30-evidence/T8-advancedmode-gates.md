# T8 — the four AdvancedMode refusal paths (#404, #405, #433, typed-hash gate)

Device: 7.14.2, variant KeepKey, mnemonic12, no PIN, no passphrase.

## VERDICT: legs A+B PASS (9/9). Leg C is diagnostic and produced a FINDING.

### Leg A — AdvancedMode OFF: four refusals, two silent by design

| gate | commit | result | screen? |
|---|---|---|---|
| TON SignTx | `efa18ad77` | `Failure 'Transaction signing disabled by policy'` | BLOCKED |
| ETH arbitrary call data | `30fbf9473` | `Failure 'Arbitrary contract data signing disabled by policy'` | BLOCKED |
| TRON SignTx | `b53b63b0a` | `Failure 'Enable AdvancedMode to blind-sign'` | **silent** |
| EthereumSignTypedHash | `424294ccc` | `Failure 'Enable AdvancedMode to blind-sign typed hashes'` | **silent** |
| negative control: `personal_sign` | — | **signed** | SIGN ETHEREUM MESSAGE |

The asymmetry is the point and it held exactly. #433 is the one with a real
signing regression behind it: before, the code called `(void)review(…, "Warning",
…)` and DISCARDED the return, falling straight through to the data screen, the
fee screen, and a signature.

The negative control matters as much as the refusals: a `BLOCKED` there would
mean `424294ccc`'s removal of the #432 SignMessage gates did not land, and every
Sign-In-With-Ethereum flow would be broken by default.

ETH step passed `chain_id=1` explicitly. The suite's own
`test_ethereum_blind_sign_blocked` no longer exercises this gate — it omits
`chain_id`, so T7's guard rejects it first.

### Leg B — AdvancedMode ON: all four sign

TON, ETH arbitrary data, TRON, and typed hash all signed. 4/4.

## FINDING — AdvancedMode PERSISTS across a power cycle

    AdvancedMode after physical replug: True

Two independent lines agree:
- **Code:** `storage_commit` at `fsm_msg_common.h:738`; bit 12 at
  `storage.c:803/920`, read back at `:862/:990`. That is flash, not session.
- **Measurement:** still `True` after unplug/replug.

The outlier is the commit messages. **Both `efa18ad77` and `b53b63b0a` state
"AdvancedMode is session state (it is off again after a power cycle)" and build
their risk analysis on it.** That reasoning is wrong on this build: once a user
enables AdvancedMode, blind-signing stays enabled until they explicitly disable
it. The blast radius is "until revoked", not "until unplugged".

**Release-note correction, not a test failure.**

⚠️ A note from the rc29 round (7.15 line) claims AdvancedMode was proven to be
session state, off after a power cycle. Either the behaviour differs between
branches or one measurement is wrong. Today's result is for 7.14.2 and is backed
by the code; **the 7.15 claim needs re-checking on its own branch before it is
relied on again.**

## Harness bugs found (would silently break other tests)

1. **`client.tron_sign_tx()` is broken in the pinned python-keepkey.** It passes
   `raw_tx=`, but `TronSignTx`'s field is `raw_data`. The call dies in protobuf
   before anything reaches the device — a test using it never tests anything.
   Build `TronSignTx(address_n=…, raw_data=…)` directly.
2. **TON requires a fully-hardened path** (ed25519). `m/44'/607'/0'/0/0` fails
   with `Failed to derive private key`; `m/44'/607'/0'/0'/0'` works. Leg A's TON
   refusal was unaffected because the policy check runs BEFORE derivation.

## Device left as

mnemonic12, no PIN, no passphrase, **AdvancedMode OFF** (verified, not assumed).
