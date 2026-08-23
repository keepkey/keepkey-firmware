# Defect Register — alpha integration, 2026-08-20/21

Every defect found while closing the alpha ← develop merge. Each entry states
what a user would have experienced, how it was found, and where it was fixed.

Written to IEEE 830 §3 conventions: each defect carries an identifier, a
verifiable statement, and its evidence.

---

## Summary

| ID | Defect | Severity | Shipped? | Status |
|---|---|---|---|---|
| D-01 | OP_RETURN poisons the duplicate-transaction detector | High | **Yes, today** | Fixed, #495 |
| D-02 | Storage magic stamped after serialising | High | **Yes, today** | Fixed, #496 |
| D-03 | Uniswap liquidity unsignable to a third party | High | Yes, alpha | Fixed, #495 |
| D-04 | Recovery accepts a non-BIP-39 word | High | alpha merge | Fixed, #497 |
| D-05 | Full ARM build over the SRAM budget | Blocker | Not shipped | Fixed, #497 |
| D-06 | Ripple address buffer contract violation | Medium | **Yes, today** | Fixed, #497 |
| D-07 | Bitcoin-only variant reports as full-feature | Medium | Yes, alpha | Fixed, #495 |
| D-08 | `secret-scan` config error skipped the whole build graph | High (process) | n/a | Fixed |
| D-09 | 12 files lost alpha's work in the merge | High | Not shipped | Fixed |
| D-10 | Solana ALT accounts undisplayable | Gap | Yes | **Open — 7.15 scope** |

---

## D-01 — An OP_RETURN output poisons the duplicate-transaction detector

**What the user sees.** They perform a THORChain or Maya swap from Bitcoin.
The next ordinary Bitcoin send is refused with:

```
WARNING: Duplicate Transaction!
Already signed a tx with the same outputs
To try again, unplug/replug KeepKey.
```

The transaction is not a duplicate. The device must be physically replugged.

**Why.** `signing.c` calls `txin_dgst_final()` once per output. The only thing
that re-initialises the SHA-256 context is `txin_dgst_save_and_reset()`, which
`compile_output()` reaches only on the pay-to-address path — the OP_RETURN
branch returns ~200 lines earlier. The context stays finalised, the next
transaction's inputs hash into it, its digest no longer matches while amount and
address still do, and that is precisely the *(same outputs, different inputs)*
shape the anti-malware check exists to flag.

**Reach.** Every THORChain/Maya swap from Bitcoin is an OP_RETURN memo. Affects
BOTH products — `compile_output()` carries no `BITCOIN_ONLY` guard here.

**Fix.** `txin_dgst_reset_only()` re-arms the hash without recording a
comparison key. Reset-only is the point: an OP_RETURN has no amount/address
worth saving, and `save_and_reset()` would write junk into the comparison keys
and could manufacture a *false* duplicate later.

**Open sub-item.** A negative control for the check's *true-positive* case
(same outputs, different inputs) does NOT fire — on fixed or pre-fix firmware.
The detector demonstrably fires (D-01 is that), but no case was constructed
where it fires correctly. Not widened on a hunch. **Tracked separately.**

---

## D-02 — Storage magic stamped after serialising

**What the user sees.** On real hardware, nothing — which is why it survived.
`device_id` comes from `desig_get_unique_id()`, not from storage, so the visible
symptom is masked on the only platform anyone runs.

**What actually happens.** `storage_commit()` set the magic in `shadow_config`
*after* `storage_writeV17()` had already copied `shadow_config.meta` into the
buffer being written. The record committed to flash carried zeroes where the
magic belongs, so `find_active_storage()` did not recognise the sector just
committed. Every boot re-ran `storage_resetUuid()` + `storage_commit()` until
the first storage-changing operation happened to write it correctly:

- a redundant flash **erase+write on every boot** (wear), and
- a window in which **no sector is valid** (power-loss exposure).

**Evidence.** Emulator, same flash image, three cold boots:

| | boot 1 | boot 2 | boot 3 |
|---|---|---|---|
| pre-fix | `44916D25…` | `9E1B54C6…` | `5BF1FD3D…` |
| post-fix | `4E70FF58…` | `4E70FF58…` | `4E70FF58…` |

**Age.** Present on upstream 7.14.1, the 7.14.2 line, and alpha. Long-standing.

---

## D-03 — Uniswap liquidity unsignable to a third party

**What the user sees.** They withdraw a Uniswap pool position to another
address. The device shows:

```
Uniswap Recipient
NOT this wallet
0x5028d647b74f12903e6d5f3969f8f624e6a9a93d
```

They approve. The device answers **"Signing cancelled by user"** — for a
transaction they just confirmed.

**Why.** `confirmFromAccountMatch()` ended in `return is_self`, so it refused
*after* the user approved. `ethereum.c` turns that false into ActionCancelled.

**Why it hid.** The three Uniswap liquidity tests are skipped whenever
`firmware_variant` starts with `"Emulator"` — and the emulator is the only thing
CI runs. **They had never executed in CI on any branch.** The skip comment
claimed "Pre-existing, unrelated to clear-signing" and "on-device this path is
exercised by the app". Both wrong.

**Fix.** Return whether the USER approved. The screen names the case and shows
the full address; withholding the signature is not what makes it safe, showing
the address is. The refusal path is unchanged.

---

## D-04 — Recovery accepts a word that is not in the BIP-39 wordlist

**What the user sees.** Cipher recovery accepts a mistyped word, continues, and
in the default (host-omitted `enforce_wordlist`) path **stores the resulting
phrase as the seed and reports success.**

**Why.** develop refuses on `!auto_completed && !enforce_wordlist`, which lets a
non-completing word through whenever the host DID set `enforce_wordlist`. alpha
refused on `!auto_completed` outright. The merge took develop's file.

---

## D-05 — Full ARM build over the SRAM budget

**Symptom.** `ld: Insufficient runtime SRAM: require 16 KiB stack/heap reserve
between _ebss and _stack`. The full product would not link.

**Measured** (local `arm-none-eabi` cross build):

| tree | reserve | |
|---|---|---|
| pre-merge alpha | 18,784 B | PASS |
| merged alpha | 14,148 B | **FAIL** (short 2,236) |
| fixed | 18,172 B | PASS |

**Cause.** 4,098 of the 4,439-byte regression in ONE symbol: `permute.8`, the
recovery-cipher wordlist permutation. alpha allocated it from the shared frame
arena via `frame_arena_scratch2049()`; develop used a private
`static uint16_t[2049]`. The merge took develop's. The arena slot exists
precisely for this — `messages.c` documents it as *"scratch2049 for the
recovery-cipher wordlist permutation"* — and its accessor was compiled in and
unused.

---

## D-06 — Ripple address buffer contract violation

`fsm_msg_ripple.h` passed `resp->address` (proto `max_size:36`) to
`ripple_getAddress()`, which hands `ripple_encode_check()` a `MAX_ADDR_SIZE`
(130 byte) destination. It does not overflow today only because a Ripple address
encodes to ~35 characters — a **one-byte margin held by a property of the input,
not by the contract**. gcc 14 rejects it (`-Werror=stringop-overflow`); gcc 10,
which CI uses, does not. Pre-existing on alpha.

---

## D-07 — The bitcoin-only variant reports as full-feature

`variant_getName()` returned `"Emulator"` for any emulator build, ignoring
`BITCOIN_ONLY`. `requires_fullFeature()` skips on `"EmulatorBTC"`, so it **never
skipped anything** and every multi-chain test ran against a device with those
chains compiled out. This is why the bitcoin-only product had no meaningful pyk
coverage.

---

## D-08 — A stage-1 gate failure silently skipped the entire build graph

`.gitleaks.toml` ended up with BOTH allowlist forms (alpha's three
`[[allowlists]]`, develop's one `[allowlist]`); gitleaks refuses that
combination at config load. `secret-scan` is a stage-1 gate, so build-emulator,
build-arm-firmware, unit-tests, python-integration-tests, python-dylib-tests and
generate-test-report **all reported "skipped"**. The run read as one red job
rather than a release with no evidence behind it.

The aggregate `CI gate` (fw #474) caught it and named all seven — working as
designed.

---

## D-09 — Twelve files lost alpha's work in the merge

The symbol gate reached 0 regressions while 24 of 79 contested files had been
taken byte-identical from develop. Twelve were real losses, including nine
EIP-712 type-validation helpers (`integer_type_family` overflow rejection) and
the entire Maya EVM dispatch, which had become unreachable dead code.

**Why the gate could not see it.** Both branches define the same function names,
so a wholesale file swap keeps every symbol and only weakens the bodies. A
`static` function dropped with its only callers scores as a "safe drop".

`tools/merge_direction_gate.py` now audits resolution *direction* per file, with
`tools/merge-direction-adjudicated.txt` recording every cleared flag and why.

**A third class exists and is not caught by either gate:** `recovery_cipher.c`
was *genuinely merged* — neither side verbatim — and still lost three alpha
features (D-04, D-05, and the previous-word indicator). Config files are a
fourth: `.gitleaks.toml` merged to valid TOML that the consuming tool rejects
(D-08). **A merged file needs its consuming tool run against it.**

---

## D-10 — Solana ALT accounts are undisplayable — OPEN

`solana.c:848`: `if (ix->external) continue; /* accounts not in the signed
message */`. An instruction whose accounts come from an Address Lookup Table
renders **nothing**.

`KKSOLSC1` schemas cannot fix this: they are instruction-scoped and reusable,
carrying "no amounts and no transaction hash", and the device decodes values out
of the bytes it is signing. With an ALT, the accounts are not in those bytes.

`SolanaSignTx` reserves tags 5–8 for "the transaction-bound `KKSOLSW1`
descriptor", which is **not implemented** — the reservation comment is the only
trace of it in the tree.

**This is in 7.15 scope.** See SRS-7.15 §3.4.
