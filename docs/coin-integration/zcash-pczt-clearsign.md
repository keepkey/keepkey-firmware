# Zcash PCZT Clear Signing

**Status:** implemented on `feature/clearsign-txs`.
**Base:** `release/7.15.0`.
**Scope:** Orchard PCZT signing.

## Threat Model

The firmware must not sign a host-provided Orchard sighash by itself. If the
companion app can choose the sighash directly, a compromised companion can turn
the hardware wallet into a blank-check signer: the user confirms one summary,
but the signature authorizes a different transaction digest.

The firmware therefore has to build the signing digest from transaction data it
can validate. The current PCZT protocol does this in layers:

1. The host sends ZIP-244 component digests and Orchard bundle metadata.
2. The device assembles the final ZIP-244 sighash from those component digests.
3. The device recomputes the Orchard digest from streamed action fields.
4. Signatures are returned only after the recomputed Orchard digest matches the
   Orchard digest used in the device-computed sighash.

## Firmware Policy

`ZcashSignPCZT` is rejected before user confirmation unless it includes:

- `header_digest`, exactly 32 bytes.
- Plaintext header fields: `tx_version`, `version_group_id`, `branch_id`,
  `lock_time`, and `expiry_height`. Firmware recomputes ZIP-244
  `header_digest` from these fields and rejects on mismatch.
- `orchard_digest`, exactly 32 bytes.
- Orchard flags, value balance, and 32-byte anchor.
- A 32-byte transparent digest when transparent inputs or outputs are present.
- Optional transparent digest, if present, must be exactly 32 bytes.

Sapling is out of scope for this signing path. Any host-provided
`sapling_digest` is rejected; firmware uses the ZIP-244 empty Sapling digest
internally.

`ZcashPCZTAction` is rejected unless each action includes the fields needed to
recompute the Orchard digest:

- `nullifier`, `cmx`, `epk`, `cv_net`, and `rk`, each 32 bytes.
- `enc_compact`, 52 bytes.
- `enc_memo`, 512 bytes.
- non-empty `enc_noncompact`.
- `out_ciphertext`, 80 bytes.
- `value`, 43-byte `recipient` (`d || pk_d`), and 32-byte `rseed` for trusted
  Orchard output display.

The legacy path where `ZcashPCZTAction.sighash` was accepted as the signing
digest is intentionally rejected.

## What Is Verified

The device now verifies `header_digest` from plaintext header fields and
recomputes `transparent_digest` from streamed transparent inputs/outputs before
emitting any transparent or Orchard signature. Sapling is not accepted in this
path. For shielded-only Orchard transactions, the transparent digest defaults to
the ZIP-244 empty transparent digest, so there is no host-provided transparent
component.

The device verifies the Orchard action digest from the action plaintext fields
available in PCZT. Each action must also carry the plaintext Orchard output
metadata needed for trusted display: raw receiver `recipient = d || pk_d`,
`value`, and `rseed`. Firmware recomputes the action `cmx` from that metadata
and the action nullifier before displaying the ZIP-316 Orchard-only Unified
Address and amount.

The device also computes the fee as:

```text
fee = transparent_input_total - transparent_output_total + orchard_value_balance
```

The computed fee must match the requested fee and must be confirmed on-device
before any final signatures are returned.

## UI Behavior

Current signing screens show:

- Shielded-only: total amount, fee, and Orchard action count.
- Transparent shielding: total amount, fee, transparent input count, and
  transparent output count, and Orchard action count.
- Transparent input signing: per-input amount and BIP-44 path validation.
- Transparent outputs: each standard P2PKH/P2SH t-address and amount.
- Orchard outputs: each ZIP-316 Orchard-only Unified Address and amount after
  note commitment binding.
- Final fee confirmation: computed fee after digest/output verification.

## Outputs

If we can derive a digest from plaintext transaction fields, we should do so for
outputs too.

Transparent outputs are streamed as recipient scripts and values. Firmware
computes the transparent digest, displays transparent destination/address and
amount, and rejects non-standard scripts until an explicit raw-script review
policy exists.

Orchard outputs are displayed from the supplied raw receiver/value/rseed
metadata only after firmware recomputes `cmx = NoteCommit(...)` and verifies it
matches the action `cmx`. This binds the displayed privacy recipient and amount
to the signed Orchard action.

## libzcash-orchard-c Review

Reviewed: https://github.com/wh00hw/libzcash-orchard-c

This repo is applicable as implementation guidance, not as a wholesale firmware
dependency. It is a pure C11 static library under MIT, but it overlaps heavily
with primitives already present in this firmware tree: BLAKE2b, Pallas,
Sinsemilla, RedPallas, secp256k1, BIP32/BIP39, Base58, and ZIP-316 helpers. The
useful part for KeepKey is its transaction-signing shape:

- Separate ZIP-244 `T.2 transparent_digest` from ZIP-244 `S.2` per-input
  transparent signature digest. These are different commitments and must not be
  collapsed into a single helper.
- Stream transparent inputs and outputs into independent BLAKE2b component
  hashers: prevouts, sequences, outputs, amounts, scripts, and per-input
  `txin_sig_digest`.
- Track transparent input/output value totals while hashing so the device can
  compute `fee = transparent_in - transparent_out + orchard_value_balance`
  locally and show that fee on-device.
- Treat Sapling as unsupported. A Sapling component would be a hidden value sink
  until the firmware has Sapling parsing and display, so this firmware path
  rejects host-provided Sapling data and uses the ZIP-244 empty Sapling digest.
- Capture every transparent output `(value, script_pubkey)` and render standard
  P2PKH/P2SH scripts as Zcash t-addresses for user review.
- For Orchard outputs, `cmx` binding is the first target: require plaintext
  `(d, pk_d, value, rseed)` metadata and recompute the note commitment against
  the action `cmx`. The stronger follow-up is memo binding: recompute
  `enc_ciphertext` and `epk` from `(recipient, value, rseed, memo)` using
  Orchard KDF + ChaCha20-Poly1305.

Reference role: KeepKey uses the transaction-signing structure and test-vector
shape while keeping the existing firmware primitives and protocol surfaces.

Key files reviewed:

- https://github.com/wh00hw/libzcash-orchard-c/blob/main/include/zip244.h
- https://github.com/wh00hw/libzcash-orchard-c/blob/main/src/zip244.c
- https://github.com/wh00hw/libzcash-orchard-c/blob/main/include/orchard_signer.h
- https://github.com/wh00hw/libzcash-orchard-c/blob/main/src/orchard_signer.c
- https://github.com/wh00hw/libzcash-orchard-c/blob/main/include/base58.h
- https://github.com/wh00hw/libzcash-orchard-c/blob/main/SECURITY.md

## Updated Implementation Plan

### Phase 1: digest helpers and policy

Status: implemented for header/transparent helpers and clear-signing policy.

- Require component digests and Orchard metadata before signing.
- Reject the legacy host-only action `sighash` path.
- Compute the ZIP-244 root sighash on-device from component digests.
- Verify the Orchard digest from streamed action fields.
- Add pure helpers for:
  - `header_digest` from plaintext header fields.
  - `transparent_digest` from plaintext transparent inputs/outputs.
  - per-input transparent `SIGHASH_ALL` digest.

### Phase 2: plaintext header and transparent streaming

Status: implemented.

- Extend the protocol with plaintext header fields and verify
  `header_digest` locally. Implemented.
- Extend transparent input messages with raw ZIP-244 digest fields:
  `prevout_txid`, `prevout_index`, `sequence`, `amount`, and `script_pubkey`.
- Add transparent output streaming:
  `index`, `amount`, and `script_pubkey`.
- Compute `transparent_digest` locally and compare it to the companion-provided
  digest during the migration period.
- Compute per-input transparent sighashes locally before ECDSA signing, instead
  of signing `ZcashTransparentInput.sighash`.
- Track transparent input and output totals, compute the fee, compare it to the
  requested fee, and display the computed fee.
- Reject transactions with transparent outputs that cannot be rendered on-device
  until the UI has an explicit "unknown script" review policy.

### Phase 3: transparent output UI

Status: implemented for standard P2PKH/P2SH scripts.

- Add a Zcash transparent script renderer for standard P2PKH and P2SH:
  - mainnet P2PKH: `t1`
  - mainnet P2SH: `t3`
  - testnet P2PKH: `tm`
  - testnet P2SH: `t2`
- Display each transparent output address and amount on the trusted screen.
- Require every displayed transparent output and the computed fee to be
  confirmed before any signature is produced.

### Phase 4: stronger Orchard output metadata binding

Status: implemented for recipient/value display via `cmx` binding.

- Extend `ZcashPCZTAction` with raw Orchard output metadata:
  `recipient` (`d || pk_d`), `rseed`, and explicit output value.
- Recompute Orchard note commitment `cmx` from `(d, pk_d, value, rho, rseed)`,
  where `rho` is the action nullifier, and reject on mismatch.
- Display the recipient as a ZIP-316 Orchard-only UA and display the output
  value. Require per-output confirmation.
- Memo display remains a separate hardening step: add ChaCha20-Poly1305 support
  if it is not linked into the firmware image, then recompute `enc_ciphertext`
  and `epk` for memo binding.
- Render empty/text/opaque memos on-device once memo binding is available.

## Crypto Library Inventory

Already available in this firmware tree:

- BLAKE2b with personalization.
- AES-256.
- Pallas field and point arithmetic.
- Pallas SWU / group hash support.
- Sinsemilla / Orchard IVK support.
- RedPallas signing.
- ZIP-316 Orchard-only unified-address helpers.
- Zcash transparent Base58Check plus standard P2PKH/P2SH script-to-address
  rendering.
- ChaCha20-Poly1305 source exists under trezor-crypto, but it is currently not
  linked into the firmware crypto target. Memo binding will need that target
  wiring plus Orchard note-encryption KDF glue.

No new primitive is required for the implemented PCZT clear-signing policy. The
remaining optional hardening work is parsing and digest construction for more
transaction components:

- Sapling parsing only if Sapling is ever intentionally added to this firmware
  path; current policy is to reject it.
- Orchard memo binding/display by recomputing note encryption from
  recipient/value/rseed/memo.

## Keystone Comparison

Keystone is a useful architecture comparison, but the audit alone is not enough
evidence. I inspected the local Keystone firmware repo:

- Path: `/Users/highlander/keepkey/keystone3-firmware`
- Branch: `master`
- Commit: `2a48ba022ac24d3b343fa4b9e59251a5de3e1160`

The actual Keystone signing path does derive the signing digest from PCZT data:

- `rust/rust_c/src/zcash/mod.rs::sign_zcash_tx` extracts a `ZcashPczt` UR and
  calls `app_zcash::sign_pczt`.
- `rust/apps/zcash/src/pczt/sign.rs::sign_pczt` builds a low-level PCZT signer,
  then calls `pczt_ext::sign_transparent` and/or `pczt_ext::sign_orchard`.
- `rust/zcash_vendor/src/pczt_ext.rs::shielded_sig_commitment` constructs the
  ZIP-244-style commitment from locally computed component digests:
  `digest_header`, `transparent_sig_digest`, `digest_sapling`, and
  `digest_orchard`.
- `digest_orchard` recomputes the Orchard digest from action fields:
  nullifier, cmx, ephemeral key, encrypted memo/ciphertext slices, cv_net, rk,
  out ciphertext, bundle flags, value balance, and anchor.
- `transparent_sig_digest` computes transparent prevouts, amounts, scripts,
  sequence, outputs, and per-input data for `SIGHASH_ALL`.

Keystone still has broader in-firmware PCZT parsing and Orchard output
decryption support. KeepKey now covers the same no-bare-sighash signing rule for
the implemented scope: header digest, transparent digest, Orchard digest,
displayed transparent outputs, displayed Orchard receiver/value metadata, and
the miner fee are all verified before signatures are released.

Keystone also does more UI-side output parsing than our current firmware:

- `rust/apps/zcash/src/pczt/parse.rs::parse_orchard_output` tries to decrypt
  Orchard outputs with external/internal OVKs, validates decoded recipient data,
  verifies a supplied `user_address` matches the decoded Orchard receiver, and
  treats undecryptable non-zero Orchard outputs as invalid.
- `src/ui/gui_chain/multi/gui_zcash.c::GuiZcashOverviewTo` displays parsed
  output value, address, change tag, and memo.
- The checker validates Orchard `cv_net`, value balance, nullifier/rk for owned
  spends, and note commitment consistency before the UI/sign flow.

This gives us a concrete target, not just an FYI:

1. KeepKey branch: reject bare host sighashes, compute the final sighash from
   required component digests, verify the Orchard digest from streamed action
   fields, and compute header/transparent digests from streamed plaintext.
2. Output UI: transparent outputs are shown directly from verified script/value.
   Orchard outputs are shown from directly supplied PCZT receiver/value/rseed
   metadata that is cryptographically checked against the action `cmx`.
3. Remaining parity step: memo binding/display by recomputing Orchard note
   encryption from recipient/value/rseed/memo.

Sources:

- Local Keystone firmware at the commit above.
- Public audit context:
  https://leastauthority.com/wp-content/uploads/2025/03/Least-Authority-ZCG-Keystone-Hardware-Wallet-Final-Audit-Report.pdf

## Tests

The TDD coverage for this policy lives in:

- `unittests/firmware/zcash.cpp`
- `deps/python-keepkey/tests/test_msg_zcash_sign_pczt.py`

The firmware unit tests cover the pure policy helper, ZIP-244 digest helpers,
transparent digest/sighash helpers, Orchard receiver encoding, and Orchard note
commitment recomputation. The Python protocol tests cover the emulator-facing
behavior: legacy host-sighash requests are rejected, verified PCZT requests
sign, missing Orchard action digest fields abort signing, transparent digests
must match streamed plaintext, host transparent sighashes are rejected, and
Orchard recipient/value tampering is rejected.

Current local verification:

- `build/bin/zcash-crypto-unit` passes 56 tests, including:
  - `ComputeHeaderDigest_FromPlaintextFields`
  - `ComputeTransparentDigest_DistinctFromPerInputSighash`
  - `ComputeTransparentDigest_EmptyBundle`
  - `ComputeTransparentSighash_RejectsUnsupportedRequest`
  - `OrchardNoteCommitment_KnownVector`
  - `OrchardReceiverToUnifiedAddress_KnownVector`
- `cmake --build build --target kkfirmware` passes.
- `cmake --build build --target kkfirmware.keepkey` passes.
- `git diff --check` is clean.
