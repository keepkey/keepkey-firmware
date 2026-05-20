# Zcash Clear-Signing Handoff

Date: 2026-05-20
Branch: `feature/clearsign-txs`
Base: `origin/release/7.15.0`
Repo: `/Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware`

## Goal

Prepare a PR to the 7.15.0 firmware branch for Zcash PCZT clear-signing work,
then test the clear-signing flow on device.

Scope is Orchard plus transparent clear-signing. Sapling is explicitly out of
scope for this branch.

## Decisions

- Do not accept host-provided action sighashes. Firmware must assemble the
  signing digest from checked transaction components.
- Sapling is out of scope. Any provided `sapling_digest` is rejected with
  `Sapling not supported`; firmware uses the ZIP-244 empty Sapling digest
  internally.
- Header digest is no longer blindly trusted. The host must send plaintext
  `tx_version`, `version_group_id`, `branch_id`, `lock_time`, and
  `expiry_height`; firmware recomputes ZIP-244 `header_digest` and rejects on
  mismatch.
- Transparent plaintext streaming is wired for standard P2PKH/P2SH
  transparent scripts. Firmware recomputes the transparent digest from streamed
  outputs and inputs before emitting any transparent or Orchard signature.
- Orchard privacy outputs are displayed from plaintext `recipient = d || pk_d`,
  `value`, and `rseed` only after firmware recomputes `cmx` and verifies it
  matches the action commitment.
- The device computes `fee = transparent_in - transparent_out +
  orchard_value_balance`, compares it to the requested fee, and requires final
  fee confirmation before signatures are returned.
- `wh00hw/libzcash-orchard-c` is used as implementation guidance and test-vector
  shape, not as a wholesale dependency.

## Implemented

- Added `docs/coin-integration/zcash-pczt-clearsign.md` with threat model,
  Keystone comparison, `libzcash-orchard-c` review, crypto inventory, and phased
  plan.
- Added clear-signing request policy helpers in
  `include/keepkey/firmware/zcash.h` and `lib/firmware/zcash.c`.
- Added ZIP-244 helpers:
  - `zcash_compute_header_digest`
  - `zcash_compute_transparent_digest`
  - `zcash_compute_transparent_sighash_digest`
- Updated `fsm_msg_zcash.h` to:
  - reject legacy host-only sighash signing
  - require component digests and Orchard metadata
  - require plaintext header fields
  - verify `header_digest` from plaintext header fields
  - reject any Sapling component
  - always use the empty Sapling digest internally
  - verify Orchard digest from streamed action fields before returning signatures
- Updated Zcash protocol definitions with plaintext header fields.
- Updated Zcash protocol definitions with transparent output streaming,
  transparent input plaintext fields, and transparent ack/signed messages.
- Updated `fsm_msg_zcash.h` to:
  - request transparent outputs before inputs
  - display standard transparent output address/amount before signatures
  - reject unknown transparent scripts
  - reject host-provided transparent input sighashes
  - verify `transparent_digest` from streamed transparent plaintext
  - derive per-input transparent sighashes locally
- Added Orchard output clear-signing metadata to `ZcashPCZTAction`:
  `recipient` and `rseed`.
- Added firmware Orchard output verification/display:
  - recompute `cmx` from `recipient`, `value`, `rseed`, and action nullifier
  - reject `cmx` mismatch before signing
  - encode the raw Orchard receiver as a ZIP-316 Orchard-only Unified Address
  - display the privacy address and amount on-device
- Added final fee verification/display from transparent totals plus
  `orchard_value_balance`.
- Updated python-keepkey client/tests to stream transparent outputs/inputs and
  expect `ZcashTransparentSigned`.
- Updated python-keepkey test client/tests to send header fields and test:
  - legacy sighash rejection
  - header digest mismatch rejection
  - Sapling digest rejection
  - Orchard digest field requirements
  - transparent digest mismatch rejection
  - host-provided transparent sighash rejection
  - Orchard recipient/value metadata mismatch rejection

## Verified

Commands run from the firmware repo:

```sh
cmake --build build --target zcash-crypto-unit
PATH=/private/tmp/kk-python-shim:$PATH cmake --build build --target kkfirmware
PATH=/private/tmp/kk-python-shim:$PATH cmake --build build --target kkfirmware.keepkey
build/bin/zcash-crypto-unit
git diff --check
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python python3 -c "import sys; sys.path.insert(0, 'deps/python-keepkey'); from keepkeylib import messages_zcash_pb2 as z; a=z.ZcashPCZTAction(index=0, recipient=b'1'*43, rseed=b'2'*32, value=1); assert a.HasField('recipient') and a.HasField('rseed'); print('zcash orchard metadata protobuf smoke ok')"
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python python3 -c "import sys; sys.path.insert(0, 'deps/python-keepkey'); from keepkeylib import mapping; from keepkeylib import messages_zcash_pb2 as z; assert mapping.get_type(z.ZcashTransparentOutput(index=0)) == 1310; assert mapping.get_type(z.ZcashTransparentAck(next_input_index=0)) == 1311; assert mapping.get_type(z.ZcashTransparentSigned(signatures=[b'0'])) == 1307; msg=z.ZcashSignPCZT(n_transparent_outputs=1,n_transparent_inputs=1); assert msg.HasField('n_transparent_outputs'); print('zcash transparent protobuf smoke ok')"
PYTHONPYCACHEPREFIX=/private/tmp/kk-pycache python3 -m py_compile deps/python-keepkey/tests/test_msg_zcash_sign_pczt.py
```

Results:

- Full `zcash-crypto-unit`: 56 tests passed.
- `kkfirmware`: builds.
- `kkfirmware.keepkey`: builds.
- `git diff --check`: clean.
- Python Zcash Orchard metadata protobuf smoke test passes.
- Python Zcash transparent protobuf smoke test passes.
- Python test file syntax check passes with bytecode cache redirected to
  `/private/tmp/kk-pycache`.

## Published Dependencies

- `BitHighlander/device-protocol`
  `feat/zcash-clearsign-protocol` -> `6ec974e`
- `BitHighlander/python-keepkey`
  `feat/zcash-clearsign-tests` -> `c9c9768`
- Firmware submodules now point at those commits:
  - `deps/device-protocol` -> `6ec974e`
  - `deps/python-keepkey` -> `c9c9768`

The python-keepkey PDF report now includes the 7.15 Zcash clear-signing section
with the new digest rejection, transparent streaming, cmx binding, and
privacy-output tests. Its screenshot filter selects the positive display flows:

- `test_multi_action_device_sighash`
- `test_signatures_are_64_bytes`
- `test_transparent_shielding_single_input`
- `test_transparent_shielding_multiple_inputs`

Screenshot capture is still driven by `KEEPKEY_SCREENSHOT=1` and ButtonRequest
callbacks; `scripts/generate-test-report.py --screenshots <dir>` embeds the
captured `btn*.png` frames for tests with screenshot labels.

## Local Tooling Notes

- Nanopb generation invokes `env python`. This machine only had `python3`, so a
  temporary shim was created:
  `/private/tmp/kk-python-shim/python -> /opt/homebrew/bin/python3`.
- `PATH=/private/tmp/kk-python-shim:$PATH` is needed for local firmware rebuilds
  unless a real `python` executable is installed.
- Local `protoc` is `libprotoc 34.1`; regenerating
  `keepkeylib/messages_zcash_pb2.py` produced a noisy modern-style diff. The
  checked-in python-keepkey branch removes the generated runtime-version guard
  so it imports with the local protobuf runtimes used during verification.
- `PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python` is useful for local imports
  with the older checked-in protobuf files.

## Remaining CI/HW Follow-up

- Run a hardware/emulator signing flow if available, because the Python tests
  exercise the client shape but were not run against a device in this handoff.
- CI should run the pushed firmware and python-keepkey branches and produce the
  PDF report with screenshots.
- Keep `.claude/` out of the PR unless explicitly requested.

## Device Test Plan

- Flash `kkfirmware.keepkey` build to a test device.
- Confirm happy-path Orchard-only PCZT signing.
- Confirm Sapling PCZT is rejected.
- Confirm header digest mismatch is rejected.
- Confirm Orchard digest mismatch is rejected.
- Confirm transparent output address/amount appears on device.
- Confirm transparent output mutation causes digest mismatch/rejection.
- Confirm transparent input sighash mutation cannot produce a signature.
- Confirm Orchard privacy output UA/amount appears on device.
- Confirm Orchard recipient, value, rseed, or cmx mutation is rejected before
  signing.
- Confirm fee mismatch is rejected.
- Confirm final computed fee confirmation appears before signatures are
  returned.
