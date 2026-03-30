# KeepKey Firmware Test System

Single source of truth for the test suite, report generation, screenshot capture, and release validation pipeline.

---

## Architecture

```
python-keepkey (release/7.14.0)
├── keepkeylib/
│   ├── client.py          # SCREENSHOT capture in callback_ButtonRequest
│   ├── debuglink.py       # read_layout() → 2048-byte OLED buffer
│   └── messages_*_pb2.py  # protobuf definitions per chain
├── tests/
│   ├── common.py          # KeepKeyTest base class + screenshot dir setup
│   ├── conftest.py        # pytest plugin: per-test screenshot directories
│   ├── config.py          # transport config (UDP host:port)
│   └── test_msg_*.py      # test files (one per chain/feature)
└── scripts/
    └── generate-test-report.py  # THE report generator (1061 lines, version-aware)
```

**Everything lives in python-keepkey.** The firmware repo consumes it as a submodule at `deps/python-keepkey/`.

---

## Report Generator: Version-Gated Sections

`scripts/generate-test-report.py` defines a `SECTIONS` array where each section has a `min_firmware_version`:

```python
SECTIONS = [
    ('C', 'Core - Device Lifecycle', '7.0.0', ...),   # always shown
    ('B', 'Bitcoin',                 '7.0.0', ...),   # always shown
    ('E', 'Ethereum',               '7.0.0', ...),   # always shown
    # ... existing chains ...
    ('V', 'EVM Clear-Signing',      '7.14.0', ...),  # shown when fw >= 7.14.0
    ('S', 'Solana',                 '7.14.0', ...),  # shown when fw >= 7.14.0
    ('T', 'TRON',                   '7.14.0', ...),  # shown when fw >= 7.14.0
    ('N', 'TON',                    '7.14.0', ...),  # shown when fw >= 7.14.0
    ('Z', 'Zcash Orchard',         '7.14.0', ...),  # shown when fw >= 7.14.0
    ('D', 'BIP-85 Child Derivation','7.14.0', ...),  # shown when fw >= 7.14.0
]
```

When the firmware version is 7.10.0 (branches before mega merge), only existing chain sections appear. When 7.14.0, new feature sections appear at the TOP of the report with `[NEW]` tags.

Each test in a section maps to a specific `test_msg_*.py::TestClass::test_method`. The generator looks up the method name in JUnit XML results to determine pass/fail/pending.

### Running the generator

```bash
# Against live emulator (auto-detects version)
python3 scripts/generate-test-report.py --output=test-report.pdf

# Against JUnit XML from CI
python3 scripts/generate-test-report.py \
  --fw-version=7.14.0 \
  --junit=test-reports/python-keepkey/junit.xml \
  --screenshots=test-reports/screenshots/ \
  --output=test-report.pdf
```

### Adding a new feature (future releases)

1. Add a new section tuple to `SECTIONS` with the target firmware version
2. Add test entries mapping to test file methods
3. Push to `release/<version>` on python-keepkey
4. The report automatically includes the section when firmware version matches

---

## Screenshot Capture System

### Why Two Phases

Screenshot capture adds a `DebugLinkGetState` round-trip on every `ButtonRequest`. This:
- Adds ~50-100ms latency per button press
- Can cause timing issues in multi-step flows (recovery cipher, complex signing)

**Phase 1**: Run screenshot-compatible tests with `KEEPKEY_SCREENSHOT=1`. These are simple request-response tests (address display, wipe) that tolerate the extra latency.

**Phase 2**: Run the full test suite without screenshots for accurate pass/fail results.

### How Screenshots Work

1. `KEEPKEY_SCREENSHOT=1` env var enables capture (client.py line 61)
2. `conftest.py` creates per-test directories: `screenshots/{module}/{test_method}/`
3. `callback_ButtonRequest()` calls `_capture_oled()` BEFORE pressing the button
4. `_capture_oled()` reads 2048-byte OLED layout via DebugLink, decodes 256x64 monochrome, writes PNG
5. Screenshots named `btn00000.png`, `btn00001.png`, etc. per test
6. Report generator skips first 2 frames (setUp wipe+load) and embeds the rest inline

### Screenshot Directory Layout

```
screenshots/
├── msg_wipedevice/
│   └── test_wipe_device/
│       ├── btn00000.png    # setUp wipe confirm (skipped in report)
│       ├── btn00001.png    # setUp load_device (skipped in report)
│       └── btn00002.png    # actual test screen (embedded in report)
├── msg_solana_getaddress/
│   └── test_solana_get_address/
│       ├── btn00000.png
│       ├── btn00001.png
│       └── btn00002.png    # Solana address display with full base58
└── ...
```

### Known Screenshot Limitations (verified 2026-03-27)

1. **`show_display=True` screenshots capture wrong screen**: `_capture_oled()` in `callback_ButtonRequest` reads the OLED buffer via DebugLink BEFORE the firmware renders the address. The captured frame shows the previous screen (recovery sentence, home screen), not the address display. This is a timing race between the DebugLink read and the firmware OLED render.

2. **Screenshot capture corrupts address responses**: When `KEEPKEY_SCREENSHOT=1`, the DebugLink round-trip in `callback_ButtonRequest` can cause the `show_display=True` response to return an empty address. Tests that assert on address content will fail in screenshot mode.

3. **TON `raw_address` proto bug**: The `TonAddress.raw_address` field is defined as proto `string` but the firmware populates it with binary data (non-UTF-8). Causes `UnicodeDecodeError` when `show_display=True`. Needs proto fix: change to `bytes` type.

4. **Screenshot file naming**: `conftest.py` uses `scr*` prefix but report generator expects `btn*` prefix. Need to align.

### Implication for Phase 1/Phase 2

Show-display tests (`test_*_show_address`) go in Phase 1 with relaxed assertions (no address content checks). Address correctness is validated by non-show tests in Phase 2. The show tests exist ONLY to trigger the OLED display flow for screenshot capture.

---

## Feature Gating (per-branch test control)

### Problem

During development, firmware branches are at different feature states:
- `develop` (7.10.0): no new chains
- After PR #1-6 merge: still 7.10.0, no new chains
- After PR #7 (mega): jumps to 7.14.0, gets Solana/TRON/TON/EVM/BIP-85
- After PR #8 (zcash): gets Zcash Orchard

The `requires_firmware("7.14.0")` check gates on version number, but two branches at "7.14.0" may have different features (mega without zcash vs mega with zcash).

### Solution: Feature-based gating

Like Trezor's test system, tests should declare which MESSAGE TYPES they need:

```python
# Existing (works for version gating)
self.requires_firmware("7.14.0")

# Existing (works for message-level feature gating)
self.requires_message("SolanaGetAddress")    # skips if proto not available
self.requires_message("TronGetAddress")
self.requires_message("ZcashSignPCZT")       # skips if Zcash not in this build
self.requires_message("EthereumTxMetadata")  # skips if EVM clear-signing not available
```

The `requires_message()` method (already on `release/7.14.0`) checks if the protobuf message type exists in the current build's pb2 modules. This handles:
- 7.10.0 branches: all new chain tests skip (no Solana/TRON/TON protos)
- Mega branch: Solana/TRON/TON/EVM/BIP-85 tests run, Zcash skips
- Zcash branch: all tests run

### Report Generator Integration

The report generator's `SECTIONS` array already gates by `min_firmware_version`. Tests that skip via `requires_message()` show as `--` (pending/grey) in the report, which is correct — the feature isn't in this build.

### Phase 1 Filter: Version-Aware

Instead of hardcoding chain names:
```bash
# WRONG: hardcoded, breaks on 7.10.0 branches
pytest -k "test_solana_get or test_tron_get or test_ton_get"

# RIGHT: run all show tests, let requires_firmware/requires_message skip
pytest -k "test_show or test_show_address or test_wipe_device or test_bip85"
```

The `requires_firmware()` and `requires_message()` decorators handle the skipping. No need to maintain a separate filter list per version.

---

## Removed Files (stray / dangerous)

The following files were removed from `tests/` on `release/7.14.0` (commit `04ef8e7`):

| File | Lines | Why Removed |
|------|-------|-------------|
| `test_zcash_complete_nownodes.py` | 416 | Hardcoded RPC credentials (`78787ba8...`), internal IP (`100.117.181.111`), NOWNodes API key, interactive `input()` prompt for MAINNET broadcast |
| `test_zcash_v5_complete.py` | 313 | External RPC calls + mainnet broadcast |
| `test_zcash_nu6.py` | 184 | Mainnet broadcast tool disguised as test |
| `test_nu6_final.py` | 150 | "Sign and automatically broadcast NU6 transaction" |

These are manual integration tools, not unit tests. pytest collected them and they failed with timeouts, polluting CI results. Zcash signing is properly tested by `test_msg_zcash_orchard.py` and `test_msg_zcash_sign_pczt.py` (emulator-only, zero external dependencies).

**Rule**: No test file in `tests/` should import `requests`, hit external APIs, contain hardcoded credentials, or prompt for user input.

---

## Local Verification Results (2026-03-27)

Verified against emulator (alpha branch, firmware 7.14.0, port 12044):

**Phase 1 (screenshots)**: 6 tests passed, 15 OLED PNGs captured
- BIP-85 seed derivation: 3 pages of mnemonic words (embedded in PDF)
- Solana address: full 44-char base58 with QR code
- TRON address: full 34-char Base58Check with QR code
- TON address: full 48-char base64url with QR code
- Wipe device: confirmation screen

**Phase 2 (full suite)**: 372 passed, 0 failed, 6 skipped

**Report generation**: 134 tests in PDF, 133 passed, 1 pending (N5 TON comment test)
- New Feature sections at top with `[NEW]` tags
- Version-gated: only shown because `fw_version=7.14.0`
- Inline OLED screenshots for BIP-85 (Solana/TRON/TON screenshots need path alignment for inline embedding)

---

## CI Pipeline Integration

### Current Flow (firmware repo)

```
scripts/emulator/python-keepkey-tests.sh:
  Phase 1: KEEPKEY_SCREENSHOT=1 pytest -k "<filter>" → junit-screenshots.xml + PNGs
  Phase 2: pytest (full suite) → junit.xml + exit status

scripts/generate-test-report.py:
  Reads junit.xml + screenshots/ → test-report.pdf
```

### Target Flow (consolidated)

```
scripts/emulator/python-keepkey-tests.sh:
  Phase 1: KEEPKEY_SCREENSHOT=1 pytest -k "<version-aware-filter>" → screenshots/
  Phase 2: pytest --junitxml=junit.xml (full suite)

deps/python-keepkey/scripts/generate-test-report.py:
  Reads junit.xml + screenshots/ + auto-detects fw version → test-report.pdf
```

The firmware repo's `scripts/generate-test-report.py` should be a thin wrapper:

```python
#!/usr/bin/env python3
"""Delegates to python-keepkey's version-aware report generator."""
import subprocess, sys, os
script = os.path.join(os.path.dirname(__file__), '..', 'deps', 'python-keepkey', 'scripts', 'generate-test-report.py')
sys.exit(subprocess.call([sys.executable, script] + sys.argv[1:]))
```

---

## Tech Debt Inventory

### BROKEN: Must Fix Before Rehearsal

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 1 | Firmware `scripts/generate-test-report.py` is 314-line dumb version on alpha | alpha branch | Replace with wrapper to python-keepkey's generator |
| 2 | Phase 1 `-k` filter hardcodes chain names, not version-aware | `python-keepkey-tests.sh` | Use `requires_firmware()` skip mechanism — run ALL display tests, let the test self-skip |
| 3 | Phase 1 filter missing EVM clear-signing, Zcash display tests | `python-keepkey-tests.sh` | Expand filter or remove filter entirely |
| 4 | `generate-test-report.py` exists in 3 places (firmware scripts/, python-keepkey scripts/, zoo scripts/) | Multiple repos | Delete firmware copies, single source in python-keepkey |
| 5 | `scripts/zoo/generate_report.py` is a separate manual review PDF | firmware repo | Keep as separate tool, do not confuse with test report |

### WRONG: Tests That Need Fixing

| # | Test | Issue | Fix |
|---|------|-------|-----|
| 1 | TON `test_ton_sign_structured` | Was sending structured fields without `raw_tx` — firmware requires it | FIXED in 4b4dc05 |
| 2 | TON `test_ton_sign_with_memo` | Same | FIXED in 4b4dc05 |
| 3 | TON `test_ton_sign_deterministic` | Same | FIXED in 4b4dc05 |
| 4 | EVM `test_valid_metadata_returns_verified` + 8 others | Client missing `ethereum_send_tx_metadata()` method | FIXED in 4b4dc05 |
| 5 | Zcash Z1-Z9 all pending in mega report | Zcash tests require `requires_message("ZcashSignPCZT")` — proto available but tests don't execute | Investigate: may be `requires_firmware` version check or pb2 import issue |

### STALE: Versions Out of Sync

| Branch | `generate-test-report.py` | python-keepkey pin | Status |
|--------|--------------------------|-------------------|--------|
| alpha | 314 lines (dumb) | BitHighlander fork `5f32810` | WRONG — needs upstream pin + wrapper |
| develop | 1058 lines (rich, inline copy) | upstream `release/7.14.0` | WRONG — inline copy, should be wrapper |
| feat/ci-test-report-v2 | 1069 lines (rich, inline copy) | upstream `release/7.14.0` | WRONG — inline copy |
| feat/7.14.0-mega-v3 | 1050 lines (rich, inline copy) | upstream `4b4dc05` | WRONG — inline copy |

**All firmware branches** should use the wrapper pattern pointing to `deps/python-keepkey/scripts/generate-test-report.py`.

---

## Release Branch Checklist

### Before creating any firmware feature branch

1. Confirm python-keepkey `release/<version>` has:
   - [ ] All test files for the feature (`test_msg_<chain>_*.py`)
   - [ ] Section entry in `SECTIONS` array with correct `min_firmware_version`
   - [ ] `conftest.py` and `common.py` screenshot infrastructure
   - [ ] `ethereum_send_tx_metadata()` or equivalent client methods for new message types
   - [ ] `requires_message()` guards for chain-specific pb2 imports

2. Confirm firmware branch has:
   - [ ] `deps/python-keepkey` pinned to upstream `release/<version>` (NOT fork)
   - [ ] `scripts/generate-test-report.py` is the thin wrapper (NOT inline copy)
   - [ ] `.github/workflows/ci.yml` calls the wrapper
   - [ ] `scripts/emulator/python-keepkey-tests.sh` Phase 1 filter includes new chain display tests

### Per-PR Review (SOP Gate 3)

For each PR's `test-report.pdf`:
1. Header matches branch, commit SHA, firmware version
2. New feature sections appear at TOP with `[NEW]` tag (if firmware version warrants)
3. Zero FAIL or ERROR
4. Every SKIP has documented justification
5. New chain sections have OLED screenshots inline (not just "OLED needed: ...")
6. No regressions — previously-passing tests still pass

---

## Merge Sequence for Test System Consolidation

This is the prerequisite work before the release dress rehearsal.

### Step 0: Prove locally

```bash
# Start emulator
cd projects/keepkey-firmware
KEEPKEY_UDP_PORT=12044 build-emu/bin/kkemu &

# Run Phase 1 (screenshots)
cd deps/python-keepkey/tests
KEEPKEY_SCREENSHOT=1 \
SCREENSHOT_DIR=/tmp/test-screenshots \
KK_TRANSPORT_MAIN=127.0.0.1:12044 \
KK_TRANSPORT_DEBUG=127.0.0.1:12045 \
pytest -v -k "test_get_address or test_getaddress or test_wipe or test_bip85" \
  --junitxml=/tmp/junit-screenshots.xml --timeout=120

# Run Phase 2 (full suite)
KK_TRANSPORT_MAIN=127.0.0.1:12044 \
KK_TRANSPORT_DEBUG=127.0.0.1:12045 \
pytest -v --junitxml=/tmp/junit.xml

# Generate report
cd ../scripts
python3 generate-test-report.py \
  --fw-version=7.14.0 \
  --junit=/tmp/junit.xml \
  --screenshots=/tmp/test-screenshots \
  --output=/tmp/test-report.pdf
```

Verify the PDF has:
- Per-chain sections with descriptions
- `[NEW]` tags on 7.14.0 features
- Inline OLED screenshots for address display tests
- Green checkmarks for passing tests

### Step 1: Update python-keepkey `release/7.14.0`

- [ ] Verify all test files present and correct
- [ ] Verify `SECTIONS` array complete for 7.14.0
- [ ] Verify conftest.py + screenshot system works
- [ ] Push any fixes

### Step 2: Update firmware `feat/ci-test-report-v2` (PR #0)

- [ ] Replace `scripts/generate-test-report.py` with thin wrapper
- [ ] Update `python-keepkey-tests.sh` Phase 1 filter (version-aware or broad)
- [ ] Pin `deps/python-keepkey` to upstream `release/7.14.0`
- [ ] Push and verify CI produces correct PDF

### Step 3: Reset develop, merge PR #0

- [ ] Reset develop to upstream
- [ ] Merge PR #0 (CI infrastructure)
- [ ] Verify develop's CI produces correct 7.10.0 baseline report

### Step 4: Sequential PR merges per SOP

- [ ] PR #1 (nanopb) → report should show 7.10.0, 91 tests, existing chains only
- [ ] PR #3 (bip39) → same
- [ ] PR #5 (lynx) → same
- [ ] PR #6 (bip85) → same (BIP-85 tests gated by 7.14.0, won't appear yet)
- [ ] PR #7 (mega) → report jumps to 7.14.0, new sections appear, screenshots required
- [ ] PR #8 (zcash) → Zcash section tests execute

### Step 5: Verify each PDF

Each PR's `test-report.pdf` is downloaded and reviewed:
- Pre-mega PRs: 91 tests, existing chains, no `[NEW]` sections
- Mega PR: 134 tests, `[NEW]` sections at top, inline OLED screenshots
- Zcash PR: Zcash section tests execute (no longer `--` pending)

---

## File Reference

| File | Location | Purpose | Owner |
|------|----------|---------|-------|
| `generate-test-report.py` | `python-keepkey/scripts/` | THE report generator (1061 lines) | python-keepkey `release/7.14.0` |
| `conftest.py` | `python-keepkey/tests/` | pytest screenshot directory plugin | python-keepkey `release/7.14.0` |
| `common.py` | `python-keepkey/tests/` | KeepKeyTest base + screenshot setup | python-keepkey `release/7.14.0` |
| `client.py` | `python-keepkey/keepkeylib/` | SCREENSHOT capture + ButtonRequest hook | python-keepkey `release/7.14.0` |
| `debuglink.py` | `python-keepkey/keepkeylib/` | `read_layout()` OLED buffer read | python-keepkey `release/7.14.0` |
| `python-keepkey-tests.sh` | firmware `scripts/emulator/` | CI test runner (Phase 1 + Phase 2) | firmware repo |
| `ci.yml` | firmware `.github/workflows/` | CI pipeline definition | firmware repo |
| `generate_report.py` | firmware `scripts/zoo/` | Manual review PDF (separate from test report) | firmware repo |
