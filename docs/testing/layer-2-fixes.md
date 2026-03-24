# Layer 2 Testing Guide — Fixes

Firmware 7.14.0 fixes. Test after merging each PR to develop.

## PR #84 — nanopb oneof memory leak fix

**What changed**: Backport of upstream nanopb fix (4fe23595) that prevents
memory leak when decoding protobuf messages with `oneof` fields.

**Risk**: Low — single function change in protobuf decoder.

### Test Plan

1. **Regression**: Run full python-keepkey test suite via emulator
   ```
   cd scripts/emulator && docker compose up --build python-keepkey
   ```
   Expected: all tests pass (306+), no new failures

2. **Memory stress**: Run 50+ sequential sign operations without reboot
   - BTC sign, ETH sign, repeated get_features
   - Verify no degradation or hangs after many operations

3. **Pass/Fail**: python-keepkey suite green, no emulator crashes

---

## PR #85 — Fault injection hardening (F3, F5)

**What changed**:
- `signatures_ok()` now uses infective aggregation + double-hash (F3)
- Firmware startup replaces full `signatures_ok()` with metadata presence
  check — bootloader is the trust anchor (F5)

**Risk**: HIGH — security-critical signature verification changes.

### Test Plan

1. **Signed firmware acceptance**: Flash a signed firmware image
   - Device should boot normally
   - `getFeatures()` should report correct version
   - No "UNOFFICIAL FIRMWARE" warning

2. **Unsigned firmware rejection** (bootloader test):
   - Attempt to flash unsigned .bin via bootloader
   - Bootloader should reject (this tests the bootloader, not the F5 change)

3. **F5 boot speed**: Measure boot time before/after
   - Expected: ~1s faster (removed crypto verification at startup)

4. **F3 fault injection** (if test harness available):
   - Verify `signatures_ok()` returns SIG_FAIL if any intermediate
     value is corrupted (infective aggregation)
   - This requires specialized hardware or emulator instrumentation

5. **Unit tests**: firmware-unit suite must pass
   ```
   cd scripts/emulator && docker compose up --build firmware-unit
   ```

6. **Pass/Fail**: Device boots with signed firmware, rejects unsigned,
   all unit tests pass

---

## PR #86 — BIP39 wordlist validation during cipher recovery

**What changed**:
- Per-word BIP39 validation: each decoded word is checked immediately
  against the wordlist, not just at finalization
- Logic fix: `!enforce_wordlist` → `enforce_wordlist` (inverted condition)

**Risk**: Medium — affects recovery flow, but improves safety.

### Test Plan

1. **Valid 12-word recovery** (emulator):
   ```
   # Mnemonic: "all" x12
   # Use cipher recovery flow — all words should auto-complete
   ```
   Expected: recovery succeeds, device stores seed

2. **Invalid word rejection**:
   - Start cipher recovery with `enforce_wordlist=True`
   - Enter characters that decode to a non-BIP39 word
   - Expected: device returns `Failure_SyntaxError` with
     "Word not found in BIP39 wordlist"
   - Recovery aborts immediately (does not wait until word 12)

3. **24-word recovery**: Same as test 1 with 24 words
   Expected: all words auto-complete, recovery succeeds

4. **Zoo capture**: Run recovery-cipher flow, verify cipher grid screenshots

5. **Pass/Fail**: Valid mnemonics recover successfully, invalid words
   rejected immediately with clear error

---

## PR #87 — Show previous word during recovery cipher

**What changed**:
- New `prev_completed_word` CONFIDENTIAL buffer in recovery_cipher.c
- After auto-complete, previous word displayed at y=50 as "N: word"
- Layout rearranged: prompt y=4, current word y=30, prev word y=50

**Risk**: Low — display-only change, CONFIDENTIAL buffer properly zeroed.

### Test Plan

1. **Visual verification** (emulator + zoo):
   - Run recovery cipher with "zoo zoo zoo ... wrong" mnemonic
   - After word 1 auto-completes, screen should show:
     - "Recovery Cipher:" at top
     - Current word progress in middle
     - "1: zoo" below current word (prev word line)
   - After word 2: prev line shows "2: zoo"
   - Continue through all 12 words

2. **First word**: No prev-word line should appear (word_pos == 0)

3. **Abort cleanup**: Start recovery, enter a few words, then abort
   - `prev_completed_word` buffer should be zeroed (verify via DebugLink
     if possible, or just confirm no stale data on next recovery)

4. **Layout overflow**: Test with long BIP39 words (e.g., "abandon",
   "abstract") — prev_info at 72px max width should not overlap cipher grid

5. **Zoo screenshots**: Capture before/after comparison showing prev word

6. **Pass/Fail**: Previous word visible after each auto-complete,
   no layout overflow, buffer zeroed on abort
