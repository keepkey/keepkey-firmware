# Layer 3 Testing Guide — Features

Firmware 7.14.0 features on existing surfaces. Test after Layer 2 merges.

## PR #89 — Add Lynx (LYNX) to coins table

**What changed**: Single line in `coins.def` adding Lynx coin parameters.

**Risk**: Minimal — additive coin table entry.

### Test Plan

1. **Address derivation**: Request a Lynx address
   - Path: `m/44'/coin_type'/0'/0/0` (check coins.def for coin_type)
   - Expected: valid base58 address with correct prefix

2. **No regression**: BTC and other coin addresses unchanged
   ```
   # Quick sanity: derive BTC, LTC, DOGE addresses — compare with known values
   ```

3. **Pass/Fail**: Lynx address derivable, no existing coin breakage

---

## PR #90 — BIP-85 child mnemonic derivation (display only)

**What changed**:
- `bip85_derive_mnemonic()` in bip85.c: HMAC-SHA512 with "bip-entropy-from-k"
- FSM handler: derives child mnemonic, displays on OLED, requires button confirm
- Supports 12/18/24 word output

**Risk**: Medium — derives entropy from master key. Display-only (never exports).

### Test Plan

1. **12-word derivation** (emulator):
   ```
   # Load "all" x12 mnemonic
   # Request BIP85: word_count=12, index=0
   # Path: m/83696968'/39'/0'/12'/0'
   ```
   Expected: 12-word mnemonic displayed on OLED
   - Verify against reference implementation (Ian Coleman BIP85 tool)
   - Words must be valid BIP39

2. **24-word derivation**: Same with word_count=24
   Expected: 24 valid BIP39 words

3. **Different indices**: index=0 and index=1 must produce different mnemonics

4. **Determinism**: Same seed + same index = same output every time

5. **Display security**:
   - Mnemonic shown on OLED only (never in USB response)
   - Requires physical button press to dismiss
   - No mnemonic bytes in protobuf response

6. **Invalid inputs**:
   - word_count=15 → should fail (only 12/18/24 supported)
   - Missing PIN → should fail (CHECK_PIN)

7. **Zoo screenshots**: Capture the mnemonic display screen

8. **Pass/Fail**: Correct mnemonic derived matching reference, display-only,
   deterministic, invalid inputs rejected

---

## PR #91 — EVM clear-signing + blind-sign policies

**What changed**:
- `signed_metadata.c` (355 lines): Verifies signed transaction metadata
  from external insight service using hardcoded public keys
- `EthereumTxMetadata` / `EthereumMetadataAck` message flow
- `confirm_with_icon()` using VERIFIED_ICON for trusted txs
- Blind-sign policy: `EthBlindSign` gate for unverified transactions

**Risk**: HIGH — security-critical signing policy change.

### Test Plan

1. **Verified transaction** (with valid signed metadata):
   - Send EthereumTxMetadata with correctly signed payload
   - Expected: "Insight Verified" screen with icon
   - Shows decoded method name, contract address, parameters
   - User confirms → sign proceeds

2. **Opaque transaction** (no metadata or invalid signature):
   - Send EthereumSignTx without prior metadata
   - Expected: blind-sign warning displayed
   - If EthBlindSign policy not enabled → rejection
   - If enabled → warning screen, user can still confirm

3. **Malformed metadata**:
   - Send metadata with corrupted signature
   - Expected: `METADATA_MALFORMED` classification, "Invalid" display

4. **Key rotation** (key_id parameter):
   - Test with key_id=0 (active key) → should verify
   - Test with key_id=99 (invalid) → should fail

5. **Contract address display**:
   - Full 42-char checksummed address displayed (no truncation)
   - Verify checksum matches EIP-55

6. **Policy enforcement**:
   - Without EthBlindSign policy: unsigned tx → rejection
   - With policy: unsigned tx → warning + allow

7. **Unit tests**: firmware-unit suite must pass

8. **Zoo screenshots**: Capture verified screen, opaque warning, rejection

9. **Pass/Fail**: Verified txs show trust indicator, opaque txs gated
   by policy, malformed metadata rejected, no address truncation
