# Layer 4 Testing Guide — New Chains

Firmware 7.14.0 new chain support. Each chain is an independent review/test unit.
Test after Layers 2-3 are merged to develop.

---

## PR #92 — Solana

**Curve**: Ed25519
**Path**: `m/44'/501'/account'` (3-4 levels, all hardened)
**Address format**: Base58 (32-byte Ed25519 pubkey)

### Test Vectors

```
Mnemonic: "all" x12
Path: m/44'/501'/0'
Expected address: (derive and record — compare across runs for determinism)
```

### Test Plan

1. **Address derivation**:
   - `SolanaGetAddress` with `show_display=True`
   - Verify Base58-encoded address on OLED
   - Verify address matches `solana-keygen` or Phantom wallet for same seed

2. **Non-standard path warning**:
   - Request address with path `m/44'/501'/0'/0'` (4 levels, valid)
   - Then try `m/44'/0'/0'` (wrong coin type)
   - Expected: warning screen for non-standard path

3. **Clear-signed transfer** (verified mode):
   - SystemProgram.Transfer instruction
   - OLED should show: "Transfer SOL", amount, destination (truncated base58)
   - Per-instruction confirmation screen

4. **SPL token transfer**:
   - Token program transfer instruction
   - If token metadata available: show symbol + amount
   - Otherwise: show token mint address

5. **Blind-sign** (opaque mode):
   - Send raw transaction bytes without parseable instructions
   - Expected: "Sign unverified Solana transaction?" warning
   - Requires SolBlindSign policy

6. **Message signing**:
   - `SolanaSignMessage` with arbitrary bytes
   - Verify Ed25519 signature with derived pubkey

7. **Multi-instruction transaction**:
   - Transaction with 3+ instructions
   - Each instruction gets its own confirmation screen

8. **Zoo screenshots**: Address display, transfer confirm, blind-sign warning

9. **Pass/Fail**: Address matches reference, clear-sign shows decoded instructions,
   blind-sign gated by policy, signatures verify externally

---

## PR #93 — TRON

**Curve**: secp256k1
**Path**: `m/44'/195'/account'/change/index`
**Address format**: Base58Check with 0x41 prefix (T-address)

### Test Vectors

```
Mnemonic: "all" x12
Path: m/44'/195'/0'/0/0
Expected address: T... (derive and record — compare with TronLink for same seed)
```

### Test Plan

1. **Address derivation**:
   - `TronGetAddress` with `show_display=True`
   - Verify T-prefixed Base58Check address on OLED
   - Cross-verify with TronLink or tronweb for same seed

2. **TRX transfer** (structured mode):
   - TransferContract with `to_address` and `amount`
   - OLED should show: "Send X TRX to\nTabc...xyz?"
   - Amount in TRX (divide by 1,000,000 from sun)

3. **TRC-20 token transfer**:
   - TriggerSmartContract with `transfer(address,uint256)` ABI
   - If known token (e.g., USDT at TR7NHq...): show symbol + amount
   - If unknown token: "Transfer unknown token at\ncontract_addr"

4. **Generic smart contract call**:
   - TriggerSmartContract with non-transfer method
   - Expected: "Call contract\naddr?\nCannot verify call data."

5. **Memo display**:
   - Transaction with memo/data field
   - Expected: hex preview (up to 32 bytes) shown before transfer confirm

6. **Fee limit confirmation**:
   - If fee_limit present: "Maximum fee:\nX TRX?"

7. **Legacy blind-sign** (raw_data only):
   - Send TronSignTx with only raw_data, no structured fields
   - Expected: "Sign unverified TRON transaction?" warning
   - Unverified hints shown if to_address/amount provided

8. **Invalid path**: Try `m/44'/60'/0'` (ETH path) → should reject

9. **Zoo screenshots**: Address, TRX transfer, TRC-20, blind-sign warning

10. **Pass/Fail**: Address matches reference, structured mode shows decoded
    fields, token lookup works, blind-sign warning displayed

---

## PR #94 — TON

**Curve**: Ed25519
**Path**: `m/44'/607'/account'` (all hardened)
**Address format**: Base64 URL-safe with CRC16-XMODEM (bounceable/non-bounceable)

### Test Vectors

```
Mnemonic: "all" x12
Path: m/44'/607'/0'
Expected address (bounceable): EQ... (derive and record)
Expected address (non-bounceable): UQ... (derive and record)
```

### Test Plan

1. **Bounceable address**:
   - `TonGetAddress` with `bounceable=True`, `show_display=True`
   - Expected: EQ-prefixed Base64 address on OLED
   - Cross-verify with Tonkeeper or ton-mnemonic-js for same seed

2. **Non-bounceable address**:
   - `TonGetAddress` with `bounceable=False`
   - Expected: UQ-prefixed address

3. **Testnet address**:
   - `TonGetAddress` with `testnet=True`
   - Expected: different tag byte in address encoding

4. **Workchain validation**:
   - workchain=0 (basechain) → success
   - workchain=-1 (masterchain) → success
   - workchain=2 → rejection

5. **Clear-signed transfer**:
   - Provide `to_address`, `amount`, and matching `raw_tx` hash
   - Device reconstructs v4r2 body cell hash and verifies match
   - OLED shows: "Send X TON to\nEQabc...xyz?"
   - No blind-sign warning (hash verified)

6. **Blind-signed transfer** (hash mismatch):
   - Provide `raw_tx` that doesn't match structured fields
   - Expected: "TON TX details cannot be verified on device.
     Sign only if you trust the sending app."

7. **Memo display**:
   - Transfer with memo/comment
   - Expected: memo shown in confirmation screen

8. **Zoo screenshots**: Bounceable addr, non-bounceable, clear-sign, blind-sign

9. **Pass/Fail**: Both address formats correct, clear-sign verifies hash,
   blind-sign shows warning, workchain validated

---

## PR #95 — Zcash Orchard

**Curves**: Ed25519 (Orchard/Pallas) + secp256k1 (transparent)
**Orchard path**: ZIP-32: `m_orchard/32'/133'/account'`
**Transparent path**: `m/44'/133'/account'/change/index`
**Protocol**: Multi-phase PCZT streaming

### Test Vectors

```
Mnemonic: "all" x12
Orchard path: [32|0x80000000, 133|0x80000000, 0|0x80000000]

Reference FVK (from orchard Rust crate):
  ak:   057ab051d4fbb0205d28648bacbc6471b533476c27beca33e5b9f511d855672b
  nk:   34a35a0bda50273b0319afa7a70f86b6b162eb311d263d8f6321def00228ba25
  rivk: 46bd2bd5e6eca5ef03e18cd76595519ea96706c5826a93ba4dca947d711a7c0a
```

### Test Plan

1. **FVK derivation** (ZcashGetOrchardFVK):
   - Request FVK for account 0
   - Verify ak, nk, rivk match reference vectors above
   - ak sign bit must be 0 (canonical)
   - nk < Pallas base field modulus p
   - rivk < Pallas scalar field modulus q

2. **FVK determinism**: Same seed + account → same FVK every time

3. **Different accounts**: account 0 vs account 1 produce different FVKs

4. **Shielded transaction signing** (ZcashSignPCZT):
   - Single Orchard action with host-provided sighash
   - Expected: "Sign shielded transaction?" with amount and fee
   - Response: 64-byte RedPallas signature

5. **Multi-action signing**:
   - 2+ Orchard actions streamed via ZcashPCZTAction
   - Progress bar displayed during signing
   - All signatures returned in final ZcashSignedPCZT

6. **Transparent shielding** (ZcashTransparentInput):
   - Phase 3: sign transparent UTXO inputs
   - Per-input confirmation: "Sign transparent input? Input N: X.XXXXXXXX ZEC"
   - Path enforcement: must match session account

7. **Path validation**:
   - Orchard: exactly 3 levels `[32', 133', account']`
   - Transparent: exactly 5 levels `[44', 133', account', change, index]`
   - Wrong path lengths → rejection

8. **Digest verification** (Phase 2b):
   - Provide header, transparent, sapling, orchard sub-digests
   - Device recomputes Orchard digest from streamed actions
   - Mismatch → signing aborted

9. **Constraints**:
   - >16 Orchard actions → rejection
   - >8 transparent inputs → rejection

10. **Zoo screenshots**: FVK request, shielded sign confirm, transparent
    input confirm, progress bar

11. **Pass/Fail**: FVK matches reference, signatures are 64 bytes and
    verify externally, path enforcement works, digest verification catches
    mismatches, constraints enforced
