# Solana Chain Support - Device Screen Review

**Firmware PR**: #92
**Chain**: Solana (SOL)
**Status**: Under Review

---

## Address Derivation

- **Path**: `m/44'/501'/account'` (3-level) or `m/44'/501'/account'/change'` (4-level)
- **Curve**: Ed25519
- **Format**: Raw Base58-encoded 32-byte public key (32-44 characters, no checksum)
- **Path Validation**: All path components must be hardened; non-standard paths trigger an on-device warning

### Device Screen

```
Solana Address
GjJyeC1r2RgGSXCnMkzz...VkXMhDPF5QLQ
```

Full Base58 address is displayed without truncation. The `confirm_ethereum_address()` layout is reused with "Solana" as the descriptor. Addresses are 32-44 characters; the OLED renders the full string across multiple lines.

### Verification Checklist

- [ ] Address displayed in full Base58 (no truncation -- truncation is a spoofing vector)
- [ ] Path `m/44'/501'/0'` accepted without warning
- [ ] Path `m/44'/501'/0'/0'` accepted without warning
- [ ] Non-standard path (e.g., `m/44'/60'/0'`) triggers "Non-standard Solana derivation path. Continue?" warning
- [ ] Non-hardened path components rejected (e.g., `m/44'/501'/0`)
- [ ] Path with fewer than 3 or more than 4 components triggers warning
- [ ] Address matches external derivation from same seed (Phantom, solana-keygen, solana-py)
- [ ] Different account indices produce different addresses
- [ ] Same path produces identical address on repeated calls (deterministic)

---

## SOL Transfer (Clear-signed)

Firmware parses `SystemProgram.Transfer` (instruction type 2) from the serialized transaction. Amount is converted from lamports to SOL (divided by 1,000,000,000).

### Device Screen

```
Instr 1/1
Send 1.000000000 SOL to
GjJyeC1r2RgGSXCnMkzz...VkXMhDPF5QLQ?
```

### Verification Checklist

- [ ] Header shows instruction counter ("Instr 1/1" for single-instruction tx)
- [ ] Amount displayed in SOL with 9 decimal places
- [ ] Recipient address displayed in full Base58
- [ ] Zero-amount transfer displays "0.000000000 SOL"
- [ ] User prompted with confirm/reject buttons
- [ ] Final "Sign this Solana transaction?" confirmation follows instruction screen

---

## SPL Token Transfer

Firmware decodes both `TokenProgram.Transfer` (instruction 3) and `TokenProgram.TransferChecked` (instruction 12). Supports both Token Program and Token-2022 Program.

### Known Token - Device Screen

When `SolanaTokenInfo` metadata is provided by the host (symbol + decimals):

```
Instr 1/1
Send 100.000000 USDC to
GjJyeC1r2RgGSXCnMkzz...VkXMhDPF5QLQ?
```

### Unknown Token - Device Screen

When no token metadata matches the mint address:

```
Instr 1/1
Send 100000000 tokens to
GjJyeC1r2RgGSXCnMkzz...VkXMhDPF5QLQ?
```

### Verification Checklist

- [ ] Known token displays symbol and decimal-adjusted amount (e.g., "100.000000 USDC")
- [ ] Unknown token displays raw integer amount with "tokens" suffix
- [ ] Token metadata matched by 32-byte mint pubkey from `SolanaTokenInfo` in `SolanaSignTx`
- [ ] Up to 4 `token_info` entries accepted per transaction
- [ ] TransferChecked instruction extracts mint from account index 1
- [ ] Destination address shown in full Base58

---

## System Program Instructions (Clear-signed)

The firmware parses 8 System Program instruction types.

| Instruction | Device Prompt | Fields Shown |
|---|---|---|
| Transfer (type 2) | "Send {amount} to {address}?" | SOL amount, recipient |
| CreateAccount (type 0) | "Create account with {amount}?" | SOL amount |
| AdvanceNonce (type 4) | "Advance nonce account?" | -- |
| WithdrawNonce (type 5) | "Withdraw nonce {amount} to {address}?" | SOL amount, recipient |
| InitializeNonce (type 6) | "Initialize nonce account?" | -- |
| AuthorizeNonce (type 7) | "Authorize nonce to {address}?" | New authority |
| Assign (type 1) | "Assign account to {address}?" | Program address |
| Allocate (type 8) | "Allocate {n} bytes?" | Byte count |

### Verification Checklist

- [ ] Each System Program instruction type displays the correct prompt text
- [ ] SOL amounts formatted with 9 decimal places
- [ ] Addresses displayed in full Base58

---

## Token Program Instructions (Clear-signed)

The firmware parses 11 Token Program instruction types (applies to both Token and Token-2022 programs).

| Instruction | Device Prompt | Fields Shown |
|---|---|---|
| Transfer (3) | "Send {amount} to {address}?" | Token amount, recipient |
| TransferChecked (12) | "Send {amount} to {address}?" | Decimal-adjusted amount, recipient |
| Approve (4) | "Approve {amount} tokens to {address}?" | Amount, delegate |
| Revoke (5) | "Revoke token approval?" | -- |
| SetAuthority (6) | "Set token authority to {address}?" | New authority |
| MintTo (7, 14) | "Mint {amount} tokens?" | Amount |
| Burn (8, 15) | "Burn {amount} tokens?" | Amount |
| CloseAccount (9) | "Close token account?" | -- |
| FreezeAccount (10) | "Freeze token account?" | -- |
| ThawAccount (11) | "Thaw token account?" | -- |
| SyncNative (17) | "Sync wrapped SOL?" | -- |

### Verification Checklist

- [ ] Token-2022 program treated identically to Token program
- [ ] MintToChecked (14) and BurnChecked (15) recognized
- [ ] Approve shows delegate address and amount
- [ ] CloseAccount/FreezeAccount/ThawAccount show confirmation without extra fields

---

## Stake Program Instructions (Clear-signed)

| Instruction | Device Prompt | Fields Shown |
|---|---|---|
| Delegate (2) | "Delegate stake?" | -- |
| Withdraw (4) | "Withdraw {amount} from stake?" | SOL amount |
| Authorize (1) | "Authorize stake to {address}?" | New authority |
| Split (3) | "Split stake by {amount}?" | SOL amount |
| Deactivate (5) | "Deactivate stake?" | -- |
| Merge (7) | "Merge stake accounts?" | -- |

### Verification Checklist

- [ ] Stake delegation shows confirmation prompt
- [ ] Withdraw and Split display SOL amount
- [ ] Authorize shows new authority address

---

## Vote Program Instructions (Clear-signed)

| Instruction | Device Prompt | Fields Shown |
|---|---|---|
| Authorize (1) | "Authorize vote to {address}?" | New authority |
| Withdraw (3) | "Withdraw vote {amount}?" | SOL amount |
| UpdateValidator (4) | "Update validator to {address}?" | Validator identity |
| UpdateCommission (5) | "Set vote commission to {n}%?" | Commission percentage |

### Verification Checklist

- [ ] Commission percentage shown as integer with `%` suffix
- [ ] Validator identity shown in full Base58

---

## Utility Instructions (Clear-signed)

| Program | Instruction | Device Prompt |
|---|---|---|
| ATA Program | Create (0) | "Create associated token account?" |
| Compute Budget | RequestHeapFrame (1) | "Set heap frame to {n} bytes?" |
| Compute Budget | SetComputeUnitLimit (2) | "Set compute unit limit to {n}?" |
| Compute Budget | SetComputeUnitPrice (3) | "Set compute unit price to {n}?" |
| Compute Budget | SetLoadedAccountsDataSize (4) | "Set loaded account data to {n} bytes?" |
| Memo Program | (any) | "Memo attached" |

### Verification Checklist

- [ ] ATA create shows confirmation without amount
- [ ] Compute budget values displayed as raw integers
- [ ] Memo program recognized without instruction data parsing

---

## Blind-Sign Warning

When the firmware cannot fully parse the transaction (unknown instructions, >8 instructions, versioned/v0 transactions with address lookup tables, or >32 accounts), it falls back to opaque signing.

### Prerequisites

Blind signing requires the `AdvancedMode` policy to be enabled on the device (storage bit 12). If not enabled, the firmware rejects with "Enable AdvancedMode to blind-sign".

### Device Screen

```
Blind Sign
Sign unverified Solana transaction?
The device cannot fully verify the contents.
```

Followed by the final confirmation:

```
Solana
Sign this Solana transaction?
```

### Unknown Instruction Screen

Individual unknown instructions within an otherwise parseable transaction show:

```
Instr 2/3
Unknown instruction to program
GjJyeC1r2RgGSXCnMkzz...VkXMhDPF5QLQ.
Cannot verify contents.
```

### Verification Checklist

- [ ] Blind-sign warning explicitly says "unverified" and "cannot fully verify"
- [ ] AdvancedMode policy must be enabled; disabled policy returns Failure
- [ ] Versioned (v0) transactions always treated as opaque (blind-sign required)
- [ ] Transactions with >8 instructions treated as opaque
- [ ] Transactions with >32 accounts treated as opaque
- [ ] Unknown program IDs within a verified tx show program address + warning per-instruction
- [ ] Malformed transactions rejected outright (not offered for blind-sign)
- [ ] Trailing bytes after instruction section cause MALFORMED rejection

---

## Message Signing

Ed25519 signature over arbitrary message bytes. The device displays the message content on screen before signing.

### Printable Message - Device Screen

```
Sign Message
Hello Solana!
```

### Binary/Long Message - Device Screen

When the message contains non-printable bytes or exceeds the display buffer:

```
Sign Bytes
48656c6c6f20576f726c64...
(128 bytes)
```

Up to 32 bytes shown as hex (64 hex characters). Messages longer than 32 bytes append a `... (N bytes)` suffix.

### Verification Checklist

- [ ] Printable ASCII messages (0x20-0x7E) displayed as text
- [ ] Non-printable messages displayed as hex preview
- [ ] Hex preview limited to first 32 bytes
- [ ] Byte count shown for messages exceeding preview length
- [ ] Empty message rejected with "Missing message" error
- [ ] Response contains both 64-byte signature and 32-byte public key
- [ ] Non-standard derivation path triggers warning before message display

---

## Multi-Instruction Transactions

Each instruction in the transaction gets its own confirmation screen. The user scrolls through all instructions sequentially before the final confirmation.

### Device Screen Flow

```
Instr 1/3                          <- Compute budget
Set compute unit price to 50000?

Instr 2/3                          <- ATA create
Create associated token account?

Instr 3/3                          <- Token transfer
Send 100.000000 USDC to
GjJyeC1r2RgGSXCnMkzz...VkXMhDPF5QLQ?

Solana                             <- Final confirmation
Sign this Solana transaction?
```

### Verification Checklist

- [ ] Instruction counter "Instr N/M" shown on each screen
- [ ] Each instruction individually cancellable
- [ ] Final "Sign this Solana transaction?" screen shown after all instructions
- [ ] Maximum 8 instructions for clear-signed flow; >8 forces opaque/blind-sign
- [ ] Cancelling any instruction aborts the entire transaction

---

## Signer Verification

The firmware verifies that the derived Ed25519 public key appears in the transaction's required signer slots (`accounts[0..num_required_sigs)`).

### Verification Checklist

- [ ] Verified transactions: signing rejected if derived key is not a required signer
- [ ] Opaque transactions: signer check applied when header was parseable (num_accounts > 0)
- [ ] Error message: "Derived key is not a signer for this tx"
- [ ] Public key compared is `node->public_key + 1` (skip 0x00 Ed25519 prefix byte)

---

## Security Summary

| Check | Status |
|---|---|
| Ed25519 derivation on hardened path (`44'/501'/...`) | Pending |
| Non-standard path warning displayed | Pending |
| All path components required hardened | Pending |
| Signer verification against tx header | Pending |
| 35 instruction types clear-signed | Pending |
| Unknown instructions show program ID + warning | Pending |
| Blind-sign gated by AdvancedMode policy | Pending |
| Versioned (v0) transactions forced opaque | Pending |
| >8 instructions forced opaque | Pending |
| >32 accounts forced opaque | Pending |
| Malformed tx rejected (not blind-signed) | Pending |
| Trailing bytes cause MALFORMED rejection | Pending |
| SOL amount formatted with 9 decimal places | Pending |
| Token metadata lookup by mint pubkey | Pending |
| Message signing shows content preview | Pending |
| Full Base58 address display (no truncation) | Pending |
| Token-2022 program recognized | Pending |
| Ed25519 signatures deterministic | Pending |

---

## Recognized Programs

| Program | Program ID | Instructions Parsed |
|---|---|---|
| System Program | `11111111111111111111111111111111` | 8 |
| Token Program | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` | 11 |
| Token-2022 Program | `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` | 11 |
| Stake Program | `Stake11111111111111111111111111111111111111` | 6 |
| Vote Program | `Vote111111111111111111111111111111111111111` | 4 |
| ATA Program | `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL` | 1 |
| Compute Budget | `ComputeBudget111111111111111111111111111111` | 4 |
| Memo Program | `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` | 1 |
| **Total** | | **35 (+1 unknown fallback)** |

---

## Test Vectors

```
Mnemonic: "all all all all all all all all all all all all"
Path:     m/44'/501'/0'/0'
Curve:    Ed25519
```

### Python Test Coverage

| Test | File | Description |
|---|---|---|
| `test_solana_get_address` | `test_msg_solana_getaddress.py` | Standard path derivation |
| `test_solana_different_accounts` | `test_msg_solana_getaddress.py` | Account index produces unique address |
| `test_solana_deterministic` | `test_msg_solana_getaddress.py` | Same path = same address |
| `test_solana_sign_system_transfer` | `test_msg_solana_signtx.py` | SystemProgram.Transfer signing |
| `test_solana_sign_message` | `test_msg_solana_signtx.py` | Arbitrary message signing |
| `test_solana_sign_empty_rejected` | `test_msg_solana_signtx.py` | Empty raw_tx rejected |
| `test_solana_sign_deterministic` | `test_msg_solana_signtx.py` | Same tx = same signature |

### Cross-Verification

- [ ] Derive address from "all" x12 mnemonic at `m/44'/501'/0'` and compare with Phantom wallet
- [ ] Derive at `m/44'/501'/0'/0'` and compare with solana-keygen
- [ ] Sign a known message and verify signature externally with `ed25519.verify()`
- [ ] Build and sign a transfer tx, submit to devnet, verify on-chain

---

## Protobuf Messages

| Message | Direction | Fields |
|---|---|---|
| `SolanaGetAddress` | Host -> Device | `address_n[]`, `coin_name`, `show_display` |
| `SolanaAddress` | Device -> Host | `address` (Base58 string) |
| `SolanaSignTx` | Host -> Device | `address_n[]`, `coin_name`, `raw_tx`, `token_info[]` (max 4) |
| `SolanaSignedTx` | Device -> Host | `signature` (64 bytes) |
| `SolanaSignMessage` | Host -> Device | `address_n[]`, `coin_name`, `message`, `show_display` |
| `SolanaMessageSignature` | Device -> Host | `public_key` (32 bytes), `signature` (64 bytes) |
| `SolanaTokenInfo` | (embedded) | `mint` (32 bytes), `symbol` (max 12 chars), `decimals` |

---

## Source Files

| File | Purpose |
|---|---|
| `include/keepkey/firmware/solana.h` | Type definitions, parsed instruction struct, API declarations |
| `lib/firmware/solana.c` | Transaction parser, amount formatters, Ed25519 signing |
| `lib/firmware/fsm_msg_solana.h` | FSM handlers: GetAddress, SignTx, SignMessage |
| `deps/device-protocol/messages-solana.proto` | Protobuf message definitions |
| `deps/device-protocol/messages-solana.options` | Nanopb size constraints |
| `deps/python-keepkey/tests/test_msg_solana_getaddress.py` | Address derivation tests |
| `deps/python-keepkey/tests/test_msg_solana_signtx.py` | Transaction and message signing tests |
