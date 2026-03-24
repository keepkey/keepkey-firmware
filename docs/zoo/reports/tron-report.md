# TRON Chain Support - Device Screen Review

**Firmware PR**: #93
**Chain**: TRON (TRX)
**Status**: Under Review

---

## Address Derivation

- **Path**: `m/44'/195'/0'/0/0`
- **Curve**: secp256k1
- **Format**: Base58Check T-address (e.g., `TJRyWwFs9w...`)
- **Path Validation**: Firmware rejects non-TRON paths (must be `44'/195'/...`)

### Device Screen

```
TRON Address
TJRyWwFs9wTFGZg3JbrVr...
```

### Verification Checklist

- [ ] Address displayed with correct `T` prefix
- [ ] Path `m/44'/195'/0'/0/0` accepted
- [ ] Non-TRON derivation paths rejected (e.g., `44'/60'/...`)
- [ ] Address matches external derivation tool output

---

## TRX Transfer (Structured)

Parsed from `TransferContract` in the transaction body. Amount is converted from SUN to TRX (divided by 1,000,000).

### Device Screen

```
Send 1.5 TRX to
Tabc...xyz?
```

### Verification Checklist

- [ ] Amount displayed in TRX (not SUN)
- [ ] Recipient address shown in full or truncated with visible prefix/suffix
- [ ] User prompted with confirm/reject buttons
- [ ] Zero-amount transfer displays correctly

---

## TRC-20 Token Transfer

Decoded from `TriggerSmartContract` with method signature `transfer(address,uint256)`.

### Known Token - Device Screen

```
Send 100 USDT to
Tabc...xyz?
```

### Unknown Token - Device Screen

```
Send token
Contract: TXyz...abc
Amount: 100000000
To: Tabc...xyz?
```

### Verification Checklist

- [ ] Known tokens (USDT, USDC, etc.) display symbol instead of contract address
- [ ] Unknown tokens show full contract address
- [ ] Amount decoded correctly from uint256
- [ ] Decimal adjustment applied for known tokens

---

## Smart Contract Call (Generic)

Any `TriggerSmartContract` that is not a recognized `transfer(address,uint256)` call.

### Device Screen

```
Call contract
Tabc...xyz?
Cannot verify call data.
```

### Verification Checklist

- [ ] Contract address displayed
- [ ] Warning about unverifiable call data shown
- [ ] User must explicitly confirm
- [ ] No misleading amount or recipient shown

---

## Memo Display

Hex-encoded memo data attached to the transaction. Up to 32 bytes displayed as a hex preview before the transfer confirmation.

### Device Screen

```
Memo (hex):
48656c6c6f20576f726c64...
```

### Verification Checklist

- [ ] Memo displayed before transfer confirmation screen
- [ ] Hex preview truncated at 32 bytes if longer
- [ ] Empty memo skips this screen
- [ ] Non-printable data rendered as hex without crash

---

## Fee Limit

Maximum fee the transaction is allowed to consume, displayed in TRX.

### Device Screen

```
Maximum fee: 10 TRX?
```

### Verification Checklist

- [ ] Fee limit shown in TRX (converted from SUN)
- [ ] Displayed before final confirmation
- [ ] Unreasonable fee limits trigger no silent acceptance

---

## Legacy Blind-Sign

When the host sends only `raw_data` without structured fields, the firmware cannot parse or verify transaction details.

### Device Screen

```
Sign unverified TRON
transaction?
```

### Verification Checklist

- [ ] Warning text clearly states "unverified"
- [ ] No amount or recipient displayed (none available)
- [ ] User must explicitly confirm blind signing
- [ ] Firmware does not crash on malformed raw_data

---

## Security Summary

| Check | Status |
|-------|--------|
| Path validation (`44'/195'/...`) enforced | Pending |
| Non-TRON paths rejected | Pending |
| SUN-to-TRX conversion correct | Pending |
| Known token symbol lookup | Pending |
| Blind-sign warning displayed | Pending |
| Memo preview before confirm | Pending |
| Fee limit shown to user | Pending |
| Generic contract call warning | Pending |
