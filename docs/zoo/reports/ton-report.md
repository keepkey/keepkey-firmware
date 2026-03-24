# TON Chain Support - Device Screen Review

**Firmware PR**: #94
**Chain**: TON (The Open Network)
**Status**: Under Review

---

## Address Derivation

- **Path**: `m/44'/607'/0'`
- **Curve**: Ed25519
- **Bounceable Format**: `EQ` prefix, Base64 URL-safe encoding
- **Non-Bounceable Format**: `UQ` prefix, Base64 URL-safe encoding
- **Testnet**: Different tag byte (bounceable `0x91`, non-bounceable `0x51`)

### Bounceable Address - Device Screen

```
TON Address (bounceable)
EQabc1234def5678...xyz
```

### Non-Bounceable Address - Device Screen

```
TON Address (non-bounceable)
UQabc1234def5678...xyz
```

### Verification Checklist

- [ ] Bounceable address displayed with `EQ` prefix
- [ ] Non-bounceable address displayed with `UQ` prefix
- [ ] Testnet addresses use correct tag bytes
- [ ] Path `m/44'/607'/0'` accepted
- [ ] Non-TON derivation paths rejected
- [ ] Address matches external derivation tool output

---

## Workchain Validation

TON supports multiple workchains. The firmware validates the workchain ID before signing.

| Workchain | ID | Status |
|-----------|-----|--------|
| Basechain | `0` | Allowed |
| Masterchain | `-1` | Allowed |
| Other | Any other value | Rejected |

### Rejection - Device Screen

```
Error: invalid workchain
```

### Verification Checklist

- [ ] Workchain `0` (basechain) accepted
- [ ] Workchain `-1` (masterchain) accepted
- [ ] All other workchain IDs rejected with error
- [ ] No crash on unexpected workchain values

---

## Clear-Signed Transfer

The device reconstructs the wallet v4r2 body cell hash from the structured fields (amount, destination, memo) and verifies it against the hash of the provided `raw_tx`. If the hashes match, the transaction details are displayed with full verification.

### Device Screen

```
Send 1.5 TON to
EQabc...xyz?
```

### With Memo

```
Memo: Payment for services

Send 1.5 TON to
EQabc...xyz?
```

### Verification Checklist

- [ ] Amount displayed in TON (not nanoTON)
- [ ] Recipient address shown with prefix
- [ ] Hash verification passes for well-formed transactions
- [ ] Memo displayed on confirmation screen when present
- [ ] Empty memo skips memo screen
- [ ] Confirm/reject buttons functional

---

## Blind-Signed Transfer

When the device-reconstructed cell hash does not match the `raw_tx` hash, the firmware falls back to blind signing with an explicit warning. This prevents silent MITM attacks while still allowing the user to proceed if they trust the sending application.

### Device Screen

```
TON TX details cannot be
verified on device.

Sign only if you trust
the sending app.
```

### Verification Checklist

- [ ] Warning displayed when hash mismatch detected
- [ ] No amount or recipient shown (cannot be trusted)
- [ ] User must explicitly confirm to proceed
- [ ] Rejecting returns failure to host
- [ ] Tampered structured fields trigger blind-sign path (not clear-sign)

---

## Memo Display

Memo text is shown in the confirmation screen before the transfer details when using clear-signed mode.

### Device Screen

```
Memo: Hello World
```

### Verification Checklist

- [ ] Memo displayed before amount/recipient confirmation
- [ ] Long memos truncated or paginated
- [ ] Empty memo omits memo screen entirely
- [ ] Special characters rendered without crash

---

## Clear-Sign Hash Verification (Security Detail)

The core security mechanism for TON transaction signing:

1. Host sends structured fields (amount, destination, memo) plus `raw_tx` (serialized BOC)
2. Device reconstructs the wallet v4r2 internal message body cell
3. Device computes SHA-256 hash of the reconstructed cell
4. Device computes SHA-256 hash of the body cell extracted from `raw_tx`
5. If hashes match: **clear-sign** path (show verified details)
6. If hashes differ: **blind-sign** path (show warning)

This prevents a compromised host from showing one transaction in the UI while sending a different one to the device for signing.

### Verification Checklist

- [ ] Matching hashes produce clear-sign flow
- [ ] Mismatched hashes produce blind-sign warning
- [ ] Reconstructed cell uses correct v4r2 wallet format
- [ ] Hash comparison is constant-time (no timing leak)
- [ ] Malformed `raw_tx` triggers blind-sign (not crash)

---

## Security Summary

| Check | Status |
|-------|--------|
| Path validation (`44'/607'/...`) enforced | Pending |
| Ed25519 curve used | Pending |
| Workchain ID validated (0 and -1 only) | Pending |
| Bounceable/non-bounceable prefixes correct | Pending |
| Clear-sign hash verification functional | Pending |
| Blind-sign warning displayed on mismatch | Pending |
| Memo shown in confirmation | Pending |
| Tampered fields detected via hash check | Pending |
| Testnet tag bytes correct | Pending |
