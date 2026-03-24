# EVM Clear-Signing Device Screen Review

**Firmware PR**: #91
**Feature**: EVM clear-signing with signed metadata verification

---

## Verified Transaction

When the device holds valid signed metadata for the target contract, the transaction is decoded and displayed with full context.

### Screen Description

```
Insight Verified [icon]
Method: transferFrom
Contract: 0xA0b8...4e3B (full 42-char checksummed)
Parameters:
  from: 0x1234...
  to: 0x5678...
  amount: 1000000
```

- "Insight Verified" label with verification icon confirms metadata signature checked out
- Decoded method name replaces raw selector bytes
- Contract address displayed in full 42-character checksummed form (no truncation)
- Parameters decoded and labeled by name

### Verification Checklist

- [ ] "Insight Verified" label and icon displayed for valid metadata
- [ ] Method name decoded from ABI metadata
- [ ] Contract address shown in full (42 chars, checksummed)
- [ ] Parameters decoded and labeled
- [ ] Signed metadata verified against hardcoded public keys

---

## Opaque Transaction (Blind Sign)

When no valid metadata exists for the contract, the transaction cannot be decoded. Signing is gated by the AdvancedMode device policy.

### Screen Description

```
WARNING: Blind Signing
This transaction could not be verified.
Contract: 0xDEAD...BEEF
Data: 0xa9059cbb...
```

A prominent warning informs the user that the transaction content is unverified.

### Policy Enforcement

| AdvancedMode | Behavior                              |
|--------------|---------------------------------------|
| Disabled     | Transaction rejected outright         |
| Enabled      | Warning displayed, user may approve   |

### Verification Checklist

- [ ] Blind-sign warning displayed for unverified transactions
- [ ] Without AdvancedMode policy: signing rejected
- [ ] With AdvancedMode policy: warning shown, user can approve
- [ ] Raw calldata shown when decode is not possible

---

## Malformed Metadata

When metadata is present but structurally invalid or fails signature verification.

### Screen Description

```
Invalid
Metadata verification failed.
```

The device displays "Invalid" and rejects the signing request. No user override is possible for malformed metadata.

### Verification Checklist

- [ ] "Invalid" displayed for malformed metadata
- [ ] Signing rejected (no override path)
- [ ] Malformed metadata does not fall through to blind-sign flow

---

## Key Rotation

The `key_id` parameter selects which verification key slot (0-3) is used to check metadata signatures. This supports key rotation without firmware updates.

| Slot | Purpose                        |
|------|--------------------------------|
| 0    | Primary production key         |
| 1    | Rotation slot                  |
| 2    | Rotation slot                  |
| 3    | Rotation slot                  |

### Verification Checklist

- [ ] key_id 0-3 each select a distinct verification key
- [ ] Invalid key_id values rejected
- [ ] Metadata signed with rotated key verifies correctly

---

## Contract Address Display

The full 42-character checksummed address is always displayed on the OLED. Address truncation is explicitly avoided because truncation is a spoofing vector -- an attacker can craft addresses that match a truncated prefix/suffix.

### Verification Checklist

- [ ] Full 42-character address displayed (no ellipsis, no truncation)
- [ ] EIP-55 mixed-case checksum applied
- [ ] Address visible on-screen without scrolling artifacts

---

## Security Properties

| Property                     | Detail                                                           |
|------------------------------|------------------------------------------------------------------|
| Metadata signing             | Verified against hardcoded public keys (slots 0-3)               |
| Blind-sign gating            | AdvancedMode policy required for opaque transactions             |
| Address display              | Full 42 chars, checksummed -- no truncation                      |
| Known contract protection    | Prevents blind-signing of contracts with available metadata       |
| Key rotation                 | key_id parameter for slot selection without firmware update       |

### Verification Checklist

- [ ] Hardcoded public keys used for metadata verification
- [ ] No path exists to blind-sign a contract that has valid metadata
- [ ] Policy enforcement cannot be bypassed by the host
- [ ] Key rotation works without firmware reflash
