# Zcash Orchard Device Screen Review

**Firmware PR**: #95
**Feature**: Zcash Orchard shielded transaction support (ZIP-32 / PCZT)

---

## FVK Derivation

**Path**: `[32', 133', account']` (ZIP-32, exactly 3 levels)

The device derives the Full Viewing Key components from the master seed using ZIP-32 key derivation. The FVK is safe to export because it grants view-only access and cannot authorize spending.

**Returned components**:
- `ak` (authorizing key, public)
- `nk` (nullifier key)
- `rivk` (randomized internal viewing key)

**Reference FVK** (mnemonic: "all" x12):
- `ak = 057ab051...`
- `nk = 34a35a0b...`
- `rivk = 46bd2bd5...`

### Screen Description

The device displays the derived FVK components for user verification against a known-good reference.

### Verification Checklist

- [ ] FVK derivation returns ak, nk, rivk
- [ ] Path enforced to exactly 3 levels (Orchard spec)
- [ ] Reference mnemonic ("all" x12) produces expected FVK values
- [ ] Seed never leaves device (storage_getRawSeed internal only)

---

## Shielded Sign (PCZT)

Multi-phase streaming protocol for signing shielded transactions using the Partially Created Zcash Transaction format.

### Screen Description

```
Sign shielded transaction?
Amount: X ZEC
Fee: Y ZEC
Actions: N
```

The device presents a single confirmation screen summarizing the full shielded transaction before signing begins.

### Progress Bar

`layoutProgress` renders a progress bar on the OLED during Orchard action streaming, giving the user visual feedback as each action is processed.

### Verification Checklist

- [ ] Confirmation screen shows amount, fee, and action count
- [ ] Progress bar updates during action streaming
- [ ] Device recomputes Orchard digest from streamed actions
- [ ] Transaction aborts if recomputed digest does not match host-provided digest

---

## Transparent Shielding

Per-input confirmation for transparent inputs being shielded.

### Screen Description

```
Sign transparent input?
Input N: X.XXXXXXXX ZEC
```

Each transparent input is confirmed individually on-device before inclusion.

### Verification Checklist

- [ ] Each transparent input gets its own confirmation screen
- [ ] Input index (N) and amount displayed per input
- [ ] Transparent paths enforced to exactly 5 levels (BIP-44)

---

## Path Enforcement

| Path Type     | Required Depth | Format                          |
|---------------|----------------|---------------------------------|
| Orchard       | Exactly 3      | `[32', 133', account']`         |
| Transparent   | Exactly 5      | BIP-44 `m/44'/133'/a'/c/i`      |

Invalid path depths are rejected before any key material is derived.

### Verification Checklist

- [ ] Orchard paths with fewer or more than 3 levels rejected
- [ ] Transparent paths with fewer or more than 5 levels rejected

---

## Digest Verification

The device independently recomputes the Orchard digest from the streamed action data. If the locally computed digest does not match the digest provided by the host, the transaction is aborted.

This prevents a malicious host from substituting actions after the user has confirmed the transaction summary.

### Verification Checklist

- [ ] Device recomputes digest from streamed actions
- [ ] Mismatch between host digest and device digest aborts signing
- [ ] No partial signatures are released on digest mismatch

---

## Constraints

| Limit                    | Value |
|--------------------------|-------|
| Max Orchard actions      | 16    |
| Max transparent inputs   | 8     |

Transactions exceeding these limits are rejected.

### Verification Checklist

- [ ] Transaction with >16 Orchard actions rejected
- [ ] Transaction with >8 transparent inputs rejected

---

## Security Properties

| Property                  | Detail                                                        |
|---------------------------|---------------------------------------------------------------|
| Curve                     | Pallas / RedPallas                                            |
| Seed access               | `storage_getRawSeed()` -- seed never leaves device            |
| Account path pinning      | Prevents host from pivoting to a different account after FVK  |
| Key derivation            | ZIP-32 HMAC-based hierarchical derivation                     |

### Verification Checklist

- [ ] Seed material never appears in USB responses
- [ ] Account path pinning prevents host pivot attacks
- [ ] Pallas curve operations execute correctly on-device
- [ ] FVK export does not leak spending authority
