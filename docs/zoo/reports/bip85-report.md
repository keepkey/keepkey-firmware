# BIP-85 Device Screen Review

**Firmware PR**: #90
**Feature**: BIP-85 deterministic entropy / child mnemonic derivation

---

## Overview

BIP-85 derives child mnemonics from the device's master seed using a deterministic one-way function. The child mnemonic is displayed on the device OLED only and is never transmitted over USB.

**Derivation path**: `m/83696968'/39'/0'/word_count'/index'`

**KDF**: HMAC-SHA512 with key `"bip-entropy-from-k"`

---

## Mnemonic Display

The device derives and displays a 12, 18, or 24-word child mnemonic on the OLED screen.

### Screen Description (Phase 1 -- Display)

```
BIP-85 Mnemonic (12 words)
Index: 0

1. abandon  2. abandon
3. abandon  4. abandon
5. abandon  6. abandon
7. abandon  8. abandon
9. abandon  10. abandon
11. abandon 12. about
```

Words are shown on the device display for the user to record. The word count and index are shown for context.

### Screen Description (Phase 2 -- Confirm)

```
I have recorded
the BIP-85 mnemonic.

[Confirm]
```

A second button press confirms the user has recorded the mnemonic.

### Verification Checklist

- [ ] 12-word mnemonic displayed on OLED
- [ ] 18-word mnemonic displayed on OLED
- [ ] 24-word mnemonic displayed on OLED
- [ ] Words are legible and correctly numbered

---

## USB Response Security

The firmware returns a `Success` message over USB after the user confirms. The mnemonic itself is never serialized into the USB response.

### Verification Checklist

- [ ] USB response is `Success` (no mnemonic payload)
- [ ] Mnemonic never appears in USB traffic (protocol capture)
- [ ] No side-channel leakage of mnemonic in error responses

---

## Button Confirmation

Two separate `ButtonRequest` events are sent to the host during the flow:

| Step | ButtonRequest | Purpose                              |
|------|---------------|--------------------------------------|
| 1    | First         | Display mnemonic on OLED             |
| 2    | Second        | User confirms recording is complete  |

### Verification Checklist

- [ ] Two ButtonRequests sent (not one, not three)
- [ ] First ButtonRequest triggers mnemonic display
- [ ] Second ButtonRequest gates final confirmation

---

## Index Variation

Different index values produce different child mnemonics from the same master seed.

| Parameter   | Mnemonic Output   |
|-------------|-------------------|
| index = 0   | Mnemonic A        |
| index = 1   | Mnemonic B        |

The two outputs must be distinct for the same seed and word count.

### Verification Checklist

- [ ] index=0 and index=1 produce different mnemonics
- [ ] Same index always produces the same mnemonic (deterministic)

---

## Invalid Input Rejection

Unsupported word counts are rejected by the firmware.

| word_count | Result   |
|------------|----------|
| 12         | Accepted |
| 18         | Accepted |
| 24         | Accepted |
| 15         | Rejected |
| 0          | Rejected |
| 48         | Rejected |

### Verification Checklist

- [ ] word_count=12 accepted
- [ ] word_count=18 accepted
- [ ] word_count=24 accepted
- [ ] word_count=15 rejected with error
- [ ] Other invalid word counts rejected

---

## Determinism

Given the same master seed, word count, and index, the derived mnemonic is identical across invocations. This is a property of the HMAC-SHA512 KDF.

### Verification Checklist

- [ ] Same (seed, word_count, index) triple produces identical mnemonic on repeated calls
- [ ] Power cycling the device does not change the output

---

## Security Properties

| Property                  | Detail                                                        |
|---------------------------|---------------------------------------------------------------|
| KDF                       | HMAC-SHA512 with key `"bip-entropy-from-k"`                  |
| Derivation path           | `m/83696968'/39'/0'/word_count'/index'`                       |
| Mnemonic display          | OLED only -- never serialized to USB                          |
| USB response              | `Success` message (no entropy payload)                        |
| Seed access               | Internal only -- master seed never leaves device              |
| One-way derivation        | Child mnemonic cannot be used to recover master seed          |

### Verification Checklist

- [ ] HMAC-SHA512 used with correct key string
- [ ] Derivation path matches BIP-85 specification
- [ ] Mnemonic never leaves device over any interface
- [ ] Child mnemonic cannot reverse-derive master seed
- [ ] Master seed access is internal-only (no USB exposure)
