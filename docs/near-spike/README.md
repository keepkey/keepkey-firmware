# NEAR Protocol Firmware Spike

Branch: `near-spike` (worktree at `projects/keepkey-firmware-near-spike/`)
Based on: `keepkey/alpha`

## What's in this spike

| File | Purpose |
|---|---|
| `docs/near-spike/messages-near.proto` | Proto definition (not yet in device-protocol) |
| `docs/near-spike/messages-near.options` | Nanopb size constraints |
| `include/keepkey/firmware/near.h` | Public API |
| `lib/firmware/near.c` | Address encoding + signing |
| `lib/firmware/fsm_msg_near.h` | FSM handlers (included by fsm.c) |
| `lib/firmware/messagemap.def` | Wired NearGetAddress + NearSignTx IN/OUT |

## Crypto decisions

**Ed25519 is already in trezor-crypto.** `curves.h` defines `ED25519_STRING`. `gpgMessageSign` in `crypto.c` already uses it. The primitive is present — no new crypto code needed.

**SLIP-0010 derivation** (hardened-only) is handled by `fsm_getDerivedNode(ED25519_NAME, ...)`. Same call as any other chain.

**Signing protocol:**
1. Host Borsh-serializes the `NearTransaction` struct
2. Sends raw bytes in `NearSignTx.raw_tx`
3. Firmware computes `SHA256(raw_tx)` → signs with `hdnode_sign_digest`
4. Returns 64-byte Ed25519 signature

This is identical to Solana's `raw_tx` approach. No Borsh parser needed in firmware.

**Address format:** Base58-encoded 32-byte Ed25519 public key. Same as Solana. `base58_encode_check` is already used throughout the firmware.

**Ed25519 pubkey layout:** trezor-crypto stores the 33-byte `node->public_key` with a `0x00` prefix byte followed by the 32-byte key. We strip byte 0 and use bytes 1–32.

## Derivation path

```
m/44'/397'/0'
```

SLIP-0044 coin type 397 = NEAR. All segments hardened (SLIP-0010 requirement for Ed25519).

## What still needs to happen before this builds

### 1. device-protocol: add proto and compile

```bash
# In keepkey-vault-v11/modules/device-protocol or a fork:
cp docs/near-spike/messages-near.proto ./messages-near.proto
cp docs/near-spike/messages-near.options ./messages-near.options

# Add MessageType enum values (messages.proto or messages-near.proto):
#   NearGetAddress    = 6xx  (check next available range)
#   NearAddress       = 6xx+1
#   NearSignTx        = 6xx+2
#   NearSignedTx      = 6xx+3

# Compile proto → nanopb .pb.h / .pb.c
make proto  # or whatever the device-protocol build target is
```

The generated `near.pb.h` satisfies the `#include "keepkey/firmware/near.pb.h"` in `near.h`.

### 2. fsm.c: add include and forward decl

In `lib/firmware/fsm.c`:

```c
// Near forward decls (alongside EOS block)
void fsm_msgNearGetAddress(const NearGetAddress *msg);
void fsm_msgNearSignTx(const NearSignTx *msg);
```

And at the bottom with the other fsm_msg includes:

```c
#include "keepkey/firmware/near.h"
#include "lib/firmware/fsm_msg_near.h"
```

### 3. CMakeLists.txt: add near.c to the firmware target

In `lib/firmware/CMakeLists.txt`, add `near.c` to the source list alongside `eos.c`:

```cmake
near.c
```

### 4. coins.def: add NEAR entry

The coin table entry for NEAR (for `fsm_getCoin` lookups):

```c
X(true, "NEAR", true, "NEAR", false, NA, true, 1000000, false, NA,
  false, "", true, 0x8000018D /*44'/397'*/, false, 0,
  true, 24, false, NO_CONTRACT, false, 0,
  false, false, false, false,
  true, "ed25519", false, "", false, "", false, false, false, 0, false, 0)
```

### 5. hdwallet (host side)

Add `hdwallet-near` package:
- `NearHDWallet` class
- `nearGetAddress(addressNList)` → calls `NearGetAddress` proto
- `nearSignTx(tx)` → Borsh-serializes tx, calls `NearSignTx` proto
- BIP-44 path helpers for coin type 397

## What the spike proves

- Ed25519 derivation path works with existing `fsm_getDerivedNode(ED25519_NAME, ...)`
- Base58 address encoding works (same API as used elsewhere)
- `hdnode_sign_digest` with SHA256-hashed input works for Ed25519
- The host-side Borsh model (send raw bytes, display fields separately) avoids firmware Borsh complexity
- MessageType numbering slot needs to be reserved in device-protocol

## NEAR vs Solana comparison

| Feature | Solana | NEAR |
|---|---|---|
| Curve | Ed25519 | Ed25519 |
| Derivation | SLIP-0010 | SLIP-0010 |
| BIP-44 coin | 501 | 397 |
| Address | Base58(pubkey) | Base58(pubkey) |
| Tx serialization | custom | Borsh |
| Pre-hash | SHA256 | SHA256 |
| Signature | 64 bytes | 64 bytes |

Implementation delta from Solana: essentially zero at the firmware crypto layer.
The only difference is the Borsh serialization format on the host side.

## Out of scope for this spike

- Named account resolution (`.near` accounts) — host-side lookup only
- Staking actions UI — need richer action parser
- Multi-action transactions — current proto takes host-rendered `action_display`
- FunctionCall argument display — blind signing for now
- NEAR Intents / chain abstraction — future work
