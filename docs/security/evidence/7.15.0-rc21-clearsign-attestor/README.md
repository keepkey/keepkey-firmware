# RC21 ClearSign Attestor OLED Evidence

These are pixel captures from the firmware emulator's real 256x64 framebuffer,
read through `DebugLinkGetState`; they are not UI mockups. The boundary schema
contains a 44-character base58 program ID, an 8-byte discriminator, every
supported argument type, 20-character program and instruction names,
16-character argument labels, and a 16-character account label.

The sequence proves that each security-relevant declaration is independently
reviewable before the device returns an attestation signature:

1. `01-schema-identity.png` — full 20-character program and instruction names;
2. `02-program-id-44chars.png` — complete program ID across two rows;
3. `03-discriminator-8bytes.png` — complete 16-hex-character discriminator;
4. `04-arg-u64-le-16char-label.png` — `u64 LE` and its full label;
5. `05-arg-u8-16char-label.png` — `u8` and its full label;
6. `06-arg-public-key-16char-label.png` — `public key` and its full label;
7. `07-arg-bytes32-hex-16char-label.png` — `bytes32 hex` and its full label;
8. `08-account-16char-label.png` — account index and its full label.

`manifest.json` records the exact firmware and device-protocol commits and all
boundary inputs. Reproduce the capture against an isolated emulator with:

```sh
python3 scripts/emulator/capture-clearsign-attestor.py \
  --main 127.0.0.1:12044 \
  --debug 127.0.0.1:12045 \
  --output docs/security/evidence/7.15.0-rc21-clearsign-attestor
```

The capture tool wipes and initializes the addressed emulator. Never point it
at hardware or an emulator instance containing state that must be preserved.
