# 7.15.0-rc26 — Taproot witness serialization and long-address display

Gate-3 OLED evidence for the two defects rc25 shipped, both fixed in rc26.

Captured from the emulator built at this branch, driven by python-keepkey with
`KEEPKEY_SCREENSHOT=1`. Seed throughout is the standard BIP-39 test vector
`abandon abandon ... about`, so every address below is a published BIP-86
value and can be checked independently.

> Emulator captures. Per the release SOP these do **not** substitute for
> on-device Gate-3 proof; they establish that the rendering logic is correct
> before anyone picks up a device.

## What rc25 got wrong

**1. Addresses longer than one line were silently truncated.**
`draw_string()` stopped at the bottom of the canvas and dropped the rest, so the
user verified a 42-character prefix while the QR code beside it encoded the whole
address — the two disagreed with no indication. This became urgent the moment
rc25 shipped Taproot, because every `bc1p` address is 62 characters.

`01` shows `m/86'/0'/0'/0/0` rendering the complete
`bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr`
across two lines, matching the QR. `02` shows the same fix for P2WSH multisig,
which had the identical defect before Taproot existed.

**2. The witness and locktime never reached the host.**
The Taproot signing branch set `has_signature` but not `has_serialized_tx`, so
nanopb omitted `serialized_tx` entirely and 70 bytes — the 66-byte witness plus
the 4-byte locktime footer — were dropped on the wire. The signature itself was
always correct, which is why every test passed.

`03`–`08` are the confirm screens for the three signing flows that now also
assert the full BIP-144 serialization. They prove the amount, destination and
fee shown to the user are unchanged by that fix.

## Frames

| File | Screen |
|---|---|
| `01-p2tr-address-full-62-chars.png` | BIP-86 receive address, complete, with QR |
| `02-p2wsh-address-full.png` | P2WSH multisig address, complete |
| `03-p2tr-spend-recipient.png` | `Send 0.0009 BTC to 1BitcoinEater…` |
| `04-p2tr-spend-fee.png` | Total `0.001 BTC`, fee `0.0001 BTC` |
| `05-p2tr-change-recipient.png` | Recipient, device-derived P2TR change omitted |
| `06-p2tr-change-fee.png` | Fee confirmation, change flow |
| `07-mixed-p2tr-legacy-recipient.png` | Recipient, mixed Taproot + legacy inputs |
| `08-mixed-p2tr-legacy-fee.png` | Fee confirmation, mixed inputs |

## Reproducing

```sh
cd scripts/emulator
docker compose build kkemu && docker compose up -d kkemu
docker compose run --rm -v "$PWD/out:/out" --entrypoint /bin/sh python-keepkey -c '
  cd /kkemu/deps/python-keepkey/tests && export PYTHONPATH=".."
  KEEPKEY_SCREENSHOT=1 SCREENSHOT_DIR=/out \
  KK_TRANSPORT_MAIN=kkemu:11044 KK_TRANSPORT_DEBUG=kkemu:11045 \
    python3 -m pytest test_msg_signtx_taproot.py test_msg_getaddress_taproot.py \
                      test_taproot_screens.py -q'
```

Frames land in `$SCREENSHOT_DIR/<module>/<test_name>/btnNNNNN.png`.

## Still owed

On-device Gate-3 for both flows: display a `bc1p` receive address and compare it
character-for-character against the QR, then spend a P2TR input and confirm the
amount, destination and fee screens appear and require a press.
