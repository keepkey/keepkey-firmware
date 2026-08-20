# T12 — altcoin amount and address binding (#408, #438, #407, #406, #430)

Device: 7.14.2, all-all-all seed, no PIN, no passphrase, AdvancedMode OFF.

## VERDICT: 7 of 8 required steps PASS. Step D (Solana SPL) NOT RUN.

| step | payload | result |
|---|---|---|
| A1 | 1234567 uosmo | PASS signed |
| A2 | **1 uosmo** — the `base_to_precision` digit-drop test | PASS signed |
| A3 | 123456789012345678 uion (non-uosmo denom) | PASS signed |
| A4 | 68-char `ibc/2739…5EB2` denom | signed (informational, see below) |
| A5 | incomplete MsgSend | PASS `Failure 'Message is missing required parameters'`, no screen |
| B | LP add, 18 fractional digits | PASS signed |
| C | **Cosmos IBC transfer** | PASS signed |
| D | Solana SPL | **NOT RUN** |
| E | **31-char Binance denom (#430)** | PASS signed, no reboot |

## What each step defends

**A2** — `strlcpy(dst,src,n)` copied `n-1` digits, dropping the last, and wrote
`dest[dest_len]`, one past the caller's buffer. The screen must read
`0.000001 OSMO`; five zeros means the digit-drop is live.

**A3** — before, `float amount = atof(...)` then `"%.6f %s"`: non-`uosmo` denoms
were never divided but still got a `.000000` tail, float32 lost everything past
~8 significant digits, **and `osmosis.c` hardcoded `"denom":"uosmo"` into the
SIGNED amino doc regardless of what was displayed.**

**C** — before, ONE screen `Transfer %s to %s?` fed with
`msg->ibc_transfer.sender`: the sender printed in the destination slot, and the
signed receiver was never displayed at all. Now three screens with distinct
bodies.

**E** — `char denom_str[14]` with `snprintf(denom_str, strlen(denom)+2, " %s",
denom)`: a 31-char denom is a 33-byte write into 14 bytes, a 19-byte stack
overflow. Device signed and did not reboot.

## A4 — informational, file against #428 not #408

`confirm_transaction_output` goes through `layout_notification_no_title_bold`,
which `confirm_helper()` does NOT measure (it only measures
`layout_standard_notification`), so a 129-char body clips with no `CUT OFF`.
**The denom displayed IS the one being hashed**, so this is a rendering gap, not
a binding defect. Record the exact last character shown against #428.

## Step D not run

Step D hand-builds a Solana message (header bytes, account index table,
instruction data). The plan flags it as fragile: if the layout is off the device
errors before drawing anything — a harness failure, not a firmware finding.
Not attempted rather than recorded as a false result.

**Whole-test pass requires A1, A2, A3, A5, B, C, D, E — so T12 is INCOMPLETE
until D runs.** Seven of the eight required steps pass.

## Harness bugs (proto field types, all silent until they throw)

- `CosmosMsgIBCTransfer.revision_height` / `.revision_number` are **strings**
- `CosmosMsgIBCTransfer.amount` is **uint64**, not a string
- `BinanceTransferMsg.BinanceInputOutput.address` is a **bech32 string**, not 20
  raw bytes. Passing bytes yields `'Failed to include transfer message in
  transaction'` — which looks like a firmware refusal but is not one.

## Photo checks with the tester

A2 `0.000001 OSMO` (six digits, last a 1) · A3 all 18 digits with no decimal
point and no `.000000` tail · B `1.234567890123456789 GAMM-1 shares?` (eighteen
fractional digits) · C screen 3 `Confirm dest. address` showing
`osmo18vhdczj…` and NOT `cosmos15cenya…` · E all 31 denom chars legible.
