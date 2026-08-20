# T6 — exact-byte pager (#428/#410/#432) · T7 — omitted chain_id (#445)

Device: 7.14.2, variant KeepKey, mnemonic12, no PIN, no passphrase, AdvancedMode=False.

## T6 — VERDICT: wire checks PASS (4/4), photo checks with the tester

| check | result |
|---|---|
| AdvancedMode is False (the #432 gates are gone) | PASS |
| BTC SignMessage with embedded NUL signed | PASS |
| ETH personal_sign with 44 spaces padding signed | PASS |
| TRON SignMessage with embedded NUL signed | PASS |

No `Failure` on any step while AdvancedMode is False — the #432 AdvancedMode
gates on ETH and TRON SignMessage are gone, deliberately, in favour of full
disclosure.

**A device that REFUSES to sign is not a pass here.** Refusal satisfies the
weaker property; this card asserts the shipped behaviour, which is that the
bytes are paged and shown. All three signed.

Photo checks remain the substance of T6: three numbered ETH pages (1/3, 2/3,
3/3), `0xATTACKER` visible in full on 3/3, a literal `\x00` mid-body on the BTC
and TRON screens, and NOT ONE real blank gap — every space must render as the
four glyphs `\x20`.

## T7 — VERDICT: PASS (4/4)

| check | result |
|---|---|
| chain_id=1 signed with EIP-155 v | PASS `signature_v=38` |
| **omitted chain_id refused BEFORE any screen** | PASS `Failure code=3 'Chain Id out of bounds'` |
| **no ButtonRequest was emitted** | PASS |
| chain_id=3 signed with EIP-155 v | PASS `signature_v=41` |

The refusal was the FIRST reply, read with `call_raw`. Because `confirm()`
writes its `ButtonRequest` before it draws, this proves the absence of a screen
ON THE WIRE — which a photo of an unchanged home screen cannot do alone.

Before `885b485c4`, omission fell through to `chain_id = 0`, execution reached
both `confirm()` calls, no screen named a network, and a hold produced
`signature_v = v + 27`: a pre-EIP-155 signature replayable on every EVM chain.

### Observation for the record, NOT a defect

Chain 3 is accepted and correctly signed (`v=41`) but matches no case in the cid
switch, so photos D/E name no network and show bare `0.1` / `0.00042` with no
ticker. **#445 closes the signing hole only.** The display ambiguity is the same
one flagged for Base/Arbitrum/Avalanche under #455.

## Device left as

Unchanged — mnemonic12, no PIN, no passphrase.
