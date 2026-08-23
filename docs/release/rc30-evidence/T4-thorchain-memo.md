# T4 — THORChain trailing memo fields disclosed (#415)

Device: 7.14.2, variant KeepKey, mnemonic12, no PIN, no passphrase (state left by T3).

## VERDICT: wire checks PASS; photo checks with the tester

| check | result |
|---|---|
| A: signed bytes contain the affiliate tail `:ss:75` | PASS |
| B: matches the 7.14.1 fixture byte for byte | PASS |

    A hex tail: ...3a3432303a73733a3735 00000000   = ":420:ss:75"
    B hex:      identical to the pinned 7.14.1 fixture

**Test A** proves the device signed exactly the bytes it displayed. Before
`354315c65`, everything after the limit — affiliate name, affiliate fee in bps,
aggregator routing — was hashed and signed with nothing on screen. A 75 bps skim
the user never saw.

**Test B** proves the new `strtok` loop does not mutate what gets hashed: a
legacy memo signs identically to 7.14.1 and gains no spurious screens.

## Card rewritten, as the plan required

The original card subclassed `common.KeepKeyTest`, which demands a DEBUG_LINK
build — not the release artifact, so its evidence would be weaker for a release
gate. That requirement was an artifact of reusing the harness: these memo screens
are entirely host-driven and the pinned serialized tx depends only on the seed.
Rewritten as a plain `KeepKeyClient` script, holds taken physically, no
`set_buttonwait`. Prev tx served from `tests/txcache/` — no network.

## Product-layer note (the reason this test matters twice)

T4 verifies the *firmware* discloses trailing memo fields. It does NOT verify any
product path ever sends them. That distinction is not hypothetical: the XRP
THORChain memo bug was firmware-innocent and lost host-side in hdwallet
(`keepkey-vault#422`), and a firmware-only test would have shown a clean pass
forever.

Vault's `/utxo/sign-transaction` schema types `outputs` as `z.array(z.any())`
(`schemas.ts:124`), so an `opReturnData` field passes through unstripped — the
structural flaw that bit XRP (`.strip()` eating tx fields) is absent here. That
is a schema reading, NOT a hardware measurement; a product-path probe is tracked
separately.

**Plan §3 should gain a sibling section: "verified in firmware but not proven
reachable in the product."** T4 belongs in it today.

## Device left as

Unchanged — mnemonic12, no PIN, no passphrase.
