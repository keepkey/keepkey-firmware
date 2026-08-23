# The token table: budget, and what the budget cannot fix

## What changed

The built-in ERC-20 table is capped at **500 entries**, down from 1,945.

```
tokens   31,104 -> 8,000 bytes      saved 23,104 B of flash
```

`tokens` was the largest read-only symbol in the ARM image — larger than
`MessagesMap` (27,264) or the BIP-39 wordlist (8,196). Policy lives in
`deps/python-keepkey/keepkeylib/eth/token_policy.py`; the firmware is unchanged.

## What the table is for

So the device can render `10.5 DAI` instead of an amount against a bare
contract address. It cannot be complete, and should not try: anything outside it
is the clear-sign provider's job, which is the direction
`docs/security/token-table-retirement.md` already sets out.

## Why 500, and why the content is not what was asked for

The ask was: a handful of top EVM chains, stablecoins and top-50 tokens.
**The data in this repository cannot express that.** Measured against
`ethereum-lists` as pinned:

| | |
|---|---|
| Ethereum mainnet entries | **1,924 of 1,945** |
| Optimism / Polygon / BSC | 2 / 3 / 3 |
| Base, Arbitrum | **no directory at all** |
| Absent | UNI, AAVE, stETH, wstETH, rETH, cbETH, PEPE |
| Absent stablecoins | FRAX, LUSD, PYUSD, crvUSD, USDe |
| `ARB` resolves to | `0xafbec4d6…`, a 2017 token named "ARBITRAGE" |

Arbitrum's real ARB (`0xB50721BC…`) is not in the table at all.

The submodule points at **`keepkey/ethereum-lists`, last commit 2023-04-06**,
and that fork's HEAD *is* the pinned commit — there is nothing newer to pull.
The source is two years stale and is the only one wired in.

So the long tail is not coverage. It is 2017-era ICO tokens occupying flash
while the assets users actually hold are missing. **USDC, USDT, DAI, WETH,
WBTC and LINK are present and correct**, and those are what the budget protects.

## The policy

1. Budget: 350 from ethereum-lists + 150 from the uniswap list.
2. Priority symbols first — stablecoins, then majors.
3. A priority symbol is taken **only when the source gives exactly one
   address**. Two entries sharing a symbol is how a scam token inherits a real
   one's label, and the device would render the attacker's name. Ambiguous
   symbols are dropped from the priority pass and reported at build time.
4. Remainder filled in the existing deterministic order, so output stays
   reproducible and diffable.

**No address is written in the policy.** Symbols are matched against the vetted
source. A hand-typed address in a token table is a mislabelling defect waiting
to happen, and the file says so, so it does not become the place one appears.

## Two groups pinned for structural reasons

- **REQUIRED_BY_COINS (26)** — tickers `coins[]` declares with a contract
  address. `Coins.TableSanity` asserts each resolves uniquely and **correctly
  failed** when the first cut dropped them: the device would advertise a coin it
  cannot name. They are 2017 tokens and are exactly what should go next — but
  that cut belongs in `coins[]`, itself a **23,808-byte** symbol and the next
  ROM reduction available.
- **REQUIRED_BY_TESTS (1)** — ADT, which
  `test_ethereum_signtx_knownerc20_eip_1559` uses as its canonical "known
  ERC-20" while asserting a hardcoded signature. A fixture should not pin
  firmware flash; migrating that test to USDC retires the entry.

## The decision this leaves open

Getting current tokens for Base, Arbitrum, Optimism and Polygon requires
**refreshing or repointing the data source**, which is a product decision with
security consequences: every new address is new trust, and a wrong one makes the
device display the wrong asset name. The mechanism is ready — `token_policy`
consumes whatever the source provides and will prioritise stablecoins the moment
they exist in it.

Three options, in increasing order of work and decreasing order of risk:

1. **Refresh KeepKey's `ethereum-lists` fork** from its upstream. Cheapest;
   inherits upstream's curation and its mistakes.
2. **Repoint at `ethereum-lists/tokens` upstream**, which is chain-id
   organised and current. Format differs, so the generator changes.
3. **Stop growing the table** and let provider schemas cover everything outside
   the top ~100. This is where `token-table-retirement.md` already points, and
   the 500-entry budget is a step along it rather than away from it.
