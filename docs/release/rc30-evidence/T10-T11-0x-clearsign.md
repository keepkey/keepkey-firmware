# T10 — transformERC20 bound to complete calldata (#444, #468)
# T11 — sellToUniswap clear-signs only when BOTH tokens resolve (#472)

Device: 7.14.2, all-all-all seed, no PIN, no passphrase.

## VERDICT: PASS (5/5)

| run | payload | AdvancedMode | result |
|---|---|---|---|
| T10 A | transformERC20, 1480 B | OFF | **REFUSED** `Arbitrary contract data signing disabled by policy` |
| T10 B | transformERC20, 1480 B | ON | SIGNED v=38 |
| T10 C | transformERC20, 1024 B | OFF | **SIGNED v=37** (clear-signed) |
| T11 A | sellToUniswap, both tokens resolve | OFF | **SIGNED v=38** (clear-signed) |
| T11 B | sellToUniswap, `tokens[0]` = PEPE | OFF | **REFUSED** |

## T10 — the wire proves RUN C without a photo

RUN A establishes that with AdvancedMode OFF the blind path is refused outright.
So the ONLY way RUN C could sign is the 0x decoder claiming it. **The gate binds
clear-signing to complete calldata without killing it** — #468 did not trade one
defect for a usability cliff.

Before `d3be389af`, `ethereum_contractHandled()` had
`if (zx_isZxTransformERC20(msg)) return true;` ABOVE the chunk-completeness
check, so the 1480-byte payload was claimed by the 0x decoder: the device showed
`TRANSFORM ERC20 / Input 53086.65334 USDT / Output 53029.30814 USDC`, then
`TRANSACTION`, and the 456 bytes past the initial chunk streamed in, were hashed,
and were never rendered. AdvancedMode was never consulted — a DEFAULT device
signed it.

RUN C caveat: synthetic payload (fixture truncated to 1024 B, transformations[]
tail cut). It is also the only sub-1024-byte transformERC20 exercise in the plan,
filling the gap T11's card declared "a separate card".

## T11 — one word apart

Legs A and B are the SAME calldata on the SAME chain with ONE 32-byte word
changed. A clear-signs; B refuses.

Before `dea1cd7e6`, `zx_isZxSwap()` claimed any `d9627aa4` call to the 0x proxy
on an allowlisted chain WITHOUT LOOKING AT THE TOKEN WORDS.
`zx_confirmZxSwap()` then called `ethereumFormatAmount()`, which emits the
literal `Unknown token value` on a lookup miss — so an unlisted sell token
produced exactly one screen, `UNISWAP / Sell Unknown token value / Buy at least
0.000389574704633884  ETH`, **and the device signed**. A screen naming a DEX,
naming no amount, hiding 296 bytes of calldata.

The refusal lives in the PREDICATE, not the confirm: a false from
`ethereum_contractConfirmed()` would be read as a user cancel.

### Evidence for the #455 diagnosis

Leg B runs on **chain 1**, where no `uint8_t` chain-id truncation occurs, and
still refuses. That is direct evidence the #455 diagnosis is right: the failure
mode is an **unresolved token lookup**, not chain-id truncation.

### Does NOT prove #414

Leg A still hides the `869584cd` affiliate tail. #414 remains open.

## Photo checks with the tester

- **B3 is load-bearing:** `CONFIRM ETHEREUM DATA` must read `1480 bytes` —
  not `456`, not `1024`. First row exactly `415565b0000000000000000000000000`.
- C2 must be `TRANSFORM ERC20` with both token lines and NO `SEND` /
  `CONFIRM ETHEREUM DATA`.
- T11 photo 1: `Sell 1 USDC` and `0.000389574704633884  ETH` — note the DOUBLE
  SPACE, the sentinel ticker is literally `"  ETH"`. `Unknown token value`
  must appear nowhere.
- T11 leg B: no `UNISWAP` screen at any point.

## Device left as

all-all-all, no PIN, no passphrase, AdvancedMode OFF.
