# Retiring the built-in ERC-20 token table

Status: **planning**. No code change proposed for 7.15.0 — this records the
measurement, the phasing, and the one ordering constraint that must not be
missed.

Companion docs: `clearsign-key-delegation-roadmap.md` (why tx-time injection
needs a delegation system), `7.15.0-rc21-clearsign-release-control.md` (what
ships today and its AdvancedMode requirement).

---

## Why this exists

The device carries a static ERC-20 table, generated at build time from
python-keepkey (`lib/firmware/CMakeLists.txt:75-78` → `ethereum_tokens.py` /
`uniswap_tokens.py`). Clear-signing's whole premise is that the host supplies
contract and asset meaning **at transaction time**, verified on arrival. Once
that works, the static table is dead weight — a shipped snapshot of a list that
is wrong the day it is compiled.

This doc quantifies the weight and sequences the removal.

## What the table costs

Measured, not estimated. Compiled the generated `.def` files into one
translation unit on a 64-bit host and read the section sizes, then converted the
struct array to ARM32 (the string pool is pointer-size independent):

```
__DATA,__const    46,656 B    struct array — 46656/1944 = exactly 24 B/entry (host)
__TEXT,__cstring  42,073 B    pooled address + ticker literals
```

| component | ARM32 |
|---|---|
| struct array — 1944 × 16 B (`const char*`×2 + `uint32_t` + `uint8_t`) | 31.1 KB |
| pooled string literals (measured) | 41.1 KB |
| **rodata total** | **~71.5 KB** |
| lookup/iteration code (`tokenByChainAddress`, `tokenIter`, `tokenByTicker`, `coinFromToken`) | ~0.5–1 KB |
| **≈ total** | **≈ 72 KB** |

For scale: ROM reclaim #339 (printf, −24.2 KB) and #340 (blake2b repin,
−12.1 KB) together recovered **34 KB**, both with real effort. The table is
roughly **double that in one deletion**.

Caveats on the number: the string pool is measured, the struct array is
arithmetic (24→16 B/entry is exact for the declared struct), and no ARM image was
linked — real reclaim also depends on `--gc-sections`. Treat ~72 KB as the
ceiling and confirm against a linker map before banking it.

The compile-out path already exists and is proven: `ethereum_tokens.h:29` sets
`TOKENS_COUNT 0` for the bitcoin-only image.

## What the table currently buys

Almost nothing, on the chains people actually use:

| chain | tokens |
|---|---|
| 1 (Ethereum) | 1924 |
| 137 / 56 / 10 / 61 / 8 / others | ~20 |
| **8453 (Base)** | **0** |
| **42161 (Arbitrum)** | **0** |
| **43114 (Avalanche)** | **0** |
| **100 (Gnosis)** | **0** |

1924 of 1944 entries are Ethereum mainnet. The generator can only emit what is
in `ethereum_networks.json`, which lists 15 networks and does not include Base,
Arbitrum, Avalanche, Gnosis, Monad, or Hyperliquid — all chains Vault supports
and advertises. So a USDC transfer on Base resolves to `UnknownToken` and the
device renders "Unknown token value" (`ethereum.c:388`) — no amount, no ticker.

Two build-hygiene problems found while measuring, worth fixing independently:

- `keepkeylib/eth/ethereum-lists` is a **submodule and is empty** in a fresh
  checkout. `ethereum_tokens.py` treats a missing directory as "no tokens for
  this network" and returns silently, so a clean build regenerates
  `ethereum_tokens.def` with ~0 rows — dropping Ethereum mainnet coverage too —
  and nothing fails. Only `uniswap_tokens.def` (568 rows, from the checked-in
  `uniswap_tokens.json`) is reproducible today. The generator should fail loudly.
- The table is therefore not reproducible from a clean tree, which makes any
  size claim about it unverifiable in CI.

## Ordering constraint — read before scheduling

`tokenByChainAddress` returns `UnknownToken` on a miss, **not NULL**
(`ethereum_tokens.c:58`). The blind-sign gate is:

```c
if (token == NULL && data_total > 0 && data_needs_confirm) {   // ethereum.c:871
```

`UnknownToken` is non-NULL, so an unrecognised ERC-20 transfer **skips the
AdvancedMode gate entirely** and takes the token-display path:

| case | today |
|---|---|
| unknown **contract call** | "Blocked", AdvancedMode required, raw-data review |
| unknown **token transfer** | ordinary-looking confirm reading "Unknown token value", no gate |

The less identifiable case gets the more permissive treatment. That is worth
fixing on its own merits, but it is **load-bearing for this plan**: once the
table is gone, *every* ERC-20 transfer takes the `UnknownToken` path. Removing
the table before fixing the asymmetry converts every token transfer into an
ungated, uninformative confirm screen.

**Fix the `NULL` vs `UnknownToken` asymmetry before phase 3, not after.**

## Phasing

### Phase 1 — prove tx-time injection (no firmware change)

When AdvancedMode is on, have the host load a clear-sign signer and send
`EthereumTxMetadata` before `EthereumSignTx` for ERC-20 transfers, and confirm
the decoded screens render.

This requires **no firmware change** and runs on shipped 7.15 rc firmware:

- `ethereum_contractHandled()` does not cover a plain ERC-20 transfer (it
  handles salary / 0x / THORChain / Maya / MakerDAO), so `data_needs_confirm`
  stays `true` (`ethereum.c:781-790`);
- the metadata block at `ethereum.c:795` fires on
  `data_needs_confirm && data_total > 0 && signed_metadata_available()`, all
  true at `data_total == 68`;
- that block runs **before** the token lookup at line 828, so `UnknownToken`
  does not interfere;
- `LoadClearsignSigner` and `EthereumTxMetadata` already exist in hdwallet.

Expected result, and the thing to not be surprised by: a loaded signer is
annotation-only (`signed_metadata_from_loaded_signer()` → `data_needs_confirm`
back to `true`), so the injected screens appear **and then** "Unknown token
value" still appears after them. Phase 1 proves the pipe; it does not remove
UNKN.

Test surface: `tests/test_msg_ethereum_clear_signing.py` already loads a signer
at `key_id=3` and drives this flow — a new vector, not a new harness, and it
lands in the zoo report as OLED evidence.

### Phase 2 — curate the table (firmware + python-keepkey, data only)

Replace the 1944-row mainnet dump with top-N + stables **across all supported
chains**. At ~38 B/row all-in:

| rows | flash | vs today |
|---|---|---|
| 200 (top-100 global + stables × chains) | ~7.6 KB | **−64 KB** |
| 500 | ~19 KB | −53 KB |
| 1000 (top-100 × 10 chains) | ~38 KB | −34 KB |

Even the 1000-row option reclaims as much as #339 + #340 combined *while* giving
Base and Arbitrum non-zero coverage for the first time. 200 rows is the
recommended target: 64 KB back, covering what people actually transact.

Prerequisites: add the missing chains to `ethereum_networks.json`, and fix the
silent-empty generator above.

### Phase 3 — delete the table

Requires metadata to *replace* the token display rather than annotate it, which
requires a non-loaded (pinned or delegated) signer — the custody decision in
`clearsign-key-delegation-roadmap.md`, marked there as
"Owner decision. Not decidable in this document." Blocked on that, not on
engineering.

Do not start phase 3 before the `NULL` / `UnknownToken` asymmetry is fixed.

## Summary

| phase | delivers | blocked on |
|---|---|---|
| 1 | injection proven end-to-end | nothing — works on shipped firmware |
| 2 | UNKN gone for real holdings, ~64 KB reclaimed | ROM/curation only |
| 3 | UNKN gone universally, ~72 KB reclaimed | delegation custody decision |
