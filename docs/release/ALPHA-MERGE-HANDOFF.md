# alpha <- develop merge: handoff

**Status: the merge is complete and green. It has NOT been run on hardware.**

Branch `alpha-merge2`. alpha carries 218 commits of 7.15 work; develop carries
the 89-commit 7.14.2 security line. 79 files were changed by both. They are two
parallel evolutions of the same firmware, not a branch and its upstream.

## Where it stands

| gate | result |
|---|---|
| `tools/merge_symbol_gate.py` | 0 regressions |
| `tools/merge_direction_gate.py` | 0 unexplained, 26 adjudicated |
| build | `firmware-unit` + `board-unit` link clean |
| `firmware-unit` | 439/439 |
| `board-unit` | 12/12 |
| determinism | 3 full single-process runs identical, and equal to one-test-per-process |
| hardware | **nothing has been run on a device** |

## Read this before trusting the symbol gate

It reached 0 while 24 of the 79 contested files had been taken byte-identical
from develop, discarding alpha's changes to them. It cannot see that class:

- Both branches define the SAME function names. A file swapped wholesale keeps
  every name and only weakens the bodies, so nothing is ever "referenced but
  undefined".
- A `static` function dropped together with its only callers scores as a SAFE
  DROP. Nine EIP-712 type-validation helpers vanished that way.
- A symbol whose DEFINITION survives while its CALL SITES came from the other
  side is invisible. The entire Maya EVM branch was unreachable dead code with
  the gate green.

**Run `tools/merge_direction_gate.py` first.** For every file both branches
changed it compares the merged blob against both sides and flags any file equal
to one side while the other had real churn. A flag is a QUESTION, not a verdict:
alpha is 218 ahead of upstream develop and 0 behind, so some of its changes
reached the fork's develop by another route. Of 24 flagged, 12 were real losses
and 12 were equivalent. Cleared files and their reasons live in
`tools/merge-direction-adjudicated.txt`; anything flagged and not listed there
has not been examined.

## How each contested file was decided

Count the churn, do not guess: `git log --oneline <base>..<side> -- <file>`.
Whichever side changed the file substantially is the BASE; the other side's
hunks are replayed onto it. Most conflicts are UNIONS -- both sides usually
added different protections to the same region.

The one rule that only points one way:

> Tests adapt to disclosure. Disclosure never weakens for a test.

Notable calls, with the reasoning in the commit messages:

- **storage.c** -- alpha's file. 18 commits vs develop's 1.
- **thorchain.c** -- alpha's labelled parser over develop's strtok, because
  strtok collapses empty fields and shows an affiliate in the limit slot, and
  because develop's withdraw screen formats basis points with `%3.2f`, which the
  device's integer-only sniprintf has no implementation for. develop's
  three-valued result contract and NUL refusal ported onto it.
- **eip712.c dsConfirm** -- develop's, the one place alpha is weaker: alpha's
  `review_with_icon()` return can never be false, so its refusal path was dead.
- **authenticator.c** -- alpha's; develop's is older and drops five checks.

## What is NOT done

1. **No hardware run.** Every claim here is from the native unit build. Gate 3
   (OLED screenshots) has not been attempted.
2. **Uniswap liquidity is unsignable to a third party.** `zxliquidtx.c`'s
   `confirmFromAccountMatch()` ends in `return is_self`, so a user who reads
   "NOT this wallet" and approves has the approval discarded. Pre-existing alpha
   defect, already a 7.15 blocker, merged as-is deliberately -- fixing it inside
   a merge commit would have hidden it.
3. **`recovery_cipher.c` lost alpha's "previous word" indicator.** Passing NULL
   to compile; `app_layout.c` still implements the argument. develop's file is
   not simply older -- it carries the #429 staging rework -- so replaying
   alpha's `prev_info` block is a real merge, not a revert.
4. **7.14.2 is still unmerged upstream** (`keepkey/keepkey-firmware` PR #458).
   Not fixable from here.

## Build recipe, and two traps that cost hours

```
export PATH="/Users/highlander/.pyenv/versions/3.10.15/bin:/Users/highlander/nanopb-0.3.9.4/generator:$PATH"
cmake -B build-emu -G Ninja -C cmake/caches/emulator.cmake \
  -DCMAKE_BUILD_TYPE=Debug \
  -DPROTOC_BINARY=/opt/homebrew/bin/protoc \
  -DNANOPB_DIR=/Users/highlander/nanopb-0.3.9.4 \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  -DCMAKE_C_FLAGS="-DPB_NO_PACKED_STRUCTS=1" \
  -DCMAKE_CXX_FLAGS="-std=c++14 -DPB_NO_PACKED_STRUCTS=1"
cmake --build build-emu --target firmware-unit board-unit -j 8
```

- **nanopb MUST be 0.3.9.4.** 0.4.x parses the plugin parameter as
  `if ',' not in params and ' -' in params`. The repo spells it
  `--nanopb_out=-f types.options:.`, which has neither, so the whole string
  lexes as one token, every `.options` file is silently ignored, and the build
  dies at the repo's own `! grep -r pb_callback_t` guard with no hint why.
- **`-DPB_NO_PACKED_STRUCTS=1` is mandatory on arm64**, else the link fails with
  "pointer not aligned in `_HDNodePathType_fields`".
- Do NOT run `git submodule update --recursive`: it pulls ~565MB of micropython
  vendor code this build never uses. Init the six top-level deps individually.
- The old note that firmware-unit hangs on this Mac is **stale for this tree**.

## Measuring the confirm suites

`kkconfirm_preload(N, 0)` queues N accept pairs plus one reject sentinel; each
screen eats 2 packets. `kkconfirm_drain()` returns `leftover - 2`, so:

- `drain == 0` -> exactly N screens shown
- `drain > 0`  -> FEWER screens than budgeted
- `drain < 0`  -> the sentinel was eaten: MORE screens than expected
- preload one screen too few and the test **hangs** rather than failing

Screen counts are VALUE-dependent: `confirm()` pages a body over `BODY_ROWS=3`,
and bytes outside `0x21..0x7e` render as 4-glyph `\xNN` escapes (space included).
**Measure with an over-large preload -- `screens = N - drain/2` -- never model it.**

The harness had a race that made this suite lie: `drain()` stopped at the first
empty read while loopback UDP delivery is asynchronous, so any zero-screen
refusal reported `-2`. It now waits a 200ms idle window. That cannot mask an
extra screen, and it was checked rather than assumed: inject one extra
`confirm()` into the SWAP path and `MemoSwapNoFeeIsThreeScreens` fails with
`drain == -2`.

## Submodules

alpha pins fork masters; already reconciled, does not need redoing:

- `BitHighlander/device-protocol` master `8bf32ed`
- `BitHighlander/python-keepkey` master `8c1492b`

**Check `git diff --submodule=short deps/` before every commit.** python-keepkey
drifted to `698e9a46` once during this work and would have ridden along silently.
