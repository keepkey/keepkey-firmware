# Integer percent rendering on the THOR/Maya withdraw confirm

Emulator captures for the change that routes all device `snprintf` calls to
newlib's integer-only `sniprintf` and rewrites the last two float format
users (`%3.2f` in `thorchain.c` / `mayachain.c`) as integer basis-point math.

- `01-thorchain-withdraw-25.05pct.png` — ETH router `deposit()` carrying memo
  `WITHDRAW:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:2505`.
  2505 bps renders as `25.05%`: the integer path preserves the `%02d`
  zero-padding of the fractional digits.
- `02-thorchain-sending-eth.png` — the amount screen from the same flow,
  showing `%llu`-family rendering is unaffected.

Reproduce with `scripts/emulator/capture-thor-percent.py` against kkemu
(`KEEPKEY_SCREENSHOT=1`, abandon test seed, no PIN). Emulator captures do not
satisfy Gate-3 on their own — an on-device pass of the THOR withdraw screen
and one Osmosis `%llu` amount screen is still owed before release.
