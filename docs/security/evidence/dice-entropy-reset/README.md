# On-device dice entropy in the ResetDevice flow

Emulator captures of `ResetDevice(dice_entropy=true, display_random=true,
strength=256)` driven by `scripts/emulator/capture-dice-flow.py` via
DebugLinkDecision.input injection.

The screen runs with `display_constant_power(true)` (PIN-matrix precedent:
dice rolls are seed material, and OLED supply current correlates with lit
pixels). The display driver fills x<128 with the inverse of x>=128, which is
why the left half of every capture shows a readable inverse copy — the user
faces the right half.

- `01-dice-screen-initial.png` — entry screen: `ROLL 1/99` counter, seven
  selector cells (digits 1–6 + `<` undo), active cell rendered inverse-video
  (white box, black glyph), `PRESS next HOLD ok` hint. Inactive digits are
  legible on hardware (white on 0x22 gray) but collapse to solid white in the
  1bpp DebugLink threshold; the inverse half documents them.
- `02-after-three-rolls.png` — after injecting `123`: counter `ROLL 4/99`,
  status `Entered 3 (3)`.
- `03-after-undo.png` — after injecting `u`: counter back to `ROLL 3/99`,
  status `Removed #3`.
- `04-digest-confirm.png` — completion screen: `99 rolls recorded. Digest:
  6CFC611198F53A73` = the first 8 bytes of SHA-256 of the ASCII roll string,
  independently recomputed host-side from the injected chunks (append/undo
  rules simulated) and matching exactly.
- `05-postmix-internal-entropy.png` — the standard Internal Entropy screen
  now shows the POST-dice-mix value: the displayed commitment is
  `SHA256(rng32 || rolls)`, produced before EntropyRequest is sent, so
  `sha256(displayed || external)` still reproduces the mnemonic (asserted by
  `test_msg_resetdevice.py::test_reset_device_dice`).
- `06-backup-explainer.png` — flow continues into the unchanged backup path.

Emulator captures do not satisfy Gate-3 on their own: an on-device pass of
the entry screen (short-press advance, 800 ms hold commit, undo, digest
match against physically entered rolls) is still owed before release. The
hardware press/release/debounce path (`dice_on_press`/`dice_on_release`)
does not execute in the emulator at all.
