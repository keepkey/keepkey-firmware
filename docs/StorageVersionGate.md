# Storage version gate — audit SOP

**A signed upgrade must never wipe. A downgrade wipes, and that is correct.**

Those two sentences are the whole policy. Everything below exists to make the
first one impossible to break by accident.

## Why an upgrade can wipe

`storage_init()` calls `storage_fromFlash()` on whatever blob is in flash. If
`version_from_int()` does not recognise the version it returns
`StorageVersion_NONE`, `storage_fromFlash()` returns `SUS_Invalid`, and
`storage_init()` runs `storage_reset()` + `storage_commit()`. No prompt, no
warning — the wallet is gone at boot.

An upgrading device always arrives carrying a blob written by the release it is
leaving. So incoming firmware must recognise every version any shipped firmware
ever wrote. There are exactly two ways to break that:

1. **Lower `STORAGE_VERSION`** below a version that has shipped.
2. **Remove, reorder, or skip an entry** in `storage_versions.inc`, so a version
   that used to be recognised no longer is.

Both compile cleanly without the gate. Both silently wipe every field device on
upgrade. Neither shows up in any functional test, because tests create storage
with the firmware under test and never cross a release boundary.

The reverse direction is not a defect: older firmware cannot read a newer blob,
so a **downgrade** legitimately lands on `SUS_Invalid` and resets. Do not
"fix" that. Do not add a compatibility shim for it. Downgrades wipe.

Signing is a separate wipe path with its own rule — see below.

## The hard checks

Two `_Static_assert`s in `lib/firmware/storage.c`, both compile-time:

| Check | Fires when |
|---|---|
| `STORAGE_VERSION >= STORAGE_VERSION_LAST_SHIPPED` | Someone lowers the version below a shipped release |
| `StorageVersion_##N == N`, on every entry | `storage_versions.inc` stops being contiguous from 1 |

The second works because the enum is emitted in `.inc` order after
`StorageVersion_NONE = 0`, so a contiguous `1..N` list makes
`StorageVersion_N == N`. Delete entry 5 and `StorageVersion_17` becomes 16, and
the build stops.

It is asserted on **every** entry, not just the last. Checking only the last
entry pins the entry *count*, which is weaker than it looks: renumbering
`ENTRY(16)` to `ENTRY(99)` leaves `StorageVersion_17` at 17 and compiles clean,
while `version_from_int` quietly loses `case 16` and every device carrying
version 16 is wiped on upgrade. That gap was found by mutation-testing the
assert rather than by reading it.

`STORAGE_VERSION_LAST_SHIPPED` lives in `include/keepkey/firmware/storage.h`.

## Auditing a change that touches storage

1. **Did `STORAGE_VERSION` change?** If it went up, the release checklist below
   applies. If it went **down**, stop — this wipes every upgrading device. There
   is no valid reason to lower it on a branch; a revert of unshipped work should
   restore the *reader* while leaving the version number alone.
2. **Did `storage_versions.inc` change?** Only ever by appending. Any deletion or
   renumbering is a wipe, and the build will say so.
3. **Did `STORAGE_VERSION_LAST_SHIPPED` change?** Only legitimate in a release
   commit, and only upward. A bump appearing in a feature branch, or any
   decrease, is the single highest-severity review item in this file — it is
   precisely the edit that disarms the gate to make a build compile.
4. **Is there a new `case` in `storage_fromFlash` for the new version, with the
   fallthrough chain intact from the oldest version forward?** The chain is how
   an old blob is migrated step by step; a missing link loads garbage rather
   than wiping, which is worse.
5. **Run the reboot regression.** Create/reset, set PIN, serialize, reload as
   after reboot, unlock, compare the recovered key. The ordinary storage tests
   never cross the serialize/reboot boundary, and that boundary is where this
   class of defect lives.

## Release checklist addition

When bumping `STORAGE_VERSION` for a release:

- Add the new entry to `storage_versions.inc` — append only.
- Add the `case` and fallthrough in `storage_fromFlash`.
- Set `STORAGE_VERSION_LAST_SHIPPED` to the new value **in the release commit**,
  not before. Until the build actually ships, the previous value is the truth.
- Verify on a production device that upgrade preserves keys. `docs/Release.md`
  has always said this; the static asserts do not replace it, they only stop the
  two failure modes that reach a device unnoticed.

## The other wipe path: signatures

Independent of versions, the bootloader erases storage unless
`should_restore()` (`tools/bootloader/usb_flash.c`) is satisfied. It requires
all three:

- `SIG_FLAG != 0` — the incoming image's metadata does not request a wipe
- `!old_firmware_was_unsigned` — the firmware being replaced was officially signed
- `signatures_ok() == SIG_OK` on the new image

Signed → signed preserves storage. Anything involving an unsigned image on
either side wipes, deliberately: it stops custom firmware from dumping storage
sectors written by official firmware.

Consequence for testing: an unsigned development or RC build **cannot** validate
the preserve path, because it fails the second and third conditions by
construction. "Upgrade did not wipe" is only ever proven with a signed build on
a production device.
