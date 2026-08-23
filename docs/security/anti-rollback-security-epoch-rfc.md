# RFC: OTP-backed firmware security epochs

Status: design required; no production implementation is authorized by this
document.

## Security invariant

After a device accepts an official firmware image in security epoch `N`, no
officially signed image with an epoch lower than `N` may be installed or booted.
The floor must never advance before the new image has passed all integrity and
signature checks.

A power loss during an update leaves the device with **no bootable
application** — see "Interruption behaviour" below. This RFC previously
required that a power loss leave the device able to boot either the previous or
the new image. That is not achievable on this hardware and the requirement has
been withdrawn.

Semantic versions are not the monotonic value. Patch and release-candidate
numbers are allowed to move independently; the security epoch advances only
when an older signed image must be permanently revoked.

## Interruption behaviour

The device has a single application slot: sectors 7-11, 128 KiB each, 640 KiB
total (`include/keepkey/board/memory.h`). A 7.15 image is roughly 568 KiB, so
two resident copies would need about 1.14 MB. **A/B slots do not fit, and no
amount of firmware work makes them fit** — this is a hardware-revision
requirement, not a backlog item, and it should not be carried in one.

For the same reason the candidate cannot be verified before erase. There is
nowhere to stage it: no spare flash, and roughly 192 KiB of RAM against a
568 KiB image, so it cannot be buffered either. The signature covers the whole
image and cannot be checked until the final byte arrives, by which point the
installed application is already gone. `handler_erase`
(`tools/bootloader/usb_flash.c`) erases sectors 7-11 on a button press, before
any image bytes exist.

What is therefore true, and what integrators may rely on:

- Between erase and the installation of the application magic there is **no
  bootable application**. An update interrupted in that window leaves the
  device in a **recovery-only** state.
- The bootloader (sectors 5-6) is never erased by an application update, so the
  device is always able to accept another image. Recovery-only is not a brick;
  re-running the update restores the device.
- The application magic is installed only after the flashed image and its epoch
  verify, so an interrupted update cannot leave a partially written image
  bootable.
- Storage is preserved across the interruption under the usual signature
  conditions (`should_restore()`): the outgoing firmware must have been
  officially signed and the incoming image must verify. An unsigned image on
  either side wipes storage by design.

Recovery-only is the honest name for this state. Documenting it is not an
endorsement: an update that cannot be made atomic is a real limitation, and the
mitigation is procedural — do not interrupt an update — until hardware with a
second slot exists.

## Why ordinary flash is insufficient

The bootloader can erase and rewrite application flash, and the attacker in
this threat model is deliberately installing an older valid image. A floor
stored beside mutable firmware or normal storage can be restored with the old
image and does not establish monotonicity.

The STM32F2 OTP region exposes sixteen 32-byte blocks. Current source assigns
manufacturing data to block 0, model data to block 1, and hardware entropy to
block 3. Before choosing any remaining block, manufacturing images and all
shipping board revisions must be audited; absence of a source reference is not
proof that a factory process never programmed it.

## Proposed representation

Reserve one audited OTP block as a 256-step unary counter. Epoch `N` is encoded
by programming the first `N` bits from 1 to 0. The decoded epoch is the length
of the contiguous programmed prefix.

Reject the OTP state if a programmed bit appears after an unprogrammed bit.
This catches torn or non-canonical values instead of interpreting them as a
lower floor. Do not lock the block after each update; the OTP 1-to-0 property is
the monotonic mechanism.

The signed application metadata needs a dedicated epoch field covered by the
existing firmware signatures. Reusing undocumented `meta_flags` bits is only
acceptable after confirming every bootloader generation parses and signs the
same bytes. A new metadata format with an explicit compatibility version is
preferred.

## Update state machine

1. Parse the candidate metadata without trusting it.
2. Decode the current OTP floor and reject malformed OTP.
3. Reject `candidate_epoch < floor` before erasing the installed image. This is
   the only candidate check that can precede the erase: the epoch is declared in
   metadata, whereas hash and signature cover an image that has not arrived yet.
4. Erase the application sectors. **From here until step 7 the device has no
   bootable application** (see "Interruption behaviour").
5. Write the candidate while preserving the existing storage-protection
   contract.
6. Re-read from flash and verify image bounds, hash, and the complete 3-of-N
   signature policy. A failure here leaves the device recovery-only, which is
   correct: a candidate that fails verification must not be bootable.
7. If `candidate_epoch > floor`, program and verify each required OTP bit.
8. Install the application magic only after image and epoch verification.
9. At every boot, reject an installed image whose epoch is below the OTP floor.

Unsigned/user-approved firmware must never advance the official floor. The RFC
must decide whether such firmware may boot at all once a floor is active; either
choice needs an explicit user-facing recovery story.

## Fault-injection requirements

- Accumulate signature results and validate sentinels as the current verifier
  does; do not add a single skippable epoch branch after signature validation.
- Read the OTP floor more than once with independent control-flow checks before
  an irreversible write.
- Verify every programmed bit and halt on disagreement.
- Ensure a glitch cannot turn malformed OTP into epoch zero.
- Include the epoch in the host-visible bootloader features and release
  evidence so operators can diagnose state without trusting firmware.

## Compatibility and rollout

This requires a bootloader campaign. Application-only deployment cannot protect
devices whose installed bootloader ignores epochs.

1. Inventory bootloader versions in the field and their update paths.
2. Prototype with a non-production test block on sacrificial devices.
3. Ship epoch-aware bootloader code with floor zero and no OTP advancement.
4. Confirm update, downgrade, unsigned-firmware, storage-preservation, and
   recovery behavior on each hardware revision.
5. Audit factory OTP contents and permanently reserve the selected block.
6. Only a later release may advance epoch one.

## Required tests

- candidate epoch below/equal/above floor;
- malformed non-contiguous OTP patterns;
- exhausted 256-step counter;
- signature failure with a higher claimed epoch;
- unsigned firmware with a higher claimed epoch;
- hash mismatch after flash write;
- power loss before erase, during image write, after image verification, during
  OTP programming, and before application magic installation — each must leave
  the device either bootable on the previous image (power loss strictly before
  erase) or recovery-only, and never bootable on an unverified image;
- boot of an installed image below the floor; and
- recovery-mode behavior when no eligible application remains.

The implementation PR must include a negative control showing that removing the
floor comparison permits a signed lower-epoch image.
