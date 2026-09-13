# Firmware scope repair — 7.15

Owner correction: bootloader changes are excluded. The durability batch crossed
that boundary through the shared find_active_storage implementation and storage
protection contract. Its integration acceptance is withdrawn.

Restore the pre-durability implementation from 77f50c016 for board memory/metadata,
flash snapshot hooks, firmware commit/recovery and their durability-only tests.
The earlier emulator sector-erase correction remains. Preserve independent
signing, credential cleanup, setup and transport fixes. On 7.14.3/7.15 preserve
the uint32_t version classifier and its regression; pending-version recovery
no longer exists. 7.14.3 retains the emulator-only CRC correction (hardware
branch unchanged). Host pins remain unchanged: optional CRC fixture support
also handles unframed records and will be revalidated.

This restores the storage selector and on-flash format to the named predecessor;
it does not claim byte-identical bootloader artifacts for the entire historical
release. Other shared firmware files remain in the release's existing scope.
No bootloader image is shipped, flashed, signed or published by this repair.

The original erase-before-replacement power-interruption finding remains OPEN,
with remediation deferred outside this release batch under the owner's scope
correction. It is not fixed, waived, or converted into a clean-review claim.
P03-009/P03-010 durability-specific regressions become inapplicable after removal;
P03-011 unsigned version classification remains applicable and fixed.
Historical durability/replay branches and evidence are retained separately;
their receipts cannot certify these corrected candidates.

Validation: fresh builds, native firmware/board suites, full pinned-host suites
and exact-head CI/ARM artifact checks are required. Results are recorded in the
central scope-repair ledger; this initial unit receipt claims no final acceptance.
Canonical updates must be normal forward commits; fork develop stays unmerged.
