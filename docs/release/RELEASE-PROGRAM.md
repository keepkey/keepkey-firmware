# Fork release product program

Owner direction: 2026-09-08. Harden and assemble 7.14.2, 7.14.3 and 7.15 through
small local audit units. The canonical procedure is [REHEARSAL-SOP.md](REHEARSAL-SOP.md).
Copilot belongs to final upstream preparation, after internal product acceptance.

## Active objective and stop condition

Owner instruction: continue until all three releases meet their written local
acceptance contracts and are ready for final Copilot review. Completion requires
three exact candidate receipts, full scope reconciliation, required checks passed,
no known unresolved in-scope or release-critical defects, and validated assembly
on the canonical fork product branches. Keep PRs into develop unmerged. Do not
request Copilot during this work or claim that local acceptance proves no possible
bugs. Required unavailable verification remains explicitly pending.

The persistent goal tool rejected replacement because an older, usage-limited goal
is unfinished. This manifest records the expanded objective without falsely marking
that earlier goal complete.

## Product identities

These are source snapshots observed on 2026-09-08, not acceptance receipts.

| Product | Canonical fork product branch | Observed source SHA | Status |
| --- | --- | --- | --- |
| 7.14.2 | `release/7.14.2` | `1e8d43c12d963ffa9e45a333b00b22c16b043c26` | Foundation assembled; CI green; later revocation fix pending combined acceptance |
| 7.14.3 | `release/7.14.3-bitcoin-only` | `abe29d1288638867dc64dfe04219b89f7a593133` | Bitcoin-only candidate; scope and acceptance pending |
| 7.15 | `release/7.15` | `a56fb3e88d7dbbe31a321179c10a8fd2023d8f0c` | Full feature inventory and acceptance pending |

The additional fork branch `release/7.15.0` was observed at
`e601d2df8f5a847e3d3c297c8d60aba65cb4b579`. Reconcile its contents with the canonical
7.15 product before excluding any unique intended work. Do not treat the names
as equivalent, overwrite either branch, or silently create a fourth product.

Fork develop was observed at `da075b8cb717b56dc1023edb52c2ccdf171b8a08`.
Product PRs #650 (7.14.2), #627 (7.14.3), and #629 (7.15) target fork develop
and remain unmerged. Canonical 7.14.2 advanced from `cdde6888c` to `1e8d43c12`
after passing CI, including ARM SRAM reserve of 22,508 bytes and 433 host tests.
Later source reconciliation reopened acceptance for a missing low-level signing
revocation fix. The other two canonical refs still retain their frozen source
heads until combined candidate acceptance; audit branches are substantive work,
but are not yet accepted canonical products.

## Current combined candidates

- `rehearsal/7142-combined-product`: accepted foundation plus low-level signing
  revocation (`91bdcf089`, audit PR #661).
- `rehearsal/7143-combined-product`: unsigned decoding, nanopb transport bounds,
  storage capacities, passphrase transitions, cipher scratch cleanup, EOS
  authorization, low-level revocation, and token generation dependencies.
  Audit PRs #645, #646, #649, #651, #653, #657, and #660.
- `rehearsal/715-combined-product`: corresponding shared fixes plus provider icon
  placement, restored FSM test coverage, authenticator credential source cleanup,
  and Zcash teardown. Audit PRs #644, #647, #648, #652, #654–#656, #658–#659.

The earlier 7.14.3 decode candidate passed all CI gates, both ARM variants and
both integration variants (run 34275309652). The earlier 7.15 decode candidate
passed 695 host tests, with 56 skips. These are predecessor evidence, not final
combined candidate receipts. Three skipped Zcash checks apply to the canonical
7.15 sources and are being enabled in the companion host audit.

The older 7.15.0 unsupported-storage lockout conflicts with the current explicit
storage downgrade policy. It is superseded rather than blindly replayed. The
experimental uncommitted change was withdrawn. Native test concurrency also
exposed shared emulator port use; run those full suites serially to avoid binding
collisions. Neither issue is grounds for weakening the release checks.

## Existing rehearsal evidence

- [7.14.2 hardening manifest](7.14.2-HARDENING-MANIFEST.md) records the earlier
  audited baseline and foundation reconstruction. Its source differs from the
  current product snapshot; reconcile subsequent fixes before assembling updates.
- [7.15 staging manifest](7.15-STAGING-MANIFEST.md) records F00–F05 and fork PRs
  #635–#640. These are an existing audit stack, not all of 7.15 or three accepted
  release products. Preserve their findings, fixes and valid test evidence.
- Shared fixes need a per-release applicability record: included with exact commit,
  pending, or not applicable with a technical reason. Never assume a 7.15 fix has
  reached 7.14.2 or the Bitcoin-only build.

## Required record for each product

Before declaring acceptance, complete a release-specific manifest with:

- Canonical branch and product PR, frozen starting head, intended features and
  variants, explicit exclusions, exact dependency pins, and required checks.
- Known findings and stable IDs, affected releases, accepted audit-unit receipts,
  and remaining feature or hardening units in dependency order.
- Assembly receipt identifying the prior product head, included unit commits,
  conflict resolutions, resulting head/tree and dependency pins.
- Executed unit, integration, ARM/resource, storage compatibility and device/OLED
  checks as applicable, including failures, skips and unavailable physical checks.
- Local acceptance result and remaining release or upstream gates. Never substitute
  an old head's passing build, a clean review, or unit-only results for this receipt.

## Execution order and completion

First reconcile the current 7.14.2 source with accepted foundation hardening, then
validate that product. Apply relevant shared hardening to 7.14.3 and validate its
Bitcoin-only contract. Continue extracting the full intended 7.15 scope into small
units; independent authoring may proceed while predecessor checks run. Assemble
only accepted units and rerun required product checks before updating a release.

A release finishes internal rehearsal when its declared feature inventory is
accounted for, all required checks pass, and no known unresolved in-scope defect
or release-critical defect remains. Freeze that receipt and stop broad rediscovery.
New concrete evidence can reopen affected acceptance; unrelated improvements get
separate units. The three-release program is not complete until all three products
have their own passing receipts. Final upstream preparation then performs the
Copilot checkpoint defined in the SOP before upstream PR creation.

## First active unit

R142-01, branch `audit/7142-storage-unsigned`, carries the existing unsigned-byte
storage decoder fix from `ce21b4ac8` to the current 7.14.2 product baseline. The
defect is present in 7.14.2 and 7.14.3; exact inspection confirmed 7.15 already
contains an equivalent unsigned-byte implementation. Baseline/candidate C
probes reproduce the signed-char failure and show the candidate passes both char
modes. All 20 storage tests pass and the V17 regression fails with the old decoder.
Full firmware-unit has 77 passes and three token-table/EVM failures, reproduced
with the original decoder and tracked separately as R142-02. Assembled-product
acceptance remains pending.
The unit receipt lives on its audit branch at
`docs/release/audit-units/R142-01-storage-unsigned.md`.

R142-01 is fork PR #641 against `release/7.14.2`, its actual predecessor;
current develop conflicts with the product-based patch. Its candidate is
`20c1f07bb`. A corresponding 7.14.3 replay is isolated on
`audit/7143-storage-unsigned`, pending variant validation. No decoder change is
needed on 7.15. Its frozen SRS additionally requires both full and Bitcoin-only
products, additive context, complete disclosure, storage compatibility and
hardware evidence; preserve this scope when completing the feature matrix.

## Current progress toward the active objective

- R142-01 now passes all 80 firmware-unit tests with fully initialized pinned
  token data. R142-02 was a local nested-dependency setup failure, closed without
  changing firmware behavior or test expectations.
- R142-03 isolates a generated-table dependency gap: declaring CMake byproducts
  makes one Ninja invocation regenerate the table and test the updated executable.
  The controlled empty-table regeneration experiment passed all 80 tests.
- Source reconciliation: the previously audited `e519dc13c` is a descendant of
  the canonical 7.14.2 snapshot, with 30 first-parent commits. Preserve and account
  for that already-reviewed hardening when assembling the product; do not mistake
  the older canonical branch for the most thoroughly audited candidate or redo
  those fixes independently. Existing foundation receipts remain supporting evidence.
- Full release acceptance is still pending exact assembled ARM/integration checks,
  shared-fix applicability, complete feature inventories and required hardware evidence.
