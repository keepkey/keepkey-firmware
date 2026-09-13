# Firmware rehearsal and acceptance SOP

Owner decision: 2026-09-07. This is the canonical procedure for the new
7.14.2 hardening foundation and subsequent extraction of alpha features.
It supersedes the alpha audit requirement for two whole-tree zero-finding
passes as a prerequisite to staging. Historical rehearsal handoffs are
evidence, not executable instructions or current branch identities.

## Two fork PR types: products and audit units

Owner clarification: 2026-09-08. The main products are the fork release branches
for 7.14.2, 7.14.3 and 7.15. Small rehearsal branches are the workspace for
hardening and feature extraction before accepted changes update those products.
All internal PRs live in the fork. Neither PR type is merged into fork develop.

| PR type | Head and target | Purpose and acceptance |
| --- | --- | --- |
| Release product | Main fork release branch → fork `develop` | Cumulative, buildable product candidate with a release manifest, exact pins, accepted-unit receipts and complete product checks. Its large diff is an integration view, not a request to rediscover every issue on every iteration. |
| Audit unit | Isolated rehearsal branch → fork `develop` when independent; otherwise → its immediate predecessor | One bounded behavior or defect, reviewed and tested locally against its recorded base. Dependent units stay stacked and unmerged into develop. |

Both types belong to the fork-develop staging program; a dependent audit PR
must target its predecessor so its review diff stays small. Do not retarget all
stack members directly to develop and recreate the cumulative review surface.
The existing F00–F05 stack is rehearsal evidence, not the complete 7.15 product.

For each release, record its canonical branch, frozen source SHA, intended
variant and required features in `RELEASE-PROGRAM.md`. Branch naming alone does
not establish that a source is accepted or that two release branches are equal.

1. Select a named gap in the product manifest and freeze its source and base.
2. Extract or harden it on small audit branches. Complete the local contract
   below before recording a unit as accepted.
3. Assemble accepted units on an isolated integration candidate based on the
   recorded product head. Resolve interactions there, preserving existing product
   content unless an omission is explicitly recorded. A conflicted replay or an
   interaction defect returns to a named audit unit for local validation.
4. Validate the assembled product, including required release variants and exact
   dependency pins. Record the included unit SHAs and resulting tree in a receipt.
5. Update the canonical fork release branch to the validated candidate, keeping
   its product PR into develop open and unmerged. Check that the remote product
   head still equals the recorded base; if it moved, reconcile and validate again.
   Prefer a normal fast-forward update; do not silently reset or force-push it.
6. Realign remaining rehearsal branches onto the accepted product or their updated
   predecessor. Assess the changed diff and affected interactions, carrying forward
   valid evidence for unchanged code. Repeat for the next named gap.

Updating a fork release branch is internal product assembly, not a develop merge,
an upstream submission, or release publication. A product is ready only when its
entire declared scope passes; accepting individual units alone is insufficient.

## Foundation first

Use the current audited 7.14.2 candidate as the selected foundation. The
initial immutable identity is recorded in `7.14.2-HARDENING-MANIFEST.md`.
Selection does not claim that this head has passed final acceptance.

Create a fresh rehearsal branch from that SHA. Do not merge alpha into it.
Existing shared develop remains preserved until the replacement is proven.
The proposed foundation is represented by an unmerged PR into fork develop.
Do not merge or reset develop under this rehearsal authorization. Alpha feature staging may proceed on the tested foundation PR before release acceptance; dependent units remain unmerged.
Promotion of a shared branch is a distinct recorded operation; this procedure
does not silently reset, force-push, merge upstream, or publish a release.

## Define a finite batch

Before editing code, record the base, source commits, exact dependency pins,
selected behaviors, affected security invariants, acceptance checks, exclusions,
and actual dependency order in a versioned manifest. Never select a moving
branch name as the sole source identity.

For the foundation, scope is defects in existing 7.14.2 behavior and validation
needed to prove their fixes. New chains, new alpha features, unrelated cleanup,
and storage-format redesign are excluded. A necessary scope change must be
recorded explicitly, with its impact on the batch and acceptance evidence.

Triage known audit findings before commissioning new broad discovery. A claim
about alpha must be reproduced or traced on the selected 7.14.2 head before it
becomes foundation work. Do not infer reachability from a shared filename.

Before replaying a historical fix, compare it with the current product's explicit
policy and later implementation. Record it as present, applicable and missing,
superseded, or excluded with a technical reason. A historical commit calling
something a vulnerability is evidence to investigate, not permission to reverse
the current contract. Check test build registration and version-based skips against
the actual candidate capabilities; a test in the tree is not evidence it ran.

## Findings and review units

Each finding has a stable ID, affected SHA/configuration, concrete failure
trace or reproduction, impact, origin (existing defect or introduced regression),
disposition, and regression evidence. Deduplicate by root cause. Missing
verification is unverified, never confirmed or refuted. Reviewer votes alone
are not proof. Record technical reasons for rejected findings.

One unit addresses one independently explainable behavior with its tests.
Author coherent commits; use separate PRs for independently reviewable units.
Do not hide many unrelated units inside a single large PR. Preserve relevant
prior audit fixes and evidence when extracting code; review extraction changes.

A new finding blocks the unit if it introduces, worsens, or depends on that
defect. A confirmed critical defect in the shipping candidate blocks release
even if outside the current unit. Other unrelated findings receive a separate
disposition and batch assignment; they do not silently expand this batch.

## Local rehearsal to convergence

Owner revision: 2026-09-08. Continue using Codex for implementation and local
review. Copilot is deferred to late upstream/release phases and is not an
internal staging acceptance gate. This revision supersedes earlier mandatory
per-PR clean-Copilot requirements and review-round ceiling blockers.

“Perfect” means the frozen unit meets its written acceptance contract with no
known unresolved in-scope defects. It is not a claim of zero possible bugs or an
instruction to keep inventing improvements. Define the finish line before work.

1. Inventory existing findings, deduplicate root causes, and pin baseline/source
   identities. Define the behavior, invariants, affected consumers and checks.
2. Implement a coherent unit. Review its actual diff against its predecessor,
   including dependency changes, bounds, failure paths, state lifetime and tests.
3. Batch concrete findings into scoped fixes. Reproduce defects where practical;
   add regression coverage that distinguishes incorrect from correct behavior.
   Run format/build checks before review so mechanical nits do not consume rounds.
4. Repeat local review of the remediation delta and affected interactions until
   no actionable in-scope findings remain. Every additional iteration must name
   the defect or missing evidence it resolves. Do not restart whole-alpha audits.
5. Freeze the candidate. Run required unit, integration, ARM/resource and storage
   compatibility checks; inspect skips, screenshots and artifacts where required.
   Reconstruct the stack and verify its tree, dependency pins and source provenance.
6. Record a candidate receipt: exact head/base, completed checks and local review,
   finding dispositions, exclusions and remaining release-only requirements.
   A passing candidate ends the internal loop. Advance to the next unit.

Before dispatching the expensive combined CI matrix, finish the capability/skip
inventory and pass the local native, host, and report-validator suites. A focused
unit pass is not that preflight. Use small local checks while reconciliation is
still changing the candidate; do not repeatedly launch a full matrix and cancel
it for the next known unit. Receipt-only documentation changes may carry forward
validated code/pin evidence when their non-documentation diff is proven empty.

A review pass is not evidence of correctness by itself. Do not weaken tests,
remove required coverage or redefine behavior merely to obtain a clean result.
Confirmed release-critical defects still block release. Optional style preferences
and unrelated improvements go to a separate backlog rather than reopening a
passing candidate. A recurring finding requires root-cause analysis or a smaller
unit, not additional unchanged review prompts.

## Copilot only at the late external checkpoint

Do not request Copilot during authoring, local hardening, predecessor propagation,
or routine fork PR staging. Do not create a PR or push solely to trigger Copilot.
Quota exhaustion, missing delivery or a historical round ceiling does not block
internal work or acceptance under the local contract above.

The final upstream SOP includes Copilot audits on the frozen, upstream-shaped
fork PRs before creating upstream PRs. This is the owner's selected late checkpoint;
it does not authorize requests during the current internal rehearsal phase.
Enter it only after the release and its proposed upstream units pass internal
acceptance and the upstream submission phase begins. Audit the small final units
and their affected interactions; do not substitute a broad product diff for them.
Never automatically start a repeat-until-silent Copilot loop. If findings arrive,
triage and fix them locally in a batch; a re-request needs a concrete reason tied
to that external checkpoint. Preserve prior dispositions and review counts.

A failed, missing or quota-limited review is not a clean review. Report Copilot's
actual status separately from internal readiness. Existing substantive findings
must still be resolved or explicitly declined on technical grounds; deferring
Copilot does not waive known defects or any upstream-required review gate.

## Final upstream SOP

1. Select an accepted release receipt and pin the live upstream target. Prepare
   the final small PR sequence on fork branches, recording source units and public
   dependency availability. Account for every intended product change or explicitly
   record what is deferred from this upstream batch.
2. Reconcile upstream-base differences locally and rerun affected checks plus the
   required assembled-candidate checks. Freeze the exact proposed heads and bases.
3. Perform final Copilot audits on these fork PRs before creating upstream PRs.
   Batch actionable findings into local fixes and revalidate. Record review IDs,
   head SHAs and technical dispositions. A quota failure is pending, not clean;
   continue independent local work but do not claim this checkpoint passed.
4. Record the final audit outcome honestly. The target is a delivered review with
   no actionable findings on the final candidate; any declined finding retains its
   rationale and must not be reported as a literal “no findings found” response.
   Material changes after review require an impact assessment and refreshed audit
   coverage before the checkpoint is considered complete.
5. Create upstream PRs from the validated sequence with concise behavior, provenance
   and test evidence. Upstream merging and release publication remain separate
   operations. Never merge the fork product PR into develop as a prerequisite.

## Evidence and invalidation

Record base/head SHAs, submodule IDs, check/artifact links, actual executed and
skipped tests, local review scope/result, dispositions, and acceptance status.
Record external review identities when available without making them implicit gates.
Retain completed review reasoning for unchanged surfaces. Reopen it when code,
dependencies, or new evidence invalidate that reasoning. A changed head needs
an explicit impact assessment and current candidate/check identity. Recheck the
changed behavior and affected interactions; preserve evidence for unchanged
surfaces. This does not require another Copilot request. Earlier evidence remains
supporting evidence rather than proof of the new candidate.

Build and test each unit green in its turn. Run required complete integration,
ARM/emulator, device/OLED, storage compatibility, and SRAM checks on the assembled
candidate as applicable to the shipped product. Do not add alpha product variants
merely because historical checklists mention them. Establish exact required
checks from the baseline and selected behaviors before implementation.

## Promotion and later alpha features

Foundation acceptance requires all selected units accepted, complete candidate
checks passing, and no unresolved release blockers. Record the accepted SHA.
Alpha features may be staged earlier in a new manifest using the same unit procedure. Release acceptance remains distinct from internal staging.

Reconstruct the accepted sequence from its recorded base and verify the expected
tree and pins before proposing any future promotion of develop. Preserve the previous develop tip.
Final contents must match the selected manifest, not all of alpha; explicitly
record intentional omissions. Keep dependent fork PRs stacked and unmerged. Future upstream submission
should preserve the independently reviewable units and dependency order.

Rehearsal success does not imply upstream acceptance. Before upstream PRs, verify
the live target base and public dependency availability. Reconcile any difference,
refresh affected evidence, and satisfy upstream dependency/merge requirements.

## Owner correction: unmerged fork stack (2026-09-08)

Fork develop and alpha are agent-controlled staging surfaces. Do not wait for
human approval to author, validate or stack internal PRs. Do not merge into
develop: the foundation targets fork develop and each dependent PR targets its
predecessor branch. Keep the new stack unmerged. A reviewer recommendation for
human review is recorded for upstream/release consideration; it does not block
internal staging. Specific unresolved defects still receive a disposition.

The existing fork develop contains later integrations. Reconstruct the selected
7.14.2 tree on an isolated descendant branch so its PR describes the proposed
foundation replacement without rewriting develop. Record the original target
SHA, exact source tree, intentional omissions and reconstruction checks.
Do not mistake the large replacement diff for a newly authored feature bundle.
