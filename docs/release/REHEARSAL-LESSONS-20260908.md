# Why the release reviews did not converge

PR size contributed, but the larger problem was inconsistent source identity and
coverage. More review prompts could not repair those bookkeeping failures.

| Observed problem | Concrete evidence | Required system behavior |
| --- | --- | --- |
| “Audited” described a different tree from the product | Canonical 7.14.2 began at cdde6888c while the selected audited successor was e519dc13c; 7.15 and 7.15.0 had divergent implementations. | Freeze sources, reconcile by behavior, and publish exact canonical acceptance receipts. |
| Tests existed but did not execute | 7.15's FSM test file was omitted from CMake. Restoring it exposed the missing credential wipe. | Check build registration and actual test counts, not filenames or prior review claims. |
| Green host totals hid required capabilities | RC18-based version gates skipped provider additivity, session lifetime, Solana LUTs, Zcash capabilities, and recovery validation present in canonical 7.15. | Reconcile every skip with current product scope; require must-run coverage in report validation. |
| Small units passed while their combination failed | Restored FSM tests and the older confirmation helper initialized the board twice, hanging the full native suite. | Run complete assembled suites before acceptance; repair the shared fixture rather than disabling coverage. |
| Historical fixes conflicted with current policy | The older unknown-version preservation behavior contradicted the selected downgrade-erasure policy. | Classify old fixes as present, missing, superseded, or excluded before replaying them. |
| Passing evidence was attributed too broadly | Earlier host/CI passes did not include subsequent teardown and Zcash fixes. | Name the exact code head, dependency pins, variants, artifacts and limits for every receipt. |
| Full CI started before reconciliation finished | Several intermediate matrices were superseded by the next known unit. | Complete capability inventory and local native/host/report preflight before dispatching expensive combined CI. |

The stopping rule is finite: the declared product contract passes, every known
applicable finding has a disposition, and the tested assembly is on the canonical
branch. Freeze it. A new concrete critical finding may reopen affected acceptance;
an unchanged broad review prompt or an unrelated improvement may not.

Keep two PR types. Product PRs are cumulative integration views into fork develop
and stay unmerged. Audit PRs target fixed immediate predecessors and carry one
explainable behavior. Final upstream preparation uses the accepted units and
performs Copilot review late; it does not restart whole-alpha discovery.

This exercise added regression evidence and restored known fixes. It did not
establish a proof of zero bugs, perform physical OLED/signed-upgrade validation,
or authorize upstream publication. Those distinctions belong in the receipt,
not in another indefinite internal review loop.
