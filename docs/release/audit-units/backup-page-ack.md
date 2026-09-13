# 7.15 backup subpage acknowledgement

Base: c8dd8717bb30c5532a226a7cf5ed02ccd51a5973.

CI 34281427504 passed static analysis, both ARM/emulator/unit variants, the
shared-library suite and Bitcoin-only integration. Full integration failed one
reset/recovery case: a delayed `Device wiped` response arrived at the recovery
prompt. The failure remained visible in the required report and aggregate gate.

The DEBUG_LINK backup pager emits a new ButtonRequest per debug-driven subpage
but retained the prior button_request_acked flag. A decision arriving before its
new acknowledgement could therefore exit the subpage early, leaving an unread
acknowledgement for subsequent protocol work. Clear that flag before each new
request, as the ordinary page-body confirmation helper already does. Physical
paging and non-debug target code are unchanged.

Deterministic regression: queue each decision before its acknowledgement for a
multi-subpage backup and inspect the remaining queue. Before the fix, the test
fails with one unread message. After the fix, it passes with none beyond the
explicit rejection sentinel. This tests protocol consumption rather than source
text or timing sleeps. Fifteen ordinary local recovery reruns had passed before
the fix, demonstrating why an ordering-specific regression was necessary.

Focused cppcheck configuration exploration and formatting/diff checks pass.
Complete native full and Bitcoin-only suites pass; full includes the new test.
Complete host preflight and assembled CI remain required for canonical promotion.
