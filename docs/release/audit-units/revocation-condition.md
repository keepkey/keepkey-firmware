# 7.15 revocation condition integration cleanup

Base: aa884ebe611ccf25d8745e7ef612a19e143879e1.

CI run 34279482948 reported one cppcheck duplicateCondition diagnostic in
session_clear_impl. Combine adjacent clear_pin blocks, preserving workflow
abort, signer clearing, and AdvancedMode revocation in their existing order.
There is no authorization or persistence behavior change.

Local acceptance: cppcheck warning/style/performance/portability with force and
inconclusive configuration exploration reports no diagnostics for storage.c;
clang-format 20 and git diff --check pass. Rebuilt firmware-unit and kkemu;
all 46 Storage, Fsm, and PassphraseTransition tests pass. Complete product CI
must pass on the assembled successor before canonical promotion.
