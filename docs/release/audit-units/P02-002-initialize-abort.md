# P02-002: Initialize must abort every workflow (7.15)

Status: reproduced and fixed; native validation passes, assembly CI pending.

7.15 Initialize called a partial list of abort routines. Its soft session clear
preserves signing state by design, so Binance, Osmosis, THORChain and MAYAChain
sessions remained initialized after the host reset. 7.14.2 and 7.14.3 already call
fsm_abort_workflows() here; the 7.15 assembly had diverged.

Use the central abort function while retaining session_clear(false), which
preserves the cached PIN. Reuse the native multi-session fixture to test both
the central function and the actual Initialize handler. The new Initialize test
fails on all four named sessions before the fix and passes afterwards. Existing
low-level soft-clear behavior remains independently tested. Removed one byte-
identical duplicate CHECK_NO_CEREMONY definition in the reviewed FSM source;
its preprocessed behavior is unchanged.

Validation: all 500 full-firmware and 93 Bitcoin-only native firmware tests pass.
Native settings are the same Apple Clang/PB_NO_PACKED_STRUCTS and nanopb workaround
recorded in P02-001. Formatting and whitespace checks pass. This does not complete
the remaining handler-retention, host integration or full-release audit.
