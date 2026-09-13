# Share the native test board bootstrap

Restoring the omitted FSM suite makes its auto-lock test initialize the board
before the confirmation tests. The older THORChain helper initialized it again,
relinking static timer queues and hanging the complete native suite. Use the
existing shared one-time bootstrap from test_board.cpp. No production behavior or
confirmation-count assertion changes.

Before: the complete firmware suite timed out at the first authenticator confirm.
After: the firmware suite passes in 25.55 seconds. Focused FSM and authenticator
checks alone could not expose this ordering problem; full-suite validation did.
