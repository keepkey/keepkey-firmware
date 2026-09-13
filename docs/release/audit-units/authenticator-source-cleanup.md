# Wipe the complete authenticator credential input

Restore the audited foundation's source-buffer cleanup while preserving 7.15's
newer display validation, duplicate rejection, and confirmation behavior. Save the
original input length before strtok modifies separators, then wipe the complete
mutable input on every exit. Reject a null input before parsing.

Restoring the omitted FSM test suite in the preceding unit exposed this gap:
Fsm.AuthenticatorCredentialSourceIsWipedOnEveryExit failed before this change.
All 46 focused FSM, storage, and passphrase transition tests now pass, including
that regression and both low-level PIN-revocation tests.
