# Revoke signing at low-level storage authorization boundaries

Reconcile the previously audited `e601d2df8` teardown behavior. Direct callers of
`session_clear_impl(..., true)` bypassed the public wrapper and left Bitcoin
signing active. Wiping storage and clearing keys also now abort active workflows.
A soft session clear preserves signing, as required by existing authorized flows.

The regression starts a real signing session and exercises both low-level paths.
The restored firmware FSM test file had been omitted from this product's CMake
source list. Its declared signing-state accessor is now implemented. Zcash abort
and runtime metadata signer revocation are included at the relevant boundaries.
The PIN regression failed before the fix and passes afterward. Of 46 focused
tests, 45 pass; the restored authenticator credential-wipe test exposes a separate
known foundation gap, to be closed by the next unit before product acceptance.

Final combined product validation remains required.
