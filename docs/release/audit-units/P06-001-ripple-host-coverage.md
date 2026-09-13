# P06-001: execute the existing Ripple memo assertion

Base firmware: 041a23d5c (P02 packet-lifetime fix).
Host predecessor: 08e491c60fe36110598a3791b2441644fcf55f76.
New host pin: fb968836ba7ef354c55b89c9ba88bae19bc2c2ce.
Host fork PR: https://github.com/BitHighlander/python-keepkey/pull/76

The memo serialization test was unconditionally skipped with a stale claim
that the protocol lacks a memo field. Full 7.15 implements the field, review
and serialization. Remove that skip, require firmware 7.15.0 and preserve the
full-feature guard and the original memo/no-memo assertions.

All three Ripple host tests pass against rebuilt full 7.15 kkemu at the base
firmware commit. All three skip correctly on Bitcoin-only. Tests ran via forced
UDP against an owned emulator with isolated temporary storage; no hardware used.
The new full host commit is fetchable through the configured submodule URL.
Only the test gate changes; no firmware source or protocol mutation.

Combined CI remains pending. This closes the unconditional skip, not the
remaining Ripple serialization, display/cancellation or client integration
audit. No Copilot request or develop merge.
