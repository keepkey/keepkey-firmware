# P06-002: displayed Ripple address response survives debug requests

Base: 7a8a873c3 (host memo coverage pin).

On full 7.15, RippleGetAddress(show_display=true) returns the expected address
without screenshot capture, but an empty address with capture enabled. The
DebugLinkGetState handler reuses the shared response arena while confirmation
is pending. The old host display test explicitly ignored this empty response.
This is a debug/emulator interaction; production DEBUG_LINK-off behavior was
not shown to fail.

Keep the derived public address in its existing local buffer for confirmation.
Populate RippleAddress only after confirmation returns. Cancellation still
clears the derived node and sends failure. No added static allocation.

Reproduction: docs/release/rehearsals/ripple_display_response.py on the P00
audit branch starts an isolated emulator with forced UDP and screenshot capture,
then asserts the displayed-address response equals the known public test vector.
It fails before and passes after the change. Full native validation is recorded
in the central P02/P06 findings receipt after execution.

Other releases, persistent host-suite response assertion, full display review,
and ARM/host integration remain pending. Full audit is not complete.
