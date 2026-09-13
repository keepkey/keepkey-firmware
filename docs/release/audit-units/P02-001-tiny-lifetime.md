# P02-001: Tiny-message credential lifetime (7.15)

Status: native regression reproduced, fixed and rechecked; assembly integration
and ARM/host validation pending. This is an existing defect, not introduced by
the P01 changes.

The ordinary protobuf dispatch buffer was wiped, but tiny-message acknowledgements
used separate persistent storage. A passphrase acknowledgement followed by an
empty ButtonAck copied the previous passphrase bytes into the later caller's
buffer. The new native UDP regression reproduces this on all three products
before the fix and passes afterwards.

Clear tiny decode storage before reception, after malformed decoding and after
copy-out. Wipe the decoder's temporary wire copy on every populated-buffer exit.
PIN/passphrase readers and confirmation exit also wipe their caller-owned copies.
The dice caller (where present) already wipes its copy at exit. No cache policy,
wire format or successful acknowledgement sequence changes.

Validation: 499 full-firmware and 93 Bitcoin-only firmware tests pass. The USBRX regression is
`USBRX.TinyAcknowledgementDoesNotReusePreviousSecret`; the existing overflow,
error-handling and nanopb capacity tests also pass. Native builds use Apple Clang
with PB_NO_PACKED_STRUCTS=1 and the documented local nanopb generator workaround;
these runs do not replace pinned ARM builds. Formatting and whitespace checks pass.

Scope is decoded tiny-message and immediate caller lifetime. Lower-level USB/UDP
packet storage and other transport interactions remain separately inventoried;
this receipt does not assert all transport copies or all P02 paths are audited.
