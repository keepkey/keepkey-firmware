# P02-003: receive packet storage lifetime

Base: f20c2497a0990a6690c5bb804414c11cac74bf58 (7.15 accumulated audit).

The persistent UDP receive buffer retains the complete packet after its callback
returns. A native callback observes the original bytes during delivery and all
64 bytes still present afterward before the fix. USB main, debug and U2F device
callbacks have the same missing cleanup, including their short-read exits.
This is residual memory retention; no remote memory-disclosure exploit is claimed.

Wipe UDP storage after polling/dispatch and device packet storage after each
callback or short read. The decoded-message and tiny-message cleanups remain
necessary separately. Normal decoding copies input; U2F copies fragments into
its reader buffer; the bootloader RAW upload consumes bytes synchronously.
None of those consumers retains the packet pointer after callback return.

Validation: new USBRX.PacketStorageIsWipedAfterCallback fails on the base and
passes with the fix; all 501 full native firmware tests and 93 Bitcoin-only
firmware tests pass. The new UDP regression runs in the full suite; the
Bitcoin-only suite validates existing behavior. Device callbacks were source
reviewed but are excluded from native builds. ARM/host integration and older
release backports are pending. No hardware execution or full-phase completion
is claimed.
