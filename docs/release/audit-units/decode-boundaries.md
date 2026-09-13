# Exact decoding and terminal transport rejection

Product: 715. This unit replays existing audited nanopb exact byte
capacity enforcement (`aec631ce3`) and transport workflow abort (`d3e147ccf`).
It preserves the product's existing features and crypto/protocol pins. Python
host tests remain based on the product's `9c398203` suite, with only the exact
transport error assertion updated (companion PR #69).

Contract: a bytes field cannot consume alignment padding beyond its declared
capacity; rejection must terminate active signing before a follow-up packet.
The three native nanopb regressions run in both full and Bitcoin-only builds.
No storage format changes or broad alpha import are included.

Local validation: firmware, board and crypto suites pass on this product's
native emulator build. 7.15 additionally passes its Pallas and Zcash crypto
suites. Host signing-boundary validation is tracked with the exact product
emulator. Native accommodations: C++14, PB_NO_PACKED_STRUCTS=1, CMake minimum
policy compatibility and nanopb 0.3.9.4 generator command spelling.

Storage power-cycle verification is a separate open harness issue: the network
guard rejects dynamically allocated loopback ports used by the owned emulator.
Do not count skipped or blocked power-cycle tests as passing. ARM/full integration
and release assembly evidence remain pending. No Copilot requested.
