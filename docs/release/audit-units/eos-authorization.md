# EOS authorization hashing and disclosure

Carry the existing foundation fix `5a0f73448` and its regressions. Hash waits
using waits_count rather than accounts_count; validate exactly one raw/derived
key source; ensure account delegations cannot use single-key confirmation.
Preserve the product's existing chain implementation and dependency suite.

The companion host pin carries the independently verified UpdateAuth vector,
without a phantom six-byte wait. Three native authorization regressions and all
34 EOS host tests passed on the full 7.15 candidate. Bitcoin-only compiles this
engine and these chain tests out; the retained full build gets the same correction
and must pass its own CI. No claim that EOS is enabled in the Bitcoin-only product.

No new feature is added. This reconciles a known audited fix into current release
sources; assembled ARM/integration evidence remains the promotion gate.
