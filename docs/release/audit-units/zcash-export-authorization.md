# Zcash viewing-key consent and account identity

Replay the applicable missing pieces of audited commit 37abce4e5. The current
nonce path already uses health-checked randomness and the newer RedPallas
implementation; preserve it. Viewing-key export still allowed the host to waive
consent, and explicit account indices still accepted the hardened bit, aliasing
account zero. Require consent unconditionally and reject the aliased range in
the shared account resolver.

Companion host regressions fail against the preceding candidate: export returns
keys despite rejection and both high-bit account values succeed. With this fix,
all 19 Orchard, fingerprint and device PCZT tests pass, including both boundary
subtests, valid account vectors, and the previously restored capability checks.
The complete native firmware suite passes in 23.54 seconds. Final combined CI is
required before canonical promotion. No equivalent feature exists in 7.14.2 or
the 7.14.3 Bitcoin-only product.
