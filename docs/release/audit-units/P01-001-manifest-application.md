# P01-001: require an application for every firmware manifest

Affected source: 7.15 a18317f8869bb905cac9322f0d76ca7aacbaf544,
`scripts/release/hash-manifest.sh` blob `e4503cd2316a0fa6e884f963072134ec491d6b43`. Origin: existing source defect, not a change
introduced by this audit. Status: reproduced and fixed; release assembly pending.

The default manifest invocation on an empty directory exited zero and printed
“Generated from the signed release artifacts: 0 application”. The same failure
occurred if the expected binary was present but lacked the KPKY descriptor.
The script already documents an exactly-one-application contract, but enforced
its nonempty condition only for --require-signed. This makes ordinary unsigned
release-manifest generation fail open when its input application is missing.

Require exactly one matching application in both modes. Preserve the separate
structural quorum check and its explicit limit: it does not verify signatures.
Correct the stale comment claiming no host signature verifier exists; the
adjacent verify-signatures.py implements that check.

Validation: before, empty default invocation exits 0 with the misleading signed
label; after, it exits 1. Extended existing self-test covers empty input and an
invalid application descriptor in both modes, plus successful explicitly unsigned
output for a valid unsigned application. Shell syntax and diff checks pass.
No production keys, signing, release tags or publication are involved.

7.14.2 and 7.14.3 do not contain this standalone script; their release workflows
have separate audited-artifact and manifest paths. Do not transplant this fix
into those products or mark those workflows reviewed based on this result.
