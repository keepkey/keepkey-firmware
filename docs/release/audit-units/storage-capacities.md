# Versioned storage buffer capacities

Product: 715. Carry the previously audited `be82c15c4` capacity checks
into the product without changing its flash format. V11 uses its actual encrypted
payload footprint; V16/V17 readers and writers validate their complete buffers;
outer record wrappers account for metadata and forward the remaining capacity.
7.15 also guards its retained V18/V19 helpers so their nested calls cannot return
early and then allow an outer out-of-bounds access or partial state mutation.

Scope includes canary/state-preservation regressions and the existing V11 fixture's
actual buffer size. The 7.15 legacy helpers retain their identity-clearing and
KDF-flag semantics. No new persistent fields are introduced.

Local checks: 7.14.3 passes 22 storage tests; 7.15 passes 29 storage tests, including
V18/V19 declared-footprint canary checks. Exact candidate power-cycle verification
uses the companion host suite with scoped emulator ports and variant-aware stamps.
Its base remains the product's original host suite, extended by PRs #69–#71.
Current Python pin: `60ce9f32fed1c3a8a509aeb264a5e772dabdfd8d`.

Product-level ARM, complete integration and acceptance receipts remain pending.
This is a bounded audit unit, not a claim of complete release acceptance.
