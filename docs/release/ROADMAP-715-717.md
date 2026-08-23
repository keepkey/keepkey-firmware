# Release roadmap: 7.15 → 7.16 → 7.17

Three gates. Each independently shippable, each independently revertible.

> **description → authority → resilience**

| | 7.15 | 7.16 | 7.17 |
|---|---|---|---|
| **Adds** | Clear-signing describes a transaction | KeepKey signs the describer | The system survives a bad describer |
| **User sees** | More screens. Never fewer. | Fewer screens, when KeepKey vouches | Assertion visibly distinct from fact |
| **Trust model** | Provider is a named third party, "NOT verified by KeepKey" | Provider carries a KeepKey delegate certificate | Certificates rotate, expire, revoke |
| **Blast radius of a compromised provider** | Can mislabel, cannot conceal | Can conceal — hence custody | Bounded by rotation + quorum |
| **Needs custody programme** | No | **Yes** | Yes |
| **Gate that separates it** | no pinned key in the image | a pinned root public key | rotation without bricking |

## Why the order is not negotiable

7.15 is safe without key management **because it cannot suppress**. The raw
review always follows, and trust dies at reboot. That bounded blast radius is
the entire reason it needs no custody programme.

7.16 removes the bound. The moment a describer can suppress the raw screen, a
compromised describer can hide transaction bytes — so 7.16 cannot ship the
suppression branch without also shipping the key management that makes it safe.
They are one release, not two.

7.17 answers "what if we get it wrong": rotation, revocation, freshness, and the
distinction between what the device *derived* and what someone *asserted*.

## The single line that separates 7.15 from 7.16

```c
if (signed_metadata_from_loaded_signer()) {
    needs_confirm = true;  data_needs_confirm = true;   // 7.15: additive
} else {
    needs_confirm = signed_metadata_schema_moves_value();
    data_needs_confirm = false;                          // 7.16: may replace
}
```

The else-branch is already in the tree and is **unreachable**: it requires a
firmware-pinned signer, and `signed_metadata.c` contains zero key bytes.

**The 7.15 release gate is therefore a single checkable property:** no pinned
provider key in the artifact. Everything else in the tier — RAM-only identities,
per-session re-confirm, "NOT verified by KeepKey" — follows from it.

## Sequencing risk

If 7.16's custody programme is not ready, **7.15 ships and keeps shipping**.
Additive clear-signing does not decay while it waits, because its safety comes
from structure rather than from key hygiene.

The reverse is not true: shipping suppression before custody would be a
one-way door.

## Documents

- `SRS-7.15.md` — requirements, verification status, exit criteria
- `SRS-7.16.md` — delegation and what changes on screen
- `../security/DESIGN-716-reductive.md` — how the reductive branch is built, and why it is small
- `TOKEN-TABLE-BUDGET.md` — the 500-entry cap, and what it cannot fix
- `SRS-7.17.md` — rotation, revocation, asserted-vs-derived context
- `DEFECTS-2026-08.md` — defect register from the alpha integration
- `../testing/ATLAS-GUIDE.md` — how to read the test report, and what it cannot tell you
