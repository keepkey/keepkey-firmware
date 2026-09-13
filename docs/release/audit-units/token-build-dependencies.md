# Generated token dependency ownership

Replay the accepted R142-02 build dependency fix: declare both token definition
files as byproducts of their generator target. Preserve this release's generator
validation command. This lets Ninja order and regenerate consumers correctly.
The original unit proved deletion and one-build regeneration. Combined native and
CI validation are required for this release candidate.
