# Storage source-policy reconciliation

The older 7.15.0 commits 3aab0c37a and 906dd41ad preserve unreadable storage
records across downgrades. The current 7.15 program's `docs/StorageVersionGate.md`
explicitly requires unknown-version downgrades to wipe and forbids adding a
compatibility shim. The retained contract is upgrade preservation, contiguous
shipped-version recognition, and deliberate downgrade erasure. The old lockout
behavior is therefore superseded, not a missing fix to replay.

An experimental uncommitted replay proved the behavioral difference and was
withdrawn before publication. No unsupported-version lockout change is included
in this candidate. Bitcoin-only band refusal retains its separately specified
behavior. Signed physical upgrade verification remains a final release gate;
emulator tests cannot prove bootloader signature handling.
