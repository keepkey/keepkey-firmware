# Alternate 7.15.0 source reconciliation

Sources are frozen: canonical `a56fb3e88` and alternate `e601d2df8`. The alternate
is an older implementation line, not a fourth product to merge wholesale.

| Older work | Disposition on the combined canonical candidate |
| --- | --- |
| RNG health, dice, BIP-85, Orchard/Pallas, protocol/build registrations | Present in current handlers, message map and compiled native suites; preserve current pins and newer crypto implementation. |
| 37abce4e5: typed-hash rejection and nonce health | Present: confirmation failures return before signing; PCZT randomness uses random_buffer_checked and the newer RedPallas API. |
| 37abce4e5: viewing-key consent and explicit account range | Missing and now restored in d4c82dd33; companion regressions reproduce both failures and pass after remediation. |
| 3aab0c37a / 906dd41ad: signing teardown, reset abandonment | Current fsm_abort_workflows and setup_abort implement the shared model. Low-level bypasses are closed by da5066be6, including Zcash abort and runtime signer revocation. |
| e601d2df8: private-key and derived-node cleanup | Present: signing_abort wipes privkey, root and node; fsm_abort_workflows wipes fsm_derived_node. Preserve current narrower cleanup on handler exits. |
| e601d2df8: stale EntropyAck after provisioning | Current storage_commit aborts an armed foreign setup ceremony before persisting; setup_commit disarms its own ceremony first. Preserve this central invariant rather than copying an older per-handler guard. |
| Unknown-version storage lockout | Superseded by the current explicit downgrade-erasure policy; see source-storage-policy.md. V18/V19 readers and current migration behavior are retained. |
| a0509f6c6 / 3aab0c37a: complete disclosure and cancel handling | Current confirm_bytes paths cover message signing/verification and identity challenges; contract dispatch bounds the complete calldata and honors confirmation results. Current Uniswap handlers have their own checks rather than the old blanket disable. |
| TON / opaque typed-hash authorization | Existing AdvancedMode gates remain. Structured EIP-712 stays disabled pending its separate canonical-display work. No attempt to enable it in this assembly. |
| Token chain identity and generated build dependencies | Current TokenType uses uint32_t chain_id; generation byproducts restored in 163652a88. |
| Orchard display and Ironwood capability | Already present in source; e08d607 removes three stale RC18 host skips. Five device PCZT tests pass. |
| Test build registration | Restored omitted FSM source and accessor in da5066be6; restored whole credential wipe in f5e00811a; shared test board bootstrap in 28cf2ae83. Full native suite passes. |
| Release signature verifier / production publishing | Remains a release-publication gate, not authority to sign, publish, or merge upstream during internal rehearsal. |

All other alternate build/style commits are superseded by current source/build
layout and required candidate CI. No wholesale merge, version rename, signature
change or new feature import is included. Physical OLED and signed upgrade checks
remain explicitly pending release gates; native and host passes do not claim them.
