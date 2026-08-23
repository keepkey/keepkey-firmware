# Clear-sign providers: Phase 0 as a shippable tier

Status: **goals**, for agreement before build. Companion to
`clearsign-key-delegation-roadmap.md` (which defines Phases 0–3) and
`7.15.0-rc21-clearsign-release-control.md` (what ships today).

The roadmap treats Phase 0 as a developer affordance — "that path is for
developers and self-service, and it should never become the production path".
That sentence is about *warning-free* rendering, which Phase 0 can never deliver.
It is not an argument against shipping Phase 0 as a **product tier that never
claims to be warning-free**. This document states that tier so it can be
accepted or rejected deliberately rather than by omission.

---

## Scope invariant — this release

Stated as rules rather than a phase number, because the number is an index into a
document: it renumbers, it collides between documents, and a reader cannot check
it. These can be checked against code in under a minute.

1. **Additive only.** A provider adds screens; it never removes one.
   Enforced in firmware — EVM: `signed_metadata_from_loaded_signer()` forces
   `needs_confirm` and `data_needs_confirm` back to true, so the raw-calldata
   review still runs (`ethereum.c`). Solana: `signed_metadata_signer_is_runtime()`
   (`fsm_msg_solana.h`). Grep the names; the line numbers rot.
2. **Never claims KeepKey approval.** A runtime signer renders the provider's own
   alias and fingerprint plus "NOT verified by KeepKey".
3. **Opt-in, per session.** `AdvancedMode` is session state and never written to
   flash, and `signed_metadata_confirm_load` is a device confirm that cannot be
   suppressed. Identities are RAM-only.

**Anything that suppresses a screen or renders a KeepKey endorsement is a
different release.** Root custody, delegate certificates, quorum and freshness all
sit on that side of the line — see `clearsign-key-delegation-roadmap.md` §0a,
where every one of those decisions is already locked.

Phase numbers in this repo label history, not scope. If a phase number and this
section ever disagree, this section wins.

---

## The model

A **clear-sign provider** is a third-party identity that supplies decode context.
It is **not** KeepKey attestation, and KeepKey never tells the user otherwise.

- **Pioneer is the first provider**, and the reference implementation.
- The Pioneer identity is **unsigned by KeepKey**. The device shows the
  provider's own alias and fingerprint; nothing represents it as endorsed.
- Until Phase 2 we **accept** that: no warning-free rendering, no KeepKey claim.
- Context is **purely additive**. The baseline raw/unverified review is retained
  after the decoded screens, exactly as firmware already enforces for runtime
  signers.

**Omission of review before the advanced gate is reserved for Phase 2 and
nothing else.** A provider adds screens; it never removes any.

The Phase 1 / Phase 2 boundary is therefore best named as the **"signed by
KeepKey" gate**. Crossing it is what buys suppression — and it is also the path
by which a provider is eventually promoted: once the KeepKey root signs a
delegate certificate for Pioneer, Pioneer becomes KeepKey-approved and its
context may render without the alarm. Until then it is a named third party and
is displayed as one.

## What already works, unchanged, on rc29

None of the following needs firmware work:

| capability | mechanism |
|---|---|
| load a provider identity at runtime | `LoadClearsignSigner` (alias, 33-byte pubkey, optional icon) |
| user sees WHO they are trusting | `signed_metadata_confirm_load(alias, fingerprint, icon)` — an on-device confirm |
| provider context is additive only | EVM: `signed_metadata_from_loaded_signer()` forces `needs_confirm` and `data_needs_confirm` back to true, so the raw-calldata review still runs (`ethereum.c`). Solana: `signed_metadata_signer_is_runtime()` (`fsm_msg_solana.h`) |
| a rogue provider cannot hide bytes | runtime signers may never suppress the raw-data review (the failure that closed fw #322) |
| trust dies on its own | identities are RAM-only: cleared by reboot, `ClearSession`, session teardown, or disabling `AdvancedMode` |
| pre-signed additive payloads | EVM v2 blobs; Solana KKSOLSC1 instruction schemas |
| live per-transaction context | `EthereumTxMetadata`, bound to the tx via `signed_metadata_matches_tx` |

## Two constraints that shape the build

### 1. Loading is confirmed on device, every session

`signed_metadata_confirm_load` is not optional and cannot be suppressed — the
firmware comment is explicit that *the whole trust model hangs on this confirm*.
Vault therefore **cannot silently auto-load a provider**, and should not try.

This is a feature for this tier, not friction: the confirm screen showing
`Pioneer` + fingerprint **is** the moment the user learns the context is
third-party. Because identities are RAM-only, it recurs every reboot, so the
disclosure cannot be shown once and forgotten.

The honest UX is therefore *"enable AdvancedMode → Vault offers to load Pioneer →
device shows the identity → user confirms"*, once per session — not a silent
background load.

### 2. Live per-tx context is EVM-only, and Solana does not need it

`EthereumTxMetadata` is transaction-bound, so a provider can sign *this*
transaction *now*. `SolanaSignTx` accepts only
`schema_payload` / `schema_signature` / `schema_signer_key_id` — instruction
scoped and reusable, with no per-tx field.

**This is not a Solana gap to close with firmware.** A Solana schema describes
how to *read* an instruction; the device decodes the actual values out of the
bytes it is about to sign, so the display is bound to the signature by
construction. Per-transaction signing would add nothing to decode correctness.

The real Solana limitation is **address lookup tables**: `solana.c:204` —
"Accounts resolved via lookup tables: unverifiable on-device" — and
`solana_schemaApplies` skips instructions whose accounts are absent from the
signed message (`if (ix->external) continue`). A live signature cannot repair
this, because the device would have to take the host's word for accounts it
cannot see, which is precisely what it refuses to do.

**The fix is host-side: the provider must inline ALT accounts into the message
before signing.** No firmware change.

Per-tx Solana attestation is only interesting later, for context that is *not*
derivable from the bytes at all (reputation, recipient labels, fiat values) —
a Phase 3 want, not a blocker here.

## What actually has to be built

Nothing in firmware. The work is provider-side and host-side:

1. **Pioneer signing service** — holds the provider key; pre-signs the schema
   catalog, and signs per-transaction EVM metadata live.
2. **Pioneer ALT inlining** — so Solana schemas can apply at all.
3. **Vault provider flow** — offer to load the provider after AdvancedMode is
   enabled, surface the device confirm, remember the *user's choice* as a Vault
   setting while the *device trust* stays session-scoped, and attach provider
   payloads only when a provider is actually loaded.
4. **Replace the CI test key.** `solana-schemas-local.json` currently ships two
   schemas signed with the CI test key in slot 3 and says so in its own notes.
   Those must be re-signed by the provider key, or removed — shipping
   test-signed material to customer devices is how a swap reaches a device that
   cannot verify it.

## What this tier explicitly does not claim

- No warning-free rendering. The blind-sign review always follows.
- No KeepKey endorsement of the provider.
- No suppression of any screen before the advanced gate.
- No persistence of device-side trust across a reboot.

A compromised provider key can therefore **mislabel** a transaction, but cannot
**conceal** it: the user still sees the raw review and an explicit
"cannot fully verify" prompt, and the trust expires on its own. That bounded
blast radius is the reason this tier needs no custody programme — and the reason
it must never be quietly upgraded into one.

## Open question for the roadmap

The roadmap already asks (§ *Open parameters*) whether a delegated v1 should
render truly warning-free or keep a subtler marker such as
*"described by KeepKey, 12 Aug"*. The same question applies one phase earlier and
is not asked there: **what marker does a Phase 0 provider carry?** Today it is
the generic blind-sign warning, which does not name the provider on the
signing screen even though the load screen did.
