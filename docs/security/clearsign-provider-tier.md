# Clear-sign providers: Phase 0 as a shippable tier

Status: release policy.

This tier never claims to be warning-free. It permits developer and
self-service providers only when the device preserves the ordinary transaction
review and clearly identifies the provider as unverified by KeepKey.

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
different release.** Root custody, delegate certificates, quorum, and
freshness are outside 7.15.

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

### 2. Live per-tx context: EVM metadata, plus Solana lookup-table accounts

`EthereumTxMetadata` is transaction-bound, so a provider can sign *this*
transaction *now*. Solana's reusable path — `schema_payload` /
`schema_signature` / `schema_signer_key_id` (`KKSOLSC1`) — is instruction
scoped, and does not need to be transaction-bound: a schema describes how to
*read* an instruction, and the device decodes the actual values out of the bytes
it is about to sign, so the display is bound to the signature by construction.

The one Solana surface that *does* need a per-transaction attestation is
**address lookup tables**: `solana.c` — "Accounts resolved via lookup tables:
unverifiable on-device" — and `solana_schemaApplies` skips instructions whose
accounts are absent from the signed message (`if (ix->external) continue`).
Such a message is forced to `SOL_TX_REVIEW_OPAQUE`, i.e. refused outright
without `AdvancedMode` and an explicit blind sign with **nothing** shown.

**That attestation ships in this release** (`KKSOLSW1`, firmware PR #500), so
the earlier "no firmware change" framing no longer describes the device:

- `SolanaSignTx` carries `lut_account` (≤ 8 × 32 bytes), `lut_signature` and
  `lut_signer_key_id`.
- `solana_lut_accounts_trusted()` (`solana.c`) verifies a **runtime** signer's
  signature over `"KeepKeySolanaTxAccounts/1" || sha256(raw_tx) ||
  count(le32) || key[i]` — domain-tagged, and bound to the exact message being
  signed, so it cannot be replayed onto another transaction.
- `fsm_msg_solana.h` then draws a "Lookup Accounts" screen naming the signer's
  alias and fingerprint plus "NOT verified by KeepKey", followed by one screen
  per base58 account.

This is the tier's invariant applied, not an exception to it: the screens are
**additive and drawn before** the blind-sign warning, never instead of it, and
an absent, malformed or unverifiable attestation draws nothing and leaves the
flow byte-for-byte what it was. The accounts stay host-supplied and are never
represented as derived — the device still cannot see them; it now names who is
claiming them, which is the whole difference between a blind sign and a
described one.

**Host-side ALT inlining remains the stronger fix where a provider can do it**,
because inlined accounts are derived from the signed bytes rather than asserted
by a third party. The attestation is the fallback for the messages where it
cannot.

Per-tx Solana attestation for context that is *not* derivable from the bytes at
all (reputation, recipient labels, fiat values) is still a Phase 3 want, not a
blocker here.

## What actually has to be built

The firmware side of the Solana lookup-table gap shipped as `KKSOLSW1` (§2
above); everything remaining is provider-side and host-side:

1. **Pioneer signing service** — holds the provider key; pre-signs the schema
   catalog, and signs per-transaction EVM metadata and `KKSOLSW1` account lists
   live.
2. **Pioneer ALT resolution** — inline lookup-table accounts into the message
   where possible, so Solana schemas can apply at all; where that is not
   possible, attest the resolved account list so the accounts are at least
   named on screen.
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

## Human-attestation gate (Solana attestor)

The constrained `KKSOLSC1` attestor is usable only while `AdvancedMode` is
enabled. Loaded signer identities are RAM-only; metadata from a runtime signer
is annotation-only and never suppresses the baseline raw/unverified review.

Before it signs, the attestor must show every security-relevant declaration:

1. program and instruction labels;
2. the complete base58 program ID on its own confirmation;
3. the complete discriminator on its own confirmation;
4. every argument's ordinal, ABI type, and label; and
5. every displayed account index and label.

Program ID and discriminator may not share one notification screen — a
44-character base58 program ID consumes two body rows, and an 8-byte
discriminator cannot reliably fit in the remaining row. Argument types may not
be omitted: two different ordered type declarations can have the same total
width while assigning the same labels to different byte offsets.

`SolanaSignTx` tags 9, 10, and 11 carry `schema_payload`, `schema_signature`,
and `schema_signer_key_id`. Tags 5, 6, and 7 are **no longer reserved**: they
are the shipped transaction-bound `KKSOLSW1` attestation (`lut_account`,
`lut_signature`, `lut_signer_key_id`). Only tag 8 is still held back, for
one-request opaque-signing consent — removing that reservation or assigning
that tag is a protocol-review event.

A host built against the older experimental schema contract (tags 5, 6, 7)
therefore no longer falls back by protobuf ignoring unknown fields: its bytes
now **decode** into the `lut_*` fields. The fallback is still safe, but the
mechanism is validation — every `lut_account` must be exactly 32 bytes, the
count must be 1–8, and the signature must verify against a loaded signer over
this transaction's own hash — so stale or foreign material is rejected and no
extra screen is drawn. That rejection remains operationally silent, so host
release notes must state which contract a reusable schema requires.

## Open question for the roadmap

The roadmap already asks (§ *Open parameters*) whether a delegated v1 should
render truly warning-free or keep a subtler marker such as
*"described by KeepKey, 12 Aug"*. The same question applies one phase earlier and
is not asked there: **what marker does a Phase 0 provider carry?** Today it is
the generic blind-sign warning, which does not name the provider on the
signing screen even though the load screen did.
