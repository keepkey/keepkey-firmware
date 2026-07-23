# Generalized Cosmos and Tendermint signing

Status: future design proposal

This document describes a path to full Cosmos SDK `SIGN_MODE_DIRECT` support,
generalized Tendermint/CometBFT-family signing, and IBC transfers across supported
chains. It is not part of the 7.15.0-rc17 release scope and does not change that
release's acceptance criteria.

The name "Tendermint" is retained where it refers to the existing KeepKey
protocol. New code should use the more precise terms "Cosmos SDK" and
"CometBFT-family."

## Product position

Blind signing with an explicit warning is a valid first support tier for a new
chain or message type. KeepKey already uses this phased model for Ethereum
contract data and opaque Solana, TRON, TON, and EOS operations. Generalized
Cosmos support should follow the same model:

1. Sign the exact transaction bytes in Advanced Mode after an unmistakable blind
   signing warning.
2. Parse and display transaction envelope fields that can be bound to those
   exact bytes.
3. Add clear-signing adapters for common messages over time.
4. Automatically replace blind review with clear review as message adapters
   become available.

Unknown does not mean forbidden. It means the device must never present an
unknown message as understood.

This distinction makes broad compatibility practical:

- A Cosmos SDK transaction using a supported key algorithm and
  `SIGN_MODE_DIRECT` can be signed even when one or more `Any` message values are
  not understood by the firmware.
- Recognized messages receive semantic clear-signing screens.
- Unrecognized messages receive blind-signing screens and an exact transaction
  commitment.
- A non-Cosmos application built on Tendermint or CometBFT can reuse the
  generalized byte-signing engine, but still needs an adapter defining its
  signing domain, preimage, and key algorithm. A Cosmos `SignDoc` is not a
  universal transaction format for every CometBFT application.

The target is therefore universal signing compatibility for supported
algorithms and defined signing domains, not a claim that the firmware
semantically understands every application.

## Goals

- Implement Cosmos SDK protobuf `SIGN_MODE_DIRECT`.
- Preserve legacy Amino support for chains that still require it.
- Blind-sign otherwise valid, unsupported Cosmos messages behind Advanced Mode.
- Progressively clear-sign known bank, staking, distribution, governance, IBC,
  authz, feegrant, CosmWasm, and chain-specific messages.
- Derive and display addresses for arbitrary compatible chains without
  conflating display names, registry identities, and Bech32 prefixes.
- Support arbitrary Cosmos coin denoms, canonical integer amounts, multiple
  coins, fee grants, and fee payers within explicit resource limits.
- Clear-sign ICS-20 transfers for all valid routes and assets, including
  voucher, factory, and long trace-derived denoms.
- Reuse a bounded, session-oriented byte-signing core for non-Cosmos
  CometBFT-family adapters.
- Keep every reviewed value cryptographically bound to the exact signed
  preimage.

## Non-goals and boundaries

- The firmware does not discover IBC paths, channels, counterparty chains, or
  relayers. The host builds the route; the device reviews the source-chain
  transaction.
- Blind signing does not provide semantic verification. A digest and byte count
  prove which bytes were approved, not what an unknown message will do.
- Host-provided labels, symbols, decimals, recipients, or amounts must never
  substitute for values parsed from the signed bytes.
- `SIGN_MODE_DIRECT` does not cover every non-Cosmos CometBFT application.
  Applications with different signing preimages or algorithms require explicit
  adapters.
- Multisig, `SIGN_MODE_DIRECT_AUX`, `SIGN_MODE_TEXTUAL`, and non-secp256k1 keys
  are not implied by the first implementation. They require explicit protocol
  and UX decisions.

## Current implementation and gaps

The existing generic Tendermint protocol is a legacy Amino implementation. It is
useful compatibility code, but it is not a base for universal support.

| Area | Current behavior | Required v2 behavior |
| --- | --- | --- |
| Sign mode | Legacy Amino JSON only | Exact protobuf `SignDoc` bytes for `SIGN_MODE_DIRECT`, plus legacy Amino |
| Generic messages | Wire schema advertises several message types; firmware handler accepts only `send` | Known messages clear-sign; every other valid `Any` can blind-sign |
| IBC | Generic IBC schema has no amount field | Bind token, sender, receiver, port, channel, timeouts, and memo |
| Amounts | Message amount is `uint64`; fee is `uint32` | Canonical unsigned decimal strings with an explicit maximum |
| Denoms | Generic denom is limited to 9 characters | Long exact denoms, including `ibc/<64-hex>` and factory denoms |
| Fees | One session-wide denom is reused | Repeated fee coins, independent message coins, gas, payer, and granter |
| Chain identity | `chain_name` is both coin lookup name and address HRP; `address_prefix` is ignored | Immutable, separate chain ID, registry ID, display name, and HRPs |
| Address support | Limited by the compiled coin registry | Validated chain descriptors and explicit path policy |
| Tests | Generic coverage is primarily session/config binding | Cross-SDK vectors, parser adversarial tests, emulator UX, and hardware QA |
| Host integration | Generic address support is partial; generic signing is not end-to-end | Protocol, hdwallet, Vault, registry, builder, and broadcast support |

The existing `Tendermint*`, `Cosmos*`, and `Osmosis*` message IDs must remain
compatible. The new design should use new v2 message IDs and implementation
state rather than changing the meaning or size limits of old fields.

## Signing and review tiers

The transaction is assigned the least-trusted tier required by any component.
One unknown message downgrades the transaction to blind or mixed review; it must
not inherit a clear-sign label from neighboring known messages.

### Tier A: clear signing

All security-relevant fields are parsed from the exact signed bytes and displayed:

- chain ID and signing account;
- message actions, senders, recipients, validators, contracts, and parameters;
- exact coin amounts and denoms;
- memo and timeout values;
- fees, gas, payer, granter, and sequence as applicable.

Friendly symbols or decimal conversion may supplement raw values only when the
metadata is trusted and the exact denom remains reviewable.

### Tier B: mixed review

The firmware understands the transaction envelope and some messages, but at
least one message or extension is opaque. It:

- clearly labels the whole transaction as containing unverified actions;
- displays all safely parsed envelope and known-message fields;
- displays each unknown `type_url`, value byte count, and value digest;
- displays an overall signing-preimage digest and byte count;
- requires Advanced Mode and explicit blind-sign confirmation.

### Tier C: blind signing

The adapter can validate the signing domain and sign the exact preimage, but
cannot semantically parse the application payload. It:

- requires Advanced Mode;
- displays a prominent "Blind Sign" warning;
- displays the chain/signing domain, derivation path or derived address, exact
  byte count, and full transaction digest;
- never displays host side-channel values as if they came from the transaction;
- signs only after an explicit final confirmation.

Malformed framing, an unsupported key algorithm, a path that cannot be bound to
the signer, an oversized payload, or an ambiguous/non-canonical clear-sign parse
is rejected. Unsupported semantics alone may fall back to Tier B or C.

Advanced Mode is a hard gate, not the only warning. Enabling it once does not
silently approve future blind signatures.

## Exact-byte invariant

The principal invariant is:

> The device hashes and signs exactly the bytes whose properties and digest it
> reviewed.

For `SIGN_MODE_DIRECT`, the secp256k1 signature is over the SHA-256 digest of the
serialized `cosmos.tx.v1beta1.SignDoc`:

- `body_bytes`
- `auth_info_bytes`
- `chain_id`
- `account_number`

The preferred protocol streams the serialized `SignDoc` bytes to the device.
The device simultaneously:

1. validates ordered chunk framing and the declared total length;
2. hashes the exact incoming bytes;
3. parses display information from those same immutable bytes;
4. binds the selected key and signer information;
5. performs the required review flow;
6. signs the accumulated digest without reconstructing a different `SignDoc`.

Hashing host-provided structured fields and later reserializing them creates an
avoidable display/signature mismatch risk. If structured transport is retained
for memory reasons, the framing itself must define one canonical serialized
preimage and the firmware must both parse and hash that exact stream.

For Tier A clear signing, protobuf handling must reject encodings whose meaning
could differ between the firmware and a node, including ambiguous duplicate
singular fields, malformed or overlong varints, invalid lengths, truncated
submessages, conflicting signer modes, and unsupported critical extension
options. A structurally valid unknown `Any` is not malformed and may use the
blind tier.

For Tier B or C, the transaction digest should be shown in full using the
existing exact-byte pager. The digest is an exact commitment, not a semantic
summary.

## Proposed v2 protocol

Exact names and field numbers require a device-protocol review. The logical flow
is:

```text
CosmosSignDirectInit
  -> CosmosSignDirectRequest(offset, max_chunk)
  -> CosmosSignDirectChunk(offset, bytes)
  -> ... repeat ...
  -> device review
  -> CosmosSignedDirect(public_key, signature, sign_doc_hash)
```

`CosmosSignDirectInit` should bind at least:

- derivation path;
- expected serialized `SignDoc` length;
- expected SHA-256 digest, used only as a transport cross-check;
- requested signing mode and key algorithm;
- optional registry identity and descriptor version;
- host-declared review expectation, which the device may only downgrade.

The device owns the running offset, remaining length, parser state, and hash.
Chunks must be contiguous and accepted exactly once. Any unexpected message,
offset, length, initialization attempt, cancellation, USB reset, or parser error
aborts and wipes the session.

The response returns the compressed public key, compact 64-byte signature, and
the device-computed `SignDoc` digest so the host can cross-check the exact
preimage.

The implementation should not accept a host-computed digest as the only thing
to sign. A future prehashed expert primitive, if ever required by a distinct
application, must be a separately named domain, use a stronger warning, and
display the complete digest.

## Direct-mode parser

The parser operates incrementally with bounded memory. It recognizes:

- `TxBody.messages` as repeated `Any { type_url, value }`;
- memo and timeout height;
- extension and non-critical extension options;
- `AuthInfo.signer_infos`, public keys, `ModeInfo`, and sequence;
- `Fee.amount`, gas limit, payer, and granter;
- tip fields where the target SDK supports them.

Initial scope should require one signer and `SIGN_MODE_DIRECT`. The firmware
derives the public key, verifies that the signer info and account address belong
to that key where those values are available, and rejects a mode substitution.
Multisig and multi-signer transactions should remain unsupported until the
review flow and signature assembly contract are specified.

Message adapters consume the exact `Any.value` bytes. They may promote a message
to clear signing only after:

- the `type_url` is an exact supported value;
- required fields and canonical encodings validate;
- signer/owner/sender fields bind to the derived key where applicable;
- all security-relevant fields fit and are reviewable;
- unknown critical fields cannot change the reviewed meaning.

An adapter failure caused by unknown semantics downgrades to blind review. A
failure caused by malformed or contradictory encoding rejects the transaction.

## Chain descriptors and addresses

A v2 chain descriptor separates values that the legacy protocol conflates:

- immutable registry ID and descriptor version;
- network chain ID;
- display name;
- account, validator, and consensus Bech32 HRPs;
- derivation path policy and SLIP-0044 coin type;
- public-key/signature algorithm;
- allowed sign modes;
- trusted native asset metadata, if any.

The transaction-bound chain ID is always displayed. A friendly chain name cannot
replace it.

Descriptors may be firmware-curated or supplied by a host registry with an
authenticated provenance model. Until that trust model is implemented,
host-supplied metadata is untrusted: display raw chain ID, HRP, path, exact denom,
and atomic amount. An unknown descriptor may still use blind signing when its
algorithm and address construction are supported.

Address requests must use the explicit account HRP, not a coin lookup name.
Non-standard paths require the existing path warning policy. The displayed
address and the signing key must be derived from the same descriptor and path.

The first algorithm target is Cosmos-style secp256k1. Ethermint
`ethsecp256k1`, ed25519, and other application key types require explicit
derivation, address, signature, and test-vector support; they must not be
silently treated as standard Cosmos secp256k1.

## Coins, amounts, and fees

The v2 schema should model Cosmos `Coin` directly:

```text
Coin {
  string denom
  string amount
}
```

- `amount` is a canonical unsigned base-10 integer string: digits only, no sign,
  whitespace, decimal point, exponent, or leading zeroes except `"0"`.
- Firmware defines and tests an explicit maximum digit count. A 256-bit ceiling
  is a reasonable initial engineering target, subject to SDK compatibility and
  OLED/resource tests.
- `denom` has a documented byte maximum large enough for IBC and factory denoms
  and validates the relevant Cosmos SDK grammar.
- Every message owns its own coin list; fee coins are independent and repeated.
- Unknown metadata displays atomic amount plus exact denom. Trusted metadata may
  add a decimal rendering but cannot hide the atomic pair.

## IBC support

The first clear-sign IBC adapter should support the protobuf
`ibc.applications.transfer.v1.MsgTransfer` forms used by target SDK versions.
Review must bind and show:

- source port and channel;
- token amount and exact denom;
- sender and receiver;
- timeout height revision number and revision height;
- timeout timestamp;
- memo, including packet-forwarding JSON as exact text unless a separately
  validated adapter interprets it.

This works for native denoms, `ibc/<hash>` voucher denoms, factory denoms, and
other valid source-chain denominations. The firmware does not need a compiled
pairwise matrix of every source and destination chain.

"IBC between all supported chains" means the host may construct any valid
source-chain ICS-20 route and the device can sign it. It does not mean the device
asserts that a channel reaches the host-claimed destination. Without trusted,
fresh channel proofs, the device should display the exact port/channel and
receiver rather than invent a destination-chain guarantee.

IBC messages from unknown modules remain viable through the blind tier.

## Legacy Amino

Legacy Amino remains available for older chains but should also receive a v2
transport rather than extending the current fixed-width schema.

Two safe approaches are possible:

1. stream the exact canonical Amino JSON sign bytes and blind-sign them; or
2. stream typed fields while the firmware constructs one canonical JSON
   preimage and clear-signs supported message adapters.

The first approach provides broad compatibility sooner. The second provides
stronger semantic review. They can coexist, with exact-byte blind support first
and structured adapters added incrementally.

The v2 Amino model must separate message and fee denoms, use string amounts,
support long denoms and multiple coins, and bind all configuration to one
session. The old protocol continues unchanged for compatibility.

## Non-Cosmos CometBFT applications

The generalized core should expose an internal adapter contract:

```text
domain identifier
preimage framing rules
hash function
key/signature algorithm
optional bounded parser
review classification
```

A new application can begin at Tier C by defining and testing its exact signing
preimage. Later parser adapters can promote its operations to Tier B or A. This
is the path to genuinely broad Tendermint/CometBFT support without pretending
all applications share Cosmos protobuf transaction semantics.

Every external protocol gets a distinct domain identifier. Cross-domain ACKs,
chunks, finalization calls, and session reuse are rejected.

## Rollout

### Phase 0: specification and vectors

- Freeze v2 threat model, wire flow, limits, canonical protobuf policy, and abort
  behavior.
- Collect `SIGN_MODE_DIRECT` golden vectors from Cosmos SDK and at least one
  independent host implementation.
- Choose an initial descriptor trust model and supported key algorithms.

### Phase 1: universal Cosmos direct blind signing

- Stream and hash exact `SignDoc` bytes on device.
- Validate the envelope enough to establish domain, chain ID, signer mode,
  signer key, and resource safety.
- Permit unknown `Any` messages through Tier B/C in Advanced Mode.
- Show the blind warning, path/address, byte count, and full digest.
- Return signature, public key, and device-computed digest.

This phase deliberately provides useful new-chain support before every module
has a clear-signing adapter.

### Phase 2: envelope clear signing

- Clear-sign chain ID, account number, sequence, memo, timeout, fee coins, gas,
  payer, and granter when parsed unambiguously.
- Add trusted/untrusted chain descriptor UX.
- Downgrade extension options that are valid but not understood.

### Phase 3: common message clear signing

- Bank send and multi-send.
- Staking delegate, undelegate, redelegate, and cancel-unbonding.
- Distribution rewards and validator commission.
- Governance vote, deposit, and proposal variants.
- ICS-20 transfer.

### Phase 4: application adapters

- CosmWasm execute/instantiate/migrate, with contract payload remaining blind
  until schema-aware review exists.
- Authz and feegrant, including nested-message downgrade rules.
- Chain-specific modules chosen by use and risk.
- Additional CometBFT signing domains and key algorithms.

### Phase 5: default clear signing

- Promote well-tested chains and message families to Tier A by default.
- Keep Advanced Mode fallback for valid unknown additions so protocol upgrades
  do not make the chain unusable.

## Workstreams

| Repository/layer | Work |
| --- | --- |
| device-protocol | Add v2 init/chunk/request/response messages, limits, generated bindings, and message IDs |
| firmware transport | Session isolation, ordered streaming, abort/wipe behavior, and response framing |
| firmware crypto | Exact-byte hashing, secp256k1 signing, key/signer binding, and domain separation |
| firmware parser | Bounded `SignDoc`, `TxBody`, `AuthInfo`, `Any`, `Coin`, and message adapters |
| firmware UX | Tier labels, blind warning, digest/byte count, exact-value paging, and cancellation |
| hdwallet | Generic address and sign APIs, chunk driver, registry plumbing, and signature cross-checks |
| Vault | Generic address/sign endpoints, policy errors, transport recovery, and no metadata substitution |
| chain registry | Versioned descriptors, HRPs, paths, algorithms, assets, and provenance |
| host integrations | Transaction building, IBC route discovery, broadcast, and chain test vectors |
| QA/release | Unit, emulator, hardware OLED, fuzzing, interoperability, and downgrade tests |

## Test and release gates

### Cryptographic and interoperability

- Device signatures match Cosmos SDK and independent host vectors.
- The returned digest equals SHA-256 of the exact serialized `SignDoc`.
- Signatures verify and broadcast on representative SDK versions and chains.
- Legacy Amino behavior remains byte-for-byte compatible.

### Parser and transport adversarial tests

- truncated fields and submessages;
- oversized lengths, integer overflow, and resource-limit boundaries;
- non-minimal/overlong varints and duplicate singular fields;
- unknown fields, unknown `Any` values, and extension options;
- chunk replay, gaps, overlap, reordering, early finalization, and excess bytes;
- session replacement, cross-domain ACKs, stale chunks, and USB interruption;
- signer-mode, public-key, path, chain-ID, fee, and sequence substitution;
- cancellation from every screen, proving that no signature is returned.

### Review classification

- fully known transactions are Tier A;
- any opaque nested or top-level action forces Tier B/C;
- unknown semantics can blind-sign in Advanced Mode;
- malformed transactions never downgrade to blind signing;
- no host-only label is presented as signed data;
- blind review always shows warning, byte count, and full digest;
- disabling Advanced Mode blocks every blind path.

### Asset and IBC matrix

- native, IBC voucher, factory, slash-containing, and maximum-length denoms;
- maximum amount values and multiple message/fee coins;
- native and non-native fee denoms;
- IBC timeout height, timeout timestamp, memo, and no-timeout edge cases;
- receivers with different valid HRPs and maximum supported length;
- packet-forwarding memos and unknown IBC module messages;
- representative Cosmos Hub, Osmosis, THORChain/MAYAChain-style legacy, and
  additional SDK chains.

### Device evidence

- full firmware and constrained configurations fit ROM/SRAM budgets;
- parser stack frames retain the required reserve;
- fuzz targets and sanitizer builds pass on the host;
- emulator and physical OLED captures prove every maximum-length field can be
  reviewed;
- cancellation and blind-sign policy behavior pass on physical hardware.

## Open decisions

- Stream a complete serialized `SignDoc`, or stream its exact field framing?
  Complete exact bytes are preferred if the incremental parser can meet memory
  limits.
- Require canonical protobuf for all tiers, or only for clear signing? The
  safest initial policy is canonical envelope encoding for every tier.
- Use only global Advanced Mode, or add a per-session blind-sign capability?
  Initial recommendation: Advanced Mode plus confirmation on every transaction.
- What descriptor provenance is trusted enough for symbols and decimals?
- What exact maxima apply to transaction bytes, nesting, messages, denoms,
  amounts, HRPs, and type URLs?
- Which Ethermint key/address variants are in the first supported algorithm set?
- How should multisig, multiple signer infos, tips, fee payers, authz nesting,
  and fee grants be reviewed?
- When should `SIGN_MODE_DIRECT_AUX` and `SIGN_MODE_TEXTUAL` be added?
- Which legacy Amino chains require exact JSON streaming before direct-mode
  support?

## Definition of done

The generalized Cosmos milestone is complete when:

- any structurally valid, resource-bounded Cosmos SDK `SIGN_MODE_DIRECT`
  transaction using a supported key algorithm can be signed through an explicit
  Advanced Mode blind path, even when its messages are unknown;
- known message adapters clear-sign only values parsed from the exact signed
  bytes;
- arbitrary valid coin denoms and integer amounts work within documented limits;
- any valid host-constructed ICS-20 source-chain transfer can be signed, without
  a compiled pairwise chain matrix;
- the address, signer key, signing mode, chain ID, and signed preimage are bound
  to one isolated session;
- malformed data, ambiguous clear-sign encodings, and unsupported algorithms
  fail closed;
- cancellation never produces a signature;
- protocol, firmware, hdwallet, Vault, registry, and hardware QA are delivered
  together.

The broader CometBFT-family milestone is complete only when each additional
application has an explicit, tested signing-domain adapter. Its initial adapter
may be blind-only; semantic clear signing can follow.
