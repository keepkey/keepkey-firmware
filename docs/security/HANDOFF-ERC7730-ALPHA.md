# Alpha ERC-7730 clear-signing handoff

Date: 2026-09-16

Status: implementation starting on `feature/alpha-erc7730`. Target base is
fork `alpha` at `7151ba3bfd1541e5e27f10517793f106225c8e92`.

## Goal

Implement the complete active ERC-7730 v2 specification on firmware alpha and
open a PR to fork `alpha`. Reusable signed metadata is the normal path. A live
per-transaction signer is used only when a fact required for an honest display
cannot be derived from the signed transaction or proven by reusable signed
definitions.

Do not describe the result as full ERC-7730 support until every required item
in the conformance section is implemented, negatively tested, and exercised by
registry fixtures on the emulator.

This work is alpha-only. It does not change 7.15, 7.14.x, a bootloader, storage
format, or an upstream release branch.

## Starting point

Alpha already has four KeepKey metadata envelopes:

- v1: live, per-transaction metadata committed to the final transaction hash;
- v2: reusable flat schemas for fixed 32-byte ABI words;
- v3: KeepKey-root-certified delegate envelopes;
- v4: a certified firmware-owned dynamic decoder, currently used for Portals.

The existing trust distinction must survive:

- runtime/self-service providers are additive and cannot suppress raw review;
- a valid KeepKey-certified definition may replace raw review only when the
  device proves complete coverage of the bytes and effects represented by the
  display;
- malformed certified metadata fails closed and never silently becomes an
  ordinary signing flow.

The current v2 and v4 decoders are too narrow for ERC-7730. Do not add another
protocol-specific v4 decoder for each registry entry.

## Reference implementation

Use Trezor's current implementation as the primary engineering reference, not
the original preliminary PR #6235.

- reviewed Trezor main: `dc99b24533b390b305682730c027231bf2244dc2`
- foundation PR: <https://github.com/trezor/trezor-firmware/pull/6235>
- current parser: `core/src/apps/ethereum/clear_signing.py`
- compiled descriptor protocol: `common/protob/messages-definitions.proto`
- signed external-definition design:
  <https://docs.trezor.io/trezor-firmware/common/external-definitions.html>

Reuse the architecture and test cases, but implement the device interpreter in
bounded C for KeepKey. Trezor Core sources are GPLv3 while this repository is
LGPLv3; preserve provenance and review licensing before copying any source
verbatim. Prefer a documented clean C implementation against ERC-7730 and ABI
specifications.

Trezor already demonstrates:

- recursive ABI type descriptions;
- strict padding and bounds checks;
- tuples, dynamic leaves and arrays;
- indexed and sliced paths;
- reusable signed definitions fetched during signing;
- generic fields and embedded-calldata expansion;
- external token definitions;
- registry-derived fixtures.

Do not inherit its current omissions. Its September 2026 implementation still
does not cover the entire ERC-7730 v2 specification, particularly EIP-712,
interpolated intents, conditional visibility, groups, encryption, all
formatters, and the complete path/reference language.

## Architecture

### Host compiler

Vault/SDK resolves a JSON descriptor and its includes, validates it against the
exact `$schema`, selects the matching context and format, and compiles it into a
canonical bounded device program. Compilation performs work that does not add
security when repeated on the device:

- canonical Solidity ABI parsing and selector calculation;
- name-to-index path resolution;
- `$ref`, definition, include, constant, map and enum resolution;
- static type checking of paths, formatters and formatter parameters;
- normalization of deployments and proxy constraints;
- expansion of groups into an ordered display program;
- explicit resource accounting.

The compiler must be deterministic. Semantically identical input must produce
byte-identical output. The signed payload records the ERC-7730 schema version,
source descriptor digest, compiler-format version and all resolved inputs.

### Signed catalog

Compiled definitions and token/network definitions live outside firmware. They
are signed once and fetched by chain, context, contract/domain and selector or
EIP-712 type hash. Prefer a signed Merkle catalog so one reviewed root covers a
large release and each response carries a compact inclusion proof.

KeepKey's existing root-certified delegation remains the authority model. Add
a purpose/domain tag dedicated to ERC-7730 catalog signing so a valid clear-sign
key or payload cannot authorize firmware, storage, Solana schemas, or another
metadata version.

The signed definition must bind at least:

- format and schema versions;
- definition kind: calldata or EIP-712;
- chain and deployment/domain constraints;
- contract and selector, or EIP-712 domain and primary type hash;
- canonical ABI/type program;
- display program and literal strings;
- token/network definition digests used by formatting;
- provider identity, issuance epoch and revocation epoch;
- source JSON digest and compiler identity.

### Device interpreter

The device verifies authority and context before executing the program. It
parses values from the exact bytes it will sign. The interpreter is bounded by
constants for calldata size, nesting, array elements, path depth, fields,
strings, definitions and embedded calls. Every arithmetic operation involving
an ABI offset or length is checked before addition or multiplication.

The device rejects:

- dirty ABI padding or non-canonical encodings;
- out-of-range pointers, lengths, slices and indices;
- overlapping or ambiguous dynamic regions where canonicality requires a
  unique interpretation;
- trailing bytes not represented by the selected ABI;
- mismatched chain, contract, selector, domain or type hash;
- unresolved mandatory display fields;
- unsupported schema/compiler versions;
- incomplete token or nested-call definitions when their formatted value is
  required for the claimed intent;
- resource exhaustion.

Rejection of a certified request must be visible and must produce no signature.
Runtime metadata remains additive and may fall back only to the existing
explicit raw-review path.

### Live endpoint

The live endpoint remains, but is not the ordinary ABI decoder. It is reserved
for information that static definitions and signed bytes cannot establish,
such as a state-dependent proxy resolution, verified external state, simulation
or risk information.

Separate live results into:

1. proven facts with evidence the device can verify;
2. certified external context bound to the complete transaction hash; and
3. advisory simulation or reputation data that can only add a sourced warning.

A live response cannot override a value decoded from the transaction or a
signed catalog definition. Conflicts fail closed. A runtime live signer never
suppresses raw review. Suppression requires the existing KeepKey-certified tier
and complete coverage.

## ERC-7730 v2 conformance target

The PR is complete only when the following are supported or the specification
explicitly marks them optional and the documented behavior satisfies its
requirement.

### Descriptor and context

- exact `$schema` major-version handling;
- includes and merge semantics;
- calldata contract deployments, factories and proxy resolution;
- EIP-712 domain, deployment and domain-separator constraints;
- metadata owner, contract name, info, constants, maps and enums;
- selector derivation from canonical function fragments;
- EIP-712 `encodeType` and primary type-hash matching;
- safe unknown-selector behavior.

### ABI and structured values

- signed and unsigned integers at every legal width;
- address, bool, fixed bytes, dynamic bytes and UTF-8 string;
- fixed and dynamic arrays;
- static and dynamic tuples, recursively nested;
- negative indices, full-array selectors and bounded slices;
- calldata and EIP-712 container paths;
- complete `#`, `$` and `@` reference semantics after host resolution;
- literal values;
- embedded calldata with recursion and cycle limits;
- ERC-4337 `PackedUserOperation` through its EIP-712 representation;
- EIP-5792 batch structures where represented by supported structured data.

### Display semantics

- `intent` objects and strings;
- `interpolatedIntent` with its required fallback behavior;
- fields, reusable definitions and recursive groups;
- ordering, array iteration and separators;
- `visible`: always, never, ifEmpty, ifNotEmpty, ifIn and ifNotIn;
- raw integers/strings/bytes;
- native amount and token amount, including token/chain paths, native aliases,
  thresholds and custom messages;
- NFT name;
- date, duration, unit, enum and chain ID;
- raw and trusted-name address rendering with source/type restrictions;
- token ticker;
- ERC-7930 interoperable addresses;
- embedded calldata;
- encrypted-field metadata and an honest fallback when decryption is
  unavailable; no plaintext claim without verified decryption.

### EIP-712

- descriptor selection by verified domain constraints and type hash;
- paths over structs and arrays;
- the same formatter, visibility, grouping and interpolation behavior as
  calldata where types permit it;
- integration with alpha's existing streamed canonical EIP-712 parser so the
  display and signed hashes share one validated value tree.

## Protocol ownership

Protocol changes are made first in the canonical fork
`BitHighlander/device-protocol` and merged to its `master`; alpha pins that
master according to `docs/release/BRANCHING-SOP.md`. Do not leave alpha pinned
to a loose feature commit or a per-firmware protocol branch.

The wire protocol should request definitions on demand during Ethereum signing,
so embedded calls and token paths can request additional signed entries without
restarting the signing session. Definitions may also be supplied in the initial
request for offline or cached operation.

## Verification plan

1. Import upstream ERC-7730 schema examples and registry `testsv2` fixtures as
   attributed test data where licensing permits.
2. Port the relevant Trezor parser, formatter and negative test shapes.
3. Differentially compile registry descriptors and compare decoded values with
   an independent host ABI implementation.
4. Fuzz the C interpreter's definition parser, ABI walker, paths, formatters and
   nested calldata. Seed with every accepted and rejected corpus case.
5. Add mutation tests for offsets, lengths, padding, selectors, deployments,
   token metadata, visibility, interpolation and nested definitions.
6. Add adversarial intent tests where the host claims action X while calldata
   performs Y; the device screen must expose Y or refuse.
7. Capture emulator OLED evidence for representative transfer, approval, swap,
   lending, staking, proxy, batch, nested calldata, EIP-712 and malformed cases.
8. Run the full firmware, board, crypto, Python/emulator, Bitcoin-only and ARM
   SRAM/ROM gates from the release SOP.
9. Run the Astra audit SOP before requesting Copilot review.

No definition may be accepted solely because the host says it came from the
registry. Tests must cover wrong roots, signatures, proof order, epochs,
purposes, chains, addresses, selectors, domains and type hashes.

## Implementation order

1. Freeze the conformance matrix against active ERC-7730 schema 2.0.0 and pin
   source commits for the ERC and registry corpus.
2. Define the canonical compiled representation and resource limits.
3. Add protocol messages and signed-catalog verification.
4. Implement and fuzz the C ABI/value walker.
5. Implement paths, conditions, formatters and generic rendering.
6. Integrate calldata signing without removing v1-v4 compatibility.
7. Integrate streamed EIP-712 using the shared value/display interpreter.
8. Build the Vault/SDK compiler, resolver, cache and on-demand request loop.
9. Add registry conformance, adversarial and OLED suites.
10. Audit, build all variants, push the branch and open the alpha PR.

## PR acceptance

The alpha PR must contain concise reviewer-facing documentation:

- what users can verify on-device;
- exactly what is authenticated and by whom;
- what remains advisory;
- descriptor and live-service failure behavior;
- complete conformance results and known optional behavior;
- firmware, device-protocol, SDK/Vault and catalog commits;
- emulator, ARM, Bitcoin-only, fuzz and audit evidence.

Do not call a registry coverage count protocol conformance. Full specification
support and the number of curated protocol descriptors are separate claims.
