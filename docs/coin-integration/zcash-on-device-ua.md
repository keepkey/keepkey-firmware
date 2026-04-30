# Zcash on-device unified address derivation (Phase 2)

**Status:** design — not yet implemented.
**Owner:** firmware (this repo)
**Companions:** `hdwallet`, `keepkey-vault`, `device-protocol`.

## 1. Why this exists

The flow shipped in PR #142 / `feature-zcash` (PR #220) verifies that a host-supplied
`(ak, nk, rivk)` matches the device's seed-derived FVK, then displays the
**host-supplied** `u1...` string on the OLED. That is **not** an attestation
that the displayed unified address is spendable by the device. A malicious
host that knows the correct FVK can submit any UA string and the device will
faithfully render it.

The only way the device can promise "this address is spendable by my seed at
this account" is to **derive the unified address itself** from material it
controls (the seed-rooted FVK + a diversifier index it accepts as input) and
display the device-derived bytes. The user then compares the device-shown
`u1...` to the wallet's claim before publishing.

Half measures (FVK match only, fingerprint binding, "trust the wallet to
display the same UA we sent") are not interchangeable with on-device
derivation. They catch a different, smaller set of attacks. This document
specifies what's actually required to make the strong claim.

## 2. Threat model

The device is asked to attest:

> The unified address rendered on the OLED is a valid encoding of an Orchard
> receiver `(d_j, pk_d_j)` where `pk_d_j = [ivk] · g_d_j`, `g_d_j` is the
> Pallas group element derived from a diversifier `d_j = FF1.Decrypt(dk, j)`,
> and `(ak, nk, rivk, dk)` is the FVK derived from the device's seed at the
> requested ZIP-32 Orchard account.

Adversaries:

1. **Compromised host process** — bun, hdwallet, sidecar, browser, USB driver. May fabricate or substitute UAs, FVKs, indexes, addresses. Cannot tamper with the device's OLED.
2. **Compromised wallet UI** — same observation surface as the host. User's only honest read is the OLED + the wallet's claim, side by side.
3. **Bit-flip / glitch** — out of scope for this document; addressed by the existing fault-injection hardening.

Properties we want against (1) and (2):

- The bytes rendered on the OLED must be a function of `(seed, account, j)` and nothing else. No host input flows into the displayed string.
- A user who reads the OLED and sees the same string in their wallet has cryptographic assurance that the UA's Orchard receiver is spendable by the device.

Properties we explicitly do **not** claim:

- Anything about non-Orchard receivers (transparent, Sapling) bundled into a multi-receiver UA. A UA can carry arbitrary other receivers; only the Orchard one is bound to this device. Display copy must scope the claim accordingly.
- Privacy / linkability of the displayed UA. ZIP-32 §6.1 fingerprinting is a separate (already-shipped) concern.

## 3. Why this is large

KeepKey firmware is C on Cortex-M3. Embedded Rust is not in this repo's
toolchain (Trezor Model T and Keystone3 both run Rust embedded; we don't).
Every primitive needed for Orchard UA derivation has to be implemented or
ported in C. The crates `orchard`, `pasta_curves`, `sinsemilla`, `f4jumble`,
`fpe`, and `zcash_keys` are the reference implementations; they don't run
here.

What we already have, verified against the active Trezor firmware crypto
submodule at `deps/crypto/trezor-firmware` commit `376c64bcf`:

- BLAKE2b (`deps/crypto/trezor-firmware/crypto/blake2b.{c,h}`)
- AES block cipher (`deps/crypto/trezor-firmware/crypto/aes/`)
- Pallas curve arithmetic (`pallas.{c,h}`) — point ops, scalar mult, modular ops
- RedPallas signatures (`redpallas.{c,h}`)
- A hard-coded RedPallas SpendAuth basepoint, useful for `ak = [ask]G_spendauth`
  but not a general `GroupHash^Pallas` implementation
- Generic Bech32/Bech32m checksum support in
  `deps/crypto/trezor-firmware/crypto/segwit_addr.{c,h}`. This still needs a
  ZIP-316-specific wrapper and may need its BIP-173 90-character output guard
  relaxed for UA strings.

What we **don't** have and must build or adapt:

| Primitive | Source / spec | Approx C LOC | Risk |
|---|---|---|---|
| FF1-AES256 (NIST SP 800-38G) for diversifier derivation | NIST SP 800-38G; `fpe` Rust crate | ~300 | Medium — AES exists, but FF1/FPE does not |
| `expand_message_xmd_blake2b` | RFC 9380 §5.3.1 | ~80 | Low |
| Pallas Simplified SWU map (`map_to_curve_simple_swu`) + isogeny | Pasta paper / Halo 2 reference | ~500 | High — algebraic, easy to get wrong, needs cross-vectors |
| `GroupHash^Pallas` + `DiversifyHash^Orchard` | ZIP-32 §5.4.2.1 / Orchard book §5.4 | ~80 | Low (composition of above) |
| Sinsemilla hash + commitment | Halo 2 spec §5.4.1.9; Orchard book §5.4 | ~500 | High — chunked commitment, easy off-by-one |
| `Commit^ivk` (specifically `ivk = SinsemillaShortCommit("z.cash:Orchard-CommitIvk", ak ‖ nk; rivk)`) | Orchard book §5.4 | ~100 | Med |
| F4Jumble (4-round Feistel-like permutation) | ZIP-316 §4.2 | ~150 | Low — well-specified |
| ZIP-316 Bech32m adapter | BIP-350 / ZIP-316 | ~50 | Low — checksum exists, but UA sizing/padding glue does not |
| ZIP-316 UA encoding (single-receiver, Orchard) | ZIP-316 §4 | ~150 | Low |
| Cross-language test harness | — | ~500 | — |
| **Subtotal — production primitives** | | **~2,500 LOC** | |

This is conservative and excludes the FSM handler, layout code, proto changes,
and unit tests for everything (probably another 1,500 LOC).

First-pass feasibility conclusion: the Trezor firmware dependency gives us the
generic base layer (BLAKE2b, AES, Pallas point/scalar arithmetic, RedPallas, and
Bech32m), but it does not give us the Orchard unified-address derivation stack.
There is no checked-in Trezor C implementation of FF1, Sinsemilla,
`expand_message_xmd_blake2b`, Pallas SWU/isogeny, Orchard `GroupHash`, F4Jumble,
or ZIP-316 UA assembly. Phase 2 therefore remains a real crypto port, not just
wiring existing Trezor libraries together.

### 3.1. Online library survey

Surveyed 2026-04-30. The pattern is clear: only FF1 has a plausible C source
to adapt. The rest should be treated as spec-driven C implementations with
Rust upstreams used for goldens.

| Needed primitive | Best upstream candidate | Language / license | Fit for KeepKey firmware | Estimated firmware LOC | Effect on plan |
|---|---|---|---|---:|---|
| FF1-AES256 for `d_j = FF1.Decrypt(dk, j)` | [`0NG/Format-Preserving-Encryption`](https://github.com/0NG/Format-Preserving-Encryption) | C / MIT | Useful algorithm reference, not drop-in. It depends on OpenSSL BIGNUM/AES; firmware should replace this with existing Trezor AES and a fixed-size radix-256 path for the 11-byte diversifier. | 300-500 | Reduces spec ambiguity, but does not avoid a port. Still needs NIST vectors and Orchard vectors. |
| FF1 specification and test source | [NIST SP 800-38G Rev. 1 draft](https://csrc.nist.gov/pubs/sp/800/38/g/r1/2pd) | Spec | Normative source. NIST's 2025 draft keeps FF1, removes FF3, and disallows floating point. | 0 production / 50-100 tests | Hard requirement for validation. Also tells us not to port code that uses floating-point `log2` or general decimal FPE assumptions blindly. |
| `expand_message_xmd_blake2b` | [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html) | Spec | Directly implement against existing BLAKE2b. No C library needed. | 80-120 | Low-risk self-contained helper. |
| Pallas Simplified SWU + isogeny | [`zcash/pasta_curves`](https://github.com/zcash/pasta_curves) / [docs.rs source](https://docs.rs/pasta_curves/latest/src/pasta_curves/pallas.rs.html) | Rust / MIT or Apache-2.0 | Authoritative reference and test-vector source only. No usable C port found. Existing KeepKey `pallas.{c,h}` gives field and point ops, but not SWU/isogeny. | 500-800 | Highest algebraic risk. Rust vectors are mandatory before using in address derivation. |
| Orchard `GroupHash^Pallas` / `DiversifyHash` | [`zcash/orchard`](https://github.com/zcash/orchard) plus `pasta_curves` | Rust / MIT or Apache-2.0 | Composition layer over `expand_message_xmd_blake2b` and SWU/isogeny. No standalone C implementation found. | 80-150 | Small LOC, but correctness depends entirely on SWU/isogeny. |
| Sinsemilla hash and commitment | [`zcash/sinsemilla`](https://github.com/zcash/sinsemilla) and Halo 2 Sinsemilla docs | Rust / MIT or Apache-2.0 | Reference only. No C implementation found. Needs fixed generators/constants and chunking rules ported carefully. | 700-1,200 | Main risk after SWU. Larger than the first estimate if constants/tables are checked in rather than generated. |
| `Commit^ivk` / Orchard IVK | [`zcash/orchard`](https://github.com/zcash/orchard) | Rust / MIT or Apache-2.0 | Thin wrapper over Sinsemilla plus scalar handling. Not useful until Sinsemilla exists. | 100-180 | Medium risk; mostly test-vector coverage. |
| F4Jumble | [`f4jumble` crate](https://docs.rs/f4jumble) / [ZIP-316](https://zips.z.cash/zip-0316) | Rust / MIT or Apache-2.0, spec MIT | Implement directly from ZIP-316 using existing BLAKE2b. No C library found; Rust crate is good for goldens. | 150-250 | Low-risk. Does not block crypto receiver derivation; needed for final `u1...` string. |
| Bech32m for ZIP-316 strings | Existing Trezor `segwit_addr.{c,h}`; optional reference [`whitslack/libbech32`](https://github.com/whitslack/libbech32) | C / existing vendored license; libbech32 MIT-style | We already have Bech32m checksum support. Need ZIP-316 use that ignores BIP-173's 90-character cap, per ZIP-316. `libbech32` is useful only if we want a comparison implementation. | 50-120 | Reduces previous estimate: no new checksum implementation, only wrapper/length-policy work. |
| ZIP-316 UA item assembly | [`zcash_address::unified`](https://docs.rs/zcash_address/latest/zcash_address/unified/index.html) / [ZIP-316](https://zips.z.cash/zip-0316) | Rust / MIT or Apache-2.0, spec MIT | Reference only. Implement compactSize item encoding for a single Orchard receiver, padding, F4Jumble, Bech32m. | 150-250 | Low-to-medium risk; mostly parser/encoding edge cases and exact HRP behavior. |

Net effect: expected new production C stays roughly **2,100-3,500 LOC** before
FSM/UI/proto/test glue. The best-case reduction from online libraries is mostly
around Bech32m and FF1; there is no library discovery that changes the hard
parts: SWU/isogeny and Sinsemilla still need first-party C ports verified
byte-for-byte against upstream Rust.

## 4. Cryptographic recipe (the actual algorithm)

References:

- Zcash Protocol Spec (NU6) §4.2.3, §5.4.1.6, §5.4.8.5
- ZIP-32 §5.4 (Orchard key derivation)
- ZIP-316 (Unified Addresses)
- Orchard book — `https://zcash.github.io/orchard/`
- Pasta paper — `https://github.com/zcash/pasta_curves`

Given device seed `S`, account index `a`:

```
# Already implemented in zcash.c
sk        = ZIP-32 Orchard derivation (S, a)
ask       = ToScalar(PRF^expand(sk, [0x06]))
nk        = ToBase  (PRF^expand(sk, [0x07]))
rivk      = ToScalar(PRF^expand(sk, [0x08]))
ak        = [ask]·G_spendauth     # already serialised by current code

# NEW — must be implemented
dk        = PRF^expand(sk, [0x09])[0..32]      # diversifier key (uses existing PRF^expand)
ivk       = SinsemillaShortCommit(
              "z.cash:Orchard-CommitIvk",
              I2LEBSP_l_ivk(ak) ‖ I2LEBSP_l_ivk(nk),
              rivk
            )

# Per-address (single diversifier index j; default j = 0)
d_j       = FF1-AES256.Decrypt(dk, /* tweak = */ "", I2LEBSP_88(j))   # 11 bytes
g_d_j     = DiversifyHash^Orchard(d_j) = GroupHash^Pallas("z.cash:Orchard-gd", d_j)
pk_d_j    = [ivk] · g_d_j         # uses existing Pallas scalar mult

raw_addr  = bytes(d_j) ‖ bytes(pk_d_j)            # 11 + 32 = 43 bytes

# UA encoding (single receiver, Orchard)
receiver  = uint8(0x03) ‖ uint8(43) ‖ raw_addr     # ZIP-316 typecode 0x03 = Orchard
hrp       = "u"
encoded   = bech32m(hrp, F4Jumble(receiver ‖ padding_for_hrp("u")))
```

The displayed string is `encoded`. Every byte that goes into it is a
deterministic function of `(S, a, j)` — the host contributes only the choice
of `j`.

## 5. API design

### 5.1 New proto messages (`device-protocol`)

```proto
// Request: device derives the canonical Orchard UA for (account, j) from its
// own seed and renders it on the OLED for user confirmation. The host does
// NOT supply any address bytes.
//
// @next ZcashUnifiedAddress
// @next Failure
message ZcashGetUnifiedAddress {
    repeated uint32 address_n = 1;   // m/32'/133'/account'
    optional uint32 account   = 2;   // alternative to address_n
    optional uint64 diversifier_index = 3;  // 88-bit; default 0
    optional bool   show_display      = 4;  // when true, render OLED + require confirm
    optional bytes  expected_seed_fingerprint = 5;  // optional ZIP-32 §6.1 binding
}

// Response.
//
// @prev ZcashGetUnifiedAddress
message ZcashUnifiedAddress {
    optional string address          = 1;  // device-derived "u1..." (max_size: 256)
    optional bytes  raw_receiver     = 2;  // d || pk_d, 43 bytes — for cross-check
    optional bytes  seed_fingerprint = 3;  // ZIP-32 §6.1 fingerprint of attesting device
    optional uint64 diversifier_index = 4; // echoed for clarity
}
```

The existing `ZcashDisplayAddress` (host supplies the string) **stays** but
is renamed in copy to "Display address (FVK match)" to reflect what it
actually proves. The new message is the strong-attestation path.

### 5.2 hdwallet wrapper

```ts
wallet.zcashGetUnifiedAddress({
  addressNList,
  account?: number,
  diversifierIndex?: bigint,           // default 0n
  showDisplay?: boolean,               // default true
  expectedSeedFingerprint?: Uint8Array,
}): Promise<{
  address: string,                     // device-derived UA — trustable
  rawReceiver: Uint8Array,             // 43 bytes
  seedFingerprint?: Uint8Array,
  diversifierIndex: bigint,
}>
```

### 5.3 Vault privacy tab

Replace the current "Verify on device" button (which calls
`ZcashDisplayAddress`) with a **two-step** flow:

1. "Show device address" → calls `ZcashGetUnifiedAddress`. UI displays the
   returned UA prominently next to the device-rendered version. User reads
   both side by side.
2. Optional "Verify host address (FVK match only)" button retained for the
   weaker check, with copy that names the limitation. This is the existing
   PR #141 button with the wording fixed.

## 6. Implementation phases

Each phase is mergeable on its own. Each closes with a cross-language test
harness verifying outputs against the upstream `orchard` Rust crate via
test vectors checked into the firmware repo.

### Phase 2.1 — Foundation primitives

**Goal:** ship FF1-AES256 + Pallas SWU + GroupHash + their tests. No new
firmware behavior — these compile into the binary and have unit tests.

**Files (estimate):**
- `deps/crypto/trezor-firmware/crypto/ff1.{c,h}` — FF1-AES256
- `deps/crypto/trezor-firmware/crypto/pallas_swu.{c,h}` — SWU map + isogeny
- Extend `pallas.{c,h}` with `expand_message_xmd_blake2b`
- `unittests/firmware/zcash_phase2.cpp`

**Test vectors needed:**
- FF1-AES256: NIST CAVP vectors + `fpe` Rust crate vectors
- SWU: `pasta_curves::pallas::map_to_curve_simple_swu` golden outputs
- GroupHash: `orchard::keys` test fixtures

**Effort:** 3–5 days dev, 2 days vectors + tests. **High-risk** on SWU isogeny.

### Phase 2.2 — Sinsemilla + Orchard receiver

**Goal:** derive `(d_j, pk_d_j)` on device. New FSM internal helper, no proto
changes yet.

**Files:**
- `deps/crypto/trezor-firmware/crypto/sinsemilla.{c,h}`
- Extend `lib/firmware/zcash.{c,h}`:
  - Add `dk` to `ZcashOrchardKeys`
  - `zcash_orchard_ivk(rivk, ak, nk, ivk_out)` — uses Sinsemilla
  - `zcash_orchard_diversifier(dk, j, d_out)` — uses FF1
  - `zcash_orchard_receiver(account, j, raw_out_43)` — composes everything

**Test vectors:** `orchard::keys::FullViewingKey::default_address` for many
`(seed, account, j)` tuples. We must agree byte-for-byte.

**Effort:** 5–7 days. **Highest-risk** phase — Sinsemilla is involved and
under-documented relative to its complexity.

### Phase 2.3 — F4Jumble + bech32m + UA encoding

**Goal:** turn 43 raw receiver bytes into a `u1...` string.

**Files:**
- `lib/firmware/zip316.{c,h}` — F4Jumble + UA assembly
- Extend bech32 helper to support the `m` constant (BIP-350)

**Test vectors:** ZIP-316 has explicit test vectors. Plus
`zcash_address::unified::Address::encode` outputs.

**Effort:** 2–3 days. Low risk.

### Phase 2.4 — Proto + FSM handler + UI

**Goal:** wire the new message end-to-end through firmware → hdwallet → vault.

**Files:**
- `device-protocol/messages-zcash.proto` — `ZcashGetUnifiedAddress` /
  `ZcashUnifiedAddress`
- `lib/firmware/fsm_msg_zcash.h` — `fsm_msgZcashGetUnifiedAddress`
- `lib/firmware/messagemap.def` + `fsm.h` — message routing
- `hdwallet-keepkey` — wrapper
- `keepkey-vault` — UI flow update + bun handler

**Effort:** 2–3 days. Mostly mechanical given primitives are tested.

### Phase 2.5 — Hardening, fault injection, hardware test

**Goal:** confirm on real hardware, scrub side channels, add fault-injection
mitigations consistent with the rest of the firmware.

**Effort:** 2–3 days + hardware time.

**Total: 14–21 working days** for a single contributor focused on this. Add
~50% for unknowns and review feedback → call it 4–5 weeks of calendar time
including review, hardware verification, and the cross-language test
infrastructure.

## 7. Testing strategy

### 7.1 Cross-language goldens

Generate goldens from the `orchard` Rust crate, check them into
`unittests/firmware/zcash_orchard_vectors.h` as C arrays:

```rust
// Generator (host-side, Rust) — run once, commit output
let seed = hex!("000102...1f");
for account in [0, 1, 7, 100, 0x7fffffff] {
    for j in [0u128, 1, 256, 0xdeadbeef, (1u128 << 88) - 1] {
        let sk = ExtendedSpendingKey::master(&seed);
        let osk = sk.derive_internal(account);
        let fvk = FullViewingKey::from(&osk);
        let addr = fvk.address_at(j, Scope::External);
        let ua  = unified::Address::try_from_items(vec![Receiver::Orchard(addr.to_raw_address_bytes())]);
        emit_c_vector(seed, account, j, addr, ua);
    }
}
```

The firmware unit test imports the header and asserts byte equality at every
intermediate stage (ivk, d, g_d, pk_d, raw_receiver, encoded UA).

### 7.2 Phase boundaries

Each phase ships with its own `unittests/firmware/zcash_phaseN.cpp` that
runs in CI via the existing `firmware-unit` target. A phase can't merge
without its goldens.

### 7.3 On-device sanity

Once Phase 2.4 lands, manual hardware test:
- Initialize a known seed (the all-allallall mnemonic)
- Call `ZcashGetUnifiedAddress(account=0, j=0)`
- Confirm OLED renders the same `u1...` string the upstream Rust crate
  computes for that mnemonic + j=0
- Repeat for j={1, 100, 2^32, 2^88-1}
- User-cancel test: long-press Cancel → device returns `Failure_ActionCancelled`
- Wrong-FVK injection: skip — there is no host-supplied FVK in this flow

## 8. Open design questions

1. **Diversifier index bounds.** Specced as 88-bit. Practical wallets use
   small indexes (≤ 2^31). Do we accept full 88-bit on the wire and reject
   ranges with no real users, or cap at 2^32 to fit a `uint32`? **Tentative:**
   accept full `uint64` on the wire (caller passes 0..2^64 range; spec
   technically allows up to 2^88 but no wallet uses that), reject any value
   > 2^64-1 with `Failure_SyntaxError`.
2. **Multi-receiver UAs.** This design only ever displays a single-receiver
   Orchard UA. Wallets that present users with `u1...` containing additional
   transparent or Sapling receivers will have a UA the device won't match.
   **Position:** the device-attested string is the *Orchard-only* UA derived
   from this device. Wallets that bundle more receivers should present
   *both* — "your full UA" and "the device-attested Orchard receiver" — and
   the user verifies the latter against the OLED.
3. **Diversifier index display.** Show `j` on the OLED alongside the UA, or
   omit? **Tentative:** show; at minimum show `j == 0` vs `j > 0` and the
   account number, so users can spot if they ask for default but the host
   slipped in a non-default index.
4. **bech32m vs raw-receiver display.** OLED is 256x64. A `u1...` Orchard
   UA fits across multiple lines (already works in PR #142). Raw receiver
   would be 86 hex chars — also displayable, less natural. **Tentative:**
   show `u1...` (consistent with what wallets show); QR encodes the full UA.
5. **Should `dk` ship in `ZcashOrchardFVK`?** Currently FVK is `(ak, nk, rivk)`.
   `dk` is part of the FVK in ZIP-32 (FVK = `(ak, nk, rivk, dk)`). Wallets
   that want to derive their own diversifiers without round-tripping the
   device need it. **Tentative:** add `dk` to `ZcashOrchardFVK` as
   `optional bytes dk = 5;`. It's not secret beyond what FVK already exposes.

## 9. Migration path

The existing `ZcashDisplayAddress` flow stays; its UI copy is downgraded to
"Display address (FVK match) — proves the FVK belongs to this device, not
that the displayed UA is spendable." The new
`ZcashGetUnifiedAddress` flow is the recommended path going forward. Wallets
that want strong attestation use the new message; older code paths continue
to work.

Once Phase 2 ships:

- Vault: replace the "Verify on device" button's primary action to call
  `ZcashGetUnifiedAddress`, drop the host-supplied address from the FSM call.
- Documentation: update `docs/zoo/reports/zcash-report.md` with the strong-
  attestation flow as the canonical "verify address" procedure.

## 10. References

- Zcash Protocol Specification, NU6 — https://zips.z.cash/protocol/protocol.pdf
- ZIP-32 — https://zips.z.cash/zip-0032
- ZIP-316 — https://zips.z.cash/zip-0316
- Orchard book — https://zcash.github.io/orchard/
- Pasta paper / curves — https://github.com/zcash/pasta_curves
- Halo 2 spec (Sinsemilla) — https://zcash.github.io/halo2/design/gadgets/sinsemilla.html
- BIP-350 (bech32m) — https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
- NIST SP 800-38G (FF1) — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf
- RFC 9380 (hash-to-curve) — https://datatracker.ietf.org/doc/rfc9380/

## 11. What this document is not

- A schedule. Effort estimates are working-days for a focused contributor;
  calendar time depends on review velocity and hardware availability.
- Final spec for diversifier-index UX. Section 8 calls out tentative
  positions; final UI copy and OLED layout are part of Phase 2.4 review.
- A claim that anything in Phase 2.1–2.3 is small. Sinsemilla and the SWU
  isogeny are the high-risk pieces and may take longer than the estimates.
  The estimates assume one contributor familiar with finite-field crypto.
