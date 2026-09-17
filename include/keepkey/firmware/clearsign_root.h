/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef KEEPKEY_FIRMWARE_CLEARSIGN_ROOT_H
#define KEEPKEY_FIRMWARE_CLEARSIGN_ROOT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── The KeepKey delegation root ─────────────────────────────────────
 *
 * This translation unit exists so that "who can reach the root key" is a
 * one-line grep. Exactly one function reads it. Adding a second caller is a
 * SECURITY CHANGE, not a refactor, and should be reviewed as one.
 *
 * The root key is what separates 7.16 from 7.15. In 7.15 a describer can
 * mislabel a transaction but cannot conceal it, because the raw review always
 * follows -- which is precisely why 7.15 needs no custody programme. A
 * KeepKey-signed describer MAY omit that review, so the key that vouches for
 * one is the whole trust boundary.
 */

/* Fixed layout. No TLV, no length fields, nothing to fuzz.
 *
 *   off  len  field
 *     0    1  cert_version, must be 0x01
 *     1    1  usage_flags; bit0 = MAY_SUPPRESS_RAW, all other bits MUST be 0
 *     2    4  scope_id, big endian, NONZERO, matched exactly against the tx
 *             network (EVM chain id, or SLIP-44 coin type for non-EVM)
 *     6    4  not_after, big endian unix seconds
 *    10   32  alias, NUL-padded ASCII
 *    42   33  delegate_pubkey, compressed secp256k1 (0x02 or 0x03)
 *    75   64  root_sig, compact ECDSA over the EIP-712 digest of cert[0..74]
 *          = 139
 */
#define CLEARSIGN_CERT_LEN 139
#define CLEARSIGN_CERT_SIGNED_LEN 75
#define CLEARSIGN_CERT_VERSION 0x01
#define CLEARSIGN_USAGE_MAY_SUPPRESS_RAW 0x01

#define CLEARSIGN_CERT_OFF_VERSION 0
#define CLEARSIGN_CERT_OFF_FLAGS 1
#define CLEARSIGN_CERT_OFF_SCOPE 2
#define CLEARSIGN_CERT_OFF_EXPIRY 6
#define CLEARSIGN_CERT_OFF_ALIAS 10
#define CLEARSIGN_CERT_OFF_PUBKEY 42
#define CLEARSIGN_CERT_OFF_SIG 75

#define CLEARSIGN_ALIAS_LEN 32
#define CLEARSIGN_PUBKEY_LEN 33

/* The EIP-712 domain separator, precomputed and compiled in.
 *
 *   keccak(keccak("EIP712Domain(string name,string version)")
 *          || keccak("KeepKey Clearsign Delegation") || keccak("1"))
 *
 * EIP-712 and not a bare sha256 tag for one concrete reason: it makes the
 * root a STOCK KeepKey. EthereumSignTypedHash takes a domain separator and a
 * message hash and signs keccak(0x19||0x01||ds||mh) -- which IS this
 * preimage -- so the ceremony needs no raw-digest signing path and no special
 * firmware on the root device. The device also low-S normalises for free.
 *
 * The domain is still ours and never transmitted, so a host can neither
 * substitute nor elide it, and a certificate preimage can never also parse as
 * a metadata payload. Versioned via the domain string. */
#define CLEARSIGN_DOMAIN_SEPARATOR                                   \
  {0x88, 0x39, 0x40, 0x1f, 0x8d, 0x01, 0x12, 0xb4, 0x34, 0x87, 0x70, \
   0xdd, 0xac, 0xe1, 0x52, 0xe9, 0x6f, 0xc5, 0xe5, 0x08, 0x1a, 0xef, \
   0xee, 0xd6, 0xb5, 0xd8, 0xbe, 0xf0, 0xd6, 0xec, 0xdf, 0x66}

/* The expiry floor, and the only revocation lever this release has.
 *
 * Set by hand at each release cut and bumped deliberately to revoke. NOT
 * derived from the build date: an auto-moving floor rots test fixtures
 * silently and cannot be reviewed in a diff, and the entire value of this
 * mechanism is that revocation is one reviewable line in a signed release.
 *
 * 1787270400 = 2026-08-21T00:00:00Z, the 7.16 cut instant. The floor IS the
 * cut, which is the only value that costs nothing and still means something:
 * it honours every certificate that had not already expired when this
 * firmware was built, and rejects every one that had. The previous value,
 * 1755000000 = 2025-08-12, predated its own cut by a year, so it passed every
 * certificate that has ever existed and the lever was decoration.
 *
 * Two bounds squeeze the next bump, and they pull opposite ways:
 *   - To revoke a delegate the floor must go ABOVE that certificate's
 *     not_after. A bump that does not clear it is not a revocation.
 *   - It must stay BELOW the not_after of every certificate meant to keep
 *     working, INCLUDING the committed unit-test fixture (1818806400 =
 *     2027-08-21T00:00:00Z). Past that the fixture has to be re-minted -- and
 *     a green test run across a bump means the boundary stopped being tested,
 *     not that nothing broke.
 *
 * Mirrored, deliberately by hand, in the ceremony signer (MIN_EXPIRY in
 * sign_delegate_cert.py) and the integration test; selfcheck.py compares the
 * signer's copy against this line and fails loudly when they drift.
 *
 * The consequence, stated plainly because it does not improve by being left
 * implicit: a device that never updates never revokes. */
#define KK_CLEARSIGN_MIN_EXPIRY 1787270400u

/* Verify a delegate certificate against the compiled-in root.
 *
 * Checks, in order: length, version, reserved flag bits, nonzero chain id,
 * expiry against the floor, delegate pubkey prefix, then the signature.
 * Returns false on any failure, and the CALLER degrades to the 7.15 additive
 * path -- never to a refusal. A stale or unverifiable describer is one we no
 * longer trust, and an undescribed transaction is what 7.15 already handles.
 *
 * THE ONLY FUNCTION THAT READS THE ROOT KEY. */
bool clearsign_root_verify_cert(const uint8_t* cert, size_t cert_len);

/* Verify a suppression-capable certificate and require its network scope. On
 * success copies the authenticated delegate identity. Non-EVM networks use
 * their SLIP-44 coin type; Solana is therefore scope 501. Certificates without
 * MAY_SUPPRESS_RAW are deliberately ineligible for this authority path. */
bool clearsign_root_cert_delegate(const uint8_t* cert, size_t cert_len,
                                  uint32_t expected_scope,
                                  uint8_t out_pubkey[CLEARSIGN_PUBKEY_LEN],
                                  char out_alias[CLEARSIGN_ALIAS_LEN + 1]);

/* Verify sha256(data) with the delegate authenticated by a root certificate
 * for `expected_scope`. This is the non-EVM equivalent of the certified v3
 * schema verification path and never consults runtime signer slots. */
bool clearsign_root_verify_delegate_attestation(
    const uint8_t* cert, size_t cert_len, uint32_t expected_scope,
    const uint8_t* data, size_t data_len, const uint8_t* sig, size_t sig_len);

/* Verify a catalog root under the ERC-7730-only purpose domain. `catalog_root`
 * is the result of the definition leaf's sorted Merkle proof. Keeping this
 * preimage construction here prevents callers from accidentally reusing the
 * generic attestation domain for a descriptor that may suppress raw review. */
bool clearsign_root_verify_erc7730_catalog(
    const uint8_t* cert, size_t cert_len, uint32_t expected_scope,
    const uint8_t catalog_root[32], const uint8_t* sig, size_t sig_len,
    char out_alias[CLEARSIGN_ALIAS_LEN + 1]);

/* True when the firmware carries no root key at all -- the mechanical 7.15
 * release gate, kept queryable so a test can assert it rather than a human
 * grepping for key bytes. */
bool clearsign_root_is_present(void);

#endif
