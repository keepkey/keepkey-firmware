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

/* KeepKey delegation root. Only clearsign_root_verify_cert() verifies against
 * the root key; adding another consumer is a SECURITY CHANGE. A root-signed
 * describer MAY omit the raw review, so this key is the whole trust boundary.
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
/* Non-EVM scope ids (SLIP-44 coin type). The EVM path refuses these: a
 * non-EVM cert must never authorize an EVM chain with the same number. */
#define CLEARSIGN_SCOPE_SOLANA 501u
#define CLEARSIGN_PUBKEY_LEN 33

/* The EIP-712 domain separator, precomputed and compiled in.
 *
 *   keccak(keccak("EIP712Domain(string name,string version)")
 *          || keccak("KeepKey Clearsign Delegation") || keccak("1"))
 *
 * EIP-712 so the root can be a stock KeepKey (EthereumSignTypedHash). The
 * domain is never transmitted, so a host cannot substitute or elide it, and a
 * cert preimage can never parse as a metadata payload. */
#define CLEARSIGN_DOMAIN_SEPARATOR                                   \
  {0x88, 0x39, 0x40, 0x1f, 0x8d, 0x01, 0x12, 0xb4, 0x34, 0x87, 0x70, \
   0xdd, 0xac, 0xe1, 0x52, 0xe9, 0x6f, 0xc5, 0xe5, 0x08, 0x1a, 0xef, \
   0xee, 0xd6, 0xb5, 0xd8, 0xbe, 0xf0, 0xd6, 0xec, 0xdf, 0x66}

/* Expiry floor: the only revocation lever. Set by hand (never from the build
 * date) so revocation is one reviewable line. 1787270400 = 2026-08-21Z, the
 * 7.16 cut. To revoke, bump ABOVE that cert's not_after; stay BELOW every
 * cert meant to keep working, incl. the unit fixture (1818806400). Mirrored
 * in sign_delegate_cert.py (checked by selfcheck.py). A device that never
 * updates never revokes. */
#define KK_CLEARSIGN_MIN_EXPIRY 1787270400u

/* Verify a cert against the compiled-in root. Checks neither MAY_SUPPRESS_RAW
 * nor scope, so it alone never authorizes suppressing the raw review; use
 * clearsign_root_cert_delegate(). A failed certified claim is refused, never
 * downgraded (SRS R-1.4). THE ONLY FUNCTION THAT VERIFIES AGAINST THE ROOT. */
bool clearsign_root_verify_cert(const uint8_t* cert, size_t cert_len);

/* Verify a cert that has MAY_SUPPRESS_RAW and exactly `expected_scope`;
 * copy out the delegate identity. */
bool clearsign_root_cert_delegate(const uint8_t* cert, size_t cert_len,
                                  uint32_t expected_scope,
                                  uint8_t out_pubkey[CLEARSIGN_PUBKEY_LEN],
                                  char out_alias[CLEARSIGN_ALIAS_LEN + 1]);

/* Verify sha256(data) by the certified delegate for `expected_scope`. Never
 * consults runtime signer slots. */
bool clearsign_root_verify_delegate_attestation(
    const uint8_t* cert, size_t cert_len, uint32_t expected_scope,
    const uint8_t* data, size_t data_len, const uint8_t* sig, size_t sig_len);

/* Verify a catalog Merkle root under the ERC-7730-only purpose domain, so the
 * generic attestation domain is never reused for a suppressing descriptor. */
bool clearsign_root_verify_erc7730_catalog(
    const uint8_t* cert, size_t cert_len, uint32_t expected_scope,
    const uint8_t catalog_root[32], const uint8_t* sig, size_t sig_len,
    char out_alias[CLEARSIGN_ALIAS_LEN + 1]);

/* Root is not all zero. Always true in 7.16; kept as a suppression conjunct. */
bool clearsign_root_is_present(void);

#if DEBUG_LINK && defined(EMULATOR)
/* Unit tests only: verify certificates against `pubkey` (33 bytes, caller
 * keeps it alive) instead of the compiled-in root; NULL restores it. */
void clearsign_root_set_test_root(const uint8_t* pubkey);

/* Unit tests only: the compiled-in root, ignoring any test root. */
const uint8_t* clearsign_root_compiled_pubkey(void);

/* Emulator startup: if KK_CLEARSIGN_TEST_ROOT holds a 33-byte compressed
 * secp256k1 key as 66 hex chars, verify against it instead of the compiled-in
 * root. An invalid value is ignored with a warning on stderr. The key comes
 * only from the environment, so no binary carries a test root. */
bool clearsign_root_load_test_root_from_env(void);
#endif

#endif
