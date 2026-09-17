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

#include "keepkey/firmware/clearsign_root.h"

#include <string.h>

#include "ecdsa.h"
#include "memzero.h"
#include "secp256k1.h"
#include "sha2.h"
#include "trezor/crypto/sha3.h"

/* ── The root public key ─────────────────────────────────────────────
 *
 * A RELEASE BUILD SHIPS NO ROOT. The array is all-zero unless the build
 * explicitly asks for the alpha root, which is the 7.15 posture carried
 * forward: with no root, no certificate can ever verify, so the suppression
 * branch is unreachable rather than merely unused. clearsign_root_is_present()
 * exposes that so a release test asserts it instead of a human grepping key
 * bytes.
 *
 * The real root will be generated on a KeepKey, will never exist as a file,
 * and gets pasted in at the release cut as a reviewable one-line diff. Making
 * the DEFAULT empty means forgetting that step produces a device that
 * clear-signs nothing -- the safe failure -- rather than one that trusts a key
 * whose private half sits in a scratch directory.
 */
#if defined(KK_CLEARSIGN_ALPHA_ROOT)
/* ALPHA KEY. Generated 2026-08-21 on a marked KeepKey; its private half never
 * left that device. This is the root that issued the public alpha delegate
 * certificates used by Vault. Production must perform a separate ceremony.
 * m/44'/60'/0'/0/0, device 393137350D4736341B003900, reseeded 2026-08-21. */
static const uint8_t kk_clearsign_root_pubkey[CLEARSIGN_PUBKEY_LEN] = {
    0x02, 0xde, 0x92, 0x31, 0xb2, 0x09, 0x44, 0x33, 0x23, 0x55, 0x32,
    0xfb, 0x19, 0x32, 0xe3, 0x24, 0xa2, 0xc7, 0x30, 0x41, 0x95, 0xe1,
    0x2e, 0x61, 0x0c, 0x67, 0x5c, 0xcc, 0xbb, 0xd6, 0x06, 0xda, 0xe7,
};
#else
static const uint8_t kk_clearsign_root_pubkey[CLEARSIGN_PUBKEY_LEN] = {0};
#endif

bool clearsign_root_is_present(void) {
  for (size_t i = 0; i < CLEARSIGN_PUBKEY_LEN; i++) {
    if (kk_clearsign_root_pubkey[i] != 0x00) return true;
  }
  return false;
}

static uint32_t be32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

bool clearsign_root_verify_cert(const uint8_t* cert, size_t cert_len) {
  if (!cert || cert_len != CLEARSIGN_CERT_LEN) return false;
  if (!clearsign_root_is_present()) return false;

  if (cert[CLEARSIGN_CERT_OFF_VERSION] != CLEARSIGN_CERT_VERSION) return false;

  /* Reserved bits must be zero. A flag we do not understand is a capability we
   * did not agree to, and accepting it silently is how a future format grants
   * itself permissions this firmware never reviewed. */
  const uint8_t flags = cert[CLEARSIGN_CERT_OFF_FLAGS];
  if ((flags & (uint8_t)~CLEARSIGN_USAGE_MAY_SUPPRESS_RAW) != 0) return false;

  /* Alias is authenticated display text, so accept only the canonical format
   * the ceremony signs: 1-31 printable ASCII bytes followed by NUL padding.
   * A signed newline/control byte would otherwise let an issuer reshape the
   * device's trust prompt even though callers use a safe "%s" format. */
  bool alias_ended = false;
  for (size_t i = 0; i < CLEARSIGN_ALIAS_LEN; i++) {
    const uint8_t c = cert[CLEARSIGN_CERT_OFF_ALIAS + i];
    if (alias_ended) {
      if (c != 0) return false;
    } else if (c == 0) {
      if (i == 0) return false;
      alias_ended = true;
    } else if (c < 0x20 || c > 0x7e) {
      return false;
    }
  }
  if (!alias_ended) return false;

  /* Chain 0 is not a chain. Requiring nonzero means a certificate is always
   * bound to exactly one network and can never be wildcard by omission. */
  if (be32(&cert[CLEARSIGN_CERT_OFF_SCOPE]) == 0) return false;

  /* The device has no clock, so this is not "is it expired now" -- it is "was
   * this issued for a window this firmware still honours". The floor moves
   * only when a signed firmware ships. */
  if (be32(&cert[CLEARSIGN_CERT_OFF_EXPIRY]) <= KK_CLEARSIGN_MIN_EXPIRY)
    return false;

  const uint8_t prefix = cert[CLEARSIGN_CERT_OFF_PUBKEY];
  if (prefix != 0x02 && prefix != 0x03) return false;

  /* keccak(0x19 || 0x01 || DOMAIN_SEP || keccak(cert[0..74])).
   *
   * Byte for byte what EthereumSignTypedHash produces, so the root can be an
   * ordinary KeepKey. The domain separator is ours and never crosses the
   * wire. */
  static const uint8_t domain_sep[32] = CLEARSIGN_DOMAIN_SEPARATOR;
  struct SHA3_CTX ctx;
  uint8_t digest[32];

  sha3_256_Init(&ctx);
  sha3_Update(&ctx, cert, CLEARSIGN_CERT_SIGNED_LEN);
  keccak_Final(&ctx, digest);

  const uint8_t prefix712[2] = {0x19, 0x01};
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, prefix712, sizeof(prefix712));
  sha3_Update(&ctx, domain_sep, sizeof(domain_sep));
  sha3_Update(&ctx, digest, sizeof(digest));
  keccak_Final(&ctx, digest);

  return ecdsa_verify_digest(&secp256k1, kk_clearsign_root_pubkey,
                             &cert[CLEARSIGN_CERT_OFF_SIG], digest) == 0;
}

bool clearsign_root_cert_delegate(const uint8_t* cert, size_t cert_len,
                                  uint32_t expected_scope,
                                  uint8_t out_pubkey[CLEARSIGN_PUBKEY_LEN],
                                  char out_alias[CLEARSIGN_ALIAS_LEN + 1]) {
  if (!out_pubkey || !out_alias || expected_scope == 0 ||
      !clearsign_root_verify_cert(cert, cert_len) ||
      (cert[CLEARSIGN_CERT_OFF_FLAGS] & CLEARSIGN_USAGE_MAY_SUPPRESS_RAW) ==
          0 ||
      be32(&cert[CLEARSIGN_CERT_OFF_SCOPE]) != expected_scope) {
    return false;
  }
  memcpy(out_pubkey, &cert[CLEARSIGN_CERT_OFF_PUBKEY], CLEARSIGN_PUBKEY_LEN);
  memcpy(out_alias, &cert[CLEARSIGN_CERT_OFF_ALIAS], CLEARSIGN_ALIAS_LEN);
  out_alias[CLEARSIGN_ALIAS_LEN] = '\0';
  return true;
}

bool clearsign_root_verify_delegate_attestation(
    const uint8_t* cert, size_t cert_len, uint32_t expected_scope,
    const uint8_t* data, size_t data_len, const uint8_t* sig, size_t sig_len) {
  if (!data || data_len == 0 || !sig || sig_len != 64) return false;
  uint8_t delegate[CLEARSIGN_PUBKEY_LEN];
  char alias[CLEARSIGN_ALIAS_LEN + 1];
  if (!clearsign_root_cert_delegate(cert, cert_len, expected_scope, delegate,
                                    alias)) {
    return false;
  }
  uint8_t digest[SHA256_DIGEST_LENGTH];
  sha256_Raw(data, data_len, digest);
  const bool ok = ecdsa_verify_digest(&secp256k1, delegate, sig, digest) == 0;
  memset(delegate, 0, sizeof(delegate));
  memset(digest, 0, sizeof(digest));
  memset(alias, 0, sizeof(alias));
  return ok;
}

bool clearsign_root_verify_erc7730_catalog(
    const uint8_t* cert, size_t cert_len, uint32_t expected_scope,
    const uint8_t catalog_root[32], const uint8_t* sig, size_t sig_len,
    char out_alias[CLEARSIGN_ALIAS_LEN + 1]) {
  static const uint8_t purpose[] = "KEEPKEY:ERC7730:CATALOG\0";
  if (!catalog_root || !sig || sig_len != 64 || !out_alias) return false;

  uint8_t delegate[CLEARSIGN_PUBKEY_LEN];
  if (!clearsign_root_cert_delegate(cert, cert_len, expected_scope, delegate,
                                    out_alias)) {
    return false;
  }

  SHA256_CTX ctx;
  uint8_t digest[SHA256_DIGEST_LENGTH];
  sha256_Init(&ctx);
  /* sizeof includes the explicit protocol NUL but excludes C's implicit NUL. */
  sha256_Update(&ctx, purpose, sizeof(purpose) - 1);
  sha256_Update(&ctx, catalog_root, 32);
  sha256_Final(&ctx, digest);
  const bool ok = ecdsa_verify_digest(&secp256k1, delegate, sig, digest) == 0;
  memzero(delegate, sizeof(delegate));
  memzero(digest, sizeof(digest));
  if (!ok) memzero(out_alias, CLEARSIGN_ALIAS_LEN + 1);
  return ok;
}
