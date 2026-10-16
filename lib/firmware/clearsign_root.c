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

#if DEBUG_LINK && defined(EMULATOR)
#include <stdio.h>
#include <stdlib.h>
#endif

#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"
#include "trezor/crypto/sha3.h"

/* Production root public-key provisioning candidate, captured 2026-10-15.
 * KKclearSignROOT, device 310BBE4832ED489FD9DF3900, official firmware 7.14.1.
 * secp256k1 m/44'/60'/0'/0/0, standard wallet with empty passphrase.
 * Two readings matched across a physical power cycle; see public-root.json
 * in the clearsign-root-provisioning-20261015 ceremony evidence.
 * Pending integration: hardened issuer upgrade, matching certificate fixtures,
 * and complete 7.16 qualification. No certificates were issued at capture.
 */
static const uint8_t kk_clearsign_root_pubkey[CLEARSIGN_PUBKEY_LEN] = {
    0x02, 0x7c, 0x1f, 0xde, 0x75, 0xdb, 0x6c, 0x36, 0x39, 0x3e, 0x09,
    0x5e, 0x0d, 0xc5, 0xab, 0x9a, 0x5b, 0xcf, 0x1a, 0xe9, 0xeb, 0x92,
    0xb5, 0xd3, 0x6e, 0x21, 0x2a, 0x2b, 0xf7, 0xf8, 0xa6, 0xe3, 0x21,
};

#if DEBUG_LINK && defined(EMULATOR)
/* Unit-test root: emulator debug-link only, unreachable by any message. */
static const uint8_t* test_root_pubkey;

void clearsign_root_set_test_root(const uint8_t* pubkey) {
  test_root_pubkey = pubkey;
}

const uint8_t* clearsign_root_compiled_pubkey(void) {
  return kk_clearsign_root_pubkey;
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool clearsign_root_load_test_root_from_env(void) {
  static uint8_t env_root[CLEARSIGN_PUBKEY_LEN];
  const char* hex = getenv("KK_CLEARSIGN_TEST_ROOT");
  if (!hex || !*hex) return false;

  uint8_t key[CLEARSIGN_PUBKEY_LEN];
  bool ok = strlen(hex) == 2 * CLEARSIGN_PUBKEY_LEN;
  for (size_t i = 0; ok && i < CLEARSIGN_PUBKEY_LEN; i++) {
    const int hi = hex_nibble(hex[2 * i]), lo = hex_nibble(hex[2 * i + 1]);
    ok = hi >= 0 && lo >= 0;
    key[i] = (uint8_t)((hi << 4) | (lo & 0x0f));
  }
  curve_point point;
  ok = ok && (key[0] == 0x02 || key[0] == 0x03) &&
       ecdsa_read_pubkey(&secp256k1, key, &point) == 1;
  if (!ok) {
    fprintf(stderr,
            "WARNING: ignoring KK_CLEARSIGN_TEST_ROOT: not a 66-hex-char "
            "compressed secp256k1 key; using the compiled-in root\n");
    return false;
  }
  memcpy(env_root, key, sizeof(env_root));
  clearsign_root_set_test_root(env_root);
  fprintf(stderr,
          "WARNING: ClearSign certificates verify against the TEST root "
          "KK_CLEARSIGN_TEST_ROOT=%s, not the compiled-in root\n",
          hex);
  return true;
}
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

  /* Reserved bits must be zero: an unknown flag is an unreviewed capability. */
  const uint8_t flags = cert[CLEARSIGN_CERT_OFF_FLAGS];
  if ((flags & (uint8_t)~CLEARSIGN_USAGE_MAY_SUPPRESS_RAW) != 0) return false;

  /* Alias: 1-31 printable ASCII then NUL padding, so no control byte can
   * reshape the trust prompt. */
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

  /* Nonzero scope: never a wildcard by omission. */
  if (be32(&cert[CLEARSIGN_CERT_OFF_SCOPE]) == 0) return false;

  /* No clock: this checks against the release floor, not "now". */
  if (be32(&cert[CLEARSIGN_CERT_OFF_EXPIRY]) <= KK_CLEARSIGN_MIN_EXPIRY)
    return false;

  const uint8_t prefix = cert[CLEARSIGN_CERT_OFF_PUBKEY];
  if (prefix != 0x02 && prefix != 0x03) return false;

  /* keccak(0x19 || 0x01 || DOMAIN_SEP || keccak(cert[0..74])), as
   * EthereumSignTypedHash produces. */
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

  const uint8_t* root = kk_clearsign_root_pubkey;
#if DEBUG_LINK && defined(EMULATOR)
  if (test_root_pubkey) root = test_root_pubkey;
#endif
  return ecdsa_verify_digest(&secp256k1, root, &cert[CLEARSIGN_CERT_OFF_SIG],
                             digest) == 0;
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

/* `digest` signed by the certified delegate for `expected_scope`. */
static bool verify_delegate_digest(const uint8_t* cert, size_t cert_len,
                                   uint32_t expected_scope,
                                   uint8_t digest[SHA256_DIGEST_LENGTH],
                                   const uint8_t* sig,
                                   char out_alias[CLEARSIGN_ALIAS_LEN + 1]) {
  uint8_t delegate[CLEARSIGN_PUBKEY_LEN];
  const bool ok = clearsign_root_cert_delegate(cert, cert_len, expected_scope,
                                               delegate, out_alias) &&
                  ecdsa_verify_digest(&secp256k1, delegate, sig, digest) == 0;
  memzero(delegate, sizeof(delegate));
  memzero(digest, SHA256_DIGEST_LENGTH);
  if (!ok) memzero(out_alias, CLEARSIGN_ALIAS_LEN + 1);
  return ok;
}

bool clearsign_root_verify_delegate_attestation(
    const uint8_t* cert, size_t cert_len, uint32_t expected_scope,
    const uint8_t* data, size_t data_len, const uint8_t* sig, size_t sig_len) {
  if (!data || data_len == 0 || !sig || sig_len != 64) return false;
  uint8_t digest[SHA256_DIGEST_LENGTH];
  char alias[CLEARSIGN_ALIAS_LEN + 1];
  sha256_Raw(data, data_len, digest);
  /* The alias is public certificate text; the helper wipes it on failure. */
  return verify_delegate_digest(cert, cert_len, expected_scope, digest, sig,
                                alias);
}

bool clearsign_root_verify_erc7730_catalog(
    const uint8_t* cert, size_t cert_len, uint32_t expected_scope,
    const uint8_t catalog_root[32], const uint8_t* sig, size_t sig_len,
    char out_alias[CLEARSIGN_ALIAS_LEN + 1]) {
  static const uint8_t purpose[] = "KEEPKEY:ERC7730:CATALOG\0";
  /* An EVM catalog: a Solana-scope cert never authorizes EVM chain 501. */
  if (!catalog_root || !sig || sig_len != 64 || !out_alias ||
      expected_scope == CLEARSIGN_SCOPE_SOLANA)
    return false;

  SHA256_CTX ctx;
  uint8_t digest[SHA256_DIGEST_LENGTH];
  sha256_Init(&ctx);
  /* sizeof includes the explicit protocol NUL but excludes C's implicit NUL. */
  sha256_Update(&ctx, purpose, sizeof(purpose) - 1);
  sha256_Update(&ctx, catalog_root, 32);
  sha256_Final(&ctx, digest);
  return verify_delegate_digest(cert, cert_len, expected_scope, digest, sig,
                                out_alias);
}
