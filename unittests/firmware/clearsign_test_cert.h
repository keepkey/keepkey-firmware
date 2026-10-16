#ifndef UNITTESTS_FIRMWARE_CLEARSIGN_TEST_CERT_H
#define UNITTESTS_FIRMWARE_CLEARSIGN_TEST_CERT_H

extern "C" {
#include "keepkey/firmware/clearsign_root.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha3.h"
}

#include "gtest/gtest.h"

#include <cstring>
#include <vector>

// The alpha root, 02de9231...dae7 (the marked root KeepKey, device
// 393137350D4736341B003900). The historical certificate fixtures were signed
// by it. 7.16 compiles in the production root instead, so tests that use those
// fixtures install this key as the emulator test root. It lives only in test
// sources; release.yml refuses any release artifact that contains it.
static const uint8_t kAlphaRootPubkey[CLEARSIGN_PUBKEY_LEN] = {
    0x02, 0xde, 0x92, 0x31, 0xb2, 0x09, 0x44, 0x33, 0x23, 0x55, 0x32,
    0xfb, 0x19, 0x32, 0xe3, 0x24, 0xa2, 0xc7, 0x30, 0x41, 0x95, 0xe1,
    0x2e, 0x61, 0x0c, 0x67, 0x5c, 0xcc, 0xbb, 0xd6, 0x06, 0xda, 0xe7,
};

// Verifies certificates against the alpha root for its lifetime, then
// restores the compiled-in root.
struct AlphaTestRoot {
  AlphaTestRoot() { clearsign_root_set_test_root(kAlphaRootPubkey); }
  ~AlphaTestRoot() { clearsign_root_set_test_root(nullptr); }
  AlphaTestRoot(const AlphaTestRoot&) = delete;
  AlphaTestRoot& operator=(const AlphaTestRoot&) = delete;
};

// A delegate certificate in the layout of clearsign_root.h, signed by
// `root_key` over keccak(0x19 || 0x01 || DOMAIN_SEP || keccak(cert[0..74])),
// the digest EthereumSignTypedHash produces on the root KeepKey.
inline std::vector<uint8_t> rootCert(
    const uint8_t root_key[32], const uint8_t delegate_pubkey[33],
    uint8_t flags = CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, uint32_t scope = 1,
    uint32_t not_after = KK_CLEARSIGN_MIN_EXPIRY + 1,
    const char* alias = "KeepKey Test") {
  std::vector<uint8_t> c(CLEARSIGN_CERT_LEN, 0);
  c[CLEARSIGN_CERT_OFF_VERSION] = CLEARSIGN_CERT_VERSION;
  c[CLEARSIGN_CERT_OFF_FLAGS] = flags;
  for (int i = 0; i < 4; i++) {
    c[CLEARSIGN_CERT_OFF_SCOPE + i] = (uint8_t)(scope >> (24 - 8 * i));
    c[CLEARSIGN_CERT_OFF_EXPIRY + i] = (uint8_t)(not_after >> (24 - 8 * i));
  }
  memcpy(c.data() + CLEARSIGN_CERT_OFF_ALIAS, alias,
         strnlen(alias, CLEARSIGN_ALIAS_LEN));
  memcpy(c.data() + CLEARSIGN_CERT_OFF_PUBKEY, delegate_pubkey,
         CLEARSIGN_PUBKEY_LEN);
  const uint8_t domain_sep[32] = CLEARSIGN_DOMAIN_SEPARATOR;
  uint8_t preimage[66] = {0x19, 0x01};
  memcpy(preimage + 2, domain_sep, 32);
  keccak_256(c.data(), CLEARSIGN_CERT_SIGNED_LEN, preimage + 34);
  uint8_t hash[32];
  keccak_256(preimage, sizeof(preimage), hash);
  EXPECT_EQ(
      ecdsa_sign_digest(&secp256k1, root_key, hash,
                        c.data() + CLEARSIGN_CERT_OFF_SIG, nullptr, nullptr),
      0);
  return c;
}

#endif
