extern "C" {
#include "keepkey/board/pubkeys.h"
#include "keepkey/board/signatures.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/secp256k1.h"
}

#include "gtest/gtest.h"

#include <string.h>

TEST(Board, SignaturesVerify3RefusesAnySingleBadSignature) {
  uint8_t priv[3][32], pub[3][65], sig[3][64], digest[32];
  for (int k = 0; k < 3; k++) {
    memset(priv[k], 0x11 * (k + 1), sizeof(priv[k]));
    ecdsa_get_public_key65(&secp256k1, priv[k], pub[k]);
  }
  memset(digest, 0xA5, sizeof(digest));
  for (int k = 0; k < 3; k++) {
    ASSERT_EQ(
        ecdsa_sign_digest(&secp256k1, priv[k], digest, sig[k], NULL, NULL), 0);
  }

  const uint8_t* const keys[3] = {pub[0], pub[1], pub[2]};
  const uint8_t* const sigs[3] = {sig[0], sig[1], sig[2]};
  ASSERT_EQ(signatures_verify3(keys, sigs, digest), (int)SIG_OK);

  for (int k = 0; k < 3; k++) {
    sig[k][10] ^= 0x01;
    EXPECT_EQ(signatures_verify3(keys, sigs, digest), (int)SIG_FAIL)
        << "signature " << k + 1 << " corrupted";
    sig[k][10] ^= 0x01;
  }

  ASSERT_EQ(signatures_verify3(keys, sigs, digest), (int)SIG_OK);
}
