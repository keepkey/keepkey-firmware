extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/thorchain.h"
#include "keepkey/firmware/tendermint.h"
#include "trezor/crypto/secp256k1.h"
}

#include "gtest/gtest.h"
#include <cstring>

// Vectors computed with the trezor-crypto library directly (see
// unittests/firmware/thorchain.cpp notes). The test file was previously
// absent from CMakeLists.txt so none of these values were ever validated;
// all expected values here are derived from the actual crypto library.

TEST(Thorchain, ThorchainGetAddress) {
  HDNode node = {
      0,
      0,
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0x03, 0xb7, 0x32, 0x9f, 0x67, 0x8e, 0x0a, 0xc1, 0x21, 0x4b, 0x77,
       0x23, 0x57, 0x54, 0x66, 0x21, 0x9c, 0x77, 0xfe, 0xdb, 0xdd, 0x95,
       0x5c, 0x33, 0x29, 0x1a, 0x74, 0xf1, 0x8b, 0xf5, 0xc8, 0xa4, 0xe2},
      &secp256k1_info};
  char addr[46];
  ASSERT_TRUE(tendermint_getAddress(&node, "thor", addr));
  EXPECT_EQ(std::string("thor1am058pdux3hyulcmfgj4m3hhrlfn8nzmpq9u6l"), addr);
}

// Shared fixtures
static const HDNode kSignNode = {
    0,
    0,
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0x04, 0xde, 0xc0, 0xcc, 0x01, 0x3c, 0xd8, 0xab, 0x70, 0x87, 0xca,
     0x14, 0x96, 0x0b, 0x76, 0x8c, 0x3d, 0x83, 0x45, 0x24, 0x48, 0xaa,
     0x00, 0x64, 0xda, 0xe6, 0xfb, 0x04, 0xb5, 0xd9, 0x34, 0x76},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    &secp256k1_info};

static const ThorchainSignTx kSignTx = {
    5,    {0x80000000 | 44, 0x80000000 | 931, 0x80000000, 0, 0},
    true, 0,
    true, "thorchain",
    true, 5000,
    true, 200000,
    true, "",
    true, 0,
    true, 1};

static const char* kToAddr = "thor18vhdczjut44gpsy804crfhnd5nq003nz0nf20v";

// Baseline RUNE send — exact signature vector
TEST(Thorchain, ThorchainSignTx) {
  HDNode node = kSignNode;
  hdnode_fill_public_key(&node);

  ASSERT_TRUE(thorchain_signTxInit(&node, &kSignTx));
  ASSERT_TRUE(thorchain_signTxUpdateMsgSend(100000, kToAddr, "rune"));

  uint8_t public_key[33];
  uint8_t signature[64];
  ASSERT_TRUE(thorchain_signTxFinalize(public_key, signature));

  EXPECT_EQ(0,
      memcmp(signature,
             (uint8_t *)"\xc3\xea\xe2\xa3\xc2\xb6\x24\x00\x8d\x8a\xc4\x49\xe2"
                        "\x53\xdb\xa5\x31\x2e\x4d\xbd\x12\xd6\x77\x39\xd3\xf9"
                        "\xce\xe1\xc3\xbd\x34\x62\x69\xd2\xaa\x8a\x79\xbe\x81"
                        "\xd8\x1a\x9e\xe3\x94\x99\x07\xbb\xe2\x08\x04\x1a\xfa"
                        "\xfe\xfa\x14\x9f\x67\xb3\x9d\x4a\xe2\x29\xc8\x47",
             64));
}

// Empty denom must produce identical output to explicit "rune"
TEST(Thorchain, ThorchainSignTxDefaultDenom) {
  HDNode node = kSignNode;
  hdnode_fill_public_key(&node);

  ASSERT_TRUE(thorchain_signTxInit(&node, &kSignTx));
  ASSERT_TRUE(thorchain_signTxUpdateMsgSend(100000, kToAddr, ""));

  uint8_t public_key[33];
  uint8_t signature[64];
  ASSERT_TRUE(thorchain_signTxFinalize(public_key, signature));

  EXPECT_EQ(0,
      memcmp(signature,
             (uint8_t *)"\xc3\xea\xe2\xa3\xc2\xb6\x24\x00\x8d\x8a\xc4\x49\xe2"
                        "\x53\xdb\xa5\x31\x2e\x4d\xbd\x12\xd6\x77\x39\xd3\xf9"
                        "\xce\xe1\xc3\xbd\x34\x62\x69\xd2\xaa\x8a\x79\xbe\x81"
                        "\xd8\x1a\x9e\xe3\x94\x99\x07\xbb\xe2\x08\x04\x1a\xfa"
                        "\xfe\xfa\x14\x9f\x67\xb3\x9d\x4a\xe2\x29\xc8\x47",
             64));
}

// TCY (THORChain native yield/governance token) — exact signature vector
TEST(Thorchain, ThorchainSignTxTCY) {
  HDNode node = kSignNode;
  hdnode_fill_public_key(&node);

  ASSERT_TRUE(thorchain_signTxInit(&node, &kSignTx));
  ASSERT_TRUE(thorchain_signTxUpdateMsgSend(100000, kToAddr, "tcy"));

  uint8_t public_key[33];
  uint8_t signature[64];
  ASSERT_TRUE(thorchain_signTxFinalize(public_key, signature));

  EXPECT_EQ(0,
      memcmp(signature,
             (uint8_t *)"\xad\xa0\xb6\xce\x50\x41\xc1\x01\x46\xf0\x86\x94\xb9"
                        "\x97\x29\x41\x13\x41\xef\x87\x70\xe8\x58\x7c\x01\xf9"
                        "\x81\x3f\x71\x8e\xbb\xc7\x58\xcf\xeb\xfc\xf9\x28\x55"
                        "\x73\xe0\x85\x31\x52\xfc\x0e\xbf\xbd\xa6\x4e\xe8\xd2"
                        "\xca\xd6\xc4\xd1\xfc\x18\x31\x13\x33\x2f\x2b\xae",
             64));
}

// RUJIRA (DEX protocol native to THORChain) — exact signature vector
TEST(Thorchain, ThorchainSignTxRujira) {
  HDNode node = kSignNode;
  hdnode_fill_public_key(&node);

  ASSERT_TRUE(thorchain_signTxInit(&node, &kSignTx));
  ASSERT_TRUE(thorchain_signTxUpdateMsgSend(100000, kToAddr, "rujira"));

  uint8_t public_key[33];
  uint8_t signature[64];
  ASSERT_TRUE(thorchain_signTxFinalize(public_key, signature));

  EXPECT_EQ(0,
      memcmp(signature,
             (uint8_t *)"\xed\x3b\x99\xac\xfa\x12\x32\xf7\x04\x72\x43\x17\x27"
                        "\x37\xbc\xb3\x15\x32\xc6\xe2\x1e\x5f\x5b\x4b\xb4\x3c"
                        "\x10\x7f\x7e\x08\x6a\x60\x28\xa3\x26\x53\x37\x44\x21"
                        "\xcb\x62\x29\xe4\x5a\xba\x82\x89\x2e\xc7\x6a\x27\x4b"
                        "\xe7\xfd\x4e\x77\xe2\xa4\x3a\x8e\x5a\x82\xbb\x17",
             64));
}

// Denom validation: only [a-z0-9./\-] is allowed; anything else is rejected
TEST(Thorchain, ThorchainDenomValidation) {
  EXPECT_TRUE(thorchain_isValidDenom("rune"));
  EXPECT_TRUE(thorchain_isValidDenom("tcy"));
  EXPECT_TRUE(thorchain_isValidDenom("rujira"));
  EXPECT_TRUE(thorchain_isValidDenom("eth.eth"));
  EXPECT_TRUE(thorchain_isValidDenom("btc/btc"));
  EXPECT_TRUE(thorchain_isValidDenom("cross-chain"));

  EXPECT_FALSE(thorchain_isValidDenom(""));           // empty → caller uses "rune"
  EXPECT_FALSE(thorchain_isValidDenom("RUNE"));       // uppercase rejected
  EXPECT_FALSE(thorchain_isValidDenom("rune\""));     // quote injection
  EXPECT_FALSE(thorchain_isValidDenom("rune\\n"));    // backslash injection
  EXPECT_FALSE(thorchain_isValidDenom(" rune"));      // leading space
  EXPECT_FALSE(thorchain_isValidDenom("ru ne"));      // embedded space
}

// Invalid denom must cause thorchain_signTxUpdateMsgSend to return false
TEST(Thorchain, ThorchainSignTxInvalidDenom) {
  HDNode node = kSignNode;
  hdnode_fill_public_key(&node);

  ASSERT_TRUE(thorchain_signTxInit(&node, &kSignTx));
  // Quote-injection attempt must be rejected at the signing layer
  EXPECT_FALSE(
      thorchain_signTxUpdateMsgSend(100000, kToAddr, "rune\",\"from_address\":\"evil"));
  thorchain_signAbort();
}
