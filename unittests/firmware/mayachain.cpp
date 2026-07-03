extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/mayachain.h"
#include "keepkey/firmware/tendermint.h"
#include "trezor/crypto/secp256k1.h"
}

#include "gtest/gtest.h"
#include <cstring>

// confirm() auto-accept driver, defined in thorchain.cpp (same binary).
// kkconfirm_preload(nYes, nNo) queues nYes accepted confirm screens then
// nNo rejected ones; kkconfirm_drain() == 0 proves the exact screen count.
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

TEST(Mayachain, MayachainGetAddress) {
  HDNode node = {
      0,
      0,
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0x03, 0x15, 0x19, 0x71, 0x3b, 0x8b, 0x42, 0xbd, 0xc3, 0x67, 0x11,
       0x2d, 0x33, 0x13, 0x2c, 0xf1, 0x4c, 0xed, 0xf9, 0x28, 0xac, 0x57,
       0x71, 0xd4, 0x44, 0xba, 0x45, 0x9b, 0x94, 0x97, 0x11, 0x7b, 0xa3},
      &secp256k1_info};
  char addr[46];
  ASSERT_TRUE(tendermint_getAddress(&node, "maya", addr));
  EXPECT_EQ(std::string("maya1ls33ayg26kmltw7jjy55p32ghjna09zp7z4etj"), addr);
}

TEST(Mayachain, MayachainSignTx) {
  HDNode node = {
      0,
      0,
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0xb9, 0x9a, 0x39, 0x3a, 0x5a, 0x53, 0x0d, 0x90, 0xef, 0x6e, 0x46,
       0x4e, 0x8e, 0x2f, 0x2b, 0x8b, 0x5c, 0x64, 0xa7, 0x97, 0x29, 0xcd,
       0x60, 0x3b, 0x1f, 0xba, 0x33, 0x81, 0x7d, 0x1a, 0x75, 0xa1},
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      &secp256k1_info};
  hdnode_fill_public_key(&node);

  const MayachainSignTx msg = {
      5,    {0x80000000 | 44, 0x80000000 | 931, 0x80000000, 0, 0},  // address_n
      true, 6359,                    // account_number
      true, "mayachain-mainnet-v1",  // chain_id
      true, 3000,                    // fee_amount
      true, 200000,                  // gas
      true, "",                      // memo
      true, 19,                      // sequence
      true, 1                        // msg_count
  };
  ASSERT_TRUE(mayachain_signTxInit(&node, &msg));

  ASSERT_TRUE(mayachain_signTxUpdateMsgSend(
      100, "maya1g9el7lzjwh9yun2c4jjzhy09j98vkhfxfqkl5k", "cacao"));

  uint8_t public_key[33];
  uint8_t signature[64];

  ASSERT_TRUE(mayachain_signTxFinalize(public_key, signature));

  // Expected value recomputed independently (python-ecdsa, RFC6979/secp256k1,
  // low-s) over the exact sign-doc JSON this fixture produces:
  //   {"account_number":"6359","chain_id":"mayachain-mainnet-v1","fee":
  //   {"amount":[{"amount":"3000","denom":"cacao"}],"gas":"200000"},"memo":
  //   "","msgs":[{"type":"mayachain/MsgSend","value":{"amount":[{"amount":
  //   "100","denom":"cacao"}],"from_address":
  //   "maya1ls33ayg26kmltw7jjy55p32ghjna09zp7z4etj","to_address":
  //   "maya1g9el7lzjwh9yun2c4jjzhy09j98vkhfxfqkl5k"}}],"sequence":"19"}
  // The bytes recorded when this file was written never matched: the file
  // was not in the unit build (see 28c74a0e) so the vector was never
  // validated, and it did not verify against this fixture's key/JSON.
  EXPECT_TRUE(
      memcmp(signature,
             (uint8_t *)"\xdf\x2f\x66\x37\x03\x08\x32\xd2\xce\x87\xfe\x47\x8d"
                        "\xdf\xe6\xd8\x21\xd2\x6b\x03\x8b\x44\xfa\xc8\x98\xe6"
                        "\xdf\x79\xe3\xfd\x10\x5d\x40\x3f\x05\x0d\x00\xad\xf9"
                        "\x7d\x3e\xd3\xa7\x3d\xa6\x9b\x19\x74\x0c\x6a\xbc\xf6"
                        "\x94\x09\x57\x29\xa3\xf0\xc3\x62\xc9\xf0\xfa\x71",
             64) == 0);
}

// Denom validation: only [a-z0-9./\-] is allowed; anything else is rejected
TEST(Mayachain, MayachainDenomValidation) {
  EXPECT_TRUE(mayachain_isValidDenom("cacao"));
  EXPECT_TRUE(mayachain_isValidDenom("maya"));
  EXPECT_TRUE(mayachain_isValidDenom("eth.eth"));
  EXPECT_TRUE(mayachain_isValidDenom("btc/btc"));
  EXPECT_TRUE(mayachain_isValidDenom("cross-chain"));

  EXPECT_FALSE(mayachain_isValidDenom(""));         // empty → caller "cacao"
  EXPECT_FALSE(mayachain_isValidDenom("CACAO"));    // uppercase rejected
  EXPECT_FALSE(mayachain_isValidDenom("cacao\""));  // quote injection
  EXPECT_FALSE(mayachain_isValidDenom("cacao\\n"));  // backslash injection
  EXPECT_FALSE(mayachain_isValidDenom(" cacao"));    // leading space
  EXPECT_FALSE(mayachain_isValidDenom("ca cao"));    // embedded space
}

/* ===================================================================== *
 *  mayachain_parseConfirmMemo — swap-memo clear-signing.
 *  Mirrors the thorchain.cpp memo tests; see kkconfirm_preload docs there.
 * ===================================================================== */

static bool parseMayaMemo(const char *memo, size_t size) {
  return mayachain_parseConfirmMemo(memo, size);
}
static bool parseMayaMemo(const char *memo) {
  return parseMayaMemo(memo, strlen(memo) + 1);
}

// Classic full-form swap memo = 4 screens (4th is the affiliate fee screen)
TEST(Mayachain, MemoSwapFullFormShowsAffiliate) {
  ASSERT_TRUE(kkconfirm_preload(4, 0));
  EXPECT_TRUE(parseMayaMemo(
      "SWAP:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:"
      "0x41e5560054824ea6b0732e656e3ad64e20e94e45:420:kk:75"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// No '.' in the asset field (no chain.asset pair): raw-memo fallback
TEST(Mayachain, MemoSwapNoChainAssetPair) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  EXPECT_FALSE(parseMayaMemo("=:e:0xdest:0/1/0:kk:75"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// Empty limit must NOT shift the affiliate into the limit slot: 4 screens
TEST(Mayachain, MemoSwapEmptyLimitDoesNotShift) {
  ASSERT_TRUE(kkconfirm_preload(4, 0));
  EXPECT_TRUE(parseMayaMemo("=:ETH.ETH:0xdest::kk:75"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// No affiliate: exactly the 3 historical screens
TEST(Mayachain, MemoSwapNoAffiliate) {
  ASSERT_TRUE(kkconfirm_preload(3, 0));
  EXPECT_TRUE(parseMayaMemo("SWAP:ETH.ETH:0xdest:420"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// ADD with a pool address: 2 screens (unchanged behavior)
TEST(Mayachain, MemoAddWithPool) {
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  EXPECT_TRUE(
      parseMayaMemo("ADD:BTC.BTC:maya1g9el7lzjwh9yun2c4jjzhy09j98vkhfxfqkl5k"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// WITHDRAW with basis points: 1 screen; without: malformed
TEST(Mayachain, MemoWithdraw) {
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_TRUE(parseMayaMemo("WITHDRAW:BTC.BTC:5000"));
  EXPECT_FALSE(parseMayaMemo("wd:BTC.BTC"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// Garbage / oversized memos fall back to raw-memo confirmation
TEST(Mayachain, MemoGarbageAndOversized) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  EXPECT_FALSE(parseMayaMemo("hello world"));
  EXPECT_FALSE(parseMayaMemo("SWAP:ETH.ETH:0xdest:420", 257));
  EXPECT_EQ(0, kkconfirm_drain());
}