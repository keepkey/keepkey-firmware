extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/ton.h"
}

#include "gtest/gtest.h"

TEST(Ton, AddressScreenNamesTheNetworkForStandardPaths) {
  const uint32_t H = 0x80000000;
  char label[NODE_STRING_LENGTH];

  const uint32_t first[6] = {H | 44, H | 607, H | 0, H, H, H};
  ASSERT_TRUE(ton_pathLabel(label, sizeof(label), first, 6, false, 0));
  EXPECT_STREQ(label, "TON Account #0");

  const uint32_t second[6] = {H | 44, H | 607, H | 1, H, H, H};
  ASSERT_TRUE(ton_pathLabel(label, sizeof(label), second, 6, false, 0));
  EXPECT_STREQ(label, "TON Account #1");

  /* A testnet address must not be labelled as plain TON. */
  ASSERT_TRUE(ton_pathLabel(label, sizeof(label), first, 6, true, 0));
  EXPECT_STREQ(label, "TON Testnet Account #0");

  /* The widest label still fits the handler's buffer. */
  const uint32_t widest[6] = {H | 44, H | 607, H | 0x7fffffff, H, H, H};
  ASSERT_TRUE(ton_pathLabel(label, sizeof(label), widest, 6, true, 0));
  EXPECT_STREQ(label, "TON Testnet Account #2147483647");

  /* Everything else falls back to the BIP-32 path in the handler. */
  EXPECT_FALSE(ton_pathLabel(label, sizeof(label), first, 6, false, -1));
  const uint32_t two[2] = {H | 44, H | 607};
  EXPECT_FALSE(ton_pathLabel(label, sizeof(label), two, 2, false, 0));
  const uint32_t three[3] = {H | 44, H | 607, H | 0};
  EXPECT_FALSE(ton_pathLabel(label, sizeof(label), three, 3, false, 0));
  const uint32_t other_tail[6] = {H | 44, H | 607, H | 0, H, H | 1, H};
  EXPECT_FALSE(ton_pathLabel(label, sizeof(label), other_tail, 6, false, 0));
  const uint32_t unhardened_tail[6] = {H | 44, H | 607, H | 0, H, H, 0};
  EXPECT_FALSE(ton_pathLabel(label, sizeof(label), unhardened_tail, 6, false, 0));
  const uint32_t unhardened_account[6] = {H | 44, H | 607, 0, H, H, H};
  EXPECT_FALSE(ton_pathLabel(label, sizeof(label), unhardened_account, 6, false, 0));
  const uint32_t solana[6] = {H | 44, H | 501, H | 0, H, H, H};
  EXPECT_FALSE(ton_pathLabel(label, sizeof(label), solana, 6, false, 0));

  char tiny[8];
  EXPECT_FALSE(ton_pathLabel(tiny, sizeof(tiny), first, 6, false, 0));
  EXPECT_STREQ(tiny, "");
}
