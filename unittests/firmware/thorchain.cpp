extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/thorchain.h"
#include "keepkey/firmware/tendermint.h"
#include "trezor/crypto/secp256k1.h"
}

#include "gtest/gtest.h"
#include <cstring>

TEST(Thorchain, MemoWithEmbeddedNulIsNotParsed) {
  /* thorchain_parseConfirmMemo() copies an explicit byte count and then hands
     the buffer to strtok, which stops at the first NUL. A memo such as
     "=:ETH.ETH:<dest>:0\0:affiliate:75" is signed in FULL -- the EVM caller
     passes the true ABI length -- but parsing and confirmation stopped at the
     zero byte, so the affiliate suffix was never shown. */
  static const char kHiddenSuffix[] =
      "=:ETH.ETH:0x41e5560054824ea6b0732e656e3ad64e20e94e45:0\0:affiliate:75";
  EXPECT_EQ(
      THORCHAIN_MEMO_UNPARSED,
      thorchain_parseConfirmMemo(kHiddenSuffix, sizeof(kHiddenSuffix) - 1));

  /* A TRAILING NUL inside the declared length is refused too.

     An earlier fix exempted this case, reasoning that nothing is hidden behind
     bytes that are all zero. It was adopted to make two fixtures pass -- and
     those fixtures were wrong, declaring 59 bytes for a 58-byte memo. Relaxing
     firmware disclosure to satisfy a test is the one move this release's
     invariant forbids.

     It is also inconsistent: a length word that does not describe its own
     content is a non-canonical ABI encoding, which the offset-word validation
     already refuses. A declaration the device cannot trust does not become
     trustworthy because the bytes it misdescribes happen to be zero. */
  static const char kTrailingNul[] =
      "ADD:ETH.ETH:0xc5b2608927ea95ed43f842f553e3a27b09c050e8:420\0";
  EXPECT_EQ(THORCHAIN_MEMO_UNPARSED,
            thorchain_parseConfirmMemo(kTrailingNul, sizeof(kTrailingNul) - 1));

  /* The SAME memo with a truthful length parses normally. This is the control:
     it shows the rule rejects the misdeclaration, not the memo. */
  EXPECT_NE(THORCHAIN_MEMO_UNPARSED,
            thorchain_parseConfirmMemo(kTrailingNul, sizeof(kTrailingNul) - 2));
}

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
  EXPECT_EQ(std::string("thor1am058pdux3hyulcmfgj4m3hhrlfn8nzm88u80q"), addr);
}

TEST(Thorchain, ThorchainSignTx) {
  HDNode node = {
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
  hdnode_fill_public_key(&node);

  const ThorchainSignTx msg = {
      5,    {0x80000000 | 44, 0x80000000 | 931, 0x80000000, 0, 0},  // address_n
      true, 0,            // account_number
      true, "thorchain",  // chain_id
      true, 5000,         // fee_amount
      true, 200000,       // gas
      true, "",           // memo
      true, 0,            // sequence
      true, 1             // msg_count
  };
  ASSERT_TRUE(thorchain_signTxInit(&node, &msg));

  ASSERT_TRUE(thorchain_signTxUpdateMsgSend(
      100000, "thor18vhdczjut44gpsy804crfhnd5nq003nz0nf20v"));

  uint8_t public_key[33];
  uint8_t signature[64];

  ASSERT_TRUE(thorchain_signTxFinalize(public_key, signature));

  EXPECT_TRUE(
      memcmp(signature,
             (uint8_t *)"\x41\x99\x66\x30\x08\xef\xea\x75\x93\x56\x35\xe6\x1a"
                        "\x11\xdf\xa3\x3c\xeb\xeb\x91\xc1\xca\xed\xc6\x0e\x5e"
                        "\xef\x3c\xa2\xc0\x1f\x83\x48\x08\x36\xe6\x21\x89\x51"
                        "\x14\x36\x64\x7f\xac\x5a\xbd\xc2\x9f\x54\xae\x3d\x7e"
                        "\x47\x56\x43\xca\x33\xc7\xad\x2c\x8a\x53\x2b\x39",
             64) == 0);
}
