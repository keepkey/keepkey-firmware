extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/thorchain.h"
#include "keepkey/firmware/tendermint.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"
}

#include "gtest/gtest.h"
#include <cstring>

// Mirrors THORCHAIN_MEMO_MAX inside thorchain_parseConfirmMemo().
static const size_t THORCHAIN_MEMO_MAX_FOR_TEST = 256;

TEST(Thorchain, AmountFormattingCoversProtocolMaximumAndFailsClosed) {
  char max_asset[THORCHAIN_ASSET_SUFFIX_LEN] = {};
  std::memset(max_asset, 'A', sizeof(max_asset) - 1);

  char rendered[21 + THORCHAIN_ASSET_SUFFIX_LEN + 1];
  ASSERT_TRUE(thorchain_formatAmount(UINT64_MAX, max_asset, rendered,
                                     sizeof(rendered)));
  EXPECT_NE(std::string::npos, std::string(rendered).find(max_asset));

  char too_small[8];
  EXPECT_FALSE(thorchain_formatAmount(UINT64_MAX, max_asset, too_small,
                                      sizeof(too_small)));
  EXPECT_FALSE(thorchain_formatAmount(1, "", rendered, sizeof(rendered)));
  EXPECT_FALSE(
      thorchain_formatAmount(1, "ETH.ETH\n", rendered, sizeof(rendered)));
  EXPECT_FALSE(
      thorchain_formatAmount(1, "ETH.\"ETH", rendered, sizeof(rendered)));
}

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

  /* The SAME memo with a truthful length parses normally -- the control that
     shows the rule rejects the misdeclaration, not the memo. It cannot be
     asserted here: parsing succeeds, so the function goes on to draw confirm
     screens, and this binary has no canvas and nothing to answer them with.
     The control runs where a device can answer:
     python-keepkey
     tests/test_msg_thorchain_signtx.py::test_sign_eth_add_liquidity signs this
     exact memo declared at its truthful 58 bytes (ABI length word 0x3a). Same
     bytes, one byte less declared, opposite outcome.

     Everything below stays inside the unit harness because each case returns
     before any screen is drawn. */

  /* Over-long memos are refused rather than truncated. */
  static const char kOversize[THORCHAIN_MEMO_MAX_FOR_TEST + 1] = {'=', ':', 'E',
                                                                  'T'};
  EXPECT_EQ(THORCHAIN_MEMO_UNPARSED,
            thorchain_parseConfirmMemo(kOversize, sizeof(kOversize)));

  /* Fewer than three tokens is UNPARSED, not CANCELLED: nothing was shown, so
     the caller must still disclose the raw bytes itself. That distinction is
     the whole point of the tri-state return. */
  static const char kTooFewFields[] = "SWAP";
  EXPECT_EQ(
      THORCHAIN_MEMO_UNPARSED,
      thorchain_parseConfirmMemo(kTooFewFields, sizeof(kTooFewFields) - 1));

  /* A colon where the chain/asset dot belongs shifts every later field. The
     tokenizer splits on ":." interchangeably, so this yields the same three
     tokens as "SWAP:ETH.USDT:dest:limit" and would be reviewed as asset USDT
     on chain ETH -- while the protocol reads USDT as the DESTINATION. It has
     to reach the raw-byte path instead. */
  static const char kColonForDot[] = "SWAP:ETH:USDT:dest:limit";
  EXPECT_EQ(THORCHAIN_MEMO_UNPARSED,
            thorchain_parseConfirmMemo(kColonForDot, sizeof(kColonForDot) - 1));

  /* No dot at all is the same defect. */
  static const char kNoDot[] = "SWAP:ETH:dest";
  EXPECT_EQ(THORCHAIN_MEMO_UNPARSED,
            thorchain_parseConfirmMemo(kNoDot, sizeof(kNoDot) - 1));

  /* A second dot outside the chain/asset field is not this grammar either. */
  static const char kExtraDot[] = "SWAP:ETH.USDT:de.st:limit";
  EXPECT_EQ(THORCHAIN_MEMO_UNPARSED,
            thorchain_parseConfirmMemo(kExtraDot, sizeof(kExtraDot) - 1));
}

TEST(Thorchain, MemoWithEmptyPositionalFieldIsNotStructured) {
  /* `::` is meaningful in the live grammar: here it omits the limit before
     affiliate `t`. strtok() used to collapse it and show `t` as the limit.
     Until the structured parser preserves positions, this must take the raw
     UTXO path or be refused by the EVM caller. */
  static const char kEmptyLimit[] =
      "=:ETH.ETH:0x41e5560054824ea6b0732e656e3ad64e20e94e45::t:10";
  EXPECT_EQ(THORCHAIN_MEMO_UNPARSED,
            thorchain_parseConfirmMemo(kEmptyLimit, sizeof(kEmptyLimit) - 1));

  /* The current savers grammar also uses an explicitly empty field before
     affiliate data. It must never be compacted into different labels. */
  static const char kSaversAffiliate[] = "+:BTC/BTC::t:10";
  EXPECT_EQ(THORCHAIN_MEMO_UNPARSED,
            thorchain_parseConfirmMemo(kSaversAffiliate,
                                       sizeof(kSaversAffiliate) - 1));
}

TEST(Thorchain, StructuredMemoRequiresExactSafeTokensAndCanonicalBps) {
  static const char* const kUnparsed[] = {
      "SWAP-extra:ETH.ETH:destination:100",
      "swap:ETH.ETH:destination:100",
      "ADDITION:ETH.ETH:destination",
      "WITHDRAWAL:ETH.ETH:100",
      "WITHDRAW:ETH.ETH:01",
      "WITHDRAW:ETH.ETH:100x",
      "WITHDRAW:ETH.ETH:10001",
      "WITHDRAW:ETH.ETH:4294967296",
      "WITHDRAW:ETH.ETH:-1",
      "SWAP:ETH.ETH:destination with space:100",
      "SWAP:ETH.ETH:destination\nnext:100",
  };

  for (const char* memo : kUnparsed) {
    EXPECT_EQ(THORCHAIN_MEMO_UNPARSED,
              thorchain_parseConfirmMemo(memo, std::strlen(memo)))
        << memo;
  }

  static const char kNonAscii[] = "SWAP:ETH.ETH:dest\x80:100";
  EXPECT_EQ(THORCHAIN_MEMO_UNPARSED,
            thorchain_parseConfirmMemo(kNonAscii, sizeof(kNonAscii) - 1));
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
  /* This file was never in the build, so this vector was never checked. Its
     old expectation, "...fn8nzm88u80q", is 42 characters and fails its own
     bech32 checksum -- a 20-byte payload encodes to 43. The value below is
     bech32(hrp="thor", ripemd160(sha256(pubkey))) computed independently of
     this firmware; the device agrees with it. */
  EXPECT_EQ(std::string("thor1am058pdux3hyulcmfgj4m3hhrlfn8nzmpq9u6l"), addr);
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

  /* The old recipient, "thor18vhdczjut44gpsy804crfhnd5nq003nz0nf20v", is the
     well-known cosmos1 test address with its prefix hand-edited to "thor" and
     the cosmos checksum left behind. It fails bech32_decode(), so this call
     returned false and the test could never have passed -- which nobody
     noticed, because the file was not compiled. Same 20-byte payload,
     correct thor checksum. */
  ASSERT_TRUE(thorchain_signTxUpdateMsgSend(
      100000, "thor18vhdczjut44gpsy804crfhnd5nq003nzf5s36n"));

  uint8_t public_key[33];
  uint8_t signature[64];

  ASSERT_TRUE(thorchain_signTxFinalize(public_key, signature));

  /* Recomputed for the corrected recipient, and independently of this
     firmware: SHA256 of the amino StdSignDoc
     {"account_number":"0","chain_id":"thorchain","fee":{...,"denom":"rune"}],
      "gas":"200000"},"memo":"","msgs":[{"type":"thorchain/MsgSend",...}],
      "sequence":"0"}
     signed with RFC6979-deterministic secp256k1 and low-S normalised. The
     device produces the same 64 bytes. */
  EXPECT_TRUE(
      memcmp(signature,
             (uint8_t*)"\xbd\x32\x29\xe7\xf5\x31\xdb\x80\xc2\x74\xff\xc5\xfc"
                       "\x6f\x43\xbf\x0f\xbc\xf9\x93\x4c\xca\x60\x3b\x40\xd6"
                       "\x58\x3a\x7b\xb2\x75\xac\x51\xe9\xbe\xf7\x6f\xed\x97"
                       "\xab\x1a\x73\x1e\xc8\x7e\x40\x53\x15\xac\xa1\x1c\x92"
                       "\x34\x6c\xef\xee\x16\x01\x35\x0f\x80\x3b\x3e\x5b",
             64) == 0);
}

TEST(Thorchain, MultiMessageSignTxSeparatesMsgsWithComma) {
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
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      &secp256k1_info};
  hdnode_fill_public_key(&node);

  const ThorchainSignTx msg = {
      5,    {0x80000000 | 44, 0x80000000 | 931, 0x80000000, 0, 0},
      true, 0,
      true, "thorchain",
      true, 5000,
      true, 200000,
      true, "",
      true, 0,
      true, 2};
  ASSERT_TRUE(thorchain_signTxInit(&node, &msg));

  const char* const to = "thor18vhdczjut44gpsy804crfhnd5nq003nzf5s36n";
  ASSERT_TRUE(thorchain_signTxUpdateMsgSend(100000, to));
  ASSERT_TRUE(thorchain_signTxUpdateMsgSend(42, to));
  ASSERT_TRUE(thorchain_signingIsFinished());

  uint8_t public_key[33];
  uint8_t signature[64];
  ASSERT_TRUE(thorchain_signTxFinalize(public_key, signature));

  char from[46];
  ASSERT_TRUE(tendermint_getAddress(&node, "thor", from));
  char doc[1024];
  const int n = snprintf(
      doc, sizeof(doc),
      "{\"account_number\":\"0\",\"chain_id\":\"thorchain\","
      "\"fee\":{\"amount\":[{\"amount\":\"5000\",\"denom\":\"rune\"}],"
      "\"gas\":\"200000\"},\"memo\":\"\",\"msgs\":["
      "{\"type\":\"thorchain/MsgSend\",\"value\":{\"amount\":[{\"amount\":"
      "\"100000\",\"denom\":\"rune\"}],\"from_address\":\"%s\","
      "\"to_address\":\"%s\"}},"
      "{\"type\":\"thorchain/MsgSend\",\"value\":{\"amount\":[{\"amount\":"
      "\"42\",\"denom\":\"rune\"}],\"from_address\":\"%s\","
      "\"to_address\":\"%s\"}}],\"sequence\":\"0\"}",
      from, to, from, to);
  ASSERT_GT(n, 0);
  ASSERT_LT((size_t)n, sizeof(doc));

  uint8_t hash[SHA256_DIGEST_LENGTH];
  sha256_Raw((const uint8_t*)doc, (size_t)n, hash);
  uint8_t expected[64];
  ASSERT_EQ(0, ecdsa_sign_digest(&secp256k1, node.private_key, hash, expected,
                                 nullptr, nullptr));
  EXPECT_EQ(0, memcmp(signature, expected, sizeof(expected)));
  thorchain_signAbort();
}

TEST(Thorchain, ZeroOrOmittedMessagesFailInitialization) {
  HDNode node = {};
  ThorchainSignTx msg = {0,    {}, true, 0,  true, "thorchain", true, 0,
                         true, 0,  true, "", true, 0,           true, 0};
  EXPECT_FALSE(thorchain_signTxInit(&node, &msg));
  EXPECT_FALSE(thorchain_signingIsInited());
  EXPECT_FALSE(thorchain_signingIsFinished());
  EXPECT_FALSE(thorchain_signTxUpdateMsgSend(1, "ignored"));

  msg.has_msg_count = false;
  msg.msg_count = 1;
  EXPECT_FALSE(thorchain_signTxInit(&node, &msg));
  EXPECT_FALSE(thorchain_signingIsInited());

  msg.has_msg_count = true;
  strcpy(msg.chain_id, "");
  EXPECT_FALSE(thorchain_signTxInit(&node, &msg));
  strcpy(msg.chain_id, "thor\nchain");
  EXPECT_FALSE(thorchain_signTxInit(&node, &msg));
}

TEST(Thorchain, DepositAssetAndSignerFailClosed) {
  HDNode node = {};
  node.curve = &secp256k1_info;
  ThorchainSignTx msg = {};
  msg.has_chain_id = true;
  strcpy(msg.chain_id, "thorchain");
  msg.has_msg_count = true;
  msg.msg_count = 1;
  ASSERT_TRUE(thorchain_signTxInit(&node, &msg));

  ThorchainMsgDeposit deposit = {};
  deposit.has_asset = true;
  strcpy(deposit.asset, "ETH.\"ETH");
  deposit.has_signer = true;
  strcpy(deposit.signer, "thor18vhdczjut44gpsy804crfhnd5nq003nzf5s36n");
  EXPECT_FALSE(thorchain_signTxUpdateMsgDeposit(&deposit));

  strcpy(deposit.asset, "ETH.ETH");
  strcpy(deposit.signer, "cosmos18vhdczjut44gpsy804crfhnd5nq003nz0nf20v");
  EXPECT_FALSE(thorchain_signTxUpdateMsgDeposit(&deposit));

  strcpy(deposit.signer, "thor18vhdczjut44gpsy804crfhnd5nq003nzf5s36n");
  EXPECT_TRUE(thorchain_signTxUpdateMsgDeposit(&deposit));
  EXPECT_TRUE(thorchain_signingIsFinished());
  thorchain_signAbort();
}
