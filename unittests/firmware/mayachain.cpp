extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/mayachain.h"
#include "keepkey/firmware/tendermint.h"
#include "trezor/crypto/secp256k1.h"
}

#include "gtest/gtest.h"
#include <cstring>
#include <string>

// confirm() auto-accept driver, defined in thorchain.cpp (same binary).
// kkconfirm_preload(nYes, nNo) queues nYes accepted confirm screens then
// nNo rejected ones; kkconfirm_drain() == 0 proves the exact screen count.
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

TEST(Mayachain, FormatsOnlyCacaoWithTenDecimals) {
  char rendered[96];

  ASSERT_TRUE(mayachain_formatAmount(10000000000ULL, "cacao", rendered,
                                     sizeof(rendered)));
  EXPECT_STREQ("1 cacao", rendered);

  ASSERT_TRUE(mayachain_formatAmount(10000000000ULL, "maya", rendered,
                                     sizeof(rendered)));
  EXPECT_STREQ("10000000000 maya", rendered);

  ASSERT_TRUE(
      mayachain_formatAmount(1, "future-denom", rendered, sizeof(rendered)));
  EXPECT_STREQ("1 future-denom", rendered);
  EXPECT_FALSE(mayachain_formatAmount(1, "", rendered, sizeof(rendered)));
  EXPECT_FALSE(
      mayachain_formatAmount(1, "ETH.ETH\n", rendered, sizeof(rendered)));
  EXPECT_FALSE(
      mayachain_formatAmount(1, "ETH.\\ETH", rendered, sizeof(rendered)));
}

TEST(Mayachain, MemoWithMisdeclaredLengthIsRefused) {
  /* What this covers, stated exactly, because the THORChain wording does not
     transfer: on Maya an embedded NUL hides nothing today. Both call sites
     pass strnlen() (fsm_msg_mayachain.h) and the signer hashes strlen(memo)
     (mayachain.c), so parsing and signing already stop at the same byte and
     nothing past a zero is signed. THORChain differs because two of its
     callers pass an externally declared length -- a BTC OP_RETURN script
     length and an ABI length word -- and there the suffix really was signed
     unseen; that case is covered in thorchain.cpp.

     So this asserts the narrower property Maya actually has: a declared length
     that does not describe its own content is refused rather than
     clear-signed, and the parser stays safe by construction if Maya ever gains
     a length-passing caller of its own. */
  static const char kEmbeddedNul[] =
      "=:ETH.ETH:0x41e5560054824ea6b0732e656e3ad64e20e94e45:0\0:affiliate:75";
  EXPECT_EQ(MAYACHAIN_MEMO_UNPARSED,
            mayachain_parseConfirmMemo(kEmbeddedNul, sizeof(kEmbeddedNul) - 1));

  /* A TRAILING NUL inside the declared length is refused on the same grounds:
     the length still misdescribes its content, and the caller's UNPARSED path
     discloses the raw bytes anyway. */
  static const char kTrailingNul[] =
      "ADD:ETH.ETH:0xc5b2608927ea95ed43f842f553e3a27b09c050e8:420\0";
  EXPECT_EQ(MAYACHAIN_MEMO_UNPARSED,
            mayachain_parseConfirmMemo(kTrailingNul, sizeof(kTrailingNul) - 1));

  /* Over-long memos are refused rather than truncated. memoBuf is 256 bytes
     and the copy needs room for the terminator the memzero'd tail supplies. */
  static const char kOversize[257] = {'=', ':', 'E', 'T', 'H'};
  EXPECT_EQ(MAYACHAIN_MEMO_UNPARSED,
            mayachain_parseConfirmMemo(kOversize, sizeof(kOversize)));

  /* A memo whose first three fields are missing is UNPARSED, not CANCELLED:
     nothing was shown, so the caller must still disclose the raw bytes. This
     is the distinction the bool return could not express. */
  static const char kTooFewFields[] = "SWAP";
  EXPECT_EQ(
      MAYACHAIN_MEMO_UNPARSED,
      mayachain_parseConfirmMemo(kTooFewFields, sizeof(kTooFewFields) - 1));

  /* A colon where the chain/asset dot belongs shifts every later field. The
     tokenizer splits on ":." interchangeably, so this yields the same three
     tokens as "SWAP:ETH.USDT:dest:limit" and would be reviewed as asset USDT
     on chain ETH -- while the protocol reads USDT as the DESTINATION. It has
     to reach the raw-byte path instead. */
  static const char kColonForDot[] = "SWAP:ETH:USDT:dest:limit";
  EXPECT_EQ(MAYACHAIN_MEMO_UNPARSED,
            mayachain_parseConfirmMemo(kColonForDot, sizeof(kColonForDot) - 1));

  /* No dot at all is the same defect. */
  static const char kNoDot[] = "SWAP:ETH:dest";
  EXPECT_EQ(MAYACHAIN_MEMO_UNPARSED,
            mayachain_parseConfirmMemo(kNoDot, sizeof(kNoDot) - 1));
}

TEST(Mayachain, StructuredMemoRequiresExactSafeTokensAndCanonicalBps) {
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
    EXPECT_EQ(MAYACHAIN_MEMO_UNPARSED,
              mayachain_parseConfirmMemo(memo, std::strlen(memo)))
        << memo;
  }

  static const char kNonAscii[] = "SWAP:ETH.ETH:dest\x80:100";
  EXPECT_EQ(MAYACHAIN_MEMO_UNPARSED,
            mayachain_parseConfirmMemo(kNonAscii, sizeof(kNonAscii) - 1));
}

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
             (uint8_t*)"\xdf\x2f\x66\x37\x03\x08\x32\xd2\xce\x87\xfe\x47\x8d"
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

  EXPECT_FALSE(mayachain_isValidDenom(""));          // empty → caller "cacao"
  EXPECT_FALSE(mayachain_isValidDenom("CACAO"));     // uppercase rejected
  EXPECT_FALSE(mayachain_isValidDenom("cacao\""));   // quote injection
  EXPECT_FALSE(mayachain_isValidDenom("cacao\\n"));  // backslash injection
  EXPECT_FALSE(mayachain_isValidDenom(" cacao"));    // leading space
  EXPECT_FALSE(mayachain_isValidDenom("ca cao"));    // embedded space
}

// The signer function itself must reject an invalid denom — not merely
// rely on the FSM caller to pre-validate — so it stays safe if reused or
// called directly. Empty denom must still default to "cacao" and succeed.
TEST(Mayachain, MayachainSignTxUpdateMsgSendRejectsInvalidDenom) {
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
      5,    {0x80000000 | 44, 0x80000000 | 931, 0x80000000, 0, 0},
      true, 6359,
      true, "mayachain-mainnet-v1",
      true, 3000,
      true, 200000,
      true, "",
      true, 19,
      true, 1};

  ASSERT_TRUE(mayachain_signTxInit(&node, &msg));
  EXPECT_FALSE(mayachain_signTxUpdateMsgSend(
      100, "maya1g9el7lzjwh9yun2c4jjzhy09j98vkhfxfqkl5k", "cacao\""));

  ASSERT_TRUE(mayachain_signTxInit(&node, &msg));
  EXPECT_TRUE(mayachain_signTxUpdateMsgSend(
      100, "maya1g9el7lzjwh9yun2c4jjzhy09j98vkhfxfqkl5k", ""));
}

/* ===================================================================== *
 *  mayachain_parseConfirmMemo — swap-memo clear-signing.
 *  Mirrors the thorchain.cpp memo tests; see kkconfirm_preload docs there.
 * ===================================================================== */

static bool parseMayaMemo(const char* memo, size_t size) {
  return mayachain_parseConfirmMemo(memo, size) == MAYACHAIN_MEMO_CONFIRMED;
}
/* strlen(memo), NOT strlen(memo) + 1 -- see the same note in thorchain.cpp.
 * Maya inherited THORChain's memo grammar and its canonical-length refusal. */
static bool parseMayaMemo(const char* memo) {
  return parseMayaMemo(memo, strlen(memo));
}

// Classic full-form swap memo = 4 screens (4th is the affiliate fee screen),
// but the asset screen is 4 rows against a 3-row body, so it pages into
// 1/2 + 2/2 = 5 presses. See thorchain.cpp for the same memo.
TEST(Mayachain, MemoSwapFullFormShowsAffiliate) {
  ASSERT_TRUE(kkconfirm_preload(5, 0));
  EXPECT_TRUE(
      parseMayaMemo("SWAP:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:"
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
// BTC OP_RETURN passes RAW memo bytes with no NUL and size = byte count.
// Every byte must survive the copy — the historical off-by-one dropped
// the last char (1-char affiliate vanished: 3 screens instead of 4).
TEST(Mayachain, MemoRawBytesNoNulKeepsLastChar) {
  ASSERT_TRUE(kkconfirm_preload(4, 0));
  const char raw[] = "=:ETH.ETH:0xdest:420:k";
  EXPECT_TRUE(parseMayaMemo(raw, sizeof(raw) - 1)); /* no NUL counted */
  EXPECT_EQ(0, kkconfirm_drain());
}

// A raw memo that fills the internal buffer's entire documented capacity
// (size == 256, the parser's own <=256 contract) must ALSO keep its last
// byte — this is the boundary the copy-length clamp missed.
TEST(Mayachain, MemoExactBufferCapacityKeepsLastChar) {
  const std::string prefix = "=:ETH.ETH:0x";
  const std::string suffix = ":420:k";  // 1-char affiliate as the last byte
  std::string memo =
      prefix + std::string(256 - prefix.size() - suffix.size(), 'd') + suffix;
  ASSERT_EQ(memo.size(), 256u);

  /* 6 presses, not 4: the 240-char destination needs 8 rows, so its screen
   * pages 3 ways (1 + 3 + 1 + 1). Every byte of the memo reaches the screen. */
  ASSERT_TRUE(kkconfirm_preload(6, 0));
  EXPECT_TRUE(parseMayaMemo(memo.c_str(), memo.size())); /* no NUL counted */
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(Mayachain, MemoGarbageAndOversized) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  EXPECT_FALSE(parseMayaMemo("hello world"));
  EXPECT_FALSE(parseMayaMemo("SWAP:ETH.ETH:0xdest:420", 257));
  EXPECT_EQ(0, kkconfirm_drain());
}
