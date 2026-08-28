extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/mayachain.h"
#include "keepkey/firmware/tendermint.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"
}

#include "gtest/gtest.h"
#include <cstring>

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

  /* A second dot outside the chain/asset field is not this grammar either. */
  static const char kExtraDot[] = "SWAP:ETH.USDT:de.st:limit";
  EXPECT_EQ(MAYACHAIN_MEMO_UNPARSED,
            mayachain_parseConfirmMemo(kExtraDot, sizeof(kExtraDot) - 1));
}

TEST(Mayachain, MemoWithEmptyPositionalFieldIsNotStructured) {
  static const char kEmptyLimit[] =
      "=:ETH.ETH:0x41e5560054824ea6b0732e656e3ad64e20e94e45::affiliate:75";
  EXPECT_EQ(MAYACHAIN_MEMO_UNPARSED,
            mayachain_parseConfirmMemo(kEmptyLimit, sizeof(kEmptyLimit) - 1));
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

  /* "cacao" is the denomination this vector was recorded with: the third
     parameter was added by 50164a2ee, which replaced a hardcoded "cacao" in
     the JSON with a caller-supplied denom. Passing it reproduces the exact
     bytes the expected signature below was computed over. */
  ASSERT_TRUE(mayachain_signTxUpdateMsgSend(
      100, "maya1g9el7lzjwh9yun2c4jjzhy09j98vkhfxfqkl5k", "cacao"));

  uint8_t public_key[33];
  uint8_t signature[64];

  ASSERT_TRUE(mayachain_signTxFinalize(public_key, signature));

  /* This file was never in the build, so this vector was never checked and it
     does not match. Recomputed independently of this firmware: SHA256 of the
     amino StdSignDoc
     {"account_number":"6359","chain_id":"mayachain-mainnet-v1",
      "fee":{"amount":[{"amount":"3000","denom":"cacao"}],"gas":"200000"},
      "memo":"","msgs":[{"type":"mayachain/MsgSend","value":{"amount":
      [{"amount":"100","denom":"cacao"}],"from_address":"maya1ls33...",
      "to_address":"maya1g9el..."}}],"sequence":"19"}
     signed with RFC6979-deterministic secp256k1 and low-S normalised. The
     device produces the same 64 bytes. */
  EXPECT_TRUE(
      memcmp(signature,
             (uint8_t*)"\xdf\x2f\x66\x37\x03\x08\x32\xd2\xce\x87\xfe\x47\x8d"
                       "\xdf\xe6\xd8\x21\xd2\x6b\x03\x8b\x44\xfa\xc8\x98\xe6"
                       "\xdf\x79\xe3\xfd\x10\x5d\x40\x3f\x05\x0d\x00\xad\xf9"
                       "\x7d\x3e\xd3\xa7\x3d\xa6\x9b\x19\x74\x0c\x6a\xbc\xf6"
                       "\x94\x09\x57\x29\xa3\xf0\xc3\x62\xc9\xf0\xfa\x71",
             64) == 0);
}

TEST(Mayachain, LongestValidDenomSerializes) {
  /* The amount/denom segment is the longest thing
     mayachain_signTxUpdateMsgSend() formats, and its scratch buffer used to be
     65 bytes against a documented 124-byte maximum. tendermint_snprintf() fails
     closed, so nothing was mis-signed -- but the refusal came after the
     confirmation screen had already been approved. A denomination at the
     protocol maximum must serialize, not fail late. */
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

  /* 68 visible characters: MayachainMsgSend.denom's max_size of 69 less NUL. */
  char denom[69];
  std::memset(denom, 'a', 68);
  denom[68] = '\0';
  ASSERT_EQ(68u, std::strlen(denom));

  /* A uint64 at its widest, so the segment is at its documented maximum. */
  EXPECT_TRUE(mayachain_signTxUpdateMsgSend(
      18446744073709551615ULL, "maya1g9el7lzjwh9yun2c4jjzhy09j98vkhfxfqkl5k",
      denom));
}

TEST(Mayachain, MultiMessageSignTxSeparatesMsgsWithComma) {
  /* Regression for the missing comma between "msgs":[...] entries: before the
     has_message guard, two MsgSends serialized back-to-back ("}}{") and the
     user approved a signature over invalid JSON. The expected document below
     is constructed BY HAND in this test -- independent of the serializer under
     test -- and signed with the same key, so the comparison fails if the
     serializer's bytes drift from the amino StdSignDoc in any way, comma
     included. */
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
      true, 6359,                    // account_number
      true, "mayachain-mainnet-v1",  // chain_id
      true, 3000,                    // fee_amount
      true, 200000,                  // gas
      true, "",                      // memo
      true, 19,                      // sequence
      true, 2                        // msg_count
  };
  ASSERT_TRUE(mayachain_signTxInit(&node, &msg));
  EXPECT_FALSE(mayachain_signingIsFinished());

  const char* const to = "maya1g9el7lzjwh9yun2c4jjzhy09j98vkhfxfqkl5k";
  ASSERT_TRUE(mayachain_signTxUpdateMsgSend(100, to, "cacao"));
  EXPECT_FALSE(mayachain_signingIsFinished());
  ASSERT_TRUE(mayachain_signTxUpdateMsgSend(42, to, "cacao"));
  EXPECT_TRUE(mayachain_signingIsFinished());

  uint8_t public_key[33];
  uint8_t signature[64];
  ASSERT_TRUE(mayachain_signTxFinalize(public_key, signature));

  char from[46];
  ASSERT_TRUE(tendermint_getAddress(&node, "maya", from));

  char doc[1024];
  int n = snprintf(
      doc, sizeof(doc),
      "{\"account_number\":\"6359\",\"chain_id\":\"mayachain-mainnet-v1\","
      "\"fee\":{\"amount\":[{\"amount\":\"3000\",\"denom\":\"cacao\"}],"
      "\"gas\":\"200000\"},\"memo\":\"\",\"msgs\":["
      "{\"type\":\"mayachain/MsgSend\",\"value\":{\"amount\":[{\"amount\":"
      "\"100\",\"denom\":\"cacao\"}],\"from_address\":\"%s\",\"to_address\":"
      "\"%s\"}},"
      "{\"type\":\"mayachain/MsgSend\",\"value\":{\"amount\":[{\"amount\":"
      "\"42\",\"denom\":\"cacao\"}],\"from_address\":\"%s\",\"to_address\":"
      "\"%s\"}}"
      "],\"sequence\":\"19\"}",
      from, to, from, to);
  ASSERT_GT(n, 0);
  ASSERT_LT((size_t)n, sizeof(doc));

  uint8_t hash[SHA256_DIGEST_LENGTH];
  sha256_Raw((const uint8_t*)doc, (size_t)n, hash);
  uint8_t expected[64];
  ASSERT_EQ(0, ecdsa_sign_digest(&secp256k1, node.private_key, hash, expected,
                                 NULL, NULL));
  EXPECT_EQ(0, memcmp(signature, expected, 64));

  mayachain_signAbort();
}

TEST(Mayachain, ZeroOrOmittedMessagesFailInitialization) {
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

  MayachainSignTx msg = {
      5,    {0x80000000 | 44, 0x80000000 | 931, 0x80000000, 0, 0},
      true, 6359,
      true, "mayachain-mainnet-v1",
      true, 3000,
      true, 200000,
      true, "",
      true, 19,
      true, 0  // msg_count
  };
  EXPECT_FALSE(mayachain_signTxInit(&node, &msg));
  EXPECT_FALSE(mayachain_signingIsInited());
  EXPECT_FALSE(mayachain_signingIsFinished());
  EXPECT_FALSE(mayachain_signTxUpdateMsgSend(1, "ignored", "cacao"));

  msg.has_msg_count = false;
  msg.msg_count = 1;
  EXPECT_FALSE(mayachain_signTxInit(&node, &msg));
  EXPECT_FALSE(mayachain_signingIsInited());

  msg.has_msg_count = true;
  strcpy(msg.chain_id, "");
  EXPECT_FALSE(mayachain_signTxInit(&node, &msg));
  strcpy(msg.chain_id, "maya\nchain");
  EXPECT_FALSE(mayachain_signTxInit(&node, &msg));
}

TEST(Mayachain, DepositAssetAndSignerFailClosed) {
  HDNode node = {};
  node.curve = &secp256k1_info;
  MayachainSignTx msg = {};
  msg.has_chain_id = true;
  strcpy(msg.chain_id, "mayachain");
  msg.has_msg_count = true;
  msg.msg_count = 1;
  ASSERT_TRUE(mayachain_signTxInit(&node, &msg));

  MayachainMsgDeposit deposit = {};
  deposit.has_asset = true;
  strcpy(deposit.asset, "ETH.ETH\n");
  deposit.has_signer = true;
  strcpy(deposit.signer, "maya1g9el7lzjwh9yun2c4jjzhy09j98vkhfxfqkl5k");
  EXPECT_FALSE(mayachain_signTxUpdateMsgDeposit(&deposit));

  strcpy(deposit.asset, "ETH.ETH");
  strcpy(deposit.signer, "thor18vhdczjut44gpsy804crfhnd5nq003nzf5s36n");
  EXPECT_FALSE(mayachain_signTxUpdateMsgDeposit(&deposit));

  strcpy(deposit.signer, "maya1g9el7lzjwh9yun2c4jjzhy09j98vkhfxfqkl5k");
  EXPECT_TRUE(mayachain_signTxUpdateMsgDeposit(&deposit));
  EXPECT_TRUE(mayachain_signingIsFinished());
  mayachain_signAbort();
}
