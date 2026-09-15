extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/osmosis.h"
#include "keepkey/firmware/tendermint.h"
#include "messages-osmosis.pb.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"
}

#include "gtest/gtest.h"
#include <cstring>

static HDNode testNode(void) {
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
  return node;
}

TEST(Osmosis, MultiMessageSignTxSeparatesMsgsWithComma) {
  /* Regression for the missing comma between "msgs":[...] entries: before the
     has_message guard, two MsgSends serialized back-to-back ("}}{") and the
     user approved a signature over invalid JSON. The expected document below
     is constructed BY HAND -- independent of the serializer under test -- and
     signed with the same key, so the comparison fails if the serializer's
     bytes drift from the amino StdSignDoc in any way, comma included. */
  HDNode node = testNode();

  const OsmosisSignTx msg = {
      5,    {0x80000000 | 44, 0x80000000 | 118, 0x80000000, 0, 0},
      true, 251252,       // account_number
      true, "osmosis-1",  // chain_id
      true, 5000,         // fee_amount
      true, 300000,       // gas
      true, "",           // memo
      true, 4,            // sequence
      true, 2             // msg_count
  };
  ASSERT_TRUE(osmosis_signTxInit(&node, &msg));
  EXPECT_FALSE(osmosis_signingIsFinished());

  const char* const to = "osmo1g9el7lzjwh9yun2c4jjzhy09j98vkhfx8tzcpt";
  ASSERT_TRUE(osmosis_signTxUpdateMsgSend("100", to, "uosmo"));
  EXPECT_FALSE(osmosis_signingIsFinished());
  ASSERT_TRUE(osmosis_signTxUpdateMsgSend("42", to, "uosmo"));
  EXPECT_TRUE(osmosis_signingIsFinished());

  uint8_t public_key[33];
  uint8_t signature[64];
  ASSERT_TRUE(osmosis_signTxFinalize(public_key, signature));

  char from[46];
  ASSERT_TRUE(tendermint_getAddress(&node, "osmo", from));

  char doc[1024];
  int n = snprintf(
      doc, sizeof(doc),
      "{\"account_number\":\"251252\",\"chain_id\":\"osmosis-1\","
      "\"fee\":{\"amount\":[{\"amount\":\"5000\",\"denom\":\"uosmo\"}],"
      "\"gas\":\"300000\"},\"memo\":\"\",\"msgs\":["
      "{\"type\":\"cosmos-sdk/MsgSend\",\"value\":{\"amount\":[{\"amount\":"
      "\"100\",\"denom\":\"uosmo\"}],\"from_address\":\"%s\",\"to_address\":"
      "\"%s\"}},"
      "{\"type\":\"cosmos-sdk/MsgSend\",\"value\":{\"amount\":[{\"amount\":"
      "\"42\",\"denom\":\"uosmo\"}],\"from_address\":\"%s\",\"to_address\":"
      "\"%s\"}}"
      "],\"sequence\":\"4\"}",
      from, to, from, to);
  ASSERT_GT(n, 0);
  ASSERT_LT((size_t)n, sizeof(doc));

  uint8_t hash[SHA256_DIGEST_LENGTH];
  sha256_Raw((const uint8_t*)doc, (size_t)n, hash);
  uint8_t expected[64];
  ASSERT_EQ(0, ecdsa_sign_digest(&secp256k1, node.private_key, hash, expected,
                                 NULL, NULL));
  EXPECT_EQ(0, memcmp(signature, expected, 64));

  osmosis_signAbort();
}

TEST(Osmosis, ZeroOrOmittedMessagesFailInitialization) {
  HDNode node = testNode();

  OsmosisSignTx msg = {
      5,    {0x80000000 | 44, 0x80000000 | 118, 0x80000000, 0, 0},
      true, 251252,
      true, "osmosis-1",
      true, 5000,
      true, 300000,
      true, "",
      true, 4,
      true, 0  // msg_count
  };
  EXPECT_FALSE(osmosis_signTxInit(&node, &msg));
  EXPECT_FALSE(osmosis_signingIsInited());
  EXPECT_FALSE(osmosis_signingIsFinished());
  EXPECT_FALSE(osmosis_signTxUpdateMsgSend("1", "ignored", "uosmo"));

  msg.has_msg_count = false;
  msg.msg_count = 1;
  EXPECT_FALSE(osmosis_signTxInit(&node, &msg));
  EXPECT_FALSE(osmosis_signingIsInited());

  msg.has_msg_count = true;
  strcpy(msg.chain_id, "");
  EXPECT_FALSE(osmosis_signTxInit(&node, &msg));
  strcpy(msg.chain_id, "osmosis\n1");
  EXPECT_FALSE(osmosis_signTxInit(&node, &msg));
  strcpy(msg.chain_id, "osmosis-1");
  EXPECT_TRUE(osmosis_signTxInit(&node, &msg));
  osmosis_signAbort();
}

TEST(Osmosis, RequiredValuesRejectEmptyAndNonDecimalAmounts) {
  EXPECT_FALSE(osmosis_validate_required_text(false, "uosmo"));
  EXPECT_FALSE(osmosis_validate_required_text(true, ""));
  EXPECT_TRUE(osmosis_validate_required_text(true, "uosmo"));
  EXPECT_TRUE(osmosis_validate_required_text(true, "ibc/0123456789ABCDEF"));
  EXPECT_FALSE(osmosis_validate_required_text(true, "u osmo"));
  EXPECT_FALSE(osmosis_validate_required_text(true, "u\"osmo"));
  EXPECT_FALSE(osmosis_validate_required_text(true, "u\\osmo"));
  EXPECT_FALSE(osmosis_validate_required_text(true, "u\nosmo"));

  EXPECT_FALSE(osmosis_validate_amount(false, "1"));
  EXPECT_FALSE(osmosis_validate_amount(true, ""));
  EXPECT_FALSE(osmosis_validate_amount(true, "1.0"));
  EXPECT_FALSE(osmosis_validate_amount(true, "-1"));
  EXPECT_FALSE(osmosis_validate_amount(true, "1e6"));
  EXPECT_TRUE(osmosis_validate_amount(true, "0"));
  EXPECT_TRUE(osmosis_validate_amount(true, "1000000"));

  /* Noncanonical padding renders differently for the same value --
     "00000001" reaches the screen as "00.000001 OSMO" -- so one amount would
     have several spellings and the host would pick which one the owner sees. */
  EXPECT_FALSE(osmosis_validate_amount(true, "01"));
  EXPECT_FALSE(osmosis_validate_amount(true, "0000001"));
  EXPECT_FALSE(osmosis_validate_amount(true, "00000001"));
  EXPECT_FALSE(osmosis_validate_amount(true, "0001000000"));
  EXPECT_FALSE(osmosis_validate_amount(true, "00"));
}
