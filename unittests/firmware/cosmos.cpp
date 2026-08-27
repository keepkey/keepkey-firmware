extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/cosmos.h"
#include "keepkey/firmware/signtx_tendermint.h"
#include "keepkey/firmware/tendermint.h"
#include "messages-tendermint.pb.h"
#include "trezor/crypto/secp256k1.h"
}

#include "gtest/gtest.h"
#include <cstring>

TEST(Cosmos, HostTextMustBeSafeForJsonAndDisplay) {
  EXPECT_FALSE(tendermint_validateSafeText(nullptr));
  EXPECT_FALSE(tendermint_validateSafeText(""));
  EXPECT_FALSE(tendermint_validateSafeText("chain id"));
  EXPECT_FALSE(tendermint_validateSafeText("chain\nname"));
  EXPECT_FALSE(tendermint_validateSafeText("chain\"name"));
  EXPECT_FALSE(tendermint_validateSafeText("chain\\name"));
  EXPECT_TRUE(tendermint_validateSafeText("cosmoshub-4"));
  EXPECT_TRUE(tendermint_validateSafeText("ibc/ABC.DEF_123"));

  EXPECT_TRUE(tendermint_validateBech32Address(
      "cosmos18vhdczjut44gpsy804crfhnd5nq003nz0nf20v", "cosmos"));
  EXPECT_FALSE(tendermint_validateBech32Address(
      "cosmos18vhdczjut44gpsy804crfhnd5nq003nz0nf20v", "thor"));
}

TEST(Cosmos, CosmosGetAddress) {
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
  ASSERT_TRUE(tendermint_getAddress(&node, "cosmos", addr));
  EXPECT_EQ(std::string("cosmos1am058pdux3hyulcmfgj4m3hhrlfn8nzm88u80q"), addr);
}

TEST(Cosmos, CosmosSignTx) {
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

  const CosmosSignTx msg = {
      5,    {0x80000000 | 44, 0x80000000 | 118, 0x80000000, 0, 0},  // address_n
      true, 0,              // account_number
      true, "cosmoshub-2",  // chain_id
      true, 5000,           // fee_amount
      true, 200000,         // gas
      true, "",             // memo
      true, 0,              // sequence
      true, 1               // msg_count
  };
  ASSERT_TRUE(tendermint_signTxInit(&node, &msg, sizeof(CosmosSignTx), "uatom",
                                    TENDERMINT_SIGNING_COSMOS));
  EXPECT_TRUE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));
  EXPECT_FALSE(tendermint_signingIsInited(TENDERMINT_SIGNING_GENERIC));

  ASSERT_TRUE(tendermint_signTxUpdateMsgSend(
      100000, "cosmos18vhdczjut44gpsy804crfhnd5nq003nz0nf20v", "cosmos",
      "uatom", "cosmos-sdk"));

  uint8_t public_key[33];
  uint8_t signature[64];
  ASSERT_TRUE(tendermint_signTxFinalize(public_key, signature));

  EXPECT_TRUE(
      memcmp(signature,
             (uint8_t*)"\x41\x99\x66\x30\x08\xef\xea\x75\x93\x56\x35\xe6\x1a"
                       "\x11\xdf\xa3\x3c\xeb\xeb\x91\xc1\xca\xed\xc6\x0e\x5e"
                       "\xef\x3c\xa2\xc0\x1f\x83\x48\x08\x36\xe6\x21\x89\x51"
                       "\x14\x36\x64\x7f\xac\x5a\xbd\xc2\x9f\x54\xae\x3d\x7e"
                       "\x47\x56\x43\xca\x33\xc7\xad\x2c\x8a\x53\x2b\x39",
             64) == 0);
}

TEST(Cosmos, TendermintSessionBindsProtocolAndAssetConfiguration) {
  HDNode node = {};
  node.curve = &secp256k1_info;
  TendermintSignTx msg = {};
  msg.has_account_number = true;
  msg.has_chain_id = true;
  strcpy(msg.chain_id, "chain-1");
  msg.has_fee_amount = true;
  msg.fee_amount = 1;
  msg.has_gas = true;
  msg.gas = 1;
  msg.has_sequence = true;
  msg.has_msg_count = true;
  msg.msg_count = 1;
  msg.has_chain_name = true;
  strcpy(msg.chain_name, "Cosmos");
  msg.has_denom = true;
  strcpy(msg.denom, "uatom");
  msg.has_message_type_prefix = true;
  strcpy(msg.message_type_prefix, "cosmos-sdk");

  ASSERT_TRUE(tendermint_signTxInit(&node, &msg, sizeof(msg), msg.denom,
                                    TENDERMINT_SIGNING_GENERIC));
  EXPECT_TRUE(tendermint_signingIsInited(TENDERMINT_SIGNING_GENERIC));
  EXPECT_FALSE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));
  EXPECT_TRUE(tendermint_signingConfigMatches("Cosmos", "uatom", "cosmos-sdk"));
  EXPECT_FALSE(
      tendermint_signingConfigMatches("Cosmos", "uosmo", "cosmos-sdk"));
  EXPECT_FALSE(
      tendermint_signingConfigMatches("Osmosis", "uatom", "cosmos-sdk"));
  EXPECT_FALSE(
      tendermint_signingConfigMatches("Cosmos", "uatom", "other-prefix"));
  tendermint_signAbort();
}

TEST(Cosmos, TendermintSessionRejectsUnsafeEnvelopeConfiguration) {
  HDNode node = {};
  node.curve = &secp256k1_info;
  TendermintSignTx msg = {};
  msg.has_chain_id = true;
  strcpy(msg.chain_id, "chain-1");
  msg.has_msg_count = true;
  msg.msg_count = 1;
  msg.has_chain_name = true;
  strcpy(msg.chain_name, "Cosmos");
  msg.has_denom = true;
  strcpy(msg.denom, "uatom");
  msg.has_message_type_prefix = true;
  strcpy(msg.message_type_prefix, "cosmos-sdk");

  strcpy(msg.chain_id, "");
  EXPECT_FALSE(tendermint_signTxInit(&node, &msg, sizeof(msg), msg.denom,
                                     TENDERMINT_SIGNING_GENERIC));
  strcpy(msg.chain_id, "chain\n1");
  EXPECT_FALSE(tendermint_signTxInit(&node, &msg, sizeof(msg), msg.denom,
                                     TENDERMINT_SIGNING_GENERIC));
  strcpy(msg.chain_id, "chain-1");
  strcpy(msg.denom, "u\"atom");
  EXPECT_FALSE(tendermint_signTxInit(&node, &msg, sizeof(msg), msg.denom,
                                     TENDERMINT_SIGNING_GENERIC));
  strcpy(msg.denom, "uatom");
  strcpy(msg.message_type_prefix, "cosmos\\sdk");
  EXPECT_FALSE(tendermint_signTxInit(&node, &msg, sizeof(msg), msg.denom,
                                     TENDERMINT_SIGNING_GENERIC));
}
