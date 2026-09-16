#include "gtest/gtest.h"

#include <algorithm>
#include <cstring>
#include <vector>

extern "C" {
#include "keepkey/board/confirm_sm.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/transaction.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/txin_check.h"
}

bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

TEST(Transaction, TaprootInputWeightIncludesWitness) {
  CoinType coin = CoinType_init_zero;
  TxInputType input = TxInputType_init_zero;
  input.script_type = InputScriptType_SPENDTAPROOT;

  // 41 non-witness bytes * 4 plus a one-item witness containing the fixed
  // 64-byte SIGHASH_DEFAULT Schnorr signature.
  ASSERT_EQ(230U, tx_input_weight(&coin, &input));
}

TEST(Transaction, MultisigQuorumRejectsUnsatisfiableScripts) {
  MultisigRedeemScriptType multisig = MultisigRedeemScriptType_init_zero;
  CoinType coin = CoinType_init_zero;
  uint8_t output[512] = {0};
  uint8_t hash[32] = {0};

  multisig.has_m = true;
  multisig.m = 2;
  multisig.pubkeys_count = 1;
  EXPECT_FALSE(transaction_multisig_quorum_is_valid(&multisig));
  EXPECT_EQ(compile_script_multisig(&coin, &multisig, output), 0U);
  EXPECT_EQ(compile_script_multisig_hash(&coin, &multisig, hash), 0U);

  multisig.m = 0;
  EXPECT_FALSE(transaction_multisig_quorum_is_valid(&multisig));
  multisig.m = 16;
  multisig.pubkeys_count = 16;
  EXPECT_FALSE(transaction_multisig_quorum_is_valid(&multisig));

  multisig.m = 2;
  multisig.pubkeys_count = 3;
  EXPECT_TRUE(transaction_multisig_quorum_is_valid(&multisig));
}

TEST(Transaction, MultisigCompilersRejectUnsatisfiableQuorums) {
  MultisigRedeemScriptType multisig = MultisigRedeemScriptType_init_zero;
  uint8_t output[256] = {0};
  uint8_t hash[32] = {0};

  struct InvalidQuorum {
    bool has_m;
    uint32_t m;
    pb_size_t n;
  };
  const InvalidQuorum invalid[] = {
      {false, 1, 1}, {true, 0, 1},  {true, 1, 0},
      {true, 2, 1},  {true, 1, 16}, {true, 16, 16},
  };

  for (const auto& test : invalid) {
    multisig.has_m = test.has_m;
    multisig.m = test.m;
    multisig.pubkeys_count = test.n;
    EXPECT_FALSE(multisig_quorum_is_valid(&multisig));
    EXPECT_EQ(0u, compile_script_multisig(nullptr, &multisig, output));
    EXPECT_EQ(0u, compile_script_multisig_hash(nullptr, &multisig, hash));
  }
}

TEST(Transaction, MultisigSerializerRejectsShortBufferWithoutWriting) {
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  MultisigRedeemScriptType multisig = MultisigRedeemScriptType_init_zero;
  multisig.has_m = true;
  multisig.m = 1;
  multisig.pubkeys_count = 1;

  HDNode node = {};
  const uint8_t seed[32] = {1};
  ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), coin->curve_name, &node));
  hdnode_fill_public_key(&node);
  auto& path = multisig.pubkeys[0];
  path.node.has_public_key = true;
  path.node.public_key.size = 33;
  memcpy(path.node.public_key.bytes, node.public_key, 33);
  path.node.chain_code.size = 32;
  memcpy(path.node.chain_code.bytes, node.chain_code, 32);

  multisig.signatures_count = 1;
  multisig.signatures[0].size = 72;
  memset(multisig.signatures[0].bytes, 0x30, 72);

  uint8_t complete[256] = {};
  const uint32_t required =
      serialize_script_multisig(coin, &multisig, 1, complete, sizeof(complete));
  ASSERT_GT(required, 0u);

  std::vector<uint8_t> short_buffer(required - 1, 0xA5);
  EXPECT_EQ(0u,
            serialize_script_multisig(coin, &multisig, 1, short_buffer.data(),
                                      short_buffer.size()));
  EXPECT_TRUE(std::all_of(short_buffer.begin(), short_buffer.end(),
                          [](uint8_t byte) { return byte == 0xA5; }));

  multisig.signatures[0].size = 73;
  std::vector<uint8_t> invalid_signature(256, 0x5A);
  EXPECT_EQ(0u, serialize_script_multisig(coin, &multisig, 1,
                                          invalid_signature.data(),
                                          invalid_signature.size()));
  EXPECT_TRUE(std::all_of(invalid_signature.begin(), invalid_signature.end(),
                          [](uint8_t byte) { return byte == 0x5A; }));
  memset(&node, 0, sizeof(node));
}

TEST(Transaction, Bip86KnownInternalKeyProducesCanonicalAddress) {
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  HDNode node = {};
  node.public_key[0] = 0x02;
  const uint8_t generator_x[32] = {
      0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62,
      0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce,
      0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};
  memcpy(node.public_key + 1, generator_x, sizeof(generator_x));
  char address[MAX_ADDR_SIZE] = {};
  ASSERT_TRUE(compute_address(coin, InputScriptType_SPENDTAPROOT, &node, false,
                              nullptr, address));
  EXPECT_STREQ(
      address,
      "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9");
}

TEST(Transaction, ChangedInputsTriggerDuplicateOutputRefusal) {
  // Initialize the FSM before seeding its transaction-history state.
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  struct ClearHistory {
    ~ClearHistory() { txin_dgst_initialize(); }
  } clear_history;
  txin_dgst_initialize();
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  HDNode root = {};
  TxOutputType output = {};
  output.has_address = true;
  std::strcpy(output.address, "1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1");
  output.amount = 380000;
  output.script_type = OutputScriptType_PAYTOADDRESS;
  TxOutputBinType compiled = {};

  const uint8_t first_input[] = {1, 2, 3};
  txin_dgst_addto(first_input, sizeof(first_input));
  txin_dgst_final();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_GT(compile_output(coin, &root, &output, &compiled, true), 0);
  ASSERT_EQ(0, kkconfirm_drain());

  // Signing initialization starts the next transaction's input hash.
  // Identical inputs and outputs remain a permitted repeat.
  txin_dgst_reset_current();
  txin_dgst_addto(first_input, sizeof(first_input));
  txin_dgst_final();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_GT(compile_output(coin, &root, &output, &compiled, true), 0);
  ASSERT_EQ(0, kkconfirm_drain());

  // A different input digest with the same output reaches the real warning
  // and refuses compilation even when the user acknowledges both screens.
  const uint8_t changed_input[] = {4, 5, 6};
  txin_dgst_reset_current();
  txin_dgst_addto(changed_input, sizeof(changed_input));
  txin_dgst_final();
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  EXPECT_EQ(-1, compile_output(coin, &root, &output, &compiled, true));
  EXPECT_EQ(0, kkconfirm_drain());

  // Refusing an output must not bless the rejected input set for a retry.
  for (int retry = 0; retry < 3; ++retry) {
    txin_dgst_reset_current();
    txin_dgst_addto(changed_input, sizeof(changed_input));
    txin_dgst_final();
    ASSERT_TRUE(kkconfirm_preload(2, 0));
    EXPECT_EQ(-1, compile_output(coin, &root, &output, &compiled, true));
    EXPECT_EQ(0, kkconfirm_drain());
  }
  // The original accepted transaction can still be retried afterward.
  txin_dgst_reset_current();
  txin_dgst_addto(first_input, sizeof(first_input));
  txin_dgst_final();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_GT(compile_output(coin, &root, &output, &compiled, true), 0);
  EXPECT_EQ(0, kkconfirm_drain());
}
TEST(Transaction, IdenticalOutputsWithinOneTransactionKeepInputHistory) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  struct ClearHistory {
    ~ClearHistory() { txin_dgst_initialize(); }
  } clear_history;
  txin_dgst_initialize();
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  HDNode root = {};
  TxOutputType output = {};
  output.has_address = true;
  std::strcpy(output.address, "1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1");
  output.amount = 380000;
  output.script_type = OutputScriptType_PAYTOADDRESS;
  TxOutputBinType compiled = {};
  const uint8_t input[] = {1, 2, 3};
  txin_dgst_addto(input, sizeof(input));
  // Mirror STAGE_REQUEST_3_OUTPUT: finalize before each output, without
  // feeding inputs again or starting a new signing request between outputs.
  for (int i = 0; i < 3; ++i) {
    if (i == 2) {
      TxOutputType memo = {};
      memo.script_type = OutputScriptType_PAYTOOPRETURN;
      memo.has_op_return_data = true;
      memo.op_return_data.size = 1;
      memo.op_return_data.bytes[0] = 'x';
      txin_dgst_final();
      ASSERT_TRUE(kkconfirm_preload(1, 0));
      ASSERT_GT(compile_output(coin, &root, &memo, &compiled, true), 0);
      ASSERT_EQ(0, kkconfirm_drain());
    }
    txin_dgst_final();
    ASSERT_TRUE(kkconfirm_preload(1, 0));
    EXPECT_GT(compile_output(coin, &root, &output, &compiled, true), 0);
    EXPECT_EQ(0, kkconfirm_drain());
  }
}
