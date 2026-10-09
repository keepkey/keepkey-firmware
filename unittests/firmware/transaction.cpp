#include "gtest/gtest.h"

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

TEST(Transaction, UnsupportedOmniDisclosesTheCompleteRawPayload) {
  std::vector<uint8_t> payload(220, 0x00);
  memcpy(payload.data(), "omni", 4);
  payload[7] = 1;  // unsupported transaction type, not Simple Send

  size_t pages = 0;
  size_t offset = 0;
  while (offset < payload.size()) {
    char page[BODY_CHAR_MAX];
    const size_t take = confirm_bytes_format_page(
        payload.data() + offset, payload.size() - offset, page, sizeof(page));
    ASSERT_GT(take, 0u);
    offset += take;
    pages++;
  }
  ASSERT_GT(pages, 1u);

  ASSERT_TRUE(kkconfirm_preload(static_cast<int>(pages), 0));
  EXPECT_TRUE(confirm_omni(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           "Confirm OMNI", payload.data(), payload.size()));
  EXPECT_EQ(0, kkconfirm_drain());
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
