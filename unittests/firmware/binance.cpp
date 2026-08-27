extern "C" {
#include "keepkey/transport/interface.h"
#include "keepkey/firmware/binance.h"
#include "trezor/crypto/secp256k1.h"
}

#include "gtest/gtest.h"

#include <cstring>
#include "trezor/crypto/secp256k1.h"

static BinanceTransferMsg transfer(const char* denom, int64_t amount) {
  BinanceTransferMsg msg = {};
  msg.inputs_count = 1;
  msg.outputs_count = 1;
  msg.inputs[0].coins_count = 1;
  msg.outputs[0].coins_count = 1;
  msg.inputs[0].has_address = true;
  msg.outputs[0].has_address = true;
  strcpy(msg.inputs[0].address, "tbnb1hgm0p7khfk85zpz5v0j8wnej3a90w709zzlffd");
  strcpy(msg.outputs[0].address, "tbnb1ss57e8sa7xnwq030k2ctr775uac9gjzglqhvpy");
  msg.inputs[0].coins[0].has_amount = true;
  msg.outputs[0].coins[0].has_amount = true;
  msg.inputs[0].coins[0].amount = amount;
  msg.outputs[0].coins[0].amount = amount;
  msg.inputs[0].coins[0].has_denom = true;
  msg.outputs[0].coins[0].has_denom = true;
  strcpy(msg.inputs[0].coins[0].denom, denom);
  strcpy(msg.outputs[0].coins[0].denom, denom);
  return msg;
}

TEST(Binance, DenomBoundsAndGrammar) {
  EXPECT_TRUE(binance_isValidDenom("BNB"));
  EXPECT_TRUE(binance_isValidDenom("RUNE-B1A"));
  EXPECT_TRUE(binance_isValidDenom("ABCDEFGH-123"));
  EXPECT_TRUE(binance_isValidDenom("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
  EXPECT_FALSE(binance_isValidDenom("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
  EXPECT_FALSE(binance_isValidDenom("bnb"));
  EXPECT_FALSE(binance_isValidDenom("BNB\""));
  EXPECT_FALSE(binance_isValidDenom("BN B"));
  EXPECT_FALSE(binance_isValidDenom(""));
}

TEST(Binance, TransferValidationFailsClosed) {
  BinanceTransferMsg msg = transfer("RUNE-B1A", 1000000000);
  EXPECT_TRUE(binance_validateTransfer(&msg));

  msg = transfer("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 1000000000);
  EXPECT_TRUE(binance_validateTransfer(&msg));
  msg = transfer("BNB", 0);
  EXPECT_FALSE(binance_validateTransfer(&msg));
  msg = transfer("BNB", -1);
  EXPECT_FALSE(binance_validateTransfer(&msg));

  msg = transfer("BNB", 1);
  msg.outputs[0].coins[0].amount = 2;
  EXPECT_FALSE(binance_validateTransfer(&msg));

  msg = transfer("BNB", 1);
  msg.outputs[0].coins[0].has_denom = false;
  EXPECT_FALSE(binance_validateTransfer(&msg));
}

TEST(Binance, SigningSessionRequiresCanonicalEnvelopeState) {
  HDNode node = {};
  node.curve = &secp256k1_info;
  BinanceSignTx envelope = {};
  EXPECT_FALSE(binance_signTxInit(&node, &envelope));
  EXPECT_FALSE(binance_signingIsInited());

  envelope.has_msg_count = true;
  envelope.msg_count = 1;
  envelope.has_account_number = true;
  envelope.has_chain_id = true;
  strcpy(envelope.chain_id, "Binance-Chain-Nile");
  envelope.has_sequence = true;
  envelope.has_source = true;
  EXPECT_TRUE(binance_signTxInit(&node, &envelope));
  EXPECT_TRUE(binance_signingIsInited());
  EXPECT_FALSE(binance_signingIsFinished());
  binance_signAbort();
}
