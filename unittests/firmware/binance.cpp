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

TEST(Binance, MultipleMessagesAreCommaSeparated) {
  /* binance_signTxInit() opens "msgs":[ and binance_signTxFinalize() closes
     it, but nothing separated the elements: with msg_count == 2 the signed
     document read "msgs":[{...}{...}], which is not JSON. Binance rejects the
     signature, so the transaction is unusable -- after the user has already
     approved both transfers on screen. msg_count is host-supplied and only
     checked non-zero, and fsm_msgBinanceTransferMsg() confirms and serialises
     each message in turn, so two messages is a reachable flow.

     The expected signature is computed OUTSIDE this firmware: SHA256 over the
     canonical sign document spelled out below, signed with RFC6979
     deterministic secp256k1 and low-S normalised. If the comma is missing, or
     placed before the first element, the digest differs and this fails. */
  HDNode node = {};
  node.curve = &secp256k1_info;
  memcpy(node.private_key,
         "\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b"
         "\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b",
         32);
  hdnode_fill_public_key(&node);

  BinanceSignTx envelope = {};
  envelope.has_msg_count = true;
  envelope.msg_count = 2;
  envelope.has_account_number = true;
  envelope.account_number = 34;
  envelope.has_chain_id = true;
  strcpy(envelope.chain_id, "Binance-Chain-Nile");
  envelope.has_memo = true;
  strcpy(envelope.memo, "multi");
  envelope.has_sequence = true;
  envelope.sequence = 31;
  envelope.has_source = true;
  envelope.source = 1;

  ASSERT_TRUE(binance_signTxInit(&node, &envelope));

  const BinanceTransferMsg first = transfer("BNB", 1000);
  ASSERT_TRUE(binance_signTxUpdateTransfer(&first));
  EXPECT_FALSE(binance_signingIsFinished());

  const BinanceTransferMsg second = transfer("BNB", 250);
  ASSERT_TRUE(binance_signTxUpdateTransfer(&second));
  EXPECT_TRUE(binance_signingIsFinished());

  uint8_t public_key[33] = {};
  uint8_t signature[64] = {};
  ASSERT_TRUE(binance_signTxFinalize(public_key, signature));

  /* {"account_number":"34","chain_id":"Binance-Chain-Nile","data":null,
      "memo":"multi","msgs":[{..1000..},{..250..}],"sequence":"31",
      "source":"1"} */
  EXPECT_EQ(0, memcmp(signature,
                      "\x5d\x9a\x60\xb4\xb3\x01\x82\x2f\x1e\x54\xcb\xff\x6e"
                      "\x77\xd2\x6b\x59\x40\xf8\x7a\x60\xb6\x8d\x1f\x7d\xdd"
                      "\xa8\x4c\x93\x0d\x06\x38\x3e\xd6\x50\xbb\x0b\xc3\xd7"
                      "\x2f\x2b\xb3\xf6\xdd\xdb\xc4\xbe\xa1\xda\xb6\xcc\x5a"
                      "\xfb\xae\x8f\x3c\x8a\xb8\xff\x77\x0c\xa6\xb5\xa7",
                      64));

  /* No stray leading comma on a single-message document: the same helper flag
     must not fire on the first element. */
  binance_signAbort();
  envelope.msg_count = 1;
  ASSERT_TRUE(binance_signTxInit(&node, &envelope));
  ASSERT_TRUE(binance_signTxUpdateTransfer(&first));
  uint8_t sig_one[64] = {};
  ASSERT_TRUE(binance_signTxFinalize(public_key, sig_one));
  EXPECT_NE(0, memcmp(sig_one, signature, 64));
  binance_signAbort();
}
