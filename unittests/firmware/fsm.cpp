extern "C" {
#include "keepkey/transport/interface.h"
#include "trezor/crypto/sha2.h"
#include "keepkey/firmware/authenticator.h"
#include "keepkey/firmware/binance.h"
#include "keepkey/firmware/eos.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/mayachain.h"
#include "keepkey/firmware/osmosis.h"
#include "keepkey/firmware/signtx_tendermint.h"
#include "keepkey/firmware/thorchain.h"
#include "trezor/crypto/secp256k1.h"
}

#include "gtest/gtest.h"

#include <cstring>

TEST(Fsm, AuthenticatorCredentialSourceIsWipedOnEveryExit) {
  char credential[] = "site:user:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  ASSERT_EQ(LARGESEED, addAuthAccount(credential));

  for (size_t i = 0; i < sizeof(credential); ++i) {
    EXPECT_EQ('\0', credential[i]);
  }
}

TEST(Fsm, AbortWorkflowsClearsEveryObservableSigningSession) {
  HDNode node = {};
  node.curve = &secp256k1_info;

  BinanceSignTx binance = {};
  binance.has_msg_count = true;
  binance.msg_count = 1;
  binance.has_account_number = true;
  binance.has_chain_id = true;
  std::strcpy(binance.chain_id, "Binance-Chain-Nile");
  binance.has_sequence = true;
  binance.has_source = true;
  ASSERT_TRUE(binance_signTxInit(&node, &binance));

  TendermintSignTx tendermint = {};
  tendermint.has_msg_count = true;
  tendermint.msg_count = 1;
  tendermint.has_chain_id = true;
  std::strcpy(tendermint.chain_id, "chain-1");
  tendermint.has_chain_name = true;
  std::strcpy(tendermint.chain_name, "Cosmos");
  tendermint.has_denom = true;
  std::strcpy(tendermint.denom, "uatom");
  tendermint.has_message_type_prefix = true;
  std::strcpy(tendermint.message_type_prefix, "cosmos-sdk");
  ASSERT_TRUE(tendermint_signTxInit(&node, &tendermint, sizeof(tendermint),
                                    "uatom", TENDERMINT_SIGNING_GENERIC));

  OsmosisSignTx osmosis = {};
  osmosis.has_msg_count = true;
  osmosis.msg_count = 1;
  osmosis.has_chain_id = true;
  std::strcpy(osmosis.chain_id, "osmosis-1");
  ASSERT_TRUE(osmosis_signTxInit(&node, &osmosis));

  ThorchainSignTx thorchain = {};
  thorchain.has_msg_count = true;
  thorchain.msg_count = 1;
  thorchain.has_chain_id = true;
  std::strcpy(thorchain.chain_id, "thorchain-1");
  ASSERT_TRUE(thorchain_signTxInit(&node, &thorchain));

  MayachainSignTx mayachain = {};
  mayachain.has_msg_count = true;
  mayachain.msg_count = 1;
  mayachain.has_chain_id = true;
  std::strcpy(mayachain.chain_id, "mayachain-mainnet-v1");
  ASSERT_TRUE(mayachain_signTxInit(&node, &mayachain));

  uint8_t eos_chain_id[32] = {};
  EosTxHeader eos_header = {};
  uint32_t eos_path[8] = {};
  eos_signingInit(eos_chain_id, 1, &eos_header, &node, eos_path, 0);

  ASSERT_TRUE(binance_signingIsInited());
  ASSERT_TRUE(tendermint_signingIsInited(TENDERMINT_SIGNING_GENERIC));
  ASSERT_TRUE(osmosis_signingIsInited());
  ASSERT_TRUE(thorchain_signingIsInited());
  ASSERT_TRUE(mayachain_signingIsInited());
  ASSERT_TRUE(eos_signingIsInited());

  fsm_abort_workflows();

  EXPECT_FALSE(binance_signingIsInited());
  EXPECT_FALSE(tendermint_signingIsInited(TENDERMINT_SIGNING_GENERIC));
  EXPECT_FALSE(osmosis_signingIsInited());
  EXPECT_FALSE(thorchain_signingIsInited());
  EXPECT_FALSE(mayachain_signingIsInited());
  EXPECT_FALSE(eos_signingIsInited());
}
