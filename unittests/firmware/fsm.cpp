extern "C" {
#include "keepkey/transport/interface.h"
#include "trezor/crypto/sha2.h"
#include "keepkey/firmware/authenticator.h"
#include "keepkey/firmware/binance.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/eos.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/mayachain.h"
#include "keepkey/firmware/osmosis.h"
#include "keepkey/firmware/signing.h"
#include "keepkey/firmware/signtx_tendermint.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/thorchain.h"
#include "trezor/crypto/secp256k1.h"
}

#include "gtest/gtest.h"

#include <cstring>

// The shared bootstrap initializes the canvas and timer queues exactly once.
// Calling timer_init() again relinks the static runnable nodes into a cycle.
void kk_test_board_init(void);

TEST(Fsm, AuthenticatorCredentialSourceIsWipedOnEveryExit) {
  char credential[] = "site:user:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  ASSERT_EQ(LARGESEED, addAuthAccount(credential));

  for (size_t i = 0; i < sizeof(credential); ++i) {
    EXPECT_EQ('\0', credential[i]);
  }
}

#if !BITCOIN_ONLY
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
#endif

TEST(Fsm, MissingBitcoinAckPayloadTerminatesSigning) {
  fsm_init();

  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);

  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  TxAck missing = {};
  fsm_msgTxAck(&missing);
  EXPECT_FALSE(signing_is_active());

  TxAck stale = {};
  stale.has_tx = true;
  fsm_msgTxAck(&stale);
  EXPECT_FALSE(signing_is_active());
}

TEST(Fsm, AutoLockTerminatesSigningWhileWaitingAwayFromHome) {
  /* Production initializes the OLED before the main loop can auto-lock. Use
   * the firmware suite's one-time board bootstrap to mirror that precondition
   * without reinitializing and corrupting the static timer queues. */
  kk_test_board_init();

  fsm_init();
  layoutHomeForced();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);

  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  leave_home();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  EXPECT_TRUE(signing_is_active());

  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());

  /* Restore a deterministic home state for subsequent tests. */
  layoutHomeForced();
}

TEST(Fsm, InvalidSecondBitcoinStartTerminatesOldSigning) {
  fsm_init();

  SignTx first = {};
  first.inputs_count = 1;
  first.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);

  signing_init(&first, coin, &root);
  ASSERT_TRUE(signing_is_active());

  SignTx invalid = {};
  fsm_msgSignTx(&invalid);
  EXPECT_FALSE(signing_is_active());

  TxAck stale = {};
  stale.has_tx = true;
  fsm_msgTxAck(&stale);
  EXPECT_FALSE(signing_is_active());
}

#if !BITCOIN_ONLY
TEST(Fsm, MissingEosCommonTerminatesSigning) {
  fsm_init();

  HDNode root = {};
  uint8_t chain_id[32] = {};
  EosTxHeader header = {};
  uint32_t path[8] = {};
  eos_signingInit(chain_id, 1, &header, &root, path, 0);
  ASSERT_TRUE(eos_signingIsInited());

  EosTxActionAck missing = {};
  fsm_msgEosTxActionAck(&missing);
  EXPECT_FALSE(eos_signingIsInited());

  EosTxActionAck stale = {};
  stale.has_common = true;
  stale.has_transfer = true;
  fsm_msgEosTxActionAck(&stale);
  EXPECT_FALSE(eos_signingIsInited());
}
#endif
