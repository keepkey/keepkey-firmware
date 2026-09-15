extern "C" {
#include "keepkey/transport/interface.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/memory.h"
#include "pb_encode.h"
#include "trezor/crypto/sha2.h"
#include "keepkey/firmware/authenticator.h"
#include "keepkey/firmware/binance.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/eos.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/recovery_cipher.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/mayachain.h"
#include "keepkey/firmware/osmosis.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/signing.h"
#include "keepkey/firmware/signtx_tendermint.h"
#include "keepkey/firmware/storage.h"
#include "storage.h"
#include "keepkey/firmware/thorchain.h"
#include "trezor/crypto/secp256k1.h"
}

#include "gtest/gtest.h"

#include <cstring>
#include <algorithm>
#include <vector>

// The shared bootstrap initializes the canvas and timer queues exactly once.
// Calling timer_init() again relinks the static runnable nodes into a cycle.
void kk_test_board_init(void);
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

TEST(Fsm, AuthenticatorCredentialSourceIsWipedOnEveryExit) {
  char credential[] = "site:user:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  ASSERT_EQ(LARGESEED, addAuthAccount(credential));

  for (size_t i = 0; i < sizeof(credential); ++i) {
    EXPECT_EQ('\0', credential[i]);
  }
}

#if !BITCOIN_ONLY
static void expectSigningSessionsCleared(bool initialize) {
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

  if (initialize) {
    kk_test_board_init();
    fsm_init();
    fsm_msgInitialize(nullptr);
  } else {
    fsm_abort_workflows();
  }

  EXPECT_FALSE(binance_signingIsInited());
  EXPECT_FALSE(tendermint_signingIsInited(TENDERMINT_SIGNING_GENERIC));
  EXPECT_FALSE(osmosis_signingIsInited());
  EXPECT_FALSE(thorchain_signingIsInited());
  EXPECT_FALSE(mayachain_signingIsInited());
  EXPECT_FALSE(eos_signingIsInited());
}

TEST(Fsm, AbortWorkflowsClearsEveryObservableSigningSession) {
  expectSigningSessionsCleared(false);
}

TEST(Fsm, InitializeClearsEveryObservableSigningSession) {
  expectSigningSessionsCleared(true);
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

/* The lock path aborts signing, and signing_abort() draws the home screen,
 * which resets the idle timer. If that reset stands, the very next tick sees
 * an idle device and replaces the screensaver with the home screen. */
TEST(Fsm, AutoLockKeepsTheScreensaverAfterAbortingSigning) {
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
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  toggle_screensaver();
  ASSERT_FALSE(signing_is_active());
  ASSERT_EQ(SCREENSAVER, home_get_state());

  increment_idle_time(1000);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state())
      << "a locked device must stay on the screensaver, not wake to home";

  layoutHomeForced();
}

namespace {
void receiveMessage(MessageType type, const pb_field_t* fields,
                    const void* msg) {
  uint8_t encoded[4096] = {};
  pb_ostream_t stream = pb_ostream_from_buffer(encoded, sizeof(encoded));
  ASSERT_TRUE(pb_encode(&stream, fields, msg));
  uint8_t frame[64] = {'?', '#', '#'};
  frame[3] = type >> 8;
  frame[4] = type & 0xff;
  const size_t size = stream.bytes_written;
  frame[5] = size >> 24;
  frame[6] = size >> 16;
  frame[7] = size >> 8;
  frame[8] = size;
  size_t sent = std::min(size, sizeof(frame) - 9);
  std::memcpy(frame + 9, encoded, sent);
  usb_test_receive(frame, sizeof(frame));
  while (sent < size) {
    std::memset(frame + 1, 0, sizeof(frame) - 1);
    const size_t chunk = std::min(size - sent, sizeof(frame) - 1);
    std::memcpy(frame + 1, encoded + sent, chunk);
    usb_test_receive(frame, sizeof(frame));
    sent += chunk;
  }
}

// firmware-unit never maps emulated flash; tests whose handlers commit storage
// borrow a zeroed image for their duration.
struct ScopedFlash {
  std::vector<uint8_t> bytes = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  uint8_t* previous = emulator_flash_base;
  ScopedFlash() {
    emulator_flash_base = bytes.data();
    storage_init();
  }
  ~ScopedFlash() {
    storage_reset();
    emulator_flash_base = previous;
  }
};

class AutoLockProgress : public ::testing::Test {
 protected:
  void SetUp() override {
    kk_test_board_init();
    fsm_init();
    setup_abort();
    layoutHomeForced();
    storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
    SignTx start = {};
    start.inputs_count = start.outputs_count = 1;
    HDNode root = {};
    const uint8_t seed[32] = {1};
    ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &root));
    signing_init(&start, coinByName("Bitcoin"), &root);
    ASSERT_TRUE(signing_is_active());
    leave_home();
  }
  void TearDown() override {
    fsm_abort_workflows();
    setup_abort();
    layoutHomeForced();
  }
};
}  // namespace

TEST_F(AutoLockProgress, FeaturePollingCannotKeepStalledSigningUnlocked) {
  GetFeatures poll = {};
  for (int i = 0; i < 4; ++i) {
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT / 4);
    receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                   &poll);
    ASSERT_EQ(AWAY_FROM_HOME, home_get_state());
    ASSERT_TRUE(signing_is_active());
    toggle_screensaver();
  }
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST(Fsm, DispatchScrubsDerivedKeyScratchAfterHandler) {
  fsm_init();
  fsm_test_seedDerivedNode();
  ASSERT_FALSE(fsm_test_derivedNodeIsZero());

  GetFeatures request = {};
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &request);

  EXPECT_TRUE(fsm_test_derivedNodeIsZero());
}

TEST(Fsm, InactiveBitcoinAckGetsATerminalResponse) {
  fsm_init();
  fsm_abort_workflows();
  fsm_test_clearLastFailure();

  TxAck stale = {};
  stale.has_tx = true;
  receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &stale);

  EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode())
      << "silently dropping an inactive ACK leaves the host blocked";
  EXPECT_FALSE(signing_is_active());
}

TEST_F(AutoLockProgress, IncompleteFrameCannotKeepStalledSigningUnlocked) {
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  // Valid Ping header, but its 60-byte payload has not arrived in full.
  uint8_t frame[64] = {'?', '#', '#', 0, 1, 0, 0, 0, 60};
  usb_test_receive(frame, sizeof(frame));
  ASSERT_TRUE(signing_is_active());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
  // Finish the pending transport message so it cannot affect later tests.
  uint8_t tail[64] = {'?'};
  usb_test_receive(tail, sizeof(tail));
}

TEST_F(AutoLockProgress, ValidBitcoinStreamProgressRenewsTheIdleDeadline) {
  TxAck ack = {};
  ack.has_tx = true;
  ack.tx.inputs_count = 1;
  ack.tx.inputs[0].prev_hash.size = 32;
  ack.tx.inputs[0].has_script_type = true;
  ack.tx.inputs[0].script_type = InputScriptType_SPENDADDRESS;
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &ack);
  ASSERT_TRUE(signing_is_active());
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  ASSERT_TRUE(signing_is_active());

  // Real next stage: supply metadata for the requested previous transaction.
  ack = {};
  ack.has_tx = true;
  ack.tx.has_inputs_cnt = ack.tx.has_outputs_cnt = true;
  ack.tx.inputs_cnt = ack.tx.outputs_cnt = 1;
  receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &ack);
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  ASSERT_TRUE(signing_is_active());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, FeaturePollingAtHomeDoesNotRenewTheIdleDeadline) {
  signing_abort();
  layoutHomeForced();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  GetFeatures poll = {};
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &poll);
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, PingCannotRenewAStalledSigningDeadline) {
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  Ping ping = {};
  receiveMessage(MessageType_MessageType_Ping, Ping_fields, &ping);
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, ProtectedPingCannotSuspendAnOlderSigningSession) {
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  Ping ping = {};
  ping.has_button_protection = true;
  ping.button_protection = true;
  fsm_test_clearLastFailure();
  receiveMessage(MessageType_MessageType_Ping, Ping_fields, &ping);

  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST_F(AutoLockProgress, TopLevelConfirmationEndsAnOlderSigningSession) {
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  ChangePin request = {};
  fsm_test_clearLastFailure();
  receiveMessage(MessageType_MessageType_ChangePin, ChangePin_fields, &request);

  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST_F(AutoLockProgress, TopLevelBoundaryEndsSigningButIsNotALock) {
  // AdvancedMode is the observable here: without a PIN, session_clear()
  // re-caches the empty PIN, so a PIN-cache check would pass even under a lock.
  ScopedFlash flash;
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  ChangePin request = {};
  receiveMessage(MessageType_MessageType_ChangePin, ChangePin_fields, &request);
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(0, kkconfirm_drain());

  Ping ping = {};
  ping.has_pin_protection = true;
  ping.pin_protection = true;
  receiveMessage(MessageType_MessageType_Ping, Ping_fields, &ping);

  EXPECT_TRUE(storage_isPolicyEnabled("AdvancedMode"))
      << "an ordinary request must not disarm AdvancedMode before signing";
}

TEST_F(AutoLockProgress, NewSigningRequestCannotCoexistWithRecovery) {
  signing_abort();
  setup_abort();
  ASSERT_TRUE(setup_stage(false, "english", "recovery", 0, 0, false));
  setup_arm(SETUP_RECOVERY);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  SignTx invalid = {};
  receiveMessage(MessageType_MessageType_SignTx, SignTx_fields, &invalid);

  EXPECT_FALSE(setup_isArmed());
  EXPECT_FALSE(signing_is_active());
  layoutHomeForced();
}

TEST_F(AutoLockProgress, HostDrivenLayoutChangesDoNotRenewTheDeadline) {
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  layoutHome();
  leave_home();
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, MalformedMultisigAddressCannotRenewTheDeadline) {
  // Deriving the address caches the root seed and commits storage.
  ScopedFlash flash;

  signing_abort();
  LoadDevice load = {};
  load.has_mnemonic = true;
  std::strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);
  storage_commit();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);

  SignTx start = {};
  start.inputs_count = start.outputs_count = 1;
  HDNode root = {};
  const uint8_t seed[32] = {1};
  ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &root));
  signing_init(&start, coinByName("Bitcoin"), &root);
  ASSERT_TRUE(signing_is_active());
  leave_home();

  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  GetAddress malformed = {};
  malformed.has_multisig = true;
  fsm_test_clearLastFailure();
  receiveMessage(MessageType_MessageType_GetAddress, GetAddress_fields,
                 &malformed);
  EXPECT_EQ(FailureType_Failure_Other, fsm_test_lastFailureCode())
      << "the request must reach the multisig rejection, not an earlier gate";
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

#if !BITCOIN_ONLY
TEST(Fsm, SolanaCertificateIsRejectedAtTheProductionHandler) {
  kk_test_board_init();
  fsm_init();
  fsm_test_clearLastFailure();

  SolanaSignTx request = {};
  request.has_clearsign_certificate = true;
  request.clearsign_certificate.size = 1;
  request.clearsign_certificate.bytes[0] = 0x01;
  receiveMessage(MessageType_MessageType_SolanaSignTx, SolanaSignTx_fields,
                 &request);

  EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode())
      << "a decoded certificate must not fall through to ordinary signing";
  layoutHomeForced();
}
#endif

TEST_F(AutoLockProgress, InvalidBitcoinAckEndsTheStream) {
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  TxAck invalid = {};
  invalid.has_tx = true;
  // Decodable protobuf, but the required 32-byte previous hash is missing.
  invalid.tx.inputs_count = 1;
  receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &invalid);
  EXPECT_FALSE(signing_is_active());
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, RecoveryEditsRenewButPollingAndEmptyDeleteDoNot) {
  signing_abort();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  recovery_cipher_init(12, false, false, "english", "idle test", false,
                       STORAGE_MIN_SCREENSAVER_TIMEOUT, 0, false);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  ASSERT_EQ(0, kkconfirm_drain());
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  CharacterAck character = {};
  character.has_character = true;
  character.character[0] = 'a';  // Every a-z character belongs to the cipher.
  receiveMessage(MessageType_MessageType_CharacterAck, CharacterAck_fields,
                 &character);
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  character = {};
  character.has_delete = character.del = true;
  receiveMessage(MessageType_MessageType_CharacterAck, CharacterAck_fields,
                 &character);
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  // The mnemonic is now empty: another delete makes no progress.
  receiveMessage(MessageType_MessageType_CharacterAck, CharacterAck_fields,
                 &character);
  GetFeatures poll = {};
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &poll);
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(setup_isArmed());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

#if !BITCOIN_ONLY
TEST_F(AutoLockProgress, EthereumChunksRenewButFeaturePollingDoesNot) {
  signing_abort();
  storage_reset();
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
  struct RestorePolicy {
    ~RestorePolicy() { storage_setPolicy("AdvancedMode", false); }
  } restore;
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EthereumSignTx start = {};
  start.has_chain_id = true;
  start.chain_id = 1;
  start.has_gas_price = start.has_gas_limit = true;
  start.gas_price.size = start.gas_limit.size = 1;
  start.gas_price.bytes[0] = start.gas_limit.bytes[0] = 1;
  start.has_to = true;
  start.to.size = 20;
  start.to.bytes[0] = 1;
  start.has_data_initial_chunk = start.has_data_length = true;
  start.data_initial_chunk.size = 1;
  start.data_initial_chunk.bytes[0] = 1;
  start.data_length = 4096;
  HDNode node = {};
  const uint8_t seed[32] = {1};
  ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &node));
  ethereum_signing_init(&start, &node, false);
  ASSERT_TRUE(ethereum_signing_isInProgress());
  ASSERT_EQ(0, kkconfirm_drain());
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  for (int i = 0; i < 2; ++i) {
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
    EthereumTxAck chunk = {};
    chunk.has_data_chunk = true;
    chunk.data_chunk.size = 128;  // Requires multiple USB frames.
    receiveMessage(MessageType_MessageType_EthereumTxAck, EthereumTxAck_fields,
                   &chunk);
    toggle_screensaver();
    ASSERT_TRUE(ethereum_signing_isInProgress());
  }
  GetFeatures poll = {};
  for (int i = 0; i < 4; ++i) {
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT / 4);
    receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                   &poll);
    toggle_screensaver();
  }
  EXPECT_FALSE(ethereum_signing_isInProgress());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, EosDataProgressRenewsButEmptyChunksDoNot) {
  signing_abort();
  storage_reset();
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
  struct RestorePolicy {
    ~RestorePolicy() { storage_setPolicy("AdvancedMode", false); }
  } restore;
  HDNode node = {};
  node.curve = &secp256k1_info;
  uint8_t chain_id[32] = {};
  EosTxHeader header = {};
  uint32_t path[8] = {};
  eos_signingInit(chain_id, 1, &header, &node, path, 0);
  ASSERT_TRUE(eos_signingIsInited());
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  leave_home();
  EosTxActionAck ack = {};
  ack.has_common = ack.has_unknown = true;
  ack.common.has_account = ack.common.has_name = true;
  ack.common.account = 0x1111;
  ack.common.name = 0x2222;
  ack.common.authorization_count = 1;
  ack.common.authorization[0].has_actor = true;
  ack.common.authorization[0].actor = 0x3333;
  ack.common.authorization[0].has_permission = true;
  ack.common.authorization[0].permission = 0x4444;
  ack.unknown.has_data_size = ack.unknown.has_data_chunk = true;
  ack.unknown.data_size = 256;
  ack.unknown.data_chunk.size = 1;
  for (int i = 0; i < 2; ++i) {
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
    receiveMessage(MessageType_MessageType_EosTxActionAck,
                   EosTxActionAck_fields, &ack);
    toggle_screensaver();
    ASSERT_TRUE(eos_signingIsInited());
  }
  ack.unknown.data_chunk.size = 0;
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  receiveMessage(MessageType_MessageType_EosTxActionAck, EosTxActionAck_fields,
                 &ack);
  ASSERT_TRUE(eos_signingIsInited());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(eos_signingIsInited());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}
#endif

/* Clearing PIN authorization revokes signing, but must not discard a staged
 * setup ceremony: recovery stages before it prompts for the PIN, and every
 * routine PIN entry lands here through the wipe-code probe. */
TEST(Fsm, PinRevocationKeepsAStagedCeremony) {
  fsm_init();
  setup_abort();
  ASSERT_TRUE(setup_stage(false, "english", "dry run", 0, 0, false));

  SessionState session = {};
  Storage storage = {};
  storage.pub.has_pin = true;
  session_clear_impl(&session, &storage, /*clear_pin=*/true);

  setup_arm(SETUP_RECOVERY);
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY))
      << "the PIN prompt must not disarm the ceremony it was asked for";

  setup_abort();
}

/* ... while the paths that really do end a session still discard it. */
TEST(Fsm, SessionClearDiscardsAStagedCeremony) {
  fsm_init();
  setup_abort();
  ASSERT_TRUE(setup_stage(false, "english", "reset", 0, 0, false));
  setup_arm(SETUP_RESET);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));

  fsm_abort_workflows();
  EXPECT_FALSE(setup_isArmedAs(SETUP_RESET));

  setup_abort();
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
TEST(Fsm, CrossWorkflowAcknowledgementsTerminateTheActiveSigner) {
  fsm_init();
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
  ASSERT_TRUE(binance_signingIsInited());

  CosmosMsgAck cosmos_ack = {};
  receiveMessage(MessageType_MessageType_CosmosMsgAck, CosmosMsgAck_fields,
                 &cosmos_ack);
  EXPECT_FALSE(binance_signingIsInited());

  TendermintSignTx cosmos = {};
  cosmos.has_msg_count = true;
  cosmos.msg_count = 1;
  cosmos.has_chain_id = true;
  std::strcpy(cosmos.chain_id, "cosmoshub-4");
  ASSERT_TRUE(tendermint_signTxInit(&node, &cosmos, sizeof(cosmos), "uatom",
                                    TENDERMINT_SIGNING_COSMOS));
  ASSERT_TRUE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));

  BinanceTransferMsg binance_ack = {};
  receiveMessage(MessageType_MessageType_BinanceTransferMsg,
                 BinanceTransferMsg_fields, &binance_ack);
  EXPECT_FALSE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));
}

TEST(Fsm, StaleEthereumAckCannotReplaceARecoveryCeremony) {
  kk_test_board_init();
  fsm_init();
  setup_abort();
  fsm_test_clearLastFailure();

  ASSERT_TRUE(setup_stage(false, "english", "recovery", 0, 0, false));
  setup_arm(SETUP_RECOVERY);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  EthereumTxAck stale = {};
  receiveMessage(MessageType_MessageType_EthereumTxAck, EthereumTxAck_fields,
                 &stale);

  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode())
      << "the stale ACK was dropped without a terminal host response";

  setup_abort();
  layoutHomeForced();
}

TEST(Fsm, PaddedZeroUnlimitedApprovalReachesTheGlobalRefusal) {
  kk_test_board_init();
  fsm_init();
  fsm_test_clearLastFailure();
  kkconfirm_drain();
  ASSERT_TRUE(kkconfirm_preload(0, 1));

  EthereumSignTx msg = {};
  msg.has_chain_id = true;
  msg.chain_id = 1;
  msg.has_gas_price = msg.has_gas_limit = true;
  msg.gas_price.size = msg.gas_limit.size = 1;
  msg.gas_price.bytes[0] = msg.gas_limit.bytes[0] = 1;
  msg.has_to = true;
  msg.to.size = 20;
  msg.to.bytes[0] = 1;
  msg.has_value = true;
  msg.value.size = 32;  // Non-canonical spelling of zero.
  msg.has_data_length = msg.has_data_initial_chunk = true;
  msg.data_length = msg.data_initial_chunk.size = 68;
  memcpy(msg.data_initial_chunk.bytes, "\x09\x5e\xa7\xb3", 4);
  memset(msg.data_initial_chunk.bytes + 36, 0xff, 32);

  HDNode node = {};
  const uint8_t seed[32] = {1};
  ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &node));
  ethereum_signing_init(&msg, &node, false);

  EXPECT_FALSE(ethereum_signing_isInProgress());
  EXPECT_EQ(0u, msg.value.size)
      << "the global ERC-20 classifier never saw canonical zero";
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_EQ(2, kkconfirm_drain())
      << "a generic-signing confirmation ran before the global refusal";
}
#endif

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

TEST(Fsm, LowLevelPinRevocationTerminatesSigning) {
  fsm_init();
  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  SessionState session = {};
  Storage storage = {};
  storage.pub.has_pin = true;
  session_clear_impl(&session, &storage, true);
  EXPECT_FALSE(signing_is_active());
  signing_abort();
}

TEST(Fsm, LowLevelSoftClearPreservesSigning) {
  fsm_init();
  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  SessionState session = {};
  Storage storage = {};
  storage.pub.has_pin = true;
  session_clear_impl(&session, &storage, false);
  EXPECT_TRUE(signing_is_active());
  signing_abort();
}

/* A rejected frame must not be able to resume a signing session -- but it must
 * not be able to destroy a setup ceremony either. Every unmapped message id
 * reaches the same handler, and on bitcoin-only firmware that is every
 * multi-chain message a host probes with, so a routine EthereumGetAddress
 * would otherwise memzero a recovery the user is 20 words into. */
TEST(Fsm, TransportFailureEndsSigningButKeepsRecoveryCeremony) {
  kk_test_board_init();
  fsm_init();
  setup_abort();

  ASSERT_TRUE(setup_stage(false, "english", "recovery", 0, 0, false));
  setup_arm(SETUP_RECOVERY);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  // Exactly what lib/board/messages.c does for a message id that is not in
  // the map, via the handler fsm_init() installed.
  call_msg_failure_handler(FailureType_Failure_UnexpectedMessage,
                           "Unknown message");

  EXPECT_FALSE(signing_is_active())
      << "a rejected frame left a signing session a later ack could resume";
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY))
      << "an unmapped host probe tore down the ceremony the user was in";

  setup_abort();
  layoutHomeForced();
}

TEST(Fsm, TransportFailureDisarmsResetBeforeAStaleEntropyAck) {
  kk_test_board_init();
  fsm_init();
  setup_abort();

  ASSERT_TRUE(setup_stage(false, "english", "reset", 0, 0, false));
  setup_arm(SETUP_RESET);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));

  call_msg_failure_handler(FailureType_Failure_UnexpectedMessage,
                           "Malformed frame");

  EXPECT_FALSE(setup_isArmed())
      << "a rejected frame left reset armed for a stale EntropyAck";
  layoutHomeForced();
}
