extern "C" {
#include "keepkey/transport/interface.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/memory.h"
#include "pb_encode.h"
#include "trezor/crypto/sha2.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/messages.h"
#include "keepkey/emulator/setup.h"
#include "keepkey/firmware/authenticator.h"
#include "keepkey/firmware/binance.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/eos.h"
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

TEST(Fsm, BitcoinOnlyLockRefusesSettingsHandlersBeforeAnyConfirm) {
  setup();  // maps the emulated flash; idempotent across test binaries
  kk_test_board_init();
  fsm_init();

  flash_erase_word(FLASH_STORAGE1);
  flash_erase_word(FLASH_STORAGE2);
  flash_erase_word(FLASH_STORAGE3);
#if BITCOIN_ONLY
  // In-band but NEWER than this build understands -- the only way a
  // bitcoin-only image reaches the same lock.
  const uint32_t version = STORAGE_VERSION_BTC_ONLY + 1;
#else
  const uint32_t version = STORAGE_VERSION_BTC_ONLY;
#endif
  ASSERT_TRUE(flash_write(FLASH_STORAGE1, 0, STORAGE_MAGIC_LEN,
                          (const uint8_t*)STORAGE_MAGIC_STR));
  // Offset 44: the version word, immediately after the 44-byte Metadata.
  ASSERT_TRUE(flash_write(FLASH_STORAGE1, 44, sizeof(version),
                          (const uint8_t*)&version));
  storage_init();
  ASSERT_TRUE(storage_isBitcoinOnlyLocked());
  ASSERT_FALSE(storage_isInitialized());

  ApplyPolicies policies = {};
  policies.policy_count = 1;
  policies.policy[0].has_policy_name = true;
  std::strcpy(policies.policy[0].policy_name, "AdvancedMode");
  policies.policy[0].has_enabled = true;
  policies.policy[0].enabled = true;
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  fsm_msgApplyPolicies(&policies);
  EXPECT_EQ(0, kkconfirm_drain())
      << "ApplyPolicies asked for a button press it could never persist";
  EXPECT_FALSE(storage_isPolicyEnabled("AdvancedMode"))
      << "the policy changed in RAM only, so this boot disagrees with flash";

  ApplySettings settings = {};
  settings.has_label = true;
  std::strcpy(settings.label, "locked");
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  fsm_msgApplySettings(&settings);
  EXPECT_EQ(0, kkconfirm_drain())
      << "ApplySettings asked for a button press it could never persist";

  ChangePin pin = {};
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  fsm_msgChangePin(&pin);
  EXPECT_EQ(0, kkconfirm_drain())
      << "ChangePin ran the Create PIN ceremony on a device it cannot write";

  storage_wipe();
  EXPECT_FALSE(storage_isBitcoinOnlyLocked());
  layoutHomeForced();
}
