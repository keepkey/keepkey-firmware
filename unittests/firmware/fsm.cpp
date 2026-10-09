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
#include "keepkey/firmware/pin_sm.h"
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
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>

// The shared bootstrap initializes the canvas and timer queues exactly once.
// Calling timer_init() again relinks the static runnable nodes into a cycle.
void kk_test_board_init(void);
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);
bool kkconfirm_sendTiny(uint16_t msgId, const uint8_t* payload, uint8_t len);
extern "C" void keepkey_user_activity(void);  // lib/firmware/home_sm.c

// Auto-lock reads home_clock_ms(). The real 1 ms tick would make the deadline
// checks below racy, so this binary's clock moves only when a test says so.
static uint32_t fake_clock_ms = 0;
extern "C" uint32_t home_clock_ms(void) { return fake_clock_ms; }
static void advance_clock(uint32_t ms) { fake_clock_ms += ms; }

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
  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  EXPECT_TRUE(signing_is_active());

  advance_clock(1);
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
  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  toggle_screensaver();
  ASSERT_FALSE(signing_is_active());
  ASSERT_EQ(SCREENSAVER, home_get_state());

  advance_clock(1000);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state())
      << "a locked device must stay on the screensaver, not wake to home";

  // ~49.7 days of further idling must not wrap the counter into "activity".
  // It holds STORAGE_MIN_SCREENSAVER_TIMEOUT + 1000 here; this brings an
  // unsaturated counter to exactly 0.
  advance_clock(UINT32_MAX - (STORAGE_MIN_SCREENSAVER_TIMEOUT + 1000) + 1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state())
      << "the idle counter wrapped and woke the locked screen";

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

// DebugLinkGetState is also serviced inside the PIN, passphrase and confirm
// waits. The suspended outer handler may already hold its pending response in
// the shared RESP_INIT arena, so the debug reply must not be built there.
TEST(Fsm, DebugLinkGetStateLeavesPendingResponseIntact) {
  kk_test_board_init();
  fsm_init();
  ScopedFlash flash;
  size_t size = 0;
  uint8_t* arena = fsm_test_responseArena(&size);
  ASSERT_NE(nullptr, arena);
  ASSERT_GT(size, 0u);
  std::memset(arena, 0x5a, size);
  DebugLinkGetState get = {};
  fsm_msgDebugLinkGetState(&get);
  for (size_t i = 0; i < size; ++i) ASSERT_EQ(0x5a, arena[i]) << "offset " << i;
}

class AutoLockProgress : public ::testing::Test {
 protected:
  void SetUp() override {
    kk_test_board_init();
    fsm_init();
    layoutHomeForced();
    storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
    keepkey_user_activity();  // the press that approved the SignTx
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

// Plays the host: waits for the next PIN prompt, then sends `pin` as matrix
// positions, the way a host relays the user's clicks on the scrambled grid.
std::thread answerPinPrompt(const char* pin) {
  return std::thread([pin] {
    for (int tries = 0; tries < 5000; tries++, usleep(1000)) {
      if (std::strcmp(get_pin_matrix(), "XXXXXXXXX") == 0) continue;
      usleep(50000);  // let the prompt finish shuffling
      const std::string matrix = get_pin_matrix();
      std::string positions;
      for (const char* d = pin; *d; d++)
        positions += (char)('1' + matrix.find(*d));
      uint8_t ack[2 + 9] = {0x0a, (uint8_t)positions.size()};
      std::memcpy(&ack[2], positions.data(), positions.size());
      kkconfirm_sendTiny(MessageType_MessageType_PinMatrixAck, ack,
                         (uint8_t)(2 + positions.size()));
      return;
    }
  });
}

// Locks a PIN-protected session by idling, then unlocks it with a protected
// Ping answered with `pin`.
void lockThenEnterPin(const char* pin) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  storage_setPin("1234");
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  layoutHomeForced();
  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  toggle_screensaver();
  ASSERT_EQ(SCREENSAVER, home_get_state());
  ASSERT_FALSE(session_isPinCached());

  Ping ping = {};
  ping.has_pin_protection = true;
  ping.pin_protection = true;
  std::thread host = answerPinPrompt(pin);
  fsm_test_clearLastFailure();
  receiveMessage(MessageType_MessageType_Ping, Ping_fields, &ping);
  host.join();
}
}  // namespace

// Host-side PIN entry presses no button, so without this the device would
// re-lock on the next main-loop tick after every unlock.
TEST(Fsm, CorrectPinAfterAutoLockRenewsTheDeadline) {
  ScopedFlash flash;
  lockThenEnterPin("1234");
  ASSERT_EQ((FailureType)0, fsm_test_lastFailureCode());
  ASSERT_TRUE(session_isPinCached());

  toggle_screensaver();
  EXPECT_NE(SCREENSAVER, home_get_state());
  EXPECT_TRUE(session_isPinCached());
  layoutHomeForced();
}

// Time spent nested in a long wait never reaches the main loop: a U2F frame
// stretched to its timeout, a prompt the host leaves open. Each main-loop pass
// must charge the real time since the last one, not a single tick, or a host
// can keep a PIN-unlocked session alive indefinitely without the user.
TEST(Fsm, AutoLockCountsTimeSpentOutsideTheMainLoop) {
  kk_test_board_init();
  ScopedFlash flash;
  fsm_init();
  storage_setPin("1234");
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  layoutHomeForced();
  keepkey_user_activity();

  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT / 2);  // nested stall
  toggle_screensaver();                                // one main-loop pass
  ASSERT_EQ(AT_HOME, home_get_state());
  ASSERT_TRUE(session_isPinCached());

  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT / 2);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
  EXPECT_FALSE(session_isPinCached());
  layoutHomeForced();
}

TEST(Fsm, UserActivityRenewsTheAutoLockDeadline) {
  kk_test_board_init();
  fsm_init();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  layoutHomeForced();
  keepkey_user_activity();

  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  keepkey_user_activity();
  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  ASSERT_EQ(AT_HOME, home_get_state());

  advance_clock(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
  layoutHomeForced();
}

// The ms counter wraps after ~49.7 days of uptime; a deadline that straddles
// the wrap must still expire on time.
TEST(Fsm, AutoLockDeadlineSurvivesClockWrap) {
  kk_test_board_init();
  fsm_init();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  layoutHomeForced();
  advance_clock(0u - fake_clock_ms - STORAGE_MIN_SCREENSAVER_TIMEOUT / 2);
  keepkey_user_activity();

  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  ASSERT_LT(fake_clock_ms, STORAGE_MIN_SCREENSAVER_TIMEOUT) << "no wrap";
  toggle_screensaver();
  ASSERT_EQ(AT_HOME, home_get_state());

  advance_clock(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
  layoutHomeForced();
}

TEST(Fsm, WrongPinAfterAutoLockDoesNotRenewTheDeadline) {
  ScopedFlash flash;
  lockThenEnterPin("5678");
  ASSERT_EQ(FailureType_Failure_PinInvalid, fsm_test_lastFailureCode());
  ASSERT_FALSE(session_isPinCached());

  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
  layoutHomeForced();
}

// An ECDSA message signature has no taproot form; labelling one with a bc1p
// address yields a signature that can never verify.
TEST(Fsm, SignMessageRefusesTaprootBeforeAnyScreen) {
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ScopedFlash flash;
  LoadDevice load = {};
  load.has_mnemonic = true;
  std::strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);
  storage_commit();

  SignMessage msg = {};
  const uint32_t path[] = {0x80000056, 0x80000000, 0x80000000, 0, 0};
  std::memcpy(msg.address_n, path, sizeof(path));
  msg.address_n_count = 5;
  msg.message.size = 5;
  std::memcpy(msg.message.bytes, "hello", 5);
  msg.has_script_type = true;
  msg.script_type = InputScriptType_SPENDTAPROOT;
  fsm_test_clearLastFailure();
  receiveMessage(MessageType_MessageType_SignMessage, SignMessage_fields, &msg);

  EXPECT_EQ(FailureType_Failure_SyntaxError, fsm_test_lastFailureCode());
  EXPECT_EQ(2, kkconfirm_drain())  // one screen's ButtonAck + decision
      << "no confirmation may be shown";
}

TEST_F(AutoLockProgress, FeaturePollingCannotKeepStalledSigningUnlocked) {
  GetFeatures poll = {};
  for (int i = 0; i < 3; ++i) {
    advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT / 4);
    receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                   &poll);
    ASSERT_EQ(AWAY_FROM_HOME, home_get_state());
    ASSERT_TRUE(signing_is_active());
    toggle_screensaver();
  }
  // The poll that arrives at the deadline is answered by a locked device.
  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT / 4);
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &poll);
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, IncompleteFrameCannotKeepStalledSigningUnlocked) {
  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  // Valid Ping header, but its 60-byte payload has not arrived in full.
  uint8_t frame[64] = {'?', '#', '#', 0, 1, 0, 0, 0, 60};
  usb_test_receive(frame, sizeof(frame));
  ASSERT_TRUE(signing_is_active());
  advance_clock(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
  // Finish the pending transport message so it cannot affect later tests.
  uint8_t tail[64] = {'?'};
  usb_test_receive(tail, sizeof(tail));
}

// A stream still making validated progress is not locked mid-flow, but a
// stall of one full delay is.
TEST_F(AutoLockProgress, ValidBitcoinStreamProgressDefersTheLockMidFlow) {
  TxAck ack = {};
  ack.has_tx = true;
  ack.tx.inputs_count = 1;
  ack.tx.inputs[0].prev_hash.size = 32;
  ack.tx.inputs[0].has_script_type = true;
  ack.tx.inputs[0].script_type = InputScriptType_SPENDADDRESS;
  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &ack);
  ASSERT_TRUE(signing_is_active());
  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  ASSERT_TRUE(signing_is_active());

  // Real next stage: supply metadata for the requested previous transaction.
  ack = {};
  ack.has_tx = true;
  ack.tx.has_inputs_cnt = ack.tx.has_outputs_cnt = true;
  ack.tx.inputs_cnt = ack.tx.outputs_cnt = 1;
  receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &ack);
  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  ASSERT_TRUE(signing_is_active());
  advance_clock(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, FeaturePollingAtHomeDoesNotRenewTheIdleDeadline) {
  signing_abort();
  layoutHomeForced();
  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  GetFeatures poll = {};
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &poll);
  advance_clock(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, PingCannotRenewAStalledSigningDeadline) {
  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  Ping ping = {};
  receiveMessage(MessageType_MessageType_Ping, Ping_fields, &ping);
  advance_clock(1);
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
  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  layoutHome();
  leave_home();
  advance_clock(1);
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

  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  GetAddress malformed = {};
  malformed.has_multisig = true;
  fsm_test_clearLastFailure();
  receiveMessage(MessageType_MessageType_GetAddress, GetAddress_fields,
                 &malformed);
  EXPECT_EQ(FailureType_Failure_Other, fsm_test_lastFailureCode())
      << "the request must reach the multisig rejection, not an earlier gate";
  advance_clock(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, InvalidBitcoinAckEndsTheStream) {
  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  TxAck invalid = {};
  invalid.has_tx = true;
  // Decodable protobuf, but the required 32-byte previous hash is missing.
  invalid.tx.inputs_count = 1;
  receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &invalid);
  EXPECT_FALSE(signing_is_active());
  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, RecoveryEditsDeferButPollingAndEmptyDeleteDoNot) {
  signing_abort();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  recovery_cipher_init(12, false, false, "english", "idle test", false,
                       STORAGE_MIN_SCREENSAVER_TIMEOUT, 0, false);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  ASSERT_EQ(0, kkconfirm_drain());
  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  CharacterAck character = {};
  character.has_character = true;
  character.character[0] = 'a';  // Every a-z character belongs to the cipher.
  receiveMessage(MessageType_MessageType_CharacterAck, CharacterAck_fields,
                 &character);
  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  character = {};
  character.has_delete = character.del = true;
  receiveMessage(MessageType_MessageType_CharacterAck, CharacterAck_fields,
                 &character);
  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  // The mnemonic is now empty: another delete makes no progress.
  receiveMessage(MessageType_MessageType_CharacterAck, CharacterAck_fields,
                 &character);
  GetFeatures poll = {};
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &poll);
  advance_clock(1);
  toggle_screensaver();
  EXPECT_FALSE(setup_isArmed());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

namespace {
// Starts a non-segwit input and answers the previous-transaction metadata
// request with a large but well-formed prev tx, so every further TxAck is a
// genuine, validated stage the host can pace as it likes without a button.
void startLongPrevTxStream(TxAck* prev_input) {
  TxAck ack = {};
  ack.has_tx = true;
  ack.tx.inputs_count = 1;
  ack.tx.inputs[0].prev_hash.size = 32;
  ack.tx.inputs[0].has_script_type = true;
  ack.tx.inputs[0].script_type = InputScriptType_SPENDADDRESS;
  receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &ack);
  ASSERT_TRUE(signing_is_active());
  ack = {};
  ack.has_tx = true;
  ack.tx.has_inputs_cnt = ack.tx.has_outputs_cnt = true;
  ack.tx.inputs_cnt = 1000;
  ack.tx.outputs_cnt = 1;
  receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &ack);
  ASSERT_TRUE(signing_is_active());
  *prev_input = {};
  prev_input->has_tx = true;
  prev_input->tx.inputs_count = 1;
  prev_input->tx.inputs[0].prev_hash.size = 32;
}

void loadPinProtectedWallet(void) {
  LoadDevice load = {};
  load.has_mnemonic = true;
  std::strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);
  storage_setPin("1234");
  storage_commit();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
}

// Asks for an xpub with a Cancel already queued for any PIN prompt. Returns
// the failure code: 0 means the key was served from the cached PIN.
FailureType requestPublicKey(void) {
  kkconfirm_sendTiny(MessageType_MessageType_Cancel, nullptr, 0);
  GetPublicKey get = {};
  const uint32_t path[] = {0x8000002c, 0x80000000, 0x80000000};
  std::memcpy(get.address_n, path, sizeof(path));
  get.address_n_count = 3;
  fsm_test_clearLastFailure();
  receiveMessage(MessageType_MessageType_GetPublicKey, GetPublicKey_fields,
                 &get);
  const FailureType code = fsm_test_lastFailureCode();
  // Drop the Cancel if the request never prompted for it.
  kkconfirm_preload(0, 0);
  kkconfirm_drain();
  return code;
}
}  // namespace

// F1: validated stream progress is host-driven. Pacing it past the deadline
// with no button press, then ending it with Initialize, must leave a locked
// session: the very next PIN-gated read prompts for the PIN, even before the
// main loop gets a pass.
TEST_F(AutoLockProgress, HostPacedSigningStreamCannotKeepThePinCached) {
  ScopedFlash flash;
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  signing_abort();
  loadPinProtectedWallet();
  keepkey_user_activity();
  SignTx start = {};
  start.inputs_count = start.outputs_count = 1;
  HDNode root = {};
  const uint8_t seed[32] = {1};
  ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &root));
  signing_init(&start, coinByName("Bitcoin"), &root);
  leave_home();

  TxAck prev_input;
  startLongPrevTxStream(&prev_input);
  for (int i = 0; i < 4; ++i) {
    advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2000);
    receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &prev_input);
    toggle_screensaver();
    ASSERT_TRUE(signing_is_active()) << "locked mid-flow at ack " << i;
    ASSERT_TRUE(session_isPinCached());
  }

  Initialize init = {};
  receiveMessage(MessageType_MessageType_Initialize, Initialize_fields, &init);
  EXPECT_FALSE(signing_is_active());
  EXPECT_FALSE(session_isPinCached())
      << "the stream ended past the deadline; the session must lock now";
  EXPECT_NE((FailureType)0, requestPublicKey())
      << "an expired deadline served an xpub from the cached PIN";
  EXPECT_FALSE(session_isPinCached());
}

// The same stream, but the user pressed the button partway through: the
// deadline runs from that press, so ending the stream inside it is no lock.
TEST_F(AutoLockProgress, ButtonPressDuringAStreamRenewsTheDeadline) {
  ScopedFlash flash;
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  signing_abort();
  loadPinProtectedWallet();
  keepkey_user_activity();
  SignTx start = {};
  start.inputs_count = start.outputs_count = 1;
  HDNode root = {};
  const uint8_t seed[32] = {1};
  ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &root));
  signing_init(&start, coinByName("Bitcoin"), &root);
  leave_home();

  TxAck prev_input;
  startLongPrevTxStream(&prev_input);
  for (int i = 0; i < 3; ++i) {
    advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2000);
    receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &prev_input);
    toggle_screensaver();
    ASSERT_TRUE(signing_is_active());
  }
  keepkey_user_activity();
  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2000);
  receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &prev_input);

  Initialize init = {};
  receiveMessage(MessageType_MessageType_Initialize, Initialize_fields, &init);
  EXPECT_FALSE(signing_is_active());
  EXPECT_TRUE(session_isPinCached());
  toggle_screensaver();
  EXPECT_NE(SCREENSAVER, home_get_state());
  EXPECT_TRUE(session_isPinCached());

  advance_clock(2000);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
  EXPECT_FALSE(session_isPinCached());
}

// A host-paced stream past the deadline, then a Ping that needs the PIN. The
// gate lets Ping through without ending the stream, so the Ping handler must
// lock before its PIN check, or one PIN-gated answer is served on the cached
// PIN.
static void expectPingPastTheStreamDeadlineNeedsThePin(const Ping& ping) {
  ScopedFlash flash;
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  signing_abort();
  loadPinProtectedWallet();
  keepkey_user_activity();
  SignTx start = {};
  start.inputs_count = start.outputs_count = 1;
  HDNode root = {};
  const uint8_t seed[32] = {1};
  ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &root));
  signing_init(&start, coinByName("Bitcoin"), &root);
  leave_home();

  TxAck prev_input;
  startLongPrevTxStream(&prev_input);
  for (int i = 0; i < 2; ++i) {
    advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2000);
    receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &prev_input);
    toggle_screensaver();
    ASSERT_TRUE(signing_is_active()) << "locked mid-flow at ack " << i;
    ASSERT_TRUE(session_isPinCached());
  }

  kkconfirm_sendTiny(MessageType_MessageType_Cancel, nullptr, 0);
  fsm_test_clearLastFailure();
  receiveMessage(MessageType_MessageType_Ping, Ping_fields, &ping);
  const FailureType code = fsm_test_lastFailureCode();
  kkconfirm_preload(0, 0);
  kkconfirm_drain();

  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(FailureType_Failure_PinCancelled, code)
      << "the Ping was answered from the PIN cached before the deadline";
  EXPECT_FALSE(session_isPinCached());
}

TEST_F(AutoLockProgress, AuthenticatorPingPastAStreamDeadlineNeedsThePin) {
  Ping ping = {};
  ping.has_message = true;
  std::strcpy(ping.message, "\x17getAccount:0");
  expectPingPastTheStreamDeadlineNeedsThePin(ping);
}

TEST_F(AutoLockProgress, PinProtectedPingPastAStreamDeadlineNeedsThePin) {
  Ping ping = {};
  ping.has_pin_protection = ping.pin_protection = true;
  expectPingPastTheStreamDeadlineNeedsThePin(ping);
}

#if !BITCOIN_ONLY
// Progress belongs to the workflow that made it. Bitcoin progress just before
// the deadline must not defer the lock for a Cosmos sign started after the
// Bitcoin stream was aborted; Cosmos never notes progress of its own.
TEST_F(AutoLockProgress, AbortedStreamProgressDoesNotDeferTheNextWorkflow) {
  TxAck ack = {};
  ack.has_tx = true;
  ack.tx.inputs_count = 1;
  ack.tx.inputs[0].prev_hash.size = 32;
  ack.tx.inputs[0].has_script_type = true;
  ack.tx.inputs[0].script_type = InputScriptType_SPENDADDRESS;
  advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1000);
  receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &ack);
  ASSERT_TRUE(signing_is_active());

  fsm_abort_workflows();

  HDNode node = {};
  node.curve = &secp256k1_info;
  TendermintSignTx cosmos = {};
  cosmos.has_msg_count = true;
  cosmos.msg_count = 1;
  cosmos.has_chain_id = true;
  std::strcpy(cosmos.chain_id, "cosmoshub-4");
  cosmos.has_chain_name = true;
  std::strcpy(cosmos.chain_name, "Cosmos");
  cosmos.has_denom = true;
  std::strcpy(cosmos.denom, "uatom");
  cosmos.has_message_type_prefix = true;
  std::strcpy(cosmos.message_type_prefix, "cosmos-sdk");
  ASSERT_TRUE(tendermint_signTxInit(&node, &cosmos, sizeof(cosmos), "uatom",
                                    TENDERMINT_SIGNING_GENERIC));

  advance_clock(1000);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state())
      << "the aborted Bitcoin stream's progress deferred the Cosmos sign";
  EXPECT_FALSE(tendermint_signingIsInited(TENDERMINT_SIGNING_GENERIC));
}
#endif

// Recovery words are typed on the host. They keep the ceremony from locking
// mid-entry, but once it ends the deadline still runs from the last press.
TEST_F(AutoLockProgress, RecoveryCharacterStreamDoesNotRenewTheDeadline) {
  signing_abort();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  recovery_cipher_init(12, false, false, "english", "idle test", false,
                       STORAGE_MIN_SCREENSAVER_TIMEOUT, 0, false);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  ASSERT_EQ(0, kkconfirm_drain());
  keepkey_user_activity();  // the press that confirmed the recovery
  for (int i = 0; i < 4; ++i) {
    advance_clock(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2000);
    // Type a letter, then delete it: every message is a real edit.
    CharacterAck character = {};
    if (i % 2 == 0) {
      character.has_character = true;
      character.character[0] = 'a';
    } else {
      character.has_delete = character.del = true;
    }
    receiveMessage(MessageType_MessageType_CharacterAck, CharacterAck_fields,
                   &character);
    toggle_screensaver();
    ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY)) << "locked mid-entry " << i;
  }

  Cancel cancel = {};
  receiveMessage(MessageType_MessageType_Cancel, Cancel_fields, &cancel);
  EXPECT_FALSE(setup_isArmed());
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state())
      << "host-typed characters renewed the deadline";
}

// F2: a nested wait that never returns to the main loop (a confirm left up,
// a U2F exchange kept alive by pings) can outlast the 2^32 ms counter. Its
// poll loop must keep sampling the clock, or the main loop's one subtraction
// sees the wrapped remainder: here, 5 s.
TEST(Fsm, NestedWaitLongerThanTheClockWrapStillLocks) {
  kk_test_board_init();
  ScopedFlash flash;
  fsm_init();
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  storage_setPin("1234");
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  layoutHomeForced();
  keepkey_user_activity();

  uint8_t buf[MSG_TINY_BFR_SZ];
  for (int i = 0; i < 4; ++i) {  // the nested wait's own poll iterations
    advance_clock(1u << 30);
    check_for_tiny_msg(buf);
  }
  advance_clock(5000);
  toggle_screensaver();  // back in the main loop: 2^32 + 5000 ms later
  EXPECT_EQ(SCREENSAVER, home_get_state());
  EXPECT_FALSE(session_isPinCached());
  layoutHomeForced();
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

  // Authenticator account changes persist too; storage_commit() would drop
  // them silently, so the command must be refused rather than succeed.
  Ping auth = {};
  auth.has_message = true;
  std::strcpy(auth.message, "\x15initializeAuth:JBSWY3DPEHPK3PXP");
  fsm_test_clearLastFailure();
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  fsm_msgPing(&auth);
  EXPECT_EQ(0, kkconfirm_drain());
  EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode())
      << "an authenticator write on a locked wallet must be refused";

  storage_wipe();
  EXPECT_FALSE(storage_isBitcoinOnlyLocked());
  layoutHomeForced();
}
