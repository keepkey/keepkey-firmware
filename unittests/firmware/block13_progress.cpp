#include "gtest/gtest.h"

extern "C" {
#include "keepkey/board/memory.h"
#include "keepkey/board/usb.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/pin_sm.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/rand/rng_health.h"
#include "pb_encode.h"
#if !BITCOIN_ONLY
#include "keepkey/firmware/binance.h"
#include "keepkey/firmware/mayachain.h"
#include "keepkey/firmware/osmosis.h"
#include "keepkey/firmware/signtx_tendermint.h"
#include "keepkey/firmware/tendermint.h"
#include "keepkey/firmware/thorchain.h"
// Generic Tendermint handlers are compiled but are not in messagemap.def.
void fsm_msgTendermintSignTx(const TendermintSignTx* msg);
void fsm_msgTendermintMsgAck(const TendermintMsgAck* msg);
#endif
}

#include <algorithm>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

void kk_test_board_init(void);
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);
std::thread kkconfirm_answerPinMatrix(const std::string& pin);

namespace {
constexpr uint32_t kDeadline = STORAGE_MIN_SCREENSAVER_TIMEOUT;

void receiveProgressMessage(MessageType type, const pb_field_t* fields,
                            const void* message) {
  uint8_t encoded[4096] = {};
  pb_ostream_t stream = pb_ostream_from_buffer(encoded, sizeof(encoded));
  ASSERT_TRUE(pb_encode(&stream, fields, message));
  uint8_t frame[64] = {'?', '#', '#'};
  frame[3] = type >> 8;
  frame[4] = type & 0xff;
  size_t size = stream.bytes_written;
  frame[5] = size >> 24;
  frame[6] = size >> 16;
  frame[7] = size >> 8;
  frame[8] = size;
  size_t sent = std::min(size, sizeof(frame) - 9);
  std::memcpy(frame + 9, encoded, sent);
  usb_test_receive(frame, sizeof(frame));
  while (sent < size) {
    std::memset(frame + 1, 0, sizeof(frame) - 1);
    size_t chunk = std::min(size - sent, sizeof(frame) - 1);
    std::memcpy(frame + 1, encoded + sent, chunk);
    usb_test_receive(frame, sizeof(frame));
    sent += chunk;
  }
}

class Block13ResetProgress : public ::testing::Test {
 protected:
  std::vector<uint8_t> flash = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  uint8_t* previous_flash = nullptr;

  void SetUp() override {
    kk_test_board_init();
    fsm_init();
    fsm_abort_workflows();
    previous_flash = emulator_flash_base;
    emulator_flash_base = flash.data();
    storage_init();
    storage_reset();
    layoutHomeForced();
    reset_idle_time();
    storage_setAutoLockDelayMs(kDeadline);
    fsm_test_clearLastFailure();
  }
  void TearDown() override {
    fsm_abort_workflows();
    kkconfirm_drain();
    storage_reset();
    emulator_flash_base = previous_flash;
    layoutHomeForced();
    reset_idle_time();
  }
  void StartReset() {
    ResetDevice start = {};
    start.has_strength = true;
    start.strength = 128;
    start.has_auto_lock_delay_ms = true;
    start.auto_lock_delay_ms = kDeadline;
    receiveProgressMessage(MessageType_MessageType_ResetDevice,
                           ResetDevice_fields, &start);
    ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
    ASSERT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
  }
  void Poll() {
    GetFeatures features = {};
    receiveProgressMessage(MessageType_MessageType_GetFeatures,
                           GetFeatures_fields, &features);
    Ping ping = {};
    receiveProgressMessage(MessageType_MessageType_Ping, Ping_fields, &ping);
  }
};

TEST_F(Block13ResetProgress, InitialRequestRenewsThenPollingExpires) {
  increment_idle_time(kDeadline - 1);
  StartReset();
  increment_idle_time(1);
  toggle_screensaver();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  EXPECT_NE(SCREENSAVER, home_get_state());
  increment_idle_time(kDeadline - 1);
  Poll();
  toggle_screensaver();
  EXPECT_FALSE(setup_isArmed());
  EXPECT_EQ(SCREENSAVER, home_get_state());
  EXPECT_FALSE(storage_isInitialized());
}

// Host PIN entry after an idle lock: the request leaves home, the reply
// returns to it, and no button is pressed. The unlock must survive the next
// tick (hardware 2026-10-03: every host unlock after 10 idle minutes relocked
// ~3.5 s later and the host asked for the PIN forever). The PIN goes through
// pin_protect(), so dropping its renewal call fails this test.
TEST_F(Block13ResetProgress, AcceptedPinAfterIdleLockHoldsThroughNextTick) {
  storage_setPin("1234");
  auto unlockAfterIdleLock = [](bool pinAccepted) {
    reset_idle_time();
    increment_idle_time(kDeadline);
    toggle_screensaver();
    EXPECT_EQ(SCREENSAVER, home_get_state());
    leave_home();
    if (pinAccepted) {
      std::thread host = kkconfirm_answerPinMatrix("1234");
      EXPECT_TRUE(pin_protect("Enter PIN"));
      host.join();
    }
    layoutHome();
    toggle_screensaver();
    return home_get_state();
  };
  EXPECT_EQ(SCREENSAVER, unlockAfterIdleLock(false));  // control: the bug
  EXPECT_NE(SCREENSAVER, unlockAfterIdleLock(true));
}

TEST_F(Block13ResetProgress, EntropyReplyAdvancesOnceIncludingAbsentAndEmpty) {
  // The protocol permits no host contribution. All three replies advance to
  // backup review once; they are not repeatable empty-chunk keepalives.
  for (int payload : {0, 1, 2}) {
    SCOPED_TRACE(payload);
    setup_abort();
    layoutHomeForced();
    reset_idle_time();
    fsm_test_clearLastFailure();
    StartReset();
    ASSERT_TRUE(kkconfirm_preload(0, 1));  // Decline backup, avoiding a commit.
    increment_idle_time(kDeadline - 1);
    EntropyAck ack = {};
    ack.has_entropy = payload != 0;
    ack.entropy.size = payload == 2 ? 32 : 0;
    receiveProgressMessage(MessageType_MessageType_EntropyAck,
                           EntropyAck_fields, &ack);
    EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
    EXPECT_FALSE(setup_isArmed());
    EXPECT_FALSE(storage_isInitialized());
    EXPECT_EQ(0, kkconfirm_drain());
    increment_idle_time(1);
    toggle_screensaver();
    ASSERT_NE(SCREENSAVER, home_get_state());
    increment_idle_time(kDeadline - 1);
    // A replay cannot turn accepted phase progress into an indefinite lease.
    receiveProgressMessage(MessageType_MessageType_EntropyAck,
                           EntropyAck_fields, &ack);
    EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode());
    toggle_screensaver();
    EXPECT_EQ(SCREENSAVER, home_get_state());
  }
}

TEST_F(Block13ResetProgress, InvalidInitialRequestDoesNotRenew) {
  ResetDevice invalid = {};
  invalid.has_strength = true;
  invalid.strength = 129;
  increment_idle_time(kDeadline - 1);
  receiveProgressMessage(MessageType_MessageType_ResetDevice,
                         ResetDevice_fields, &invalid);
  EXPECT_EQ(FailureType_Failure_SyntaxError, fsm_test_lastFailureCode());
  EXPECT_FALSE(setup_isArmed());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

#if !BITCOIN_ONLY

enum class ProgressChain { Binance, Cosmos, Osmosis, Thorchain, Mayachain,
                           TendermintDirectHandler };

template <typename T>
T signingEnvelope(const char* chain, bool valid = true) {
  T msg = {};
  msg.has_account_number = msg.has_chain_id = msg.has_fee_amount = true;
  msg.has_gas = msg.has_sequence = msg.has_msg_count = true;
  msg.account_number = msg.sequence = 1;
  msg.fee_amount = 1;
  msg.gas = 200000;
  msg.msg_count = valid ? 4 : 0;
  std::strcpy(msg.chain_id, chain);
  return msg;
}

class Block13CoinProgress : public Block13ResetProgress,
                            public ::testing::WithParamInterface<ProgressChain> {
 protected:
  void SetUp() override {
    Block13ResetProgress::SetUp();
    LoadDevice load = {};
    load.has_mnemonic = true;
    std::strcpy(load.mnemonic, "all all all all all all all all all all all all");
    storage_loadDevice(&load);
    storage_commit();
    storage_setAutoLockDelayMs(kDeadline);
    ASSERT_TRUE(storage_isInitialized());
  }

  void Start(bool valid = true) {
    fsm_test_clearLastFailure();
#define START_WIRE(NAME, CHAIN) do { \
    auto msg = signingEnvelope<NAME##SignTx>(CHAIN, valid); \
    receiveProgressMessage(MessageType_MessageType_##NAME##SignTx, \
                           NAME##SignTx_fields, &msg); \
  } while (0)
    switch (GetParam()) {
      case ProgressChain::Binance: {
        BinanceSignTx msg = {};
        msg.has_account_number = msg.has_chain_id = msg.has_sequence = true;
        msg.has_source = msg.has_msg_count = true;
        msg.msg_count = valid ? 4 : 0;
        std::strcpy(msg.chain_id, "Binance-Chain-Tigris");
        receiveProgressMessage(MessageType_MessageType_BinanceSignTx,
                               BinanceSignTx_fields, &msg);
        break;
      }
      case ProgressChain::Cosmos: START_WIRE(Cosmos, "cosmoshub-4"); break;
      case ProgressChain::Osmosis: START_WIRE(Osmosis, "osmosis-1"); break;
      case ProgressChain::Thorchain: START_WIRE(Thorchain, "thorchain-1"); break;
      case ProgressChain::Mayachain: START_WIRE(Mayachain, "mayachain-mainnet-v1"); break;
      case ProgressChain::TendermintDirectHandler: {
        auto msg = signingEnvelope<TendermintSignTx>("cosmoshub-4", valid);
        msg.has_chain_name = msg.has_denom = msg.has_message_type_prefix = true;
        std::strcpy(msg.chain_name, "Cosmos");
        std::strcpy(msg.denom, "uatom");
        std::strcpy(msg.message_type_prefix, "cosmos-sdk");
        fsm_msgTendermintSignTx(&msg);
        break;
      }
    }
#undef START_WIRE
  }
  bool Active() {
    switch (GetParam()) {
      case ProgressChain::Binance: return binance_signingIsInited();
      case ProgressChain::Cosmos: return tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS);
      case ProgressChain::Osmosis: return osmosis_signingIsInited();
      case ProgressChain::Thorchain: return thorchain_signingIsInited();
      case ProgressChain::Mayachain: return mayachain_signingIsInited();
      case ProgressChain::TendermintDirectHandler: return tendermint_signingIsInited(TENDERMINT_SIGNING_GENERIC);
    }
    return false;
  }
  std::string Address(const char* prefix) {
    HDNode node = {};
    if (!storage_getRootNode("secp256k1", true, &node)) return "";
    hdnode_fill_public_key(&node);
    char address[128] = {};
    if (!tendermint_getAddress(&node, prefix, address)) return "";
    return address;
  }
  // mode: valid, absent message payload, or malformed recipient before review.
  void Continue(int mode = 0) {
    const char* bad = "invalid";
#define SEND_WIRE(NAME, PREFIX) do { \
    NAME##MsgAck msg = {}; \
    if (mode != 1) { \
      msg.has_send = true; \
      msg.send.has_to_address = msg.send.has_amount = true; \
      msg.send.amount = 1; \
      std::strcpy(msg.send.to_address, mode == 2 ? bad : Address(PREFIX).c_str()); \
    } \
    receiveProgressMessage(MessageType_MessageType_##NAME##MsgAck, \
                           NAME##MsgAck_fields, &msg); \
  } while (0)
    switch (GetParam()) {
      case ProgressChain::Binance: {
        BinanceTransferMsg msg = {};
        if (mode != 1) {
          msg.inputs_count = msg.outputs_count = 1;
          for (auto* io : {&msg.inputs[0], &msg.outputs[0]}) {
            io->has_address = true;
            std::strcpy(io->address, Address("bnb").c_str());
            io->coins_count = 1;
            io->coins[0].has_amount = io->coins[0].has_denom = true;
            io->coins[0].amount = 1;
            std::strcpy(io->coins[0].denom, "BNB");
          }
          if (mode == 2) std::strcpy(msg.outputs[0].address, bad);
        }
        receiveProgressMessage(MessageType_MessageType_BinanceTransferMsg,
                               BinanceTransferMsg_fields, &msg);
        break;
      }
      case ProgressChain::Cosmos: SEND_WIRE(Cosmos, "cosmos"); break;
      case ProgressChain::Thorchain: SEND_WIRE(Thorchain, "thor"); break;
      case ProgressChain::Mayachain: {
        MayachainMsgAck msg = {};
        if (mode != 1) {
          msg.has_send = true;
          msg.send.has_to_address = msg.send.has_amount = msg.send.has_denom = true;
          msg.send.amount = 1;
          std::strcpy(msg.send.denom, "cacao");
          std::strcpy(msg.send.to_address, mode == 2 ? bad : Address("maya").c_str());
        }
        receiveProgressMessage(MessageType_MessageType_MayachainMsgAck,
                               MayachainMsgAck_fields, &msg);
        break;
      }
      case ProgressChain::Osmosis: {
        OsmosisMsgAck msg = {};
        if (mode != 1) {
          msg.has_send = true;
          msg.send.has_to_address = msg.send.has_amount = msg.send.has_denom = true;
          std::strcpy(msg.send.to_address, mode == 2 ? bad : Address("osmo").c_str());
          std::strcpy(msg.send.amount, "1");
          std::strcpy(msg.send.denom, "uosmo");
        }
        receiveProgressMessage(MessageType_MessageType_OsmosisMsgAck,
                               OsmosisMsgAck_fields, &msg);
        break;
      }
      case ProgressChain::TendermintDirectHandler: {
        TendermintMsgAck msg = {};
        msg.has_chain_name = msg.has_denom = msg.has_message_type_prefix = true;
        std::strcpy(msg.chain_name, "Cosmos");
        std::strcpy(msg.denom, "uatom");
        std::strcpy(msg.message_type_prefix, "cosmos-sdk");
        if (mode != 1) {
          msg.has_send = true;
          msg.send.has_to_address = msg.send.has_amount = true;
          msg.send.amount = 1;
          std::strcpy(msg.send.to_address, mode == 2 ? bad : Address("cosmos").c_str());
        }
        fsm_msgTendermintMsgAck(&msg);
        break;
      }
    }
#undef SEND_WIRE
  }
  int ReviewCount() {
    return GetParam() == ProgressChain::Thorchain ||
           GetParam() == ProgressChain::Mayachain ? 2 : 1;
  }
};

TEST_P(Block13CoinProgress, AcceptedInitialRequestRenewsDeadline) {
  increment_idle_time(kDeadline - 1);
  Start();
  ASSERT_TRUE(Active());
  ASSERT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
  increment_idle_time(1);
  toggle_screensaver();
  ASSERT_TRUE(Active());
  increment_idle_time(kDeadline - 1);
  Poll();
  toggle_screensaver();
  EXPECT_FALSE(Active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_P(Block13CoinProgress, InvalidInitialRequestCannotRenewDeadline) {
  increment_idle_time(kDeadline - 1);
  Start(false);
  EXPECT_FALSE(Active());
  EXPECT_NE(0, static_cast<int>(fsm_test_lastFailureCode()));
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_P(Block13CoinProgress, AcceptedContinuationsRenewThenPollingExpires) {
  Start();
  ASSERT_TRUE(Active());
  for (int i = 0; i < 2; ++i) {
    ASSERT_TRUE(kkconfirm_preload(ReviewCount(), 0));
    increment_idle_time(kDeadline - 1);
    Continue();
    EXPECT_EQ(0, kkconfirm_drain());
    ASSERT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
    increment_idle_time(1);
    toggle_screensaver();
    ASSERT_TRUE(Active());
  }
  increment_idle_time(kDeadline - 1);
  Poll();
  toggle_screensaver();
  EXPECT_FALSE(Active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_P(Block13CoinProgress, EmptyAndInvalidContinuationsAbortWithoutRenewal) {
  for (int mode : {1, 2}) {
    SCOPED_TRACE(mode);
    layoutHomeForced();
    reset_idle_time();
    Start();
    ASSERT_TRUE(Active());
    ASSERT_TRUE(kkconfirm_preload(0, 1));
    increment_idle_time(kDeadline - 1);
    Continue(mode);
    EXPECT_EQ(2, kkconfirm_drain()) << "invalid input reached a review";
    EXPECT_FALSE(Active());
    EXPECT_NE(0, static_cast<int>(fsm_test_lastFailureCode()));
    increment_idle_time(1);
    toggle_screensaver();
    EXPECT_EQ(SCREENSAVER, home_get_state());
  }
}

TEST_P(Block13CoinProgress, DeclinedContinuationCannotRenewAndFreshRetryWorks) {
  Start();
  ASSERT_TRUE(Active());
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  increment_idle_time(kDeadline - 1);
  Continue();
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_FALSE(Active());
  EXPECT_EQ(0, kkconfirm_drain());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
  layoutHomeForced();
  reset_idle_time();
  Start();
  ASSERT_TRUE(Active());
  ASSERT_TRUE(kkconfirm_preload(ReviewCount(), 0));
  Continue();
  EXPECT_EQ(0, kkconfirm_drain());
  EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
  EXPECT_TRUE(Active());
}

INSTANTIATE_TEST_CASE_P(
    Chains, Block13CoinProgress,
    ::testing::Values(ProgressChain::Binance, ProgressChain::Cosmos,
                      ProgressChain::Osmosis, ProgressChain::Thorchain,
                      ProgressChain::Mayachain,
                      ProgressChain::TendermintDirectHandler),
    [](const ::testing::TestParamInfo<ProgressChain>& p) {
      const char* names[] = {"Binance", "Cosmos", "Osmosis", "Thorchain",
                             "Mayachain", "TendermintDirectHandler"};
      return names[static_cast<int>(p.param)];
    });

TEST_F(Block13ResetProgress, GenericTendermintWireSurfaceRemainsUnmapped) {
  // Compiled handler coverage above is deliberately not a wire reachability
  // claim. Restoring the retired generic wire family is outside this block.
  TendermintSignTx start = {};
  increment_idle_time(kDeadline - 1);
  receiveProgressMessage(MessageType_MessageType_TendermintSignTx,
                         TendermintSignTx_fields, &start);
  EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode());
  EXPECT_FALSE(tendermint_signingIsInited(TENDERMINT_SIGNING_GENERIC));
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

class Block13OsmosisWire : public Block13ResetProgress {
 protected:
  HDNode node = {};
  char address[128] = {};
  void SetUp() override {
    Block13ResetProgress::SetUp();
    const uint8_t seed[32] = {1};
    ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &node));
    hdnode_fill_public_key(&node);
    ASSERT_TRUE(tendermint_getAddress(&node, "osmo", address));
  }
  void Start() {
    auto start = signingEnvelope<OsmosisSignTx>("osmosis-1");
    ASSERT_TRUE(osmosis_signTxInit(&node, &start));
    layoutHomeForced();
    reset_idle_time();
    fsm_test_clearLastFailure();
  }
  OsmosisMsgAck Send(const char* amount, const char* denom = "uosmo") {
    OsmosisMsgAck ack = {};
    ack.has_send = true;
    ack.send.has_to_address = ack.send.has_amount = ack.send.has_denom = true;
    std::strcpy(ack.send.to_address, address);
    std::strcpy(ack.send.amount, amount);
    std::strcpy(ack.send.denom, denom);
    return ack;
  }
  void Receive(OsmosisMsgAck& ack) {
    receiveProgressMessage(MessageType_MessageType_OsmosisMsgAck,
                           OsmosisMsgAck_fields, &ack);
  }
};

TEST_F(Block13OsmosisWire, SendAcceptsCanonicalUint64BoundaryAndZero) {
  for (const char* amount : {"0", "1", "18446744073709551614", "18446744073709551615"}) {
    SCOPED_TRACE(amount);
    Start();
    ASSERT_TRUE(kkconfirm_preload(1, 0));
    auto ack = Send(amount);
    increment_idle_time(kDeadline - 1);
    Receive(ack);
    EXPECT_EQ(0, kkconfirm_drain());
    EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
    increment_idle_time(1);
    toggle_screensaver();
    EXPECT_TRUE(osmosis_signingIsInited());
  }
}

TEST_F(Block13OsmosisWire, SendRejectsOverflowAndNoncanonicalBeforeReview) {
  for (const char* amount : {"18446744073709551616", "99999999999999999999",
                             "100000000000000000000", "", "00", "01",
                             "-1", "+1", "1.0", "1e6", " 1", "1 "}) {
    SCOPED_TRACE(amount);
    Start();
    ASSERT_TRUE(kkconfirm_preload(0, 1));
    auto ack = Send(amount);
    increment_idle_time(kDeadline - 1);
    Receive(ack);
    EXPECT_EQ(FailureType_Failure_SyntaxError, fsm_test_lastFailureCode());
    EXPECT_FALSE(osmosis_signingIsInited());
    EXPECT_EQ(2, kkconfirm_drain());
    increment_idle_time(1);
    toggle_screensaver();
    EXPECT_EQ(SCREENSAVER, home_get_state());
    // The rejected session cannot resume, but a new valid one can proceed.
    Receive(ack);
    EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode());
  }
  Start();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  auto valid = Send("1");
  Receive(valid);
  EXPECT_TRUE(osmosis_signingIsInited());
  EXPECT_EQ(0, kkconfirm_drain());
}

// The uint64 bound is the native-denomination policy. An 18-decimal IBC or
// factory asset legitimately exceeds it, and the wire already limits the
// amount to 32 digits and the denomination to 68 characters.
TEST_F(Block13OsmosisWire, NonNativeDenominationsAreNotCappedAtUint64) {
  const std::string ibc = "ibc/" + std::string(64, 'A');
  const std::string factory = "factory/" + std::string(32, 'b') + "/token";
  for (const std::string& denom : {ibc, factory}) {
    for (const char* amount : {"18446744073709551616", "99999999999999999999",
                               "12345678901234567890123456789012"}) {
      SCOPED_TRACE(denom + " " + amount);
      Start();
      // A wide amount beside a long denomination paginates over several
      // confirmation screens, so approve generously and assert the outcome:
      // it reached review and was accepted rather than refused or declined.
      ASSERT_TRUE(kkconfirm_preload(8, 0));
      auto ack = Send(amount, denom.c_str());
      Receive(ack);
      EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
      EXPECT_TRUE(osmosis_signingIsInited());
    }
  }
}

TEST_F(Block13OsmosisWire, NativeDenominationStaysCappedForWideAmounts) {
  for (const char* amount :
       {"18446744073709551616", "12345678901234567890123456789012"}) {
    SCOPED_TRACE(amount);
    Start();
    ASSERT_TRUE(kkconfirm_preload(0, 1));
    auto ack = Send(amount, "uosmo");
    Receive(ack);
    EXPECT_EQ(FailureType_Failure_SyntaxError, fsm_test_lastFailureCode());
    EXPECT_FALSE(osmosis_signingIsInited());
    EXPECT_EQ(2, kkconfirm_drain());
  }
}

TEST_F(Block13OsmosisWire, MissingAmountAndInvalidDenomFailBeforeReview) {
  for (int mode : {0, 1, 2}) {
    Start();
    auto ack = Send("1", mode == 2 ? "u osmo" : "uosmo");
    if (mode == 0) ack.send.has_amount = false;
    if (mode == 1) ack.send.has_denom = false;
    ASSERT_TRUE(kkconfirm_preload(0, 1));
    Receive(ack);
    EXPECT_EQ(FailureType_Failure_SyntaxError, fsm_test_lastFailureCode());
    EXPECT_FALSE(osmosis_signingIsInited());
    EXPECT_EQ(2, kkconfirm_drain());
  }
}

TEST_F(Block13OsmosisWire, SwapAndPoolAmountsRemainWiderThanUint64) {
  constexpr char wide[] = "18446744073709551616";
  for (bool pool : {false, true}) {
    Start();
    OsmosisMsgAck ack = {};
    if (pool) {
      ack.has_lp_add = true;
      auto& msg = ack.lp_add;
      msg.has_sender = msg.has_pool_id = msg.has_share_out_amount = true;
      msg.has_denom_in_max_a = msg.has_amount_in_max_a = true;
      msg.has_denom_in_max_b = msg.has_amount_in_max_b = true;
      msg.pool_id = 1;
      std::strcpy(msg.sender, address);
      std::strcpy(msg.share_out_amount, wide);
      std::strcpy(msg.amount_in_max_a, wide);
      std::strcpy(msg.amount_in_max_b, wide);
      std::strcpy(msg.denom_in_max_a, "uosmo");
      std::strcpy(msg.denom_in_max_b, "uatom");
    } else {
      ack.has_swap = true;
      auto& msg = ack.swap;
      msg.has_sender = msg.has_pool_id = true;
      msg.has_token_in_denom = msg.has_token_out_denom = true;
      msg.has_token_in_amount = msg.has_token_out_min_amount = true;
      msg.pool_id = 1;
      std::strcpy(msg.sender, address);
      std::strcpy(msg.token_in_denom, "uosmo");
      std::strcpy(msg.token_out_denom, "uatom");
      std::strcpy(msg.token_in_amount, wide);
      std::strcpy(msg.token_out_min_amount, wide);
    }
    ASSERT_TRUE(kkconfirm_preload(pool ? 4 : 2, 0));
    Receive(ack);
    EXPECT_EQ(0, kkconfirm_drain());
    EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
    EXPECT_TRUE(osmosis_signingIsInited());
  }
}
#endif
}  // namespace
