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

}  // namespace
