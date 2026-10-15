#include "gtest/gtest.h"
#include <atomic>
#include <cstring>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>
extern "C" {
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/memory.h"
#include "keepkey/emulator/setup.h"
#include "keepkey/transport/interface.h"
#include "keepkey/board/usb.h"
#include "pb_encode.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/pin_sm.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/storage.h"
#include "storage.h"
}
void kk_test_board_init(void);
bool kkconfirm_preload(int, int);
int kkconfirm_drain(void);
bool kkconfirm_sendTiny(uint16_t, const uint8_t*, uint8_t);
void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);
extern "C" bool keepkey_before_message_dispatch(MessageType);

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

struct AuditFlash {
  std::vector<uint8_t> bytes = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  uint8_t* previous = emulator_flash_base;
  AuditFlash() {
    emulator_flash_base = bytes.data();
    storage_init();
  }
  ~AuditFlash() {
    storage_reset();
    emulator_flash_base = previous;
  }
};
}  // namespace

class SetupUx : public ::testing::Test {
 protected:
  AuditFlash flash;
  void SetUp() override {
    ASSERT_TRUE(kkconfirm_preload(0, 0));
    kkconfirm_drain();
    fsm_init();
    setup_abort();
    storage_reset();
    reset_idle_time();
    layoutHomeForced();
    fsm_test_clearLastFailure();
    kkconfirm_capture_start();
  }
  void TearDown() override {
    reset_idle_time();
    fsm_abort_workflows();
    kkconfirm_drain();
    kkconfirm_capture_finish();
  }
  void entropy(uint32_t size = 1024) {
    GetEntropy msg = {};
    msg.size = size;
    receiveMessage(MessageType_MessageType_GetEntropy, GetEntropy_fields, &msg);
  }
};

TEST_F(SetupUx, OneApprovalCovers64KiBAudit) {
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  for (int i = 0; i < 64; ++i) {
    // Vault may poll Features between chunks; a read-only poll is not a
    // new operation and must not turn this back into one press per chunk.
    keepkey_before_message_dispatch(MessageType_MessageType_GetFeatures);
    entropy();
    ASSERT_EQ((FailureType)0, fsm_test_lastFailureCode()) << "chunk " << i;
  }
  EXPECT_EQ(1u, kkconfirm_capture_finish().size());
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST_F(SetupUx, AuditGrantIsBoundedByReturnedBytes) {
  ASSERT_TRUE(kkconfirm_preload(1, 1));
  // Oversized requests must charge only the 1024 bytes actually returned.
  for (int i = 0; i < 8192; ++i) {
    entropy(8192);
    ASSERT_EQ((FailureType)0, fsm_test_lastFailureCode()) << "chunk " << i;
  }
  entropy();
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_EQ(2u, kkconfirm_capture_finish().size());
}

TEST_F(SetupUx, OtherMessagesRevokeAuditApproval) {
  for (auto id :
       {MessageType_MessageType_Cancel, MessageType_MessageType_Initialize,
        MessageType_MessageType_ClearSession,
        MessageType_MessageType_ResetDevice}) {
    SCOPED_TRACE((int)id);
    ASSERT_TRUE(kkconfirm_preload(1, 1));
    fsm_test_clearLastFailure();
    entropy();
    ASSERT_EQ((FailureType)0, fsm_test_lastFailureCode());
    keepkey_before_message_dispatch(id);
    entropy();
    EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
    kkconfirm_drain();
  }
}

TEST_F(SetupUx, InitializedWalletAlwaysRequiresApproval) {
  storage_setMnemonic(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon about");
  ASSERT_TRUE(storage_isInitialized());
  ASSERT_TRUE(kkconfirm_preload(1, 1));
  entropy();
  ASSERT_EQ((FailureType)0, fsm_test_lastFailureCode());
  entropy();
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_EQ(2u, kkconfirm_capture_finish().size());
}

TEST_F(SetupUx, DecliningAuditDoesNotGrantLaterRequests) {
  ASSERT_TRUE(kkconfirm_preload(0, 2));
  entropy();
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  fsm_test_clearLastFailure();
  entropy();
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_EQ(2u, kkconfirm_capture_finish().size());
}

TEST_F(SetupUx, ArmedSetupRejectsEntropyWithoutDiscardingCeremony) {
  ASSERT_TRUE(setup_stage(false, "english", "test", 0, 0, false));
  setup_arm(SETUP_RESET);
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  entropy();
  EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode());
  EXPECT_TRUE(setup_isArmedAs(SETUP_RESET));
  EXPECT_TRUE(kkconfirm_capture_finish().empty());
}

// Drive the actual PIN protocol before dice. On the old ordering the device
// waits for dice instead; a bounded watchdog cancels it and the count fails.
static int resetWithPinThenCancel(bool mismatch) {
  std::atomic<int> answered{0};
  std::thread host([&] {
    std::string seen = "XXXXXXXXX";
    for (int prompt = 0; prompt < 2; ++prompt) {
      bool found = false;
      for (int tries = 0; tries < 2000; ++tries, usleep(1000)) {
        const std::string first = get_pin_matrix();
        if (first == "XXXXXXXXX" || first == seen) continue;
        usleep(50000);
        const std::string matrix = get_pin_matrix();
        std::string positions;
        const char* pin = mismatch && prompt == 1 ? "5678" : "1234";
        for (const char* d = pin; *d; ++d)
          positions += (char)('1' + matrix.find(*d));
        uint8_t ack[11] = {0x0a, (uint8_t)positions.size()};
        std::memcpy(&ack[2], positions.data(), positions.size());
        kkconfirm_sendTiny(MessageType_MessageType_PinMatrixAck, ack,
                           (uint8_t)(2 + positions.size()));
        seen = matrix;
        ++answered;
        found = true;
        break;
      }
      if (!found) break;
    }
    usleep(100000);
    kkconfirm_sendTiny(MessageType_MessageType_Cancel, nullptr, 0);
  });
  ResetDevice reset = {};
  reset.has_strength = true;
  reset.strength = 128;
  reset.has_pin_protection = reset.pin_protection = true;
  reset.has_dice_entropy = reset.dice_entropy = true;
  receiveMessage(MessageType_MessageType_ResetDevice, ResetDevice_fields,
                 &reset);
  host.join();
  return answered;
}

TEST_F(SetupUx, PinMismatchHappensBeforeDiceAndLeavesNoWallet) {
  EXPECT_EQ(2, resetWithPinThenCancel(true));
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_FALSE(setup_isArmed());
  EXPECT_FALSE(storage_isInitialized());
  EXPECT_FALSE(storage_hasPin());
  uint8_t digest[32] = {};
  EXPECT_EQ(0u, reset_get_dice_digest(digest));
}

TEST_F(SetupUx, DiceCancelAfterPinLeavesNoWalletOrStagedPin) {
  EXPECT_EQ(2, resetWithPinThenCancel(false));
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_FALSE(setup_isArmed());
  EXPECT_FALSE(storage_isInitialized());
  EXPECT_FALSE(storage_hasPin());
  uint8_t digest[32] = {};
  EXPECT_EQ(0u, reset_get_dice_digest(digest));
  setup_arm(SETUP_RESET);  // abort also removed the staged ceremony
  EXPECT_FALSE(setup_isArmed());
}
