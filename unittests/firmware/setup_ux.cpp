#include "gtest/gtest.h"
#include <functional>
#include <cstring>
#include <string>
#include <vector>
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
#include "keepkey/firmware/u2f.h"
#include "keepkey/firmware/u2f/u2f.h"
#include "storage.h"
}
void kk_test_board_init(void);
bool kkconfirm_preload(int, int);
int kkconfirm_drain(void);
bool kkconfirm_sendTiny(uint16_t, const uint8_t*, uint8_t);
void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);
extern "C" bool keepkey_before_message_dispatch(MessageType);
size_t kk_test_u2f_reply_count(void);
uint8_t kk_test_u2f_last_reply_command(void);
void kk_test_set_poll_hook(std::function<void()>);
void kk_test_set_message_hook(std::function<void(MessageType, const void*)>);

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
    // This line advertises an initial 64 KiB press-free audit budget.
    // Exhaust it before testing the separately approved bulk grant.
    ASSERT_TRUE(kkconfirm_preload(0, 1));
    for (int i = 0; i < 64; ++i) {
      entropy();
      if (fsm_test_lastFailureCode() != (FailureType)0) break;
    }
    kkconfirm_drain();
    fsm_test_clearLastFailure();
    kkconfirm_capture_start();
  }
  void TearDown() override {
    kk_test_set_poll_hook({});
    kk_test_set_message_hook({});
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
  // Oversized requests must charge only the capped bytes actually returned.
  for (size_t i = 0; i < (8u * 1024u * 1024u) / ENTROPY_BUF; ++i) {
    entropy(ENTROPY_BUF * 2);
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

// Respond only after observing the corresponding request. Both callbacks run
// on the firmware thread; the matrix is stable at its USB polling boundary.
struct PinRun {
  int answered = 0;
  int dice_requests = 0;
  int cancels = 0;
  int polls = 0;
  bool watchdog = false;
  std::string failure;
};
static PinRun resetWithPinThenCancel(bool mismatch) {
  PinRun result;
  MessageType pending = (MessageType)0;
  kk_test_set_message_hook([&](MessageType id, const void* msg) {
    if (id == MessageType_MessageType_PinMatrixRequest) pending = id;
    if (id == MessageType_MessageType_ButtonRequest &&
        ((const ButtonRequest*)msg)->code ==
            ButtonRequestType_ButtonRequest_DiceRoll) {
      ++result.dice_requests;
      pending = MessageType_MessageType_Cancel;
    }
    if (id == MessageType_MessageType_Failure)
      result.failure = ((const Failure*)msg)->message;
  });
  kk_test_set_poll_hook([&] {
    if (++result.polls > 10000) {
      result.watchdog = true;
      pending = MessageType_MessageType_Cancel;
    }
    if (pending == MessageType_MessageType_PinMatrixRequest) {
      const std::string matrix = get_pin_matrix();
      const char* pin = mismatch && result.answered == 1 ? "5678" : "1234";
      PinMatrixAck ack = {};
      for (size_t i = 0; i < 4; ++i) {
        const auto pos = matrix.find(pin[i]);
        EXPECT_NE(std::string::npos, pos);
        if (pos == std::string::npos) {
          result.watchdog = true;
          pending = MessageType_MessageType_Cancel;
          return;
        }
        ack.pin[i] = '1' + pos;
      }
      pending = (MessageType)0;
      ++result.answered;
      receiveMessage(MessageType_MessageType_PinMatrixAck, PinMatrixAck_fields,
                     &ack);
    } else if (pending == MessageType_MessageType_Cancel) {
      pending = (MessageType)0;
      ++result.cancels;
      Cancel cancel = {};
      receiveMessage(MessageType_MessageType_Cancel, Cancel_fields, &cancel);
    }
  });
  ResetDevice reset = {};
  reset.has_strength = true;
  reset.strength = 128;
  reset.has_pin_protection = reset.pin_protection = true;
  reset.has_dice_entropy = reset.dice_entropy = true;
  receiveMessage(MessageType_MessageType_ResetDevice, ResetDevice_fields,
                 &reset);
  kk_test_set_poll_hook({});
  kk_test_set_message_hook({});
  return result;
}

TEST_F(SetupUx, PinMismatchHappensBeforeDiceAndLeavesNoWallet) {
  const auto run = resetWithPinThenCancel(true);
  EXPECT_EQ(2, run.answered);
  EXPECT_EQ("PINs do not match", run.failure);
  EXPECT_EQ(0, run.dice_requests);
  EXPECT_EQ(0, run.cancels);
  EXPECT_FALSE(run.watchdog);
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_FALSE(setup_isArmed());
  EXPECT_FALSE(storage_isInitialized());
  EXPECT_FALSE(storage_hasPin());
  uint8_t digest[32] = {};
  EXPECT_EQ(0u, reset_get_dice_digest(digest));
}

TEST_F(SetupUx, DiceCancelAfterPinLeavesNoWalletOrStagedPin) {
  const auto run = resetWithPinThenCancel(false);
  EXPECT_EQ(2, run.answered);
  EXPECT_EQ(1, run.dice_requests);
  EXPECT_EQ(1, run.cancels);
  EXPECT_FALSE(run.watchdog);
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_FALSE(setup_isArmed());
  EXPECT_FALSE(storage_isInitialized());
  EXPECT_FALSE(storage_hasPin());
  uint8_t digest[32] = {};
  EXPECT_EQ(0u, reset_get_dice_digest(digest));
  setup_arm(SETUP_RESET);  // abort also removed the staged ceremony
  EXPECT_FALSE(setup_isArmed());
}

TEST_F(SetupUx, U2fPingAndInitRevokeAuditApproval) {
  usb_set_u2f_rx_callback(u2fhid_read);
  for (uint8_t cmd : {U2FHID_PING, U2FHID_INIT}) {
    SCOPED_TRACE((int)cmd);
    ASSERT_TRUE(kkconfirm_preload(1, 1));
    fsm_test_clearLastFailure();
    entropy();
    entropy();  // positive control: the grant works before U2F
    ASSERT_EQ((FailureType)0, fsm_test_lastFailureCode());
    U2FHID_FRAME frame = {};
    frame.cid = cmd == U2FHID_INIT ? CID_BROADCAST : 0x01020304;
    frame.init.cmd = cmd;
    frame.init.bcntl = cmd == U2FHID_INIT ? 8 : 1;
    frame.init.data[0] = 0x42;
    const auto replies = kk_test_u2f_reply_count();
    usb_test_receive_u2f(&frame);
    ASSERT_EQ(replies + 1, kk_test_u2f_reply_count());
    EXPECT_EQ(cmd, kk_test_u2f_last_reply_command());
    entropy();
    EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
    kkconfirm_drain();
  }
}
