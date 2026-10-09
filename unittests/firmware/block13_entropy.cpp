extern "C" {
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/usb.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/recovery_cipher.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/storage.h"
#include "pb_decode.h"
#include "pb_encode.h"
}

#include "gtest/gtest.h"

#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <cstring>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

void kk_test_board_init(void);
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

namespace {
using Frame = std::array<uint8_t, 64>;

Frame emptyFrame(MessageType id) {
  Frame frame = {};
  frame[0] = '?';
  frame[1] = frame[2] = '#';
  frame[3] = id >> 8;
  frame[4] = id;
  return frame;
}

class Block13Entropy : public ::testing::Test {
 protected:
  std::vector<uint8_t> flash = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  uint8_t* previous_flash = nullptr;
  int fd = -1;
  std::vector<Frame> replies;

  void SetUp() override {
    previous_flash = emulator_flash_base;
    emulator_flash_base = flash.data();
    kk_test_board_init();
    fsm_init();
    // Both refusal flags are sticky until a wipe, including in native tests.
    storage_wipe();
    storage_init();
    ASSERT_TRUE(kkconfirm_preload(0, 0));
    ASSERT_EQ(0, kkconfirm_drain());
    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_GE(fd, 0);
    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(11044);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(
        0, connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)));

    // The real transport remembers its most recent sender for USB replies.
    queue(emptyFrame(MessageType_MessageType_GetFeatures));
    for (int attempt = 0; attempt < 100 && replies.empty(); ++attempt) {
      usbPoll();
      collect();
    }
    ASSERT_EQ(1u, count(MessageType_MessageType_Features));
    replies.clear();

    // Refresh the volatile budget through the actual confirmed wipe handler,
    // so these tests are independent of other entropy tests and shuffle order.
    approve();
    dispatch(emptyFrame(MessageType_MessageType_WipeDevice));
    ASSERT_EQ(1u, count(MessageType_MessageType_Success));
    ASSERT_EQ(0u, count(MessageType_MessageType_Failure));
    replies.clear();
    layoutHomeForced();
    storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
    reset_idle_time();
  }

  void TearDown() override {
    alarm(0);
    drainTiny();
    storage_wipe();
    storage_reset();
    // A normal frame also clears transport-rejection state before successors.
    const auto frame = emptyFrame(MessageType_MessageType_GetFeatures);
    usb_test_receive(frame.data(), frame.size());
    if (fd >= 0) close(fd);
    emulator_flash_base = previous_flash;
    layoutHomeForced();
  }

  void queue(const Frame& frame) {
    ASSERT_EQ(static_cast<ssize_t>(frame.size()),
              send(fd, frame.data(), frame.size(), 0));
  }

  void collect() {
    pollfd ready = {fd, POLLIN, 0};
    while (poll(&ready, 1, 20) > 0) {
      Frame frame = {};
      ASSERT_EQ(static_cast<ssize_t>(frame.size()),
                recv(fd, frame.data(), frame.size(), 0));
      replies.push_back(frame);
    }
  }

  void drainTiny() {
    uint8_t bytes[MSG_TINY_BFR_SZ] = {};
    while (check_for_tiny_msg(bytes) != MSG_TINY_TYPE_ERROR) {
    }
  }

  size_t count(MessageType id) const {
    return std::count_if(replies.begin(), replies.end(), [id](const Frame& f) {
      return f[0] == '?' && f[1] == '#' && f[2] == '#' &&
             ((f[3] << 8) | f[4]) == id;
    });
  }

  template <typename T>
  T response(MessageType id, const pb_field_t* fields) const {
    T result = {};
    bool found = false;
    for (size_t i = 0; i < replies.size(); ++i) {
      const auto& frame = replies[i];
      if (frame[1] != '#' || frame[2] != '#' ||
          ((frame[3] << 8) | frame[4]) != id)
        continue;
      found = true;
      const size_t size = (uint32_t(frame[5]) << 24) |
                          (uint32_t(frame[6]) << 16) |
                          (uint32_t(frame[7]) << 8) | frame[8];
      EXPECT_LE(size, 4096u);
      if (size > 4096) continue;
      const size_t first = std::min(size, size_t(55));
      std::vector<uint8_t> encoded(frame.begin() + 9,
                                   frame.begin() + 9 + first);
      while (encoded.size() < size && i + 1 < replies.size()) {
        const auto& fragment = replies[++i];
        EXPECT_EQ('?', fragment[0]);
        const size_t take = std::min(size - encoded.size(), size_t(63));
        encoded.insert(encoded.end(), fragment.begin() + 1,
                       fragment.begin() + 1 + take);
      }
      EXPECT_EQ(size, encoded.size());
      pb_istream_t stream =
          pb_istream_from_buffer(encoded.data(), encoded.size());
      EXPECT_TRUE(pb_decode(&stream, fields, &result));
    }
    EXPECT_TRUE(found);
    return result;
  }

  void dispatch(const Frame& frame) {
    // A broken consent path fails promptly rather than hanging the binary.
    alarm(3);
    usb_test_receive(frame.data(), frame.size());
    alarm(0);
    collect();
  }

  void dispatch(MessageType id, const pb_field_t* fields, const void* request) {
    Frame frame = emptyFrame(id);
    pb_ostream_t stream = pb_ostream_from_buffer(frame.data() + 9, 55);
    ASSERT_TRUE(pb_encode(&stream, fields, request));
    frame[8] = stream.bytes_written;
    dispatch(frame);
  }

  void approve() {
    queue(emptyFrame(MessageType_MessageType_ButtonAck));
    auto decision = emptyFrame(MessageType_MessageType_DebugLinkDecision);
    decision[8] = 2;
    decision[9] = 0x08;
    decision[10] = 0x01;
    queue(decision);
  }

  void sample(uint32_t size) {
    // If a mutation unexpectedly demands consent, terminate it safely. A
    // press-free or rejected request leaves this packet queued; drain it as a
    // tiny packet afterward without dispatching Cancel into the ceremony.
    queue(emptyFrame(MessageType_MessageType_Cancel));
    GetEntropy request = {};
    request.size = size;
    dispatch(MessageType_MessageType_GetEntropy, GetEntropy_fields, &request);
    drainTiny();
  }

  void decline() {
    queue(emptyFrame(MessageType_MessageType_ButtonAck));
    auto decision = emptyFrame(MessageType_MessageType_DebugLinkDecision);
    decision[8] = 2;
    decision[9] = 0x08;
    queue(decision);
  }

  void refuseStoredVersion(uint32_t version) {
    storage_wipe();
    auto* sector =
        reinterpret_cast<uint8_t*>(flash_write_helper(FLASH_STORAGE1));
    std::memset(sector, 0, FLASH_STORAGE_LEN);
    std::memcpy(sector, "stor", 4);
    for (size_t i = 0; i < sizeof(version); ++i)
      sector[44 + i] = version >> (8 * i);
    storage_init();
    ASSERT_FALSE(storage_isInitialized());
  }

  void expectConfirmedRefusalPreservesFlash() {
    const auto before = flash;
    sample(1);
    EXPECT_EQ(1u, count(MessageType_MessageType_ButtonRequest));
    EXPECT_EQ(ButtonRequestType_ButtonRequest_GetEntropy,
              response<ButtonRequest>(MessageType_MessageType_ButtonRequest,
                                      ButtonRequest_fields)
                  .code);
    EXPECT_EQ(1u, count(MessageType_MessageType_Failure));
    EXPECT_EQ(FailureType_Failure_ActionCancelled,
              response<Failure>(MessageType_MessageType_Failure, Failure_fields)
                  .code);
    EXPECT_EQ(0u, count(MessageType_MessageType_Entropy));
    EXPECT_EQ(before, flash);
  }

  void expectSetupRefusal(SetupKind kind) {
    ASSERT_TRUE(setup_isArmedAs(kind));
    leave_home();
    reset_idle_time();
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
    sample(1);
    EXPECT_EQ(0u, count(MessageType_MessageType_ButtonRequest));
    EXPECT_EQ(0u, count(MessageType_MessageType_Entropy));
    EXPECT_EQ(1u, count(MessageType_MessageType_Failure));
    EXPECT_EQ(FailureType_Failure_UnexpectedMessage,
              response<Failure>(MessageType_MessageType_Failure, Failure_fields)
                  .code);
    EXPECT_TRUE(setup_isArmedAs(kind));
    EXPECT_EQ(AWAY_FROM_HOME, home_get_state());
    increment_idle_time(1);
    toggle_screensaver();
    EXPECT_EQ(SCREENSAVER, home_get_state());
    EXPECT_FALSE(setup_isArmed());
  }
  void expectWalletCreationRefusedUntilWipe() {
    const auto before = flash;
    LoadDevice load = {};
    load.has_mnemonic = true;
    std::strcpy(load.mnemonic,
                "all all all all all all all all all all all all");
    ResetDevice reset = {};
    reset.has_strength = true;
    reset.strength = 128;
    RecoveryDevice recovery = {};
    recovery.has_word_count = true;
    recovery.word_count = 12;
    const struct {
      MessageType type;
      const pb_field_t* fields;
      const void* request;
    } operations[] = {
        {MessageType_MessageType_LoadDevice, LoadDevice_fields, &load},
        {MessageType_MessageType_ResetDevice, ResetDevice_fields, &reset},
        {MessageType_MessageType_RecoveryDevice, RecoveryDevice_fields,
         &recovery},
    };
    for (const auto& operation : operations) {
      SCOPED_TRACE(operation.type);
      replies.clear();
      // The old missing gate reaches consent. Decline it so the negative
      // control reports the wrong response rather than blocking the suite.
      decline();
      dispatch(operation.type, operation.fields, operation.request);
      drainTiny();
      EXPECT_EQ(0u, count(MessageType_MessageType_ButtonRequest));
      EXPECT_EQ(1u, count(MessageType_MessageType_Failure));
      const FailureType expected =
          storage_isBitcoinOnlyLocked() &&
                  operation.type != MessageType_MessageType_RecoveryDevice
              ? FailureType_Failure_Other
              : FailureType_Failure_UnexpectedMessage;
      EXPECT_EQ(expected, response<Failure>(MessageType_MessageType_Failure,
                                            Failure_fields)
                              .code);
      EXPECT_EQ(0u, count(MessageType_MessageType_Success));
      EXPECT_EQ(0u, count(MessageType_MessageType_EntropyRequest));
      EXPECT_EQ(0u, count(MessageType_MessageType_CharacterRequest));
      EXPECT_FALSE(setup_isArmed());
      EXPECT_FALSE(storage_isInitialized());
      EXPECT_EQ(before, flash);
      // A failing old-code control must not lend its armed ceremony to the
      // next operation and mask that operation's missing refusal gate.
      setup_abort();
    }

    // An explicit, confirmed wipe is still the way to discard the retained
    // record and begin a new wallet on this firmware.
    replies.clear();
    approve();
    dispatch(emptyFrame(MessageType_MessageType_WipeDevice));
    ASSERT_EQ(1u, count(MessageType_MessageType_ButtonRequest));
    ASSERT_EQ(1u, count(MessageType_MessageType_Success));
    ASSERT_EQ(0u, count(MessageType_MessageType_Failure));
    EXPECT_FALSE(storage_isFirmwareTooOld());
    EXPECT_FALSE(storage_isBitcoinOnlyLocked());
    EXPECT_NE(before, flash);
    EXPECT_FALSE(storage_isInitialized());

    replies.clear();
    approve();
    dispatch(MessageType_MessageType_LoadDevice, LoadDevice_fields, &load);
    EXPECT_EQ(1u, count(MessageType_MessageType_Success));
    EXPECT_EQ(0u, count(MessageType_MessageType_Failure));
    ASSERT_TRUE(storage_isInitialized());
    // Reload the disposable image through the production boot storage path.
    // This does not qualify physical reboot or signed firmware installation.
    storage_init();
    EXPECT_TRUE(storage_isInitialized());
  }
};
}  // namespace

TEST_F(Block13Entropy, NewerNormalBandWalletRequiresConsent) {
  refuseStoredVersion(STORAGE_VERSION + 1);
  ASSERT_TRUE(storage_isFirmwareTooOld());
  ASSERT_FALSE(storage_isBitcoinOnlyLocked());
  expectConfirmedRefusalPreservesFlash();
}

TEST_F(Block13Entropy, NewerBitcoinBandWalletRequiresConsent) {
  refuseStoredVersion(STORAGE_VERSION_BTC_ONLY + 1);
  ASSERT_TRUE(storage_isBitcoinOnlyLocked());
  ASSERT_FALSE(storage_isFirmwareTooOld());
  expectConfirmedRefusalPreservesFlash();
}

TEST_F(Block13Entropy, PendingResetRejectsWithoutRenewingDeadline) {
  ASSERT_TRUE(setup_stage(false, "english", "pending reset",
                          STORAGE_MIN_SCREENSAVER_TIMEOUT, 0, false));
  setup_arm(SETUP_RESET);
  expectSetupRefusal(SETUP_RESET);
}

TEST_F(Block13Entropy, NewerNormalBandRefusesAllWalletCreationUntilWipe) {
  refuseStoredVersion(STORAGE_VERSION + 1);
  ASSERT_TRUE(storage_isFirmwareTooOld());
  expectWalletCreationRefusedUntilWipe();
}

TEST_F(Block13Entropy, NewerBitcoinBandRefusesAllWalletCreationUntilWipe) {
  refuseStoredVersion(STORAGE_VERSION_BTC_ONLY + 1);
  ASSERT_TRUE(storage_isBitcoinOnlyLocked());
  expectWalletCreationRefusedUntilWipe();
}

TEST_F(Block13Entropy, ActiveRecoveryRejectsAndPreservesCipherUntilDeadline) {
  approve();
  RecoveryDevice request = {};
  request.has_word_count = true;
  request.word_count = 12;
  dispatch(MessageType_MessageType_RecoveryDevice, RecoveryDevice_fields,
           &request);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  ASSERT_EQ(1u, count(MessageType_MessageType_CharacterRequest));
  const std::string cipher = recovery_get_cipher();
  ASSERT_EQ(26u, cipher.size());
  replies.clear();

  leave_home();
  reset_idle_time();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  sample(1);
  EXPECT_EQ(0u, count(MessageType_MessageType_ButtonRequest));
  EXPECT_EQ(0u, count(MessageType_MessageType_Entropy));
  EXPECT_EQ(1u, count(MessageType_MessageType_Failure));
  EXPECT_EQ(
      FailureType_Failure_UnexpectedMessage,
      response<Failure>(MessageType_MessageType_Failure, Failure_fields).code);
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_EQ(cipher, recovery_get_cipher());
  EXPECT_EQ(AWAY_FROM_HOME, home_get_state());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(setup_isArmed());
  EXPECT_EQ(SCREENSAVER, home_get_state());
  EXPECT_STREQ("", recovery_get_cipher());
}

TEST_F(Block13Entropy, MissingSizeFailsDecodeAndZeroDoesNotRenewDeadline) {
  leave_home();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  // size is required: an empty protobuf must never reach fsm_msgGetEntropy.
  queue(emptyFrame(MessageType_MessageType_Cancel));
  dispatch(emptyFrame(MessageType_MessageType_GetEntropy));
  drainTiny();
  EXPECT_EQ(0u, count(MessageType_MessageType_ButtonRequest));
  EXPECT_EQ(0u, count(MessageType_MessageType_Entropy));
  EXPECT_EQ(1u, count(MessageType_MessageType_Failure));
  EXPECT_EQ(
      FailureType_Failure_UnexpectedMessage,
      response<Failure>(MessageType_MessageType_Failure, Failure_fields).code);
  replies.clear();

  sample(0);
  EXPECT_EQ(0u, count(MessageType_MessageType_ButtonRequest));
  EXPECT_EQ(0u, count(MessageType_MessageType_Failure));
  ASSERT_EQ(1u, count(MessageType_MessageType_Entropy));
  EXPECT_EQ(0u,
            response<Entropy>(MessageType_MessageType_Entropy, Entropy_fields)
                .entropy.size);
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}
