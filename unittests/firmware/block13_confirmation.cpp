extern "C" {
#include "keepkey/board/layout.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/usb.h"
#include "keepkey/firmware/app_layout.h"
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
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

void kk_test_board_init(void);
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

namespace {
using Frame = std::array<uint8_t, 64>;

Frame tinyFrame(uint16_t id, std::initializer_list<uint8_t> payload = {}) {
  Frame frame = {};
  frame[0] = '?';
  frame[1] = frame[2] = '#';
  frame[3] = id >> 8;
  frame[4] = id;
  frame[8] = payload.size();
  std::copy(payload.begin(), payload.end(), frame.begin() + 9);
  return frame;
}

class Block13Confirmation : public ::testing::Test {
 protected:
  std::vector<uint8_t> flash = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  uint8_t* previous_flash = nullptr;
  int fd = -1;
  std::vector<Frame> replies;

  void SetUp() override {
    kk_test_board_init();
    fsm_init();
    ASSERT_TRUE(kkconfirm_preload(0, 0));
    ASSERT_EQ(0, kkconfirm_drain());
    previous_flash = emulator_flash_base;
    emulator_flash_base = flash.data();
    storage_wipe();
    storage_init();
    setup_abort();
    layoutHomeForced();
    storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
    reset_idle_time();
    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_GE(fd, 0);
    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(11044);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(
        0, connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)));
    // Establish this socket as the real emulator USB reply destination.
    queue(tinyFrame(MessageType_MessageType_GetFeatures));
    // Loopback delivery is asynchronous. A single poll can miss this packet,
    // leaving GetFeatures queued until the next protected confirmation and
    // shifting every later decision into the following request.
    for (int attempt = 0;
         attempt < 100 && count(MessageType_MessageType_Features) == 0;
         ++attempt) {
      usbPoll();
      collect();
    }
    ASSERT_EQ(1u, count(MessageType_MessageType_Features));
    replies.clear();
  }

  void TearDown() override {
    alarm(0);
    fsm_abort_workflows();
    // A normal receive clears a tiny rejection before other tests use USB.
    auto frame = tinyFrame(MessageType_MessageType_GetFeatures);
    usb_test_receive(frame.data(), frame.size());
    if (fd >= 0) close(fd);
    storage_reset();
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

  struct Reply {
    uint16_t id;
    std::vector<uint8_t> payload;
  };

  std::vector<Reply> messages() const {
    std::vector<Reply> result;
    size_t remaining = 0;
    for (const auto& frame : replies) {
      if (frame[0] != '?') {
        ADD_FAILURE() << "Invalid response report";
        return {};
      }
      size_t offset = 1;
      if (remaining == 0) {
        if (frame[1] != '#' || frame[2] != '#') {
          ADD_FAILURE() << "Invalid response header";
          return {};
        }
        result.push_back({uint16_t((uint16_t(frame[3]) << 8) | frame[4]), {}});
        remaining = (uint32_t(frame[5]) << 24) | (uint32_t(frame[6]) << 16) |
                    (uint32_t(frame[7]) << 8) | frame[8];
        offset = 9;
      }
      const size_t take = std::min(remaining, frame.size() - offset);
      result.back().payload.insert(result.back().payload.end(),
                                   frame.begin() + offset,
                                   frame.begin() + offset + take);
      remaining -= take;
    }
    EXPECT_EQ(0u, remaining) << "Truncated response";
    return result;
  }

  size_t count(MessageType id) const {
    const auto decoded = messages();
    return std::count_if(decoded.begin(), decoded.end(),
                         [id](const Reply& reply) { return reply.id == id; });
  }

  template <typename T>
  T response(MessageType id, const pb_field_t* fields) const {
    T result = {};
    bool found = false;
    for (const auto& reply : messages()) {
      if (reply.id != id) continue;
      found = true;
      pb_istream_t stream =
          pb_istream_from_buffer(reply.payload.data(), reply.payload.size());
      EXPECT_TRUE(pb_decode(&stream, fields, &result));
    }
    EXPECT_TRUE(found);
    return result;
  }

  void dispatch(MessageType id, const pb_field_t* fields, const void* request) {
    uint8_t encoded[4096] = {};
    pb_ostream_t stream = pb_ostream_from_buffer(encoded, sizeof(encoded));
    ASSERT_TRUE(pb_encode(&stream, fields, request));
    Frame frame = tinyFrame(id);
    const size_t size = stream.bytes_written;
    frame[5] = size >> 24;
    frame[6] = size >> 16;
    frame[7] = size >> 8;
    frame[8] = size;
    size_t sent = std::min(size, size_t(55));
    std::memcpy(frame.data() + 9, encoded, sent);
    usb_test_receive(frame.data(), frame.size());
    while (sent < size) {
      frame.fill(0);
      frame[0] = '?';
      const size_t chunk = std::min(size - sent, size_t(63));
      std::memcpy(frame.data() + 1, encoded + sent, chunk);
      usb_test_receive(frame.data(), frame.size());
      sent += chunk;
    }
    collect();
  }

  void sign() {
    SignMessage request = {};
    request.address_n_count = 5;
    request.address_n[0] = 0x8000002c;
    request.address_n[1] = request.address_n[2] = 0x80000000;
    request.message.size = 4;
    std::memcpy(request.message.bytes, "test", 4);
    // A broken unwind terminates this test instead of hanging the suite.
    alarm(3);
    dispatch(MessageType_MessageType_SignMessage, SignMessage_fields, &request);
    alarm(0);
  }

  void approve() {
    queue(tinyFrame(MessageType_MessageType_ButtonAck));
    queue(tinyFrame(MessageType_MessageType_DebugLinkDecision, {0x08, 0x01}));
  }

  void seedWallet() {
    // The load helper also installs a valid cached storage key. A bare
    // storage_setMnemonic after storage_init's empty-flash return leaves the
    // session key zero, so an Initialize cannot reopen that artificial seed.
    LoadDevice request = {};
    request.has_mnemonic = true;
    std::strcpy(request.mnemonic,
                "all all all all all all all all all all all all");
    storage_loadDevice(&request);
    storage_commit();
    ASSERT_TRUE(storage_isInitialized());
  }

  void startRecovery() {
    approve();
    RecoveryDevice request = {};
    request.has_word_count = true;
    request.word_count = 12;
    request.has_enforce_wordlist = true;
    request.enforce_wordlist = true;
    dispatch(MessageType_MessageType_RecoveryDevice, RecoveryDevice_fields,
             &request);
    ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
    ASSERT_EQ(1u, count(MessageType_MessageType_CharacterRequest));
    replies.clear();
  }

  void letter(char plain) {
    CharacterAck request = {};
    request.has_character = true;
    request.character[0] =
        plain == ' ' ? ' ' : recovery_get_cipher()[plain - 'a'];
    dispatch(MessageType_MessageType_CharacterAck, CharacterAck_fields,
             &request);
    ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  }

  std::vector<uint8_t> pixels() {
    // Finish the real cipher animation before comparing its whole framebuffer.
    for (int i = 0; i < 100; ++i) {
      force_animation_start();
      animate();
    }
    return framebuffer();
  }

  std::vector<uint8_t> framebuffer() const {
    const Canvas* canvas = layout_get_canvas();
    return {canvas->buffer, canvas->buffer + canvas->width * canvas->height};
  }

  void advanceAnimation(uint32_t milliseconds) {
    for (uint32_t tick = 0; tick < milliseconds; ++tick) {
      timerisr_usr();
      animate();
    }
  }

  size_t lastCipherGlyphPixels() const {
    const Canvas* canvas = layout_get_canvas();
    size_t foreground = 0;
    // Last cipher cell, under the Z label: its animation begins only after
    // 250 ms. The label/grid alone cannot satisfy this foreground check.
    for (int y = 48; y < 59; ++y)
      for (int x = 240; x < 256; ++x)
        if (canvas->buffer[y * canvas->width + x] > CIPHER_STEP_1) ++foreground;
    return foreground;
  }
};
}  // namespace

TEST_F(Block13Confirmation, UnknownAndMalformedTinyPacketsUnwindSigningOnce) {
  seedWallet();
  auto malformed_header = tinyFrame(MessageType_MessageType_ButtonAck);
  malformed_header[1] = '!';
  auto oversized = tinyFrame(MessageType_MessageType_ButtonAck);
  oversized[8] = 56;
  const Frame packets[] = {
      tinyFrame(0xffff), malformed_header, oversized,
      tinyFrame(MessageType_MessageType_DebugLinkDecision, {0x08})};
  for (const auto& packet : packets) {
    replies.clear();
    queue(packet);
    sign();
    EXPECT_EQ(1u, count(MessageType_MessageType_ButtonRequest));
    EXPECT_EQ(1u, count(MessageType_MessageType_Failure));
    EXPECT_EQ(0u, count(MessageType_MessageType_MessageSignature));
    EXPECT_EQ(0u, count(MessageType_MessageType_Success));
    const Failure failure =
        response<Failure>(MessageType_MessageType_Failure, Failure_fields);
    EXPECT_EQ(packet[4] == MessageType_MessageType_DebugLinkDecision
                  ? FailureType_Failure_SyntaxError
                  : FailureType_Failure_UnexpectedMessage,
              failure.code);
    EXPECT_TRUE(fsm_test_derivedNodeIsZero());
    EXPECT_FALSE(msg_handler_rejected());

    // A fresh user approval must work after every terminal receive rejection.
    replies.clear();
    approve();
    sign();
    EXPECT_EQ(0u, count(MessageType_MessageType_Failure));
    EXPECT_EQ(1u, count(MessageType_MessageType_MessageSignature));
  }
}

TEST_F(Block13Confirmation, DeclineCancelAndInitializeDoNotSignAndAllowRetry) {
  seedWallet();
  for (uint16_t decision : {uint16_t(MessageType_MessageType_DebugLinkDecision),
                            uint16_t(MessageType_MessageType_Cancel),
                            uint16_t(MessageType_MessageType_Initialize)}) {
    replies.clear();
    if (decision == MessageType_MessageType_DebugLinkDecision) {
      queue(tinyFrame(MessageType_MessageType_ButtonAck));
      queue(tinyFrame(decision, {0x08, 0x00}));
    } else {
      queue(tinyFrame(decision));
    }
    sign();
    EXPECT_EQ(0u, count(MessageType_MessageType_MessageSignature));
    EXPECT_EQ(decision == MessageType_MessageType_Initialize ? 0u : 1u,
              count(MessageType_MessageType_Failure));
    EXPECT_EQ(decision == MessageType_MessageType_Initialize ? 1u : 0u,
              count(MessageType_MessageType_Features));
    EXPECT_TRUE(fsm_test_derivedNodeIsZero());
    replies.clear();
    approve();
    sign();
    EXPECT_EQ(1u, count(MessageType_MessageType_MessageSignature));
  }
}

TEST_F(Block13Confirmation,
       RecoveryRejectionRestoresCipherAndPreservesProgress) {
  startRecovery();
  for (char ch : {'a', 'l', 'l', ' ', 'a', 'b', 'a'}) letter(ch);
  const std::string cipher = recovery_get_cipher();
  const std::string completed = recovery_get_auto_completed_word();
  ASSERT_EQ("abandon", completed);
  const auto expected = pixels();
  replies.clear();

  GetEntropy entropy = {};
  entropy.size = 32;
  dispatch(MessageType_MessageType_GetEntropy, GetEntropy_fields, &entropy);
  EXPECT_EQ(1u, messages().size());
  EXPECT_EQ(
      FailureType_Failure_UnexpectedMessage,
      response<Failure>(MessageType_MessageType_Failure, Failure_fields).code);
  EXPECT_EQ(0u, count(MessageType_MessageType_Entropy));
  EXPECT_EQ(0u, count(MessageType_MessageType_ButtonRequest));
  EXPECT_EQ(cipher, recovery_get_cipher());
  EXPECT_EQ(expected, pixels());
  replies.clear();

  // Any other request is refused by the dispatch gate before its handler
  // can draw, keeping the recovery ceremony armed and on screen.
  VerifyMessage unrelated = {};
  unrelated.has_address = unrelated.has_message = true;
  std::strcpy(unrelated.address, "invalid-address");
  unrelated.message.size = 1;
  unrelated.message.bytes[0] = 'x';
  dispatch(MessageType_MessageType_VerifyMessage, VerifyMessage_fields,
           &unrelated);
  EXPECT_EQ(1u, count(MessageType_MessageType_Failure));
  EXPECT_EQ(
      FailureType_Failure_UnexpectedMessage,
      response<Failure>(MessageType_MessageType_Failure, Failure_fields).code);
  EXPECT_EQ(0u, count(MessageType_MessageType_CharacterRequest));
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_EQ(cipher, recovery_get_cipher());
  EXPECT_EQ(completed, recovery_get_auto_completed_word());
  EXPECT_EQ(expected, framebuffer());

  // The transport rejection also restores an obscured screen, and sends no
  // recovery text or extra CharacterRequest over the wire.
  layout_warning_static("Unrelated error");
  ASSERT_NE(expected, pixels());
  replies.clear();
  auto unknown = tinyFrame(0xffff);
  usb_test_receive(unknown.data(), unknown.size());
  collect();
  EXPECT_EQ(1u, messages().size());
  EXPECT_EQ(1u, count(MessageType_MessageType_Failure));
  EXPECT_EQ(cipher, recovery_get_cipher());
  EXPECT_EQ(expected, framebuffer());

  replies.clear();
  letter('n');
  const auto next = response<CharacterRequest>(
      MessageType_MessageType_CharacterRequest, CharacterRequest_fields);
  EXPECT_EQ(1u, next.word_pos);
  EXPECT_EQ(4u, next.character_pos);
  EXPECT_STREQ("abandon", recovery_get_auto_completed_word());
}

TEST_F(Block13Confirmation,
       RecoveryRedrawDoesNotRenewDeadlineOrResurrectAfterLock) {
  startRecovery();
  letter('a');
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  layout_warning_static("Unrelated error");
  const auto unknown = tinyFrame(0xffff);
  usb_test_receive(unknown.data(), unknown.size());
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_EQ(AWAY_FROM_HOME, home_get_state());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(setup_isArmed());
  EXPECT_EQ(SCREENSAVER, home_get_state());
  EXPECT_STREQ("", recovery_get_cipher());
  GetFeatures poll = {};
  dispatch(MessageType_MessageType_GetFeatures, GetFeatures_fields, &poll);
  EXPECT_EQ(SCREENSAVER, home_get_state());
  EXPECT_STREQ("", recovery_get_cipher());
}

TEST_F(Block13Confirmation, AcceptedRecoveryStartRenewsThenEventuallyExpires) {
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  startRecovery();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_EQ(AWAY_FROM_HOME, home_get_state());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(setup_isArmed());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(Block13Confirmation, DeclinedRecoveryStartDoesNotRenewDeadline) {
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  queue(tinyFrame(MessageType_MessageType_ButtonAck));
  queue(tinyFrame(MessageType_MessageType_DebugLinkDecision, {0x08, 0x00}));
  RecoveryDevice request = {};
  request.has_word_count = true;
  request.word_count = 12;
  alarm(3);
  dispatch(MessageType_MessageType_RecoveryDevice, RecoveryDevice_fields,
           &request);
  alarm(0);
  EXPECT_EQ(1u, count(MessageType_MessageType_Failure));
  EXPECT_FALSE(setup_isArmed());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(Block13Confirmation, PollingPreservesVisibleCipherAndAnimationProgress) {
  startRecovery();
  const std::string cipher = recovery_get_cipher();
  EXPECT_EQ(0u, lastCipherGlyphPixels());
  GetFeatures features = {};
  Ping ping = {};

  // Drive the actual animation timer one tick at a time while polling faster
  // than the introduction completes. Never force or finish the animation
  // between polls: its late glyph must become visible despite the traffic.
  for (int poll = 0; poll < 20; ++poll) {
    const auto before = framebuffer();
    dispatch(MessageType_MessageType_GetFeatures, GetFeatures_fields,
             &features);
    EXPECT_EQ(before, framebuffer());
    advanceAnimation(ANIMATION_PERIOD);
  }
  EXPECT_GT(lastCipherGlyphPixels(), 0u);
  const auto complete = framebuffer();
  advanceAnimation(300);
  EXPECT_EQ(complete, framebuffer());

  // A completed mapping must remain visible at each handler return. Ping
  // draws Home itself, so its recovery restoration must be immediate.
  for (int poll = 0; poll < 8; ++poll) {
    dispatch(MessageType_MessageType_GetFeatures, GetFeatures_fields,
             &features);
    EXPECT_EQ(complete, framebuffer());
    dispatch(MessageType_MessageType_Ping, Ping_fields, &ping);
    EXPECT_EQ(complete, framebuffer());
    EXPECT_GT(lastCipherGlyphPixels(), 0u);
    advanceAnimation(ANIMATION_PERIOD);
    EXPECT_EQ(complete, framebuffer());
  }
  EXPECT_EQ(cipher, recovery_get_cipher());

  // Accepted input still creates a fresh animated cipher, even though the
  // previous recovery layout was visible before the handler ran.
  letter('a');
  EXPECT_EQ(0u, lastCipherGlyphPixels());
  advanceAnimation(400);
  EXPECT_GT(lastCipherGlyphPixels(), 0u);
}
