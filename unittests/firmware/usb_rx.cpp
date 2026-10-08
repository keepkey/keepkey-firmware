#include "gtest/gtest.h"

extern "C" {
#include "keepkey/board/messages.h"
#include "keepkey/board/usb.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/pin_sm.h"
#include "keepkey/firmware/passphrase_sm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/board/confirm_sm.h"
}

extern "C" {
void usb_rx_helper(const void *buf, size_t length, MessageMapType type);
void set_msg_failure_handler(msg_failure_t failure_func);
bool test_tiny_buffer_is_clear(void);
}

static int failure_count;
static std::string message;

static void setup() {
  failure_count = 0;

  set_msg_failure_handler(+[](FailureType code, const char *text) {
    failure_count++;
    message = text;
  });
}

TEST(USBRX, Overflow) {
  fsm_init();
  setup();

  char msg[64];
  TrezorFrame *frame = (TrezorFrame *)msg;
  TrezorFrameFragment *frame_fragment = (TrezorFrameFragment *)msg;

  frame->usb_header.hid_type = '?';
  frame->header.pre1 = '#';
  frame->header.pre2 = '#';
  frame->header.id = __builtin_bswap16(MessageType_MessageType_Initialize);
  frame->header.len = __builtin_bswap32(0xffffffff);
  usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);

  frame->header.pre1 = '0';
  frame->header.pre2 = '0';

  // Send packets up until the point just before where the buffer internal to
  // usb_rx_helper would overflow. All of these should succeeed.
  for (unsigned i = 0; i < 1039; i++) {
    usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
    ASSERT_EQ(failure_count, 0);
  }

  // Then on the last one, check that we detect the overflow before it happens:
  usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
  ASSERT_EQ(failure_count, 1);
  ASSERT_EQ(message, "Malformed message");

  // And check that the state got cleared out afterward:
  usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
  ASSERT_EQ(failure_count, 2);
  ASSERT_EQ(message, "Malformed packet");
}

TEST(USBRX, ErrorHandling) {
  fsm_init();
  setup();

  char msg[64];
  memset(msg, 0, sizeof(msg));

  // Missing '?'
  usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
  ASSERT_EQ(failure_count, 1);
  ASSERT_EQ(message, "Malformed packet");

  msg[0] = '?';

  // Missing '#'
  usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
  ASSERT_EQ(failure_count, 2);
  ASSERT_EQ(message, "Malformed packet");

  msg[1] = '#';

  // Missing '#'
  usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
  ASSERT_EQ(failure_count, 3);
  ASSERT_EQ(message, "Malformed packet");

  msg[2] = '#';
  msg[3] = 0xff;
  msg[6] = 0xff;

  // Unknown msgId
  usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
  ASSERT_EQ(failure_count, 4);
  ASSERT_EQ(message, "Unknown message");
}

// A short USB packet ends the receive in progress, so a frame that would have
// continued a partial message is read as a new (malformed) message instead.
TEST(USBRX, ShortPacketDropsAPartialMessage) {
  fsm_init();
  setup();

  char msg[64];
  TrezorFrame *frame = (TrezorFrame *)msg;
  memset(msg, 0, sizeof(msg));
  frame->usb_header.hid_type = '?';
  frame->header.pre1 = '#';
  frame->header.pre2 = '#';
  frame->header.id = __builtin_bswap16(MessageType_MessageType_Initialize);
  frame->header.len = __builtin_bswap32(200);  // needs more frames
  usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
  ASSERT_EQ(failure_count, 0);

  msg_reject_short_tiny_packet();

  frame->header.pre1 = '0';  // a continuation frame
  frame->header.pre2 = '0';
  usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
  EXPECT_EQ(failure_count, 1);
  EXPECT_EQ(message, "Malformed packet");
}

#include "test_board.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

TEST(USBRX, TinyAcknowledgementDoesNotReusePreviousSecret) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  ASSERT_GE(fd, 0);
  struct sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_port = htons(11044);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  const char secret[] = "previous-passphrase-secret";
  uint8_t frame[64] = {'?', '#', '#'};
  frame[3] = MessageType_MessageType_PassphraseAck >> 8;
  frame[4] = MessageType_MessageType_PassphraseAck & 0xff;
  frame[8] = sizeof(secret) + 1;
  frame[9] = 0x0a;
  frame[10] = sizeof(secret) - 1;
  memcpy(frame + 11, secret, sizeof(secret) - 1);
  EXPECT_EQ(sizeof(frame), sendto(fd, frame, sizeof(frame), 0,
                                  reinterpret_cast<struct sockaddr *>(&address),
                                  sizeof(address)));
  uint8_t received[MSG_TINY_BFR_SZ] = {};
  uint16_t id = MSG_TINY_TYPE_ERROR;
  for (int attempt = 0; attempt < 1000 && id == MSG_TINY_TYPE_ERROR;
       ++attempt) {
    id = check_for_tiny_msg(received);
    if (id == MSG_TINY_TYPE_ERROR) usleep(1000);
  }
  EXPECT_EQ(MessageType_MessageType_PassphraseAck, id);
  EXPECT_STREQ(secret, reinterpret_cast<PassphraseAck *>(received)->passphrase);
  EXPECT_TRUE(test_tiny_buffer_is_clear());

  memset(frame, 0, sizeof(frame));
  frame[0] = '?';
  frame[1] = frame[2] = '#';
  frame[3] = MessageType_MessageType_ButtonAck >> 8;
  frame[4] = MessageType_MessageType_ButtonAck & 0xff;
  EXPECT_EQ(sizeof(frame), sendto(fd, frame, sizeof(frame), 0,
                                  reinterpret_cast<struct sockaddr *>(&address),
                                  sizeof(address)));
  id = MSG_TINY_TYPE_ERROR;
  for (int attempt = 0; attempt < 1000 && id == MSG_TINY_TYPE_ERROR;
       ++attempt) {
    id = check_for_tiny_msg(received);
    if (id == MSG_TINY_TYPE_ERROR) usleep(1000);
  }
  close(fd);
  ASSERT_EQ(MessageType_MessageType_ButtonAck, id);
  for (uint8_t byte : received) EXPECT_EQ(0, byte);
}

static void expectMalformedTinyPacketRejected(size_t packet_length) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  fsm_init();
  setup();

  const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  ASSERT_GE(fd, 0);
  struct sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_port = htons(11044);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  uint8_t frame[64] = {'?', '#', '#'};
  frame[3] = MessageType_MessageType_PassphraseAck >> 8;
  frame[4] = MessageType_MessageType_PassphraseAck & 0xff;
  frame[8] = packet_length == sizeof(frame)
                 ? 56
                 : 0;  // More than the 55 payload bytes a tiny frame can hold.
  ASSERT_EQ(packet_length, sendto(fd, frame, packet_length, 0,
                                  reinterpret_cast<struct sockaddr *>(&address),
                                  sizeof(address)));

  uint8_t received[MSG_TINY_BFR_SZ];
  memset(received, 0xa5, sizeof(received));
  uint16_t id = MSG_TINY_TYPE_ERROR;
  for (int attempt = 0; attempt < 1000 && id == MSG_TINY_TYPE_ERROR;
       ++attempt) {
    id = check_for_tiny_msg(received);
    if (id == MSG_TINY_TYPE_ERROR) usleep(1000);
  }
  close(fd);
  EXPECT_EQ(MessageType_MessageType_Cancel, id);
  EXPECT_EQ(1, failure_count);
  EXPECT_TRUE(test_tiny_buffer_is_clear());
  for (uint8_t byte : received) EXPECT_EQ(0, byte);

  // A subsequent normal dispatch resets the tiny rejection state.
  uint8_t reset_frame[64] = {};
  handle_usb_rx(reset_frame, sizeof(reset_frame));
}

TEST(USBRX, MalformedTinyPacketCancelsAndClearsPendingBuffer) {
  expectMalformedTinyPacketRejected(64);
}

TEST(USBRX, ShortTinyPacketCancelsAndClearsPendingBuffer) {
  expectMalformedTinyPacketRejected(12);
}

static const uint8_t *observed_packet;
static size_t observed_length;
static void observe_packet(const void *packet, size_t length) {
  observed_packet = static_cast<const uint8_t *>(packet);
  observed_length = length;
  EXPECT_EQ(0x5a, observed_packet[20]);
}

TEST(USBRX, PacketStorageIsWipedAfterCallback) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  ASSERT_GE(fd, 0);
  struct sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_port = htons(11044);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  uint8_t frame[64];
  memset(frame, 0x5a, sizeof(frame));
  observed_packet = nullptr;
  observed_length = 0;
  usb_set_rx_callback(observe_packet);
  EXPECT_EQ(sizeof(frame), sendto(fd, frame, sizeof(frame), 0,
                                  reinterpret_cast<struct sockaddr *>(&address),
                                  sizeof(address)));
  for (int attempt = 0; attempt < 1000 && !observed_packet; ++attempt) {
    usbPoll();
    if (!observed_packet) usleep(1000);
  }
  close(fd);
  fsm_init();  // Restore the real callback before any fatal assertion.
  ASSERT_NE(nullptr, observed_packet);
  ASSERT_EQ(sizeof(frame), observed_length);
  // The transport owns static storage; observe its lifetime after callback.
  for (size_t i = 0; i < sizeof(frame); ++i) EXPECT_EQ(0, observed_packet[i]);
}

TEST(USBRX, BlockingMalformedTinyPacketReturnsWithoutAnotherHostMessage) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  fsm_init();
  setup();
  const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  ASSERT_GE(fd, 0);
  struct sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_port = htons(11044);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  uint8_t frame[64] = {'?', '#', '#'};
  frame[3] = MessageType_MessageType_PassphraseAck >> 8;
  frame[4] = MessageType_MessageType_PassphraseAck & 0xff;
  frame[8] = 56;
  ASSERT_EQ(sizeof(frame), sendto(fd, frame, sizeof(frame), 0,
                                  reinterpret_cast<struct sockaddr *>(&address),
                                  sizeof(address)));
  close(fd);
  uint8_t received[MSG_TINY_BFR_SZ];
  memset(received, 0xa5, sizeof(received));
  // A regression terminates this test process instead of hanging CI forever.
  alarm(3);
  const MessageType id = wait_for_tiny_msg(received);
  alarm(0);
  EXPECT_EQ(MessageType_MessageType_Cancel, id);
  EXPECT_EQ(1, failure_count);
  EXPECT_TRUE(test_tiny_buffer_is_clear());
  for (uint8_t byte : received) EXPECT_EQ(0, byte);
  uint8_t reset_frame[64] = {};
  handle_usb_rx(reset_frame, sizeof(reset_frame));
}

// Queue a valid acknowledgement for the wrong waiting handler, followed by
// Cancel so the old implementation terminates instead of hanging the suite.
// Only the rejection of the first message satisfies this contract.
static void expectWrongAcknowledgementRejected(MessageType wrong, int handler) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  fsm_init();
  setup();
  storage_reset();
  if (handler == 0) storage_setPin("1234");
  if (handler == 1) storage_setPassphraseProtected(true);
  const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  ASSERT_GE(fd, 0);
  struct sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_port = htons(11044);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  for (MessageType type : {wrong, MessageType_MessageType_Cancel}) {
    uint8_t frame[64] = {'?', '#', '#'};
    frame[3] = type >> 8;
    frame[4] = type & 0xff;
    if (type == MessageType_MessageType_PassphraseAck) {
      frame[8] = 2;
      frame[9] = 0x0a;  // Required passphrase string, empty but valid.
    }
    EXPECT_EQ(
        sizeof(frame),
        sendto(fd, frame, sizeof(frame), 0,
               reinterpret_cast<struct sockaddr *>(&address), sizeof(address)));
  }
  close(fd);
  if (handler == 0) EXPECT_FALSE(pin_protect_uncached());
  if (handler == 1) EXPECT_FALSE(passphrase_protect());
  if (handler == 2)
    EXPECT_FALSE(confirm(ButtonRequestType_ButtonRequest_Other,
                         "P02 acknowledgement", "Reject a foreign reply"));
  EXPECT_EQ(1, failure_count);
  EXPECT_TRUE(msg_handler_rejected());
  EXPECT_FALSE(session_isPassphraseCached());

  // A normal frame clears the rejection marker before the trailing Cancel is
  // drained. The next tiny poll would clear it as well.
  uint8_t reset_frame[64] = {};
  handle_usb_rx(reset_frame, sizeof(reset_frame));
  (void)kkconfirm_drain();
  fsm_init();
  storage_reset();
}

TEST(USBRX, PinWaitRejectsForeignAcknowledgement) {
  expectWrongAcknowledgementRejected(MessageType_MessageType_ButtonAck, 0);
}
TEST(USBRX, PassphraseWaitRejectsForeignAcknowledgement) {
  expectWrongAcknowledgementRejected(MessageType_MessageType_ButtonAck, 1);
}
TEST(USBRX, ButtonWaitRejectsForeignAcknowledgement) {
  expectWrongAcknowledgementRejected(MessageType_MessageType_PassphraseAck, 2);
}

TEST(USBRX, MalformedTinyFrameUnwindsAndNextPollRecovers) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  setup();

  const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  ASSERT_GE(fd, 0);
  struct sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_port = htons(11044);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  uint8_t frame[64] = {'?', '#', '#'};
  frame[3] = MessageType_MessageType_ButtonAck >> 8;
  frame[4] = MessageType_MessageType_ButtonAck & 0xff;
  uint8_t received[MSG_TINY_BFR_SZ] = {};
  EXPECT_EQ(
      sizeof(frame) - 1,
      sendto(fd, frame, sizeof(frame) - 1, 0,
             reinterpret_cast<struct sockaddr *>(&address), sizeof(address)));

  uint16_t id = MSG_TINY_TYPE_ERROR;
  for (int attempt = 0; attempt < 1000 && id == MSG_TINY_TYPE_ERROR;
       ++attempt) {
    id = check_for_tiny_msg(received);
    if (id == MSG_TINY_TYPE_ERROR) usleep(1000);
  }
  EXPECT_EQ(MessageType_MessageType_Cancel, id);
  EXPECT_EQ(1, failure_count);
  EXPECT_TRUE(msg_handler_rejected());

  EXPECT_EQ(sizeof(frame), sendto(fd, frame, sizeof(frame), 0,
                                  reinterpret_cast<struct sockaddr *>(&address),
                                  sizeof(address)));
  id = MSG_TINY_TYPE_ERROR;
  for (int attempt = 0; attempt < 1000 && id == MSG_TINY_TYPE_ERROR;
       ++attempt) {
    id = check_for_tiny_msg(received);
    if (id == MSG_TINY_TYPE_ERROR) usleep(1000);
  }
  close(fd);
  EXPECT_EQ(MessageType_MessageType_ButtonAck, id);
  EXPECT_EQ(1, failure_count);
  EXPECT_FALSE(msg_handler_rejected());
}

TEST(USBRX, DebugDispatchClearsAnEarlierTinyRejection) {
  fsm_init();
  setup();
  uint8_t frame[64] = {'?', '#', '#'};
  // Normal dispatch begins a fresh rejection scope.
  handle_usb_rx(frame, sizeof(frame));
  msg_reject_unexpected_tiny();
  ASSERT_TRUE(msg_handler_rejected());
  frame[3] = MessageType_MessageType_DebugLinkStop >> 8;
  frame[4] = MessageType_MessageType_DebugLinkStop & 0xff;
  handle_debug_usb_rx(frame, sizeof(frame));
  EXPECT_FALSE(msg_handler_rejected());
  const int before = failure_count;
  msg_reject_unexpected_tiny();
  EXPECT_EQ(before + 1, failure_count);
  handle_usb_rx(frame, sizeof(frame));
  fsm_init();
}
