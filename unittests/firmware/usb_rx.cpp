extern "C" {
#include "keepkey/board/messages.h"
#include "keepkey/board/usb.h"
#include "keepkey/firmware/fsm.h"
}

#include "gtest/gtest.h"

extern "C" {
void usb_rx_helper(const void *buf, size_t length, MessageMapType type);
void set_msg_failure_handler(msg_failure_t failure_func);
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

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

void kk_test_board_init(void);

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
