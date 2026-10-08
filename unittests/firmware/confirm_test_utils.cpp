extern "C" {
#include "keepkey/board/messages.h"
#include "keepkey/board/usb.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/pin_sm.h"
#include "messages.pb.h"
#include "pb_decode.h"
}

#include <arpa/inet.h>
#include <cstring>
#include <string>
#include <thread>
#include <vector>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// The board bootstrap lives in test_board.cpp and runs at most once per
// binary: a second kk_board_init()/timer_init() relinks the already-linked
// runnables[] and the queue walk in post_periodic() never returns.
#include "test_board.h"

/*
 * confirm() auto-accept driver for unit tests.
 *
 * In the emulator/unittest build (always DEBUG_LINK), confirm_helper()
 * busy-polls the emulator's UDP "usb" port for tiny messages and returns
 * once it has seen a ButtonAck plus a DebugLinkDecision. Each confirm screen
 * consumes exactly one pair. The trailing rejection sentinel makes an
 * under-budgeted test fail quickly instead of hanging until CI timeout.
 *
 * This source is unconditional because both full and bitcoin-only suites now
 * exercise security disclosures through confirm_bytes().
 */

static bool capture_screens;
static std::vector<std::string> captured_screens;
extern "C" void emulator_confirm_screen(const char*, const char* body) {
  if (capture_screens) captured_screens.emplace_back(body ? body : "");
}
void kkconfirm_capture_start(void) {
  captured_screens.clear();
  capture_screens = true;
}
std::vector<std::string> kkconfirm_capture_finish(void) {
  capture_screens = false;
  return std::move(captured_screens);
}

static int kkconfirm_fd = -1;

bool kkconfirm_sendTiny(uint16_t msgId, const uint8_t* payload, uint8_t len) {
  if (kkconfirm_fd < 0) kkconfirm_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (kkconfirm_fd < 0) return false;

  uint8_t frame[64] = {0};
  frame[0] = '?';
  frame[1] = '#';
  frame[2] = '#';
  frame[3] = msgId >> 8;
  frame[4] = msgId & 0xff;
  frame[8] = len;  // bytes 5..7 are the high bits of the big-endian size
  if (len) memcpy(&frame[9], payload, len);

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(11044);  // emulator main "usb" port
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  return sendto(kkconfirm_fd, frame, sizeof(frame), 0, (struct sockaddr*)&addr,
                sizeof(addr)) == (ssize_t)sizeof(frame);
}

/* One ButtonAck + one DebugLinkDecision, i.e. what a single screen eats. */
#define KKCONFIRM_MSGS_PER_SCREEN 2

static bool kkconfirm_preload_impl(int nYes, int nNo, bool sentinel) {
  static bool initialized = false;
  if (!initialized) {
    kk_test_board_init();  // canvas + runnable queues for confirm's draw path
    fsm_init();            // registers the usb rx callback + message maps
    usbInit("");           // binds the emulator UDP ports
    initialized = true;
  }

  // Start from a known-empty queue so a failed preceding test cannot lend its
  // decisions to the next one.
  {
    uint8_t stale[MSG_TINY_BFR_SZ];
    volatile uint16_t id;
    while ((id = (uint16_t)check_for_tiny_msg(stale)) != MSG_TINY_TYPE_ERROR) {
    }
    // The same client socket receives ButtonRequests and terminal responses.
    // Discard earlier output so response assertions cannot pass on stale data.
    while (kkconfirm_fd >= 0 &&
           recv(kkconfirm_fd, stale, sizeof(stale), MSG_DONTWAIT) > 0) {
    }
  }

  static const uint8_t yes[] = {0x08, 0x01};  // DebugLinkDecision.yes_no
  static const uint8_t no[] = {0x08, 0x00};
  for (int i = 0; i < nYes + nNo + (sentinel ? 1 : 0); i++) {
    if (!kkconfirm_sendTiny(MessageType_MessageType_ButtonAck, NULL, 0))
      return false;
    const uint8_t* decision = (i < nYes) ? yes : no;
    if (!kkconfirm_sendTiny(MessageType_MessageType_DebugLinkDecision, decision,
                            2))
      return false;
  }
  return true;
}

bool kkconfirm_preload(int nYes, int nNo) {
  return kkconfirm_preload_impl(nYes, nNo, true);
}

/* For a flow whose confirmations are followed by a wait that rejects any
 * foreign acknowledgement (the PIN prompt): the trailing sentinel pair would
 * reach that wait and cancel it as an unexpected message. The caller must end
 * the flow itself (for example with kkconfirm_sendCancel()), because an
 * under-budgeted test now blocks instead of failing fast. */
bool kkconfirm_preload_no_sentinel(int nYes, int nNo) {
  return kkconfirm_preload_impl(nYes, nNo, false);
}

// Wait after the last packet because loopback delivery is asynchronous. The
// final pair is the rejection sentinel and is discounted from the result.
#define KKCONFIRM_DRAIN_GRACE_US 200000
int kkconfirm_drain(void) {
  uint8_t buf[MSG_TINY_BFR_SZ];
  int n = 0;
  int idle_us = 0;
  while (idle_us < KKCONFIRM_DRAIN_GRACE_US) {
    volatile uint16_t id = (uint16_t)check_for_tiny_msg(buf);
    if (id != MSG_TINY_TYPE_ERROR) {
      n++;
      idle_us = 0;
      continue;
    }
    usleep(1000);
    idle_us += 1000;
  }
  return n - KKCONFIRM_MSGS_PER_SCREEN;
}

// Queue a host Cancel behind the confirmations already preloaded, so a later
// PIN prompt is cancelled as a host would.
bool kkconfirm_sendCancel(void) {
  return kkconfirm_sendTiny(MessageType_MessageType_Cancel, NULL, 0);
}

// Read real encoded USB response frames from the confirmation client's UDP
// socket. This remains outside firmware code and survives the shared frame
// arena's mandatory wipe on completion of an inbound request.
bool kkconfirm_readResponse(uint16_t expected, const pb_field_t* fields,
                            void* result) {
  uint8_t payload[2048] = {};
  // Every message, wanted or not, is tracked by its announced length. A frame
  // starts a message only when the previous one is complete: continuation
  // payload is arbitrary protobuf and may legitimately begin with "##".
  size_t announced = 0, consumed = 0;
  bool matching = false;
  for (int idle_us = 0; idle_us < KKCONFIRM_DRAIN_GRACE_US;) {
    uint8_t frame[64] = {};
    const ssize_t count =
        recv(kkconfirm_fd, frame, sizeof(frame), MSG_DONTWAIT);
    if (count <= 0) {
      usleep(1000);
      idle_us += 1000;
      continue;
    }
    if (count != sizeof(frame) || frame[0] != '?') return false;
    size_t offset = 1;
    if (consumed == announced) {
      if (frame[1] != '#' || frame[2] != '#') return false;
      matching = ((uint16_t(frame[3]) << 8) | frame[4]) == expected;
      announced = (uint32_t(frame[5]) << 24) | (uint32_t(frame[6]) << 16) |
                  (uint32_t(frame[7]) << 8) | frame[8];
      consumed = 0;
      offset = 9;
      if (matching && announced > sizeof(payload)) return false;
    }
    const size_t available = sizeof(frame) - offset;
    const size_t take =
        announced - consumed < available ? announced - consumed : available;
    if (matching) memcpy(payload + consumed, frame + offset, take);
    consumed += take;
    if (matching && consumed == announced) {
      pb_istream_t stream = pb_istream_from_buffer(payload, announced);
      return pb_decode(&stream, fields, result);
    }
  }
  return false;
}

#include "gtest/gtest.h"
extern "C" {
#include "keepkey/board/confirm_sm.h"
}

TEST(Confirmation, BackupSubpagesConsumeTheirOwnAcknowledgements) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  const char body[] = "one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\n";
  size_t pages = 0;
  for (const char* cursor = body; *cursor;) {
    const size_t take = confirm_constant_power_subpage_take(cursor);
    ASSERT_GT(take, 0u);
    cursor += take;
    pages++;
  }
  ASSERT_GT(pages, 1u);
  const uint8_t yes[] = {0x08, 0x01};
  const uint8_t no[] = {0x08, 0x00};
  // Decisions can arrive before acknowledgements on the separate debug link.
  for (size_t page = 0; page < pages; page++) {
    ASSERT_TRUE(kkconfirm_sendTiny(MessageType_MessageType_DebugLinkDecision,
                                   yes, sizeof(yes)));
    ASSERT_TRUE(kkconfirm_sendTiny(MessageType_MessageType_ButtonAck, NULL, 0));
  }
  ASSERT_TRUE(kkconfirm_sendTiny(MessageType_MessageType_ButtonAck, NULL, 0));
  ASSERT_TRUE(kkconfirm_sendTiny(MessageType_MessageType_DebugLinkDecision, no,
                                 sizeof(no)));
  EXPECT_TRUE(confirm_constant_power_paged(
      ButtonRequestType_ButtonRequest_ConfirmWord, "Backup", body));
  EXPECT_EQ(0, kkconfirm_drain());
}

// A client of the emulator's debug "usb" port. The emulator answers PING with
// PONG and from then on sends debug-channel output to this socket.
static int kkconfirm_debug_fd = -1;
bool kkconfirm_openDebugPeer(void) {
  if (!kkconfirm_preload(0, 0)) return false;  // one-time usbInit()
  if (kkconfirm_debug_fd < 0)
    kkconfirm_debug_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (kkconfirm_debug_fd < 0) return false;
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(11045);  // emulator debug "usb" port
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  static const char ping[] = {'P', 'I', 'N', 'G', 'P', 'I', 'N', 'G'};
  if (sendto(kkconfirm_debug_fd, ping, sizeof(ping), 0,
             (struct sockaddr*)&addr, sizeof(addr)) != (ssize_t)sizeof(ping))
    return false;
  if (kkconfirm_drain() != 0) return false;  // polls the ports
  uint8_t pong[64] = {};
  return recv(kkconfirm_debug_fd, pong, sizeof(pong), MSG_DONTWAIT) == 8 &&
         memcmp(pong, "PONGPONG", 8) == 0;
}

bool kkconfirm_readDebugFrame(uint8_t frame[64]) {
  for (int idle_us = 0; idle_us < KKCONFIRM_DRAIN_GRACE_US; idle_us += 1000) {
    if (recv(kkconfirm_debug_fd, frame, 64, MSG_DONTWAIT) == 64) return true;
    usleep(1000);
  }
  return false;
}

// Answers the device's next PinMatrixRequest as a host does, from its own
// thread while the caller blocks in pin_protect(): once the request frame
// arrives the scrambled matrix is final, so send the positions of `pin` in it.
std::thread kkconfirm_answerPinMatrix(const std::string& pin) {
  // Bind the emulator's main port to this client before the wait starts.
  kkconfirm_preload(0, 0);
  kkconfirm_drain();
  return std::thread([pin] {
    PinMatrixRequest request = {};
    bool requested = false;
    for (int i = 0; i < 25 && !requested; ++i) {
      requested = kkconfirm_readResponse(MessageType_MessageType_PinMatrixRequest,
                                         PinMatrixRequest_fields, &request);
    }
    const std::string matrix = get_pin_matrix();
    std::string positions;
    for (char digit : pin) {
      positions += static_cast<char>('1' + matrix.find(digit));
    }
    std::vector<uint8_t> ack = {0x0a, static_cast<uint8_t>(positions.size())};
    ack.insert(ack.end(), positions.begin(), positions.end());
    kkconfirm_sendTiny(MessageType_MessageType_PinMatrixAck, ack.data(),
                       static_cast<uint8_t>(ack.size()));
  });
}
