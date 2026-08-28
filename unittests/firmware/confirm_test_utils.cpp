extern "C" {
#include "keepkey/board/messages.h"
#include "keepkey/board/usb.h"
#include "keepkey/firmware/fsm.h"
#include "messages.pb.h"
}

#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// The board bootstrap lives in test_board.cpp and runs at most once per
// binary: a second kk_board_init()/timer_init() relinks the already-linked
// runnables[] and the queue walk in post_periodic() never returns.
void kk_test_board_init(void);

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

static bool kkconfirm_sendTiny(uint16_t msgId, const uint8_t* payload,
                               uint8_t len) {
  static int fd = -1;
  if (fd < 0) fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0) return false;

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
  return sendto(fd, frame, sizeof(frame), 0, (struct sockaddr*)&addr,
                sizeof(addr)) == (ssize_t)sizeof(frame);
}

/* One ButtonAck + one DebugLinkDecision, i.e. what a single screen eats. */
#define KKCONFIRM_MSGS_PER_SCREEN 2

bool kkconfirm_preload(int nYes, int nNo) {
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
  }

  static const uint8_t yes[] = {0x08, 0x01};  // DebugLinkDecision.yes_no
  static const uint8_t no[] = {0x08, 0x00};
  for (int i = 0; i < nYes + nNo + 1; i++) {
    if (!kkconfirm_sendTiny(MessageType_MessageType_ButtonAck, NULL, 0))
      return false;
    const uint8_t* decision = (i < nYes) ? yes : no;
    if (!kkconfirm_sendTiny(MessageType_MessageType_DebugLinkDecision, decision,
                            2))
      return false;
  }
  return true;
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
