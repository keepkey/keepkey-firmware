#include "gtest/gtest.h"
#include <cstring>
#include <cstdint>
#include <cstddef>

extern "C" {
#include "keepkey/board/usb.h"
#include "trezor/crypto/memzero.h"
}

namespace {
int read_result;
int deliveries;
int rejections;
int endpoint;
uint8_t* read_buffer;
usb_rx_callback_t user_rx_callback;
usb_rx_callback_t user_debug_rx_callback;
usb_u2f_rx_callback_t user_u2f_rx_callback;
char tiny;

int usbd_ep_read_packet(usbd_device*, uint8_t ep, void* buf, uint16_t length) {
  endpoint = ep;
  read_buffer = static_cast<uint8_t*>(buf);
  EXPECT_EQ(64, length);
  // Dirty the entire buffer, including bytes outside a short read. The
  // callback must scrub retained bytes on every return path.
  std::memset(buf, 0xa5, length);
  return read_result;
}
void msg_reject_short_tiny_packet() { ++rejections; }
#define CONFIDENTIAL
#define debugLog(L, B, T) ((void)0)
#define ENDPOINT_ADDRESS_MAIN_OUT 0x01
#include "../../lib/board/usb_rx_callbacks.h"
#undef ENDPOINT_ADDRESS_MAIN_OUT
#undef debugLog
#undef CONFIDENTIAL

void receive(const void* buf, size_t length) {
  ++deliveries;
  EXPECT_EQ(64u, length);
  EXPECT_EQ(0xa5, static_cast<const uint8_t*>(buf)[63]);
}

void check_callback(void (*callback)(usbd_device*, uint8_t), int expected_ep) {
  user_rx_callback = user_debug_rx_callback = receive;
  for (int result : {-1, 0, 1, 12, 63, 64}) {
    SCOPED_TRACE(result);
    read_result = result;
    deliveries = rejections = 0;
    callback(nullptr, 0xff);  // callbacks must use their registered endpoint
    EXPECT_EQ(expected_ep, endpoint);
    EXPECT_EQ(result == 64 ? 1 : 0, deliveries);
    EXPECT_EQ(result > 0 && result < 64 ? 1 : 0, rejections);
    for (size_t i = 0; i < 64; ++i) EXPECT_EQ(0, read_buffer[i]);
  }
  user_rx_callback = user_debug_rx_callback = nullptr;
  read_result = 64;
  deliveries = 0;
  callback(nullptr, 0xff);
  EXPECT_EQ(0, deliveries);
  for (size_t i = 0; i < 64; ++i) EXPECT_EQ(0, read_buffer[i]);
}
}  // namespace

TEST(USBCallbacks, MainShortCompleteEmptyErrorAndScrubbing) {
  check_callback(main_rx_callback, 0x01);
}
TEST(USBCallbacks, DebugShortCompleteEmptyErrorAndScrubbing) {
  check_callback(debug_rx_callback, 0x02);
}
