extern "C" {
#include "keepkey/emulator/libkkemu.h"
#include "keepkey/board/keepkey_display.h"
}
#include "gtest/gtest.h"
#include <atomic>
#include <cstring>
#include <thread>
#include <vector>
#include <unistd.h>

class EmulatorLifecycle : public ::testing::Test {
 protected:
  std::vector<uint8_t> flash = std::vector<uint8_t>(KKEMU_FLASH_SIZE, 0xff);
  void SetUp() override {
    ASSERT_EQ(0, kkemu_init(flash.data(), flash.size()));
    // This test drives the firmware clock explicitly, as threaded hosts do.
    ualarm(0, 0);
    uint8_t frame[2048];
    while (kkemu_pop_frame(frame)) {
    }
  }
  void TearDown() override {
    kkemu_shutdown();
    ualarm(0, 0);
  }
  static void capture(unsigned value) {
    Canvas* canvas = display_canvas();
    for (size_t y = 0; y < 64; ++y)
      for (size_t x = 0; x < 256; ++x)
        canvas->buffer[y * 256 + x] = ((value >> (x % 16)) & 1) ? 255 : 0;
    canvas->dirty = true;
    display_refresh();
  }
  static unsigned decode(const uint8_t* frame) {
    unsigned value = 0;
    for (unsigned x = 0; x < 16; ++x)
      if (frame[x]) value |= 1u << x;
    return value;
  }
};

TEST_F(EmulatorLifecycle, OverflowPreservesUnreadFramesAndRetriesDroppedFrame) {
  for (unsigned i = 1; i <= 65; ++i) capture(i);
  uint8_t frame[2048];
  for (unsigned i = 1; i <= 64; ++i) {
    ASSERT_EQ(1, kkemu_pop_frame(frame));
    EXPECT_EQ(i, decode(frame));
  }
  EXPECT_EQ(0, kkemu_pop_frame(frame));
  capture(65);  // previous drop must not suppress this retry as a duplicate
  ASSERT_EQ(1, kkemu_pop_frame(frame));
  EXPECT_EQ(65u, decode(frame));
}

TEST_F(EmulatorLifecycle, ConcurrentCaptureNeverTearsOrReordersUnreadSlots) {
  std::atomic<bool> done{false};
  std::thread producer([&] {
    for (unsigned i = 1; i <= 2000; ++i) capture(i);
    done.store(true);
  });
  uint8_t frame[2048];
  unsigned previous = 0, received = 0;
  for (;;) {
    if (!kkemu_pop_frame(frame)) {
      if (done.load()) break;
      std::this_thread::yield();
      continue;
    }
    unsigned value = decode(frame);
    EXPECT_GT(value, previous);
    for (size_t i = 0; i < sizeof(frame); ++i)
      EXPECT_EQ((value >> (i % 16)) & 1 ? 255 : 0, frame[i]);
    previous = value;
    ++received;
  }
  producer.join();
  EXPECT_GT(received, 0u);
}

TEST_F(EmulatorLifecycle, ShutdownStopsPollThreadAndAllowsRestart) {
  ASSERT_EQ(0, kkemu_start());
  usleep(20000);
  kkemu_shutdown();
  EXPECT_EQ(0, kkemu_is_running());
  EXPECT_EQ(-1, kkemu_start());
  ASSERT_EQ(0, kkemu_init(flash.data(), flash.size()));
  ualarm(0, 0);
  ASSERT_EQ(0, kkemu_start());
  usleep(20000);
  kkemu_shutdown();
  EXPECT_EQ(0, kkemu_is_running());
}

TEST_F(EmulatorLifecycle, ShutdownWakesConfirmationWaitingForHostDecision) {
  // Ping {button_protection:true}: park the actual firmware confirm loop.
  uint8_t request[64] = {'?', '#', '#', 0, 1, 0, 0, 0, 2, 0x10, 1};
  ASSERT_EQ(0, kkemu_write(request, sizeof(request), KKEMU_IFACE_MAIN));
  ASSERT_EQ(0, kkemu_start());
  bool waiting = false;
  for (int i = 0; i < 500 && !waiting; ++i) {
    uint8_t reply[64];
    if (kkemu_read(reply, sizeof(reply), KKEMU_IFACE_MAIN) == 64)
      waiting = reply[3] == 0 && reply[4] == 26;  // ButtonRequest
    if (!waiting) usleep(1000);
  }
  ASSERT_TRUE(waiting);
  kkemu_shutdown();
  EXPECT_EQ(0, kkemu_is_running());
}

TEST_F(EmulatorLifecycle, UnlockReleasesLockAcquiredBeforeConcurrentStop) {
  ASSERT_EQ(0, kkemu_start());
  kkemu_lock();
  usleep(50000);  // let the poll thread block on the lock we hold
  std::atomic<bool> stopped{false};
  std::thread stopper([&] {
    kkemu_stop();
    stopped.store(true);
  });
  // trylock is a no-op success once kkemu_stop() has cleared the flag.
  while (!kkemu_trylock()) std::this_thread::yield();
  kkemu_unlock();  // must still release the acquisition made while running
  for (int i = 0; i < 2000 && !stopped.load(); ++i) usleep(1000);
  if (!stopped.load()) {
    stopper.detach();
    FAIL() << "kkemu_stop() never joined: the lock was not released";
  }
  stopper.join();
  ASSERT_EQ(0, kkemu_start());  // a leaked lock would park the new poll thread
  bool acquired = false;
  for (int i = 0; i < 2000 && !acquired; ++i)
    if (!(acquired = kkemu_trylock())) usleep(1000);
  ASSERT_TRUE(acquired);
  kkemu_unlock();
}

// Serve any queued request in host-driven mode; a leftover wake Cancel would
// be answered with an unsolicited Failure.
static bool hostPollAnswersNothing() {
  for (int i = 0; i < 10; ++i) EXPECT_EQ(0, kkemu_poll());
  uint8_t reply[64];
  return kkemu_read(reply, sizeof(reply), KKEMU_IFACE_MAIN) == 0;
}

TEST_F(EmulatorLifecycle, StopOfIdlePollThreadLeavesNoCancelBehind) {
  ASSERT_EQ(0, kkemu_start());
  usleep(20000);
  kkemu_stop();
  EXPECT_TRUE(hostPollAnswersNothing());
}

TEST_F(EmulatorLifecycle, StopDiscardsCancelThePollThreadNeverRead) {
  ASSERT_EQ(0, kkemu_start());
  kkemu_lock();  // the thread blocks on the lock, so stop must inject a Cancel
  usleep(50000);
  std::thread stopper([] { kkemu_stop(); });
  usleep(100000);  // past the stop's quiesce wait: the Cancel is queued now
  kkemu_unlock();  // the thread takes the lock, sees the flag and exits
  stopper.join();
  EXPECT_TRUE(hostPollAnswersNothing());
}
