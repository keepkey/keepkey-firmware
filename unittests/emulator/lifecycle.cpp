extern "C" {
#include "keepkey/emulator/libkkemu.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/timer.h"
#include "keepkey/firmware/storage.h"
}
#include "gtest/gtest.h"
#include <atomic>
#include <chrono>
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
  // A stop request no longer drops mutex ownership. A second acquisition
  // must not report success and let its unlock release our outer snapshot.
  usleep(100000);
  EXPECT_EQ(0, kkemu_trylock());
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

TEST_F(EmulatorLifecycle, HostDrivenDelaysAdvanceWithoutSignals) {
  uint32_t before = getSysTime();
  delay_ms(10);
  EXPECT_EQ(10u, getSysTime() - before);
  before = getSysTime();
  delay_ms_with_callback(10, [] {}, 2);
  EXPECT_EQ(10u, getSysTime() - before);
}

TEST_F(EmulatorLifecycle, ThreePinFailuresStillReachPinPrompt) {
  storage_setPin("1234");
  for (int i = 0; i < 3; ++i) storage_increasePinFails();
  session_clear(true);
  uint8_t request[64] = {'?', '#', '#', 0, 1, 0, 0, 0, 2, 0x18, 1};
  ASSERT_EQ(0, kkemu_write(request, sizeof(request), KKEMU_IFACE_MAIN));
  auto began = std::chrono::steady_clock::now();
  ASSERT_EQ(0, kkemu_start());
  bool prompt = false;
  while (std::chrono::steady_clock::now() - began < std::chrono::seconds(12)) {
    uint8_t reply[64];
    if (kkemu_read(reply, sizeof(reply), KKEMU_IFACE_MAIN) == 64 &&
        reply[3] == 0 && reply[4] == 18) {
      prompt = true;
      break;
    }
    usleep(1000);
  }
  EXPECT_TRUE(prompt);
  // The fix must not remove the real seven-second backoff at fail_count=3.
  EXPECT_GE(std::chrono::steady_clock::now() - began, std::chrono::seconds(7));
  EXPECT_EQ(0, kkemu_stop_timeout(1000));
}

TEST_F(EmulatorLifecycle, TimeoutPreservesOwnershipAndCanBeRetried) {
  ASSERT_EQ(0, kkemu_start());
  kkemu_lock();
  usleep(50000);  // park the poll thread on the host-owned lock
  std::atomic<int> stopped{0};
  auto began = std::chrono::steady_clock::now();
  std::thread stopper([&] { stopped = kkemu_shutdown_timeout(100); });
  stopper.join();
  EXPECT_EQ(-1, stopped.load());
  EXPECT_LT(std::chrono::steady_clock::now() - began,
            std::chrono::milliseconds(500));
  EXPECT_EQ(1, kkemu_is_running());
  EXPECT_EQ(-1, kkemu_start());
  EXPECT_EQ(0, kkemu_poll());  // cannot run a second firmware loop
  std::atomic<int> acquired{1};
  std::thread reader([&] {
    acquired = kkemu_trylock();
    if (acquired) kkemu_unlock();
  });
  reader.join();
  EXPECT_EQ(0, acquired.load());
  kkemu_unlock();
  ASSERT_EQ(0, kkemu_stop_timeout(1000));
  EXPECT_TRUE(hostPollAnswersNothing());
  EXPECT_EQ(0, kkemu_shutdown_timeout(1000));
  ASSERT_EQ(0, kkemu_init(flash.data(), flash.size()));
  ASSERT_EQ(0, kkemu_start());
  EXPECT_EQ(0, kkemu_shutdown_timeout(1000));
}

TEST_F(EmulatorLifecycle, FullInputRingDoesNotDefeatStopDeadline) {
  ASSERT_EQ(0, kkemu_start());
  kkemu_lock();
  usleep(50000);
  uint8_t request[64] = {'?', '#', '#', 0, 1};
  unsigned queued = 0;
  while (kkemu_write(request, sizeof(request), KKEMU_IFACE_MAIN) == 0) ++queued;
  ASSERT_GT(queued, 0u);
  auto began = std::chrono::steady_clock::now();
  std::atomic<int> result{0};
  std::thread stopper([&] { result = kkemu_stop_timeout(100); });
  stopper.join();
  EXPECT_EQ(-1, result.load());
  EXPECT_LT(std::chrono::steady_clock::now() - began,
            std::chrono::milliseconds(500));
  kkemu_unlock();
  EXPECT_EQ(0, kkemu_shutdown_timeout(1000));
}

TEST_F(EmulatorLifecycle, StopDuringPinBackoffTimesOutThenJoins) {
  storage_setPin("1234");
  for (int i = 0; i < 3; ++i) storage_increasePinFails();
  session_clear(true);
  uint8_t request[64] = {'?', '#', '#', 0, 1, 0, 0, 0, 2, 0x18, 1};
  ASSERT_EQ(0, kkemu_write(request, sizeof(request), KKEMU_IFACE_MAIN));
  ASSERT_EQ(0, kkemu_start());
  usleep(100000);
  EXPECT_EQ(-1, kkemu_stop_timeout(100));
  EXPECT_EQ(-1, kkemu_start());
  EXPECT_EQ(0, kkemu_trylock());
  EXPECT_EQ(0, kkemu_shutdown_timeout(12000));
}
