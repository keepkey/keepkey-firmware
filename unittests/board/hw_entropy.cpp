#include "gtest/gtest.h"
extern "C" {
#include "hw_entropy_probe.h"
}

TEST(HardwareEntropy, FirstHealthyBootProgramsAndLocksBeforeConsumption) {
  const auto result =
      test_collect_hw_entropy(true, false, true, 0xff, OTP_HEALTHY);
  EXPECT_TRUE(result.returned);
  EXPECT_FALSE(result.halted);
  EXPECT_TRUE(result.locked);
  EXPECT_EQ(1u, result.draws);
  EXPECT_EQ(32u, result.writes);
  EXPECT_EQ(1u, result.locks);
  EXPECT_EQ(2u, result.reads);
  EXPECT_EQ(2u, result.reads_before_lock);
  for (size_t i = 0; i < 12; ++i) EXPECT_EQ(i, result.collected[i]);
  for (size_t i = 0; i < 32; ++i) {
    EXPECT_EQ(0x40 + i, result.otp[i]);
    EXPECT_EQ(0x40 + i, result.collected[12 + i]);
  }
}

TEST(HardwareEntropy,
     RejectedFirstDrawHaltsBeforeErasedOrPartialOtpConsumption) {
  for (uint8_t previous : {uint8_t(0xff), uint8_t(0x19)}) {
    const auto result =
        test_collect_hw_entropy(true, false, false, previous, OTP_HEALTHY);
    EXPECT_FALSE(result.returned);
    EXPECT_TRUE(result.halted);
    EXPECT_TRUE(result.local_cleared);
    EXPECT_TRUE(result.global_cleared);
    EXPECT_FALSE(result.locked);
    EXPECT_EQ(1u, result.draws);
    EXPECT_EQ(0u, result.writes);
    EXPECT_EQ(0u, result.locks);
    EXPECT_EQ(0u, result.reads);
    for (uint8_t byte : result.otp) EXPECT_EQ(previous, byte);
    for (uint8_t byte : result.collected) EXPECT_EQ(0, byte);
  }
}

TEST(HardwareEntropy, ExistingLockedEntropyDoesNotNeedANewDraw) {
  const auto result =
      test_collect_hw_entropy(true, true, false, 0x71, OTP_HEALTHY);
  EXPECT_TRUE(result.returned);
  EXPECT_FALSE(result.halted);
  EXPECT_EQ(0u, result.draws);
  EXPECT_EQ(0u, result.writes);
  EXPECT_EQ(0u, result.locks);
  EXPECT_EQ(1u, result.reads);
  for (size_t i = 0; i < 12; ++i) EXPECT_EQ(i, result.collected[i]);
  for (size_t i = 12; i < 44; ++i) EXPECT_EQ(0x71, result.collected[i]);
}

TEST(HardwareEntropy, UnsignedFirmwareRetainsItsDocumentedFixedEntropy) {
  const auto result =
      test_collect_hw_entropy(false, false, false, 0xff, OTP_HEALTHY);
  EXPECT_TRUE(result.returned);
  EXPECT_FALSE(result.halted);
  EXPECT_EQ(0u, result.draws + result.writes + result.locks + result.reads);
  for (uint8_t byte : result.collected) EXPECT_EQ(0x3c, byte);
}

TEST(HardwareEntropy, FailedOrPartialProgrammingCannotLockOrReleaseEntropy) {
  for (auto fault : {OTP_WRITE_REJECTED, OTP_WRITE_DROPPED, OTP_WRITE_PARTIAL,
                     OTP_READ_REJECTED}) {
    const auto result = test_collect_hw_entropy(true, false, true, 0xff, fault);
    EXPECT_TRUE(result.halted);
    EXPECT_FALSE(result.returned);
    EXPECT_TRUE(result.local_cleared);
    EXPECT_TRUE(result.global_cleared);
    EXPECT_FALSE(result.locked);
    EXPECT_EQ(0u, result.locks);
    for (uint8_t byte : result.collected) EXPECT_EQ(0, byte);
  }
}

TEST(HardwareEntropy, FailedLockCannotReleaseVerifiedButMutableEntropy) {
  for (auto fault : {OTP_LOCK_REJECTED, OTP_LOCK_DROPPED}) {
    const auto result = test_collect_hw_entropy(true, false, true, 0xff, fault);
    EXPECT_TRUE(result.halted);
    EXPECT_FALSE(result.returned);
    EXPECT_TRUE(result.local_cleared);
    EXPECT_TRUE(result.global_cleared);
    EXPECT_FALSE(result.locked);
    EXPECT_EQ(32u, result.writes);
    EXPECT_EQ(2u, result.reads_before_lock);
    EXPECT_EQ(1u, result.locks);
    for (uint8_t byte : result.collected) EXPECT_EQ(0, byte);
  }
}

TEST(HardwareEntropy, FailedReadOfLockedBlockCannotReleasePartialEntropy) {
  const auto result =
      test_collect_hw_entropy(true, true, false, 0x71, OTP_READ_REJECTED);
  EXPECT_TRUE(result.halted);
  EXPECT_FALSE(result.returned);
  EXPECT_TRUE(result.global_cleared);
  EXPECT_TRUE(result.locked);
  EXPECT_EQ(0u, result.draws + result.writes + result.locks);
  EXPECT_EQ(1u, result.reads);
  for (uint8_t byte : result.collected) EXPECT_EQ(0, byte);
}

// OTP bits only clear. A boot that halted after programming must not leave a
// block that no later boot can complete.
TEST(HardwareEntropy, ProgrammedButUnlockedBlockIsKeptAndLocked) {
  const auto result =
      test_collect_hw_entropy(true, false, true, 0x19, OTP_HEALTHY);
  EXPECT_TRUE(result.returned);
  EXPECT_FALSE(result.halted);
  EXPECT_TRUE(result.locked);
  EXPECT_EQ(0u, result.writes);
  EXPECT_EQ(1u, result.locks);
  for (size_t i = 0; i < 32; ++i) {
    EXPECT_EQ(0x19, result.otp[i]);
    EXPECT_EQ(0x19, result.collected[12 + i]);
  }
}

TEST(HardwareEntropy, InterruptedFirstBootCompletesOnNextHealthyBoot) {
  for (auto fault : {OTP_WRITE_PARTIAL, OTP_LOCK_REJECTED, OTP_LOCK_DROPPED}) {
    auto first = test_collect_hw_entropy(true, false, true, 0xff, fault);
    ASSERT_TRUE(first.halted);
    ASSERT_FALSE(first.locked);
    const auto next = test_reboot_hw_entropy(&first, true, OTP_HEALTHY);
    EXPECT_TRUE(next.returned);
    EXPECT_FALSE(next.halted);
    EXPECT_TRUE(next.locked);
    EXPECT_EQ(fault == OTP_WRITE_PARTIAL ? 16u : 0u, next.writes);
    // Bytes the first boot programmed survive; only erased bytes take the
    // second, different draw.
    for (size_t i = 0; i < 32; ++i) {
      const bool first = fault != OTP_WRITE_PARTIAL || i < 16;
      const uint8_t expected =
          first ? uint8_t(0x40 + i)
                : uint8_t((0x40 + i) ^ TEST_REBOOT_DRAW_SALT);
      EXPECT_EQ(expected, next.otp[i]);
      EXPECT_EQ(expected, next.collected[12 + i]);
    }
  }
}
