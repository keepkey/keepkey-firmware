extern "C" {
#include "keepkey/firmware/dice_input.h"
}

#include "gtest/gtest.h"

#include <cstring>
#include <string>

static std::string hexlify(const uint8_t *bytes, size_t len) {
  static const char *alph = "0123456789abcdef";
  std::string out;
  for (size_t i = 0; i < len; i++) {
    out += alph[bytes[i] >> 4];
    out += alph[bytes[i] & 0xF];
  }
  return out;
}

TEST(Dice, RollsForStrength) {
  // d6 = 2.585 bits/roll; Coldcard-convention targets.
  EXPECT_EQ(dice_rolls_for_strength(128), 50u);
  EXPECT_EQ(dice_rolls_for_strength(192), 75u);
  EXPECT_EQ(dice_rolls_for_strength(256), 99u);
}

TEST(Dice, MixZeroEntropyVector) {
  // SHA256(0x00*32 || "123456")
  uint8_t entropy[32];
  memset(entropy, 0, sizeof(entropy));
  dice_mix(entropy, "123456", 6);
  EXPECT_EQ(hexlify(entropy, 32),
            "16ba88244e0230b0fc84868b703a0e32c344be1b0284f2e67e59715f123748d6");
}

TEST(Dice, MixNonZeroEntropyVector) {
  // SHA256(0x00..0x1f || "654321165243")
  uint8_t entropy[32];
  for (int i = 0; i < 32; i++) entropy[i] = (uint8_t)i;
  dice_mix(entropy, "654321165243", 12);
  EXPECT_EQ(hexlify(entropy, 32),
            "d1ab5a0b7f106313b6ba44d6863c5d1b90397d9e4a0f87a0a6baa25bad00ae97");
}

TEST(Dice, MixDependsOnRolls) {
  uint8_t a[32], b[32];
  memset(a, 0xAB, sizeof(a));
  memset(b, 0xAB, sizeof(b));
  dice_mix(a, "111111", 6);
  dice_mix(b, "111112", 6);
  EXPECT_NE(0, memcmp(a, b, 32));
}

TEST(Dice, MixUsesExactCount) {
  // Only `count` bytes of the roll buffer may contribute.
  uint8_t a[32], b[32];
  memset(a, 0, sizeof(a));
  memset(b, 0, sizeof(b));
  const char rolls_a[8] = {'1', '2', '3', '4', '5', '6', '1', '2'};
  const char rolls_b[8] = {'1', '2', '3', '4', '5', '6', '6', '5'};
  dice_mix(a, rolls_a, 6);
  dice_mix(b, rolls_b, 6);
  EXPECT_EQ(0, memcmp(a, b, 32));
}
