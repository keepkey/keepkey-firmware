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

// Expected values below were computed in Python from the published formulas,
// not captured from this code: a vector produced by the function under test
// would only prove the function agrees with itself.

TEST(Dice, DeriveOnlyIsPlainSha256OfRolls) {
  // SHA256("123456") -- the Coldcard Dice-Rolls-Only derivation.
  uint8_t out[32];
  dice_derive_only("123456", 6, out);
  EXPECT_EQ(hexlify(out, 32),
            "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92");
}

TEST(Dice, DeriveMixedVector) {
  // SHA256d("KK\x01SM" || 0x00..0x1f || SHA256("KK\x01D" || "654321165243"))
  uint8_t device[32];
  for (int i = 0; i < 32; i++) device[i] = (uint8_t)i;
  uint8_t out[32];
  dice_derive_mixed(device, "654321165243", 12, out);
  EXPECT_EQ(hexlify(out, 32),
            "17a9fa5d19f12732194d3ff3fd73a8960880914fa902a799c7c3dc71ede30b58");
}

TEST(Dice, DeriveMixedZeroDeviceVector) {
  uint8_t device[32];
  memset(device, 0, sizeof(device));
  uint8_t out[32];
  dice_derive_mixed(device, "123456", 6, out);
  EXPECT_EQ(hexlify(out, 32),
            "ea5a7aaab1b6a55383edf17b1f55a6dcb0f3530c0a91a2d8940aeee68374864f");
}

TEST(Dice, DeriveMixedAliasesInPlace) {
  // reset.c derives into the same buffer the device draw lives in.
  uint8_t device[32], separate[32];
  for (int i = 0; i < 32; i++) device[i] = (uint8_t)i;
  dice_derive_mixed(device, "654321165243", 12, separate);
  dice_derive_mixed(device, "654321165243", 12, device);
  EXPECT_EQ(0, memcmp(device, separate, 32));
}

TEST(Dice, DeriveMixedDiffersFromUntaggedMix) {
  // The tagged derivation must not collide with what earlier firmware
  // derived for the same inputs, SHA256(draw || rolls) -- here
  // SHA256(0x00*32 || "123456"), computed in Python -- or a wallet could be
  // silently re-derived under the wrong formula.
  uint8_t device[32];
  memset(device, 0, sizeof(device));
  dice_derive_mixed(device, "123456", 6, device);
  EXPECT_NE(hexlify(device, 32),
            "16ba88244e0230b0fc84868b703a0e32c344be1b0284f2e67e59715f123748d6");
}

TEST(Dice, DeriveOnlyUsesExactCount) {
  // Only `count` bytes of the roll buffer may contribute.
  uint8_t a[32], b[32];
  const char rolls_a[8] = {'1', '2', '3', '4', '5', '6', '1', '2'};
  const char rolls_b[8] = {'1', '2', '3', '4', '5', '6', '6', '5'};
  dice_derive_only(rolls_a, 6, a);
  dice_derive_only(rolls_b, 6, b);
  EXPECT_EQ(0, memcmp(a, b, 32));
}

static std::string rolls_with_ones(size_t ones, size_t total) {
  std::string s(ones, '1');
  const char *rest = "23456";
  for (size_t i = 0; s.size() < total; i++) s += rest[i % 5];
  return s;
}

static std::string rolls_with_face(char face, size_t hits, size_t total) {
  std::string s(hits, face);
  for (size_t i = 0; s.size() < total; i++) {
    char c = (char)('1' + i % 6);
    if (c != face) s += c;
  }
  return s;
}

TEST(Dice, BiasGateRefusesOnlyAtOneInAMillion) {
  // Thresholds computed in Python as exact multinomial tail probabilities for
  // a fair d6: P(some face >= t) is 3.4e-7 (50 rolls, t=25), 6.2e-7 (75,
  // t=32) and 3.7e-7 (99, t=39); one roll lower each is above 1e-6.
  // t-1 must pass and t must refuse, on every face.
  const size_t n[3] = {50, 75, 99};
  const size_t t[3] = {25, 32, 39};
  for (int i = 0; i < 3; i++) {
    for (char face = '1'; face <= '6'; face++) {
      SCOPED_TRACE(std::string(1, face) + " of " + std::to_string(n[i]));
      EXPECT_FALSE(dice_rolls_look_biased(
          rolls_with_face(face, t[i] - 1, n[i]).c_str(), n[i]));
      EXPECT_TRUE(dice_rolls_look_biased(
          rolls_with_face(face, t[i], n[i]).c_str(), n[i]));
    }
    EXPECT_TRUE(dice_rolls_look_biased(std::string(n[i], '4').c_str(), n[i]));
  }
}

TEST(Dice, BiasGateAcceptsFairRolls) {
  // Python random.Random(20261007), 99 fair rolls; the 50- and 75-roll
  // prefixes are used as is (the 50 hold 15 ones, a 30% face).
  const char *fair =
      "23135565613255114162615221362354215336561251161111514163136116425456"
      "4225546215563143345143362442344";
  EXPECT_FALSE(dice_rolls_look_biased(fair, 50));
  EXPECT_FALSE(dice_rolls_look_biased(fair, 75));
  EXPECT_FALSE(dice_rolls_look_biased(fair, 99));
}

TEST(Dice, BiasGateRefusesCountsWithoutABound) {
  EXPECT_TRUE(dice_rolls_look_biased("1234561", 7));
}

TEST(Dice, BiasGateRejectsNonDiceBytes) {
  // A non-d6 byte anywhere inside `count` is refused, whatever the
  // distribution of the rest. (An earlier version of this test placed the bad
  // byte past `count`, where it is correctly never examined.)
  std::string s = rolls_with_ones(8, 50);
  EXPECT_FALSE(dice_rolls_look_biased(s.c_str(), 50));
  s[10] = '0';
  EXPECT_TRUE(dice_rolls_look_biased(s.c_str(), 50));
  s[10] = '7';
  EXPECT_TRUE(dice_rolls_look_biased(s.c_str(), 50));
  EXPECT_TRUE(dice_rolls_look_biased("1234567", 7));
}
