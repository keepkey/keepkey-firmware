extern "C" {
#include "pallas_ct.h"
}

#include <array>
#include <cstdint>
#include <cstring>

#include "gtest/gtest.h"

namespace {

const curve_point kPallasGenerator = {
    {/* x = p - 1 */ {0x00000000, 0x09698768, 0x133e46e6, 0x0d31f812,
                      0x00000224, 0x00000000, 0x00000000, 0x00000000,
                      0x00400000}},
    {/* y = 2 */ {0x00000002, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                  0x00000000, 0x00000000, 0x00000000, 0x00000000}},
};

const bignum256 kPallasPrime = {{0x00000001, 0x09698768, 0x133e46e6, 0x0d31f812,
                                 0x00000224, 0x00000000, 0x00000000, 0x00000000,
                                 0x00400000}};

const bignum256 kPallasOrder = {{0x00000001, 0x02375908, 0x052a3763, 0x0d31f813,
                                 0x00000224, 0x00000000, 0x00000000, 0x00000000,
                                 0x00400000}};

bignum256 ScalarWithBit(unsigned bit) {
  bignum256 scalar = {{0}};
  scalar.val[bit / BN_BITS_PER_LIMB] = UINT32_C(1) << (bit % BN_BITS_PER_LIMB);
  return scalar;
}

bignum256 DenseScalar() {
  bignum256 scalar;
  for (size_t i = 0; i < BN_LIMBS - 1; ++i) {
    scalar.val[i] = BN_LIMB_MASK;
  }
  scalar.val[BN_LIMBS - 1] = (UINT32_C(1) << 22) - 1;
  return scalar;
}

bignum256 Max256() {
  bignum256 value;
  for (size_t i = 0; i < BN_LIMBS - 1; ++i) {
    value.val[i] = BN_LIMB_MASK;
  }
  value.val[BN_LIMBS - 1] = UINT32_C(0x00ffffff);
  return value;
}

bool PointsEqual(const curve_point& lhs, const curve_point& rhs) {
  return std::memcmp(&lhs, &rhs, sizeof(lhs)) == 0;
}

bool BignumsEqual(const bignum256& lhs, const bignum256& rhs) {
  return std::memcmp(&lhs, &rhs, sizeof(lhs)) == 0;
}

void ExpectCountsEqual(const pallas_ct_counts& lhs,
                       const pallas_ct_counts& rhs) {
  EXPECT_EQ(lhs.field_add, rhs.field_add);
  EXPECT_EQ(lhs.field_sub, rhs.field_sub);
  EXPECT_EQ(lhs.field_mul, rhs.field_mul);
  EXPECT_EQ(lhs.field_select, rhs.field_select);
  EXPECT_EQ(lhs.point_add, rhs.point_add);
  EXPECT_EQ(lhs.point_double, rhs.point_double);
  EXPECT_EQ(lhs.scalar_round, rhs.scalar_round);
}

pallas_ct_counts MultiplyAndCount(const bignum256& scalar,
                                  curve_point* result) {
  pallas_ct_counts counts;
  pallas_ct_test_reset_counts();
  pallas_ct_point_mult(&scalar, &kPallasGenerator, result);
  pallas_ct_test_get_counts(&counts);
  return counts;
}

struct ProgressCapture {
  uint32_t calls = 0;
  uint32_t last_completed = 0;
  uint32_t last_total = 0;
  bool monotonic = true;
};

void CaptureProgress(uint32_t completed, uint32_t total, void* context) {
  auto* capture = static_cast<ProgressCapture*>(context);
  if (completed <= capture->last_completed) capture->monotonic = false;
  capture->calls++;
  capture->last_completed = completed;
  capture->last_total = total;
}

TEST(PallasConstantTime, ScalarScheduleDoesNotDependOnSecretBits) {
  const bignum256 zero = {{0}};
  const bignum256 one = ScalarWithBit(0);
  const bignum256 low_sparse = ScalarWithBit(17);
  const bignum256 high_sparse = ScalarWithBit(254);
  const bignum256 dense = DenseScalar();
  const bignum256 max_256 = Max256();
  bignum256 order_plus_one = kPallasOrder;
  ++order_plus_one.val[0];
  const std::array<bignum256, 8> scalars = {
      zero,  one,     low_sparse,   high_sparse,
      dense, max_256, kPallasOrder, order_plus_one,
  };

  curve_point result;
  const pallas_ct_counts baseline = MultiplyAndCount(scalars[0], &result);
  EXPECT_EQ(255u, baseline.scalar_round);
  EXPECT_EQ(255u, baseline.point_add);
  EXPECT_EQ(510u, baseline.point_double);

  for (size_t i = 1; i < scalars.size(); ++i) {
    const pallas_ct_counts counts = MultiplyAndCount(scalars[i], &result);
    ExpectCountsEqual(baseline, counts);
  }
}

TEST(PallasConstantTime, ProgressVariantMatchesAndReportsEveryFixedRound) {
  const bignum256 scalar = DenseScalar();
  curve_point expected, actual;
  pallas_ct_point_mult(&scalar, &kPallasGenerator, &expected);

  ProgressCapture progress;
  pallas_ct_point_mult_progress(&scalar, &kPallasGenerator, &actual,
                                CaptureProgress, &progress);

  EXPECT_TRUE(PointsEqual(expected, actual));
  EXPECT_TRUE(progress.monotonic);
  EXPECT_EQ(255u, progress.calls);
  EXPECT_EQ(255u, progress.last_completed);
  EXPECT_EQ(255u, progress.last_total);
}

TEST(PallasConstantTime, ZeroAndOneScalarResultsAreCanonical) {
  const bignum256 zero = {{0}};
  const bignum256 one = ScalarWithBit(0);
  const curve_point identity = {{{0}}, {{0}}};
  curve_point result;

  MultiplyAndCount(zero, &result);
  EXPECT_TRUE(PointsEqual(identity, result));

  MultiplyAndCount(one, &result);
  EXPECT_TRUE(PointsEqual(kPallasGenerator, result));
}

TEST(PallasConstantTime, PointAdditionHandlesExceptionalCases) {
  const curve_point identity = {{{0}}, {{0}}};
  curve_point result;

  pallas_ct_point_add(&identity, &kPallasGenerator, &result);
  EXPECT_TRUE(PointsEqual(kPallasGenerator, result));

  pallas_ct_point_add(&kPallasGenerator, &identity, &result);
  EXPECT_TRUE(PointsEqual(kPallasGenerator, result));

  curve_point inverse = kPallasGenerator;
  inverse.y.val[0] = 0x1fffffff;
  inverse.y.val[1] = 0x09698767;
  inverse.y.val[2] = 0x133e46e6;
  inverse.y.val[3] = 0x0d31f812;
  inverse.y.val[4] = 0x00000224;
  inverse.y.val[8] = 0x00400000;
  pallas_ct_point_add(&kPallasGenerator, &inverse, &result);
  EXPECT_TRUE(PointsEqual(identity, result));
}

TEST(PallasConstantTime, FieldArithmeticCanonicalizesBoundaryValues) {
  const bignum256 zero = {{0}};
  const bignum256 one = ScalarWithBit(0);
  bignum256 prime_plus_one = kPallasPrime;
  bignum256 prime_minus_one = kPallasPrime;
  bignum256 prime_minus_two = kPallasPrime;
  const bignum256 max_256 = Max256();
  const bignum256 max_reduced = {{0x1ffffffc, 0x03c369c7, 0x06452b4d,
                                  0x186a17c8, 0x1ffff992, 0x1fffffff,
                                  0x1fffffff, 0x1fffffff, 0x003fffff}};
  bignum256 result;
  ++prime_plus_one.val[0];
  --prime_minus_one.val[0];
  prime_minus_two.val[0] = BN_LIMB_MASK;
  --prime_minus_two.val[1];

  result = kPallasPrime;
  pallas_ct_mod_p(&result);
  EXPECT_TRUE(BignumsEqual(zero, result));

  result = prime_plus_one;
  pallas_ct_mod_p(&result);
  EXPECT_TRUE(BignumsEqual(one, result));

  result = max_256;
  pallas_ct_mod_p(&result);
  EXPECT_TRUE(BignumsEqual(max_reduced, result));

  result = prime_minus_one;
  pallas_ct_mul_mod_p(&result, &prime_minus_one);
  EXPECT_TRUE(BignumsEqual(one, result));

  result = prime_minus_one;
  pallas_ct_inv_mod_p(&result);
  EXPECT_TRUE(BignumsEqual(prime_minus_one, result));

  pallas_ct_add_mod_p(&prime_minus_one, &prime_minus_one, &result);
  EXPECT_TRUE(BignumsEqual(prime_minus_two, result));

  pallas_ct_sub_mod_p(&zero, &one, &result);
  EXPECT_TRUE(BignumsEqual(prime_minus_one, result));
}

TEST(PallasConstantTime, ScalarArithmeticAndMultiplicationReduceModOrder) {
  const bignum256 zero = {{0}};
  const bignum256 one = ScalarWithBit(0);
  bignum256 order_plus_one = kPallasOrder;
  bignum256 order_minus_one = kPallasOrder;
  const bignum256 max_256 = Max256();
  const bignum256 max_reduced = {{0x1ffffffc, 0x1959f4e7, 0x108159d6,
                                  0x186a17c6, 0x1ffff992, 0x1fffffff,
                                  0x1fffffff, 0x1fffffff, 0x003fffff}};
  bignum256 result;
  curve_point point;
  const curve_point identity = {{{0}}, {{0}}};
  ++order_plus_one.val[0];
  --order_minus_one.val[0];

  result = kPallasOrder;
  pallas_ct_mod_q(&result);
  EXPECT_TRUE(BignumsEqual(zero, result));

  result = order_plus_one;
  pallas_ct_mod_q(&result);
  EXPECT_TRUE(BignumsEqual(one, result));

  result = max_256;
  pallas_ct_mod_q(&result);
  EXPECT_TRUE(BignumsEqual(max_reduced, result));

  result = order_minus_one;
  pallas_ct_mul_mod_q(&result, &order_minus_one);
  EXPECT_TRUE(BignumsEqual(one, result));

  result = order_minus_one;
  pallas_ct_add_mod_q(&result, &one);
  EXPECT_TRUE(BignumsEqual(zero, result));

  MultiplyAndCount(kPallasOrder, &point);
  EXPECT_TRUE(PointsEqual(identity, point));

  MultiplyAndCount(order_plus_one, &point);
  EXPECT_TRUE(PointsEqual(kPallasGenerator, point));
}

TEST(PallasConstantTime, NonzeroScalarNormalizationIsBranchlessAndCanonical) {
  bignum256 zero = {{0}};
  bignum256 one = ScalarWithBit(0);
  bignum256 max_256 = Max256();
  const bignum256 expected_one = one;
  const bignum256 expected_max = max_256;

  pallas_ct_scalar_replace_zero_with_one(&zero);
  pallas_ct_scalar_replace_zero_with_one(&one);
  pallas_ct_scalar_replace_zero_with_one(&max_256);

  EXPECT_TRUE(BignumsEqual(expected_one, zero));
  EXPECT_TRUE(BignumsEqual(expected_one, one));
  EXPECT_TRUE(BignumsEqual(expected_max, max_256));
}

}  // namespace
