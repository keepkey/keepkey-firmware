extern "C" {
// interface.h first: it is what neutralises the `delete` field in
// messages.pb.h, which is a keyword in C++.
#include "keepkey/transport/interface.h"
#include "keepkey/firmware/osmosis.h"
}

#include "gtest/gtest.h"

#include <string>

static std::string fmt(const char *value, const char *denom) {
  char out[OSMOSIS_AMOUNT_STR_LEN] = {0};
  osmosis_formatAmount(out, sizeof(out), value, denom);
  return std::string(out);
}

TEST(Osmosis, FormatAmountScalesUosmo) {
  EXPECT_EQ(fmt("1500000", "uosmo"), "1.500000 OSMO");
  EXPECT_EQ(fmt("1000000", "uosmo"), "1.000000 OSMO");
  EXPECT_EQ(fmt("0", "uosmo"), "0.000000 OSMO");
  // Sub-unit amounts keep every digit rather than collapsing to zero.
  EXPECT_EQ(fmt("500", "uosmo"), "0.000500 OSMO");
  EXPECT_EQ(fmt("1", "uosmo"), "0.000001 OSMO");
}

/*
 * The reason this formatter exists. A float carries ~7 significant decimal
 * digits, so the old atof() + "%.6f" path rendered large amounts rounded on
 * the screen the user approves — 123456789.123456 OSMO came out as
 * 123456792.000000. Integer formatting is exact at any magnitude.
 */
TEST(Osmosis, FormatAmountIsExactBeyondFloatPrecision) {
  EXPECT_EQ(fmt("123456789123456", "uosmo"), "123456789.123456 OSMO");
  EXPECT_EQ(fmt("999999999999999", "uosmo"), "999999999.999999 OSMO");
  EXPECT_EQ(fmt("18446744073709551615", "uosmo"), "18446744073709.551615 OSMO");
}

TEST(Osmosis, FormatAmountLeavesUnknownDenomsAlone) {
  // The device does not know the precision of an arbitrary denom, so the
  // base-unit integer is shown verbatim — never scaled by a guess.
  EXPECT_EQ(fmt("1500000", "uatom"), "1500000 uatom");
  EXPECT_EQ(fmt("42", "ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA6"),
            "42 ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA6");
  // "uosmo" must match exactly — a lookalike denom is not OSMO.
  EXPECT_EQ(fmt("1500000", "uosmox"), "1500000 uosmox");
}
