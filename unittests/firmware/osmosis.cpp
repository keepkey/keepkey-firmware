extern "C" {
// interface.h first: it is what neutralises the `delete` field in
// messages.pb.h, which is a keyword in C++.
#include "keepkey/transport/interface.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/osmosis.h"
#include "trezor/crypto/secp256k1.h"
}

#include "gtest/gtest.h"

#include <string>

bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

static std::string fmt(const char *value, const char *denom) {
  char out[OSMOSIS_AMOUNT_STR_LEN] = {0};
  EXPECT_TRUE(osmosis_formatAmount(out, sizeof(out), value, denom));
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
  EXPECT_EQ(
      fmt("42", "ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA6"),
      "42 ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA6");
  // "uosmo" must match exactly — a lookalike denom is not OSMO.
  EXPECT_EQ(fmt("1500000", "uosmox"), "1500000 uosmox");
}

TEST(Osmosis, FormatAmountRejectsNoncanonicalOrOutOfSchemaValues) {
  const char *invalid[] = {"",
                           "01",
                           "+1",
                           "-1",
                           " 1",
                           "1 ",
                           "0x1",
                           "1a",
                           "18446744073709551616",
                           "123456789012345678901234567890123"};
  for (const char *value : invalid) {
    char out[OSMOSIS_AMOUNT_STR_LEN] = "unchanged";
    EXPECT_FALSE(osmosis_formatAmount(out, sizeof(out), value, "uosmo"));
    EXPECT_STREQ(out, "");
  }

  char out[OSMOSIS_AMOUNT_STR_LEN] = {0};
  EXPECT_FALSE(osmosis_formatAmount(out, sizeof(out), "1", "bad denom"));
  EXPECT_FALSE(osmosis_formatAmount(out, sizeof(out), "1", "bad\"denom"));
  EXPECT_FALSE(osmosis_formatAmount(
      out, sizeof(out), "1",
      "ibc/12345678901234567890123456789012345678901234567890123456789012345"));
  EXPECT_FALSE(osmosis_formatAmount(out, 4, "1", "uosmo"));
}

TEST(Osmosis, BaseToPrecisionPreservesMaxLpAmountAndCanary) {
  struct {
    uint8_t out[34];
    uint8_t canary;
  } guarded = {{0}, 0xa5};
  const char value[] = "12345678901234567890123456789012";

  ASSERT_EQ(0, base_to_precision(guarded.out, (const uint8_t *)value,
                                 sizeof(guarded.out), strlen(value), 18));
  EXPECT_STREQ((const char *)guarded.out, "12345678901234.567890123456789012");
  EXPECT_EQ(guarded.canary, 0xa5);
}

TEST(Osmosis, BaseToPrecisionRejectsTruncationAndNoncanonicalValues) {
  uint8_t out[34] = {0};
  const char max_value[] = "12345678901234567890123456789012";
  EXPECT_LT(base_to_precision(out, (const uint8_t *)max_value, sizeof(out) - 1,
                              strlen(max_value), 18),
            0);
  EXPECT_LT(base_to_precision(out, (const uint8_t *)"01", sizeof(out), 2, 18),
            0);
  EXPECT_LT(base_to_precision(out, (const uint8_t *)"1x", sizeof(out), 2, 18),
            0);
}

TEST(Osmosis, MaxSwapAssetsAreRendererPagedCompletely) {
  const char denom[] =
      "ibc/1234567890123456789012345678901234567890123456789012345678901234";
  static_assert(sizeof(denom) - 1 == OSMOSIS_MAX_DENOM_LEN,
                "fixture must exercise the schema maximum");
  char token[OSMOSIS_AMOUNT_STR_LEN] = {0};
  ASSERT_TRUE(osmosis_formatAmount(token, sizeof(token),
                                   "12345678901234567890123456789012", denom));

  // The old combined sentence required more than the OLED's three rows. Each
  // 101-character asset now gets its own measured page, so both signed values
  // are fully accepted in exactly two independent confirmations.
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  EXPECT_TRUE(confirm_bytes(ButtonRequestType_ButtonRequest_Other, "Swap Input",
                            (const uint8_t *)token, strlen(token)));
  EXPECT_TRUE(confirm_bytes(ButtonRequestType_ButtonRequest_Other,
                            "Minimum Output", (const uint8_t *)token,
                            strlen(token)));
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(Osmosis, MsgSendSignsCanonicalNonNativeDenomination) {
  HDNode node = {
      0,
      0,
      {0},
      {0xb9, 0x9a, 0x39, 0x3a, 0x5a, 0x53, 0x0d, 0x90, 0xef, 0x6e, 0x46,
       0x4e, 0x8e, 0x2f, 0x2b, 0x8b, 0x5c, 0x64, 0xa7, 0x97, 0x29, 0xcd,
       0x8b, 0x6c, 0x69, 0x5c, 0x71, 0x72, 0x03, 0x02, 0xf1, 0x76},
      {0},
      {0},
      &secp256k1_info};
  hdnode_fill_public_key(&node);

  OsmosisSignTx msg = {};
  msg.account_number = 0;
  msg.has_chain_id = true;
  strlcpy(msg.chain_id, "osmosis-1", sizeof(msg.chain_id));
  msg.fee_amount = 800;
  msg.gas = 290000;
  msg.has_memo = true;
  msg.sequence = 0;
  msg.has_msg_count = true;
  msg.msg_count = 1;
  ASSERT_TRUE(osmosis_signTxInit(&node, &msg));

  const char denom[] =
      "ibc/1234567890123456789012345678901234567890123456789012345678901234";
  static_assert(sizeof(denom) - 1 == OSMOSIS_MAX_DENOM_LEN,
                "fixture must exercise the schema maximum");
  EXPECT_TRUE(osmosis_signTxUpdateMsgSend(
      "7", "osmo1rs7fckgznkaxs4sq02pexwjgar43p5wnkx9s92", denom));
}

TEST(Osmosis, RequiredValuesRejectEmptyAndNonDecimalAmounts) {
  EXPECT_FALSE(osmosis_validate_required_text(false, "uosmo"));
  EXPECT_FALSE(osmosis_validate_required_text(true, ""));
  EXPECT_TRUE(osmosis_validate_required_text(true, "uosmo"));
  EXPECT_TRUE(osmosis_validate_required_text(true, "ibc/0123456789ABCDEF"));
  EXPECT_FALSE(osmosis_validate_required_text(true, "u osmo"));
  EXPECT_FALSE(osmosis_validate_required_text(true, "u\"osmo"));
  EXPECT_FALSE(osmosis_validate_required_text(true, "u\\osmo"));
  EXPECT_FALSE(osmosis_validate_required_text(true, "u\nosmo"));

  EXPECT_FALSE(osmosis_validate_amount(false, "1"));
  EXPECT_FALSE(osmosis_validate_amount(true, ""));
  EXPECT_FALSE(osmosis_validate_amount(true, "1.0"));
  EXPECT_FALSE(osmosis_validate_amount(true, "-1"));
  EXPECT_FALSE(osmosis_validate_amount(true, "1e6"));
  EXPECT_TRUE(osmosis_validate_amount(true, "0"));
  EXPECT_TRUE(osmosis_validate_amount(true, "1000000"));

  /* Noncanonical padding renders differently for the same value --
     "00000001" reaches the screen as "00.000001 OSMO" -- so one amount would
     have several spellings and the host would pick which one the owner sees. */
  EXPECT_FALSE(osmosis_validate_amount(true, "01"));
  EXPECT_FALSE(osmosis_validate_amount(true, "0000001"));
  EXPECT_FALSE(osmosis_validate_amount(true, "00000001"));
  EXPECT_FALSE(osmosis_validate_amount(true, "0001000000"));
  EXPECT_FALSE(osmosis_validate_amount(true, "00"));
}
