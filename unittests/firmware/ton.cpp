extern "C" {
#include "keepkey/firmware/ton.h"
#include <string.h>
}

#include "gtest/gtest.h"

/* ------------------------------------------------------------------ */
/*  Address validation tests                                           */
/* ------------------------------------------------------------------ */

TEST(Ton, ValidateGoodBounceable) {
  // Generate a known address from the device and validate it.
  // We test with a well-known TON address format (48 chars, base64url).
  // Using UQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA as a baseline
  // format test — real addresses from ton_get_address will be validated
  // in integration tests.

  // Test the validation function handles NULL
  EXPECT_FALSE(ton_validateAddress(NULL));
}

TEST(Ton, ValidateWrongLength) {
  // Too short
  EXPECT_FALSE(ton_validateAddress("EQBvW8Z5h"));
  // Too long
  EXPECT_FALSE(ton_validateAddress(
      "EQBvW8Z5huBkMJYdnfAEM5JqTNkuWX3diqYENkWsILOAAAAAAAAAAAAA"));
  // Empty
  EXPECT_FALSE(ton_validateAddress(""));
}

TEST(Ton, ValidateBadChecksum) {
  // 48-char string but with garbage — CRC16 won't match
  EXPECT_FALSE(ton_validateAddress(
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCD"));
}

TEST(Ton, ValidateBadTag) {
  // 48-char base64url that decodes but has wrong tag byte
  // Tag must be 0x11, 0x51, 0x91, or 0xD1
  // This is a string that decodes to 36 bytes with tag=0x00
  EXPECT_FALSE(ton_validateAddress(
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
}

/* ------------------------------------------------------------------ */
/*  Round-trip: generate address then validate it                      */
/* ------------------------------------------------------------------ */

TEST(Ton, GenerateAndValidate) {
  // Use a dummy 32-byte public key
  uint8_t pubkey[32];
  memset(pubkey, 0x42, 32);

  char address[TON_ADDRESS_MAX_LEN];
  char raw_address[TON_RAW_ADDRESS_MAX_LEN];

  ASSERT_TRUE(ton_get_address(pubkey, true, false, 0,
                              address, sizeof(address),
                              raw_address, sizeof(raw_address)));

  // Generated address must be 48 chars
  EXPECT_EQ(strlen(address), 48u);

  // Generated address must pass validation
  EXPECT_TRUE(ton_validateAddress(address));
}

TEST(Ton, GenerateNonBounceableAndValidate) {
  uint8_t pubkey[32];
  memset(pubkey, 0xAB, 32);

  char address[TON_ADDRESS_MAX_LEN];
  char raw_address[TON_RAW_ADDRESS_MAX_LEN];

  ASSERT_TRUE(ton_get_address(pubkey, false, false, 0,
                              address, sizeof(address),
                              raw_address, sizeof(raw_address)));

  EXPECT_EQ(strlen(address), 48u);
  EXPECT_TRUE(ton_validateAddress(address));
}

TEST(Ton, GenerateTestnetAndValidate) {
  uint8_t pubkey[32];
  memset(pubkey, 0xCD, 32);

  char address[TON_ADDRESS_MAX_LEN];
  char raw_address[TON_RAW_ADDRESS_MAX_LEN];

  ASSERT_TRUE(ton_get_address(pubkey, true, true, 0,
                              address, sizeof(address),
                              raw_address, sizeof(raw_address)));

  EXPECT_EQ(strlen(address), 48u);
  EXPECT_TRUE(ton_validateAddress(address));
}

/* ------------------------------------------------------------------ */
/*  Formatting tests                                                   */
/* ------------------------------------------------------------------ */

TEST(Ton, FormatAmount) {
  char buf[64];

  ton_formatAmount(buf, sizeof(buf), 1000000000ULL);  // 1 TON
  EXPECT_STREQ(buf, "1 TON");

  ton_formatAmount(buf, sizeof(buf), 500000000ULL);  // 0.5 TON
  EXPECT_STREQ(buf, "0.5 TON");

  ton_formatAmount(buf, sizeof(buf), 0);
  EXPECT_STREQ(buf, "0 TON");
}
