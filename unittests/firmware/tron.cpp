extern "C" {
#include "keepkey/firmware/tron.h"
#include "messages-tron.pb.h"
#include <string.h>
}

#include "gtest/gtest.h"

/* ------------------------------------------------------------------ */
/*  Address encoding / decoding tests                                  */
/* ------------------------------------------------------------------ */

TEST(Tron, DecodeValidAddress) {
  // TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t  (USDT contract)
  uint8_t raw[TRON_ADDRESS_SIZE];
  ASSERT_TRUE(tron_decodeAddress("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", raw));
  EXPECT_EQ(raw[0], 0x41);
}

TEST(Tron, DecodeInvalidAddress) {
  uint8_t raw[TRON_ADDRESS_SIZE];
  // Too short
  EXPECT_FALSE(tron_decodeAddress("T", raw));
  // Bad checksum
  EXPECT_FALSE(tron_decodeAddress("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6X", raw));
  // NULL
  EXPECT_FALSE(tron_decodeAddress(NULL, raw));
}

TEST(Tron, ValidateAddress) {
  EXPECT_TRUE(tron_validateAddress("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"));
  EXPECT_FALSE(tron_validateAddress("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6X"));
  EXPECT_FALSE(tron_validateAddress(NULL));
}

/* ------------------------------------------------------------------ */
/*  TRC-20 ABI decoding tests                                          */
/* ------------------------------------------------------------------ */

TEST(Tron, DecodeTRC20Transfer) {
  // Real TRC-20 transfer(address,uint256) ABI encoding:
  // selector: a9059cbb
  // to: 000000000000000000000000 + 20-byte EVM address
  // amount: 32-byte big-endian
  uint8_t data[68];
  memset(data, 0, sizeof(data));

  // selector
  data[0] = 0xa9; data[1] = 0x05; data[2] = 0x9c; data[3] = 0xbb;
  // EVM address at bytes 16..35 (12 zero pad + 20 addr)
  data[16] = 0xDE; data[17] = 0xAD; data[35] = 0xBE;
  // Amount: 1000000 (0xF4240) at last 3 bytes
  data[65] = 0x0F; data[66] = 0x42; data[67] = 0x40;

  uint8_t to_raw[TRON_ADDRESS_SIZE];
  uint8_t amount[32];
  ASSERT_TRUE(tron_decodeTRC20Transfer(data, sizeof(data), to_raw, amount));

  // Must prepend 0x41 TRON prefix
  EXPECT_EQ(to_raw[0], 0x41);
  EXPECT_EQ(to_raw[1], 0xDE);
  EXPECT_EQ(to_raw[2], 0xAD);

  // Amount check
  EXPECT_EQ(amount[29], 0x0F);
  EXPECT_EQ(amount[30], 0x42);
  EXPECT_EQ(amount[31], 0x40);
}

TEST(Tron, DecodeTRC20WrongSelector) {
  uint8_t data[68];
  memset(data, 0, sizeof(data));
  data[0] = 0x12; data[1] = 0x34; data[2] = 0x56; data[3] = 0x78;

  uint8_t to_raw[TRON_ADDRESS_SIZE];
  uint8_t amount[32];
  EXPECT_FALSE(tron_decodeTRC20Transfer(data, sizeof(data), to_raw, amount));
}

TEST(Tron, DecodeTRC20TooShort) {
  uint8_t data[60];
  memset(data, 0, sizeof(data));
  data[0] = 0xa9; data[1] = 0x05; data[2] = 0x9c; data[3] = 0xbb;

  uint8_t to_raw[TRON_ADDRESS_SIZE];
  uint8_t amount[32];
  EXPECT_FALSE(tron_decodeTRC20Transfer(data, sizeof(data), to_raw, amount));
}

TEST(Tron, DecodeTRC20NonZeroPadding) {
  // If the 12 leading pad bytes aren't all zero, reject
  uint8_t data[68];
  memset(data, 0, sizeof(data));
  data[0] = 0xa9; data[1] = 0x05; data[2] = 0x9c; data[3] = 0xbb;
  data[4] = 0x01;  // non-zero in padding area

  uint8_t to_raw[TRON_ADDRESS_SIZE];
  uint8_t amount[32];
  EXPECT_FALSE(tron_decodeTRC20Transfer(data, sizeof(data), to_raw, amount));
}

/* ------------------------------------------------------------------ */
/*  Formatting tests                                                   */
/* ------------------------------------------------------------------ */

TEST(Tron, FormatAmount) {
  char buf[64];

  tron_formatAmount(buf, sizeof(buf), 1000000);  // 1 TRX
  EXPECT_STREQ(buf, "1 TRX");

  tron_formatAmount(buf, sizeof(buf), 500000);  // 0.5 TRX
  EXPECT_STREQ(buf, "0.5 TRX");

  tron_formatAmount(buf, sizeof(buf), 0);
  EXPECT_STREQ(buf, "0 TRX");
}

TEST(Tron, FormatTokenAmount) {
  char buf[64];

  // 1 USDT (6 decimals) = 1000000
  uint8_t amount1[32];
  memset(amount1, 0, 32);
  amount1[29] = 0x0F; amount1[30] = 0x42; amount1[31] = 0x40;  // 1000000
  tron_formatTokenAmount(buf, sizeof(buf), amount1, 6, "USDT");
  EXPECT_STREQ(buf, "1 USDT");
}
