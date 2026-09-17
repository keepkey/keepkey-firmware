#include <gtest/gtest.h>

extern "C" {
#include "keepkey/firmware/erc7730_format.h"
}

#include <cstring>

namespace {

bool format(uint8_t kind, uint16_t size, const uint8_t* value, size_t length,
            char* output, size_t output_size) {
  const Erc7730AbiNode nodes[] = {
      {ERC7730_ABI_TUPLE, 0, 1, 1, 0},
      {kind, size, 0, 0, 0},
  };
  const Erc7730AbiProgram program{nodes, 2, 0};
  Erc7730AbiCapture capture{};
  capture.node = 1;
  capture.length = length;
  memcpy(capture.data, value, length);
  return erc7730_format_raw(&program, &capture, output, output_size);
}

}  // namespace

TEST(Erc7730Format, FormatsUnsignedAndSigned256BitIntegers) {
  uint8_t value[32] = {0};
  value[31] = 42;
  char output[ERC7730_FORMATTED_VALUE_MAX + 1];
  ASSERT_TRUE(format(ERC7730_ABI_UINT, 256, value, sizeof(value), output,
                     sizeof(output)));
  EXPECT_STREQ(output, "42");

  memset(value, 0xff, sizeof(value));
  ASSERT_TRUE(format(ERC7730_ABI_INT, 256, value, sizeof(value), output,
                     sizeof(output)));
  EXPECT_STREQ(output, "-1");

  memset(value, 0xff, sizeof(value));
  value[0] = 0x7f;
  ASSERT_TRUE(format(ERC7730_ABI_UINT, 256, value, sizeof(value), output,
                     sizeof(output)));
  EXPECT_STREQ(output,
               "578960446186580977117854925043439539266349923328202820197287920"
               "03956564819967");
}

TEST(Erc7730Format, FormatsAddressBoolAndBytesCanonically) {
  uint8_t value[32] = {0};
  for (size_t i = 0; i < 20; i++) value[12 + i] = i;
  char output[ERC7730_FORMATTED_VALUE_MAX + 1];
  ASSERT_TRUE(format(ERC7730_ABI_ADDRESS, 0, value, sizeof(value), output,
                     sizeof(output)));
  EXPECT_STREQ(output, "0x000102030405060708090a0b0c0d0e0f10111213");
  memset(value, 0, sizeof(value));
  value[31] = 1;
  ASSERT_TRUE(format(ERC7730_ABI_BOOL, 0, value, sizeof(value), output,
                     sizeof(output)));
  EXPECT_STREQ(output, "true");
  const uint8_t bytes[] = {0xaa, 0x00, 0xff};
  ASSERT_TRUE(format(ERC7730_ABI_BYTES, 0, bytes, sizeof(bytes), output,
                     sizeof(output)));
  EXPECT_STREQ(output, "0xaa00ff");
}

TEST(Erc7730Format, PreservesValidatedUtf8AndRejectsSmallOutput) {
  const uint8_t value[] = {'h', 'i', 0xe2, 0x82, 0xac};
  char output[16];
  ASSERT_TRUE(format(ERC7730_ABI_STRING, 0, value, sizeof(value), output,
                     sizeof(output)));
  EXPECT_EQ(memcmp(output, value, sizeof(value)), 0);
  char small[5];
  EXPECT_FALSE(format(ERC7730_ABI_STRING, 0, value, sizeof(value), small,
                      sizeof(small)));
}

TEST(Erc7730Format, FormatsDecimalAmountsWithoutFloatingPoint) {
  const Erc7730AbiNode nodes[] = {
      {ERC7730_ABI_TUPLE, 0, 1, 1, 0},
      {ERC7730_ABI_UINT, 256, 0, 0, 0},
  };
  const Erc7730AbiProgram program{nodes, 2, 0};
  Erc7730AbiCapture capture{};
  capture.node = 1;
  capture.length = 32;
  char output[128];

  capture.data[24] = 0x0d;
  capture.data[25] = 0xe0;
  capture.data[26] = 0xb6;
  capture.data[27] = 0xb3;
  capture.data[28] = 0xa7;
  capture.data[29] = 0x64;
  capture.data[30] = 0x00;
  capture.data[31] = 0x00;  // 1e18
  ASSERT_TRUE(erc7730_format_amount(&program, &capture, 18, "ETH", output,
                                    sizeof(output)));
  EXPECT_STREQ(output, "1 ETH");

  memset(capture.data, 0, sizeof(capture.data));
  capture.data[31] = 1;
  ASSERT_TRUE(erc7730_format_amount(&program, &capture, 6, "USDC", output,
                                    sizeof(output)));
  EXPECT_STREQ(output, "0.000001 USDC");

  memset(capture.data, 0, sizeof(capture.data));
  ASSERT_TRUE(erc7730_format_amount(&program, &capture, 18, nullptr, output,
                                    sizeof(output)));
  EXPECT_STREQ(output, "0");
}

TEST(Erc7730Format, TrimsOnlyFractionalTrailingZeroes) {
  const Erc7730AbiNode nodes[] = {
      {ERC7730_ABI_TUPLE, 0, 1, 1, 0},
      {ERC7730_ABI_UINT, 256, 0, 0, 0},
  };
  const Erc7730AbiProgram program{nodes, 2, 0};
  Erc7730AbiCapture capture{};
  capture.node = 1;
  capture.length = 32;
  capture.data[30] = 0x30;
  capture.data[31] = 0x39;  // 12345
  char output[32];
  ASSERT_TRUE(erc7730_format_amount(&program, &capture, 3, nullptr, output,
                                    sizeof(output)));
  EXPECT_STREQ(output, "12.345");
  capture.data[30] = 0x2e;
  capture.data[31] = 0xe0;  // 12000
  ASSERT_TRUE(erc7730_format_amount(&program, &capture, 3, nullptr, output,
                                    sizeof(output)));
  EXPECT_STREQ(output, "12");
}

TEST(Erc7730Format, FormatsDurationsWithoutIntegerNarrowing) {
  Erc7730AbiNode node{};
  node.kind = ERC7730_ABI_UINT;
  node.size = 256;
  Erc7730AbiProgram program{&node, 1, 0};
  Erc7730AbiCapture capture{};
  capture.node = 0;
  capture.length = 32;
  capture.data[30] = 0x20;
  capture.data[31] = 0x3a;  // 8250 seconds
  char output[ERC7730_FORMATTED_VALUE_MAX + 1];
  ASSERT_TRUE(
      erc7730_format_duration(&program, &capture, output, sizeof(output)));
  EXPECT_STREQ(output, "02:17:30");

  capture.data[29] = 0x05;
  capture.data[30] = 0x7e;
  capture.data[31] = 0x3f;  // 359999 seconds
  ASSERT_TRUE(
      erc7730_format_duration(&program, &capture, output, sizeof(output)));
  EXPECT_STREQ(output, "99:59:59");

  node.kind = ERC7730_ABI_INT;
  memset(capture.data, 0xff, sizeof(capture.data));
  ASSERT_TRUE(
      erc7730_format_duration(&program, &capture, output, sizeof(output)));
  EXPECT_STREQ(output, "-00:00:01");

  node.kind = ERC7730_ABI_ADDRESS;
  EXPECT_FALSE(
      erc7730_format_duration(&program, &capture, output, sizeof(output)));
}
