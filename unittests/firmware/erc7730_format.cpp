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
