#include <gtest/gtest.h>

extern "C" {
#include "keepkey/firmware/erc7730_field.h"
#include "keepkey/firmware/erc7730_format.h"
}

#include <cstring>
#include <string>

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

namespace {
/* erc7730_format_unit's scaled line: the value at `decimals`, then the base. */
void ExpectUnit(const uint8_t value[32], uint8_t decimals, const char* base,
                const char* scaled) {
  char output[512];
  ASSERT_TRUE(
      erc7730_format_unit(value, decimals, base, output, sizeof(output)));
  const std::string text(output);
  EXPECT_EQ(text.substr(0, text.find("\nraw ")),
            std::string("unit set by signer\n") + scaled);
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
  // EIP-55 specification test vector.
  const uint8_t address[20] = {0x5a, 0xae, 0xb6, 0x05, 0x3f, 0x3e, 0x94,
                               0xc9, 0xb9, 0xa0, 0x9f, 0x33, 0x66, 0x94,
                               0x35, 0xe7, 0xef, 0x1b, 0xea, 0xed};
  uint8_t value[32] = {0};
  memcpy(value + 12, address, sizeof(address));
  char output[ERC7730_FORMATTED_VALUE_MAX + 1];
  ASSERT_TRUE(format(ERC7730_ABI_ADDRESS, 0, value, sizeof(value), output,
                     sizeof(output)));
  EXPECT_STREQ(output, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
  char exact[43];
  EXPECT_TRUE(format(ERC7730_ABI_ADDRESS, 0, value, sizeof(value), exact,
                     sizeof(exact)));
  EXPECT_FALSE(format(ERC7730_ABI_ADDRESS, 0, value, sizeof(value), exact,
                      sizeof(exact) - 1));
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

TEST(Erc7730Format, EscapesStringCapturesAndRejectsSmallOutput) {
  const uint8_t value[] = {'h', 'i', 0xe2, 0x82, 0xac};
  char output[16];
  ASSERT_TRUE(format(ERC7730_ABI_STRING, 0, value, sizeof(value), output,
                     sizeof(output)));
  EXPECT_STREQ(output, "hi\\xe2\\x82\\xac");
  char small[5];
  EXPECT_FALSE(format(ERC7730_ABI_STRING, 0, value, sizeof(value), small,
                      sizeof(small)));
  EXPECT_STREQ(small, "");

  // An embedded NUL used to end the confirm("%s") body early; it is escaped.
  const uint8_t nul[] = {'O', 'K', 0x00, 'X'};
  ASSERT_TRUE(
      format(ERC7730_ABI_STRING, 0, nul, sizeof(nul), output, sizeof(output)));
  EXPECT_STREQ(output, "OK\\x00X");

  // A full-size capture of non-ASCII bytes fits the documented maximum.
  uint8_t wide[ERC7730_ABI_CAPTURE_MAX];
  memset(wide, 0xff, sizeof(wide));
  char widest[ERC7730_FORMATTED_VALUE_MAX + 1];
  ASSERT_TRUE(format(ERC7730_ABI_STRING, 0, wide, sizeof(wide), widest,
                     sizeof(widest)));
  EXPECT_EQ(strlen(widest), (size_t)ERC7730_FORMATTED_VALUE_MAX);
}

namespace {

bool text(const char* input, size_t length, char* output, size_t size) {
  return erc7730_format_text(reinterpret_cast<const uint8_t*>(input), length,
                             output, size);
}

}  // namespace

// Control bytes and DEL are escaped like non-ASCII bytes, so a value that
// holds one is shown one-to-one instead of failing mid-review.
TEST(Erc7730Format, TextEscapesNulControlsAndDelete) {
  char output[32];
  for (int byte = 0; byte < 0x20; byte++) {
    const char input[3] = {'a', (char)byte, 'b'};
    char expected[16];
    snprintf(expected, sizeof(expected), "a\\x%02xb", byte);
    ASSERT_TRUE(text(input, sizeof(input), output, sizeof(output))) << byte;
    EXPECT_STREQ(output, expected) << byte;
  }
  ASSERT_TRUE(text("a\x7f", 2, output, sizeof(output)));
  EXPECT_STREQ(output, "a\\x7f");
  ASSERT_TRUE(text("\t", 1, output, sizeof(output)));
  EXPECT_STREQ(output, "\\x09");
}

// Every space is escaped, not only edge or doubled ones: the renderer drops a
// space at a line wrap or page start, so a literal one can vanish.
TEST(Erc7730Format, TextEscapesBackslashSpacesAndNonAscii) {
  char output[64];
  ASSERT_TRUE(text("a\\b", 3, output, sizeof(output)));
  EXPECT_STREQ(output, "a\\\\b");
  ASSERT_TRUE(text("a b", 3, output, sizeof(output)));
  EXPECT_STREQ(output, "a\\x20b");
  ASSERT_TRUE(text("pay to 0x1", 10, output, sizeof(output)));
  EXPECT_STREQ(output, "pay\\x20to\\x200x1");
  ASSERT_TRUE(text(" ab", 3, output, sizeof(output)));
  EXPECT_STREQ(output, "\\x20ab");
  ASSERT_TRUE(text("ab ", 3, output, sizeof(output)));
  EXPECT_STREQ(output, "ab\\x20");
  ASSERT_TRUE(text("a  b", 4, output, sizeof(output)));
  EXPECT_STREQ(output, "a\\x20\\x20b");
  ASSERT_TRUE(text(" ", 1, output, sizeof(output)));
  EXPECT_STREQ(output, "\\x20");
  // U+00E9 and U+1F600 in UTF-8.
  ASSERT_TRUE(text("\xc3\xa9", 2, output, sizeof(output)));
  EXPECT_STREQ(output, "\\xc3\\xa9");
  ASSERT_TRUE(text("x\xf0\x9f\x98\x80", 5, output, sizeof(output)));
  EXPECT_STREQ(output, "x\\xf0\\x9f\\x98\\x80");
  ASSERT_TRUE(text("!~", 2, output, sizeof(output)));
  EXPECT_STREQ(output, "!~");
  ASSERT_TRUE(text("", 0, output, sizeof(output)));
  EXPECT_STREQ(output, "");
}

TEST(Erc7730Format, TextFitsExactlyOrFailsClosed) {
  char output[8];
  ASSERT_TRUE(text("abcdefg", 7, output, 8));
  EXPECT_STREQ(output, "abcdefg");
  EXPECT_FALSE(text("abcdefgh", 8, output, 8));
  EXPECT_STREQ(output, "");
  ASSERT_TRUE(text("ab\xff", 3, output, 7));
  EXPECT_STREQ(output, "ab\\xff");
  EXPECT_FALSE(text("ab\xff", 3, output, 6));
  EXPECT_STREQ(output, "");
  ASSERT_TRUE(text("a\\", 2, output, 4));
  EXPECT_FALSE(text("a\\", 2, output, 3));
  EXPECT_FALSE(text("a", 1, output, 0));
  EXPECT_FALSE(text("a", 1, nullptr, 8));
}

namespace {

bool label(const char* input, char* output, size_t size) {
  return erc7730_format_label(reinterpret_cast<const uint8_t*>(input),
                              strlen(input), output, size);
}

}  // namespace

// Signer-authored text keeps a single interior space; edge and doubled spaces,
// backslashes, controls and non-ASCII bytes are escaped as in a value.
TEST(Erc7730Format, LabelKeepsSingleSpacesOnly) {
  char output[64];
  ASSERT_TRUE(label("Audit protocol", output, sizeof(output)));
  EXPECT_STREQ(output, "Audit protocol");
  ASSERT_TRUE(label("sign multisig operation", output, sizeof(output)));
  EXPECT_STREQ(output, "sign multisig operation");
  ASSERT_TRUE(label(" ab", output, sizeof(output)));
  EXPECT_STREQ(output, "\\x20ab");
  ASSERT_TRUE(label("ab ", output, sizeof(output)));
  EXPECT_STREQ(output, "ab\\x20");
  ASSERT_TRUE(label("a  b", output, sizeof(output)));
  EXPECT_STREQ(output, "a\\x20\\x20b");
  ASSERT_TRUE(label(" ", output, sizeof(output)));
  EXPECT_STREQ(output, "\\x20");
  ASSERT_TRUE(label("a\\b \xc3\xa9\n", output, sizeof(output)));
  EXPECT_STREQ(output, "a\\\\b \\xc3\\xa9\\x0a");
  ASSERT_TRUE(label("a\tb", output, sizeof(output)));
  EXPECT_STREQ(output, "a\\x09b");
  char small[4];
  EXPECT_FALSE(label("a b c", small, sizeof(small)));
  EXPECT_STREQ(small, "");
}

// The same bytes as a signed value still escape every space: an interpolated
// intent shows its text parts as labels and its value parts as values.
TEST(Erc7730Format, IntentTextPartsKeepSpacesButValuePartsDoNot) {
  char part[64], value[64];
  ASSERT_TRUE(label("Send to", part, sizeof(part)));
  EXPECT_STREQ(part, "Send to");
  const uint8_t captured[] = {'p', 'a', 'y', ' ', 't', 'o'};
  ASSERT_TRUE(format(ERC7730_ABI_STRING, 0, captured, sizeof(captured), value,
                     sizeof(value)));
  EXPECT_STREQ(value, "pay\\x20to");
  ASSERT_TRUE(text("Audit protocol", 14, value, sizeof(value)));
  EXPECT_STREQ(value, "Audit\\x20protocol");
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
  ExpectUnit(capture.data, 18, "ETH", "1 ETH");

  memset(capture.data, 0, sizeof(capture.data));
  capture.data[31] = 1;
  ExpectUnit(capture.data, 6, "USDC", "0.000001 USDC");

  memset(capture.data, 0, sizeof(capture.data));
  ExpectUnit(capture.data, 18, "", "0");
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
  ExpectUnit(capture.data, 3, "", "12.345");
  capture.data[30] = 0x2e;
  capture.data[31] = 0xe0;  // 12000
  ExpectUnit(capture.data, 3, "", "12");
}
