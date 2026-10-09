#include <gtest/gtest.h>

extern "C" {
#include "keepkey/firmware/erc7730_format.h"
}

#include <cstring>

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
