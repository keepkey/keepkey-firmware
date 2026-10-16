extern "C" {
#include "keepkey/firmware/app_confirm.h"
}
#include "gtest/gtest.h"
#include "test_board.h"
#include <string>

TEST(AppConfirm, AllByteValuesHaveAnUnambiguousVisibleRepresentation) {
  for (unsigned value = 0; value < 256; ++value) {
    const uint8_t byte = value;
    char actual[5];
    char expected[5];
    if (value >= 0x21 && value <= 0x7e && value != 0x5c) {
      expected[0] = value;
      expected[1] = 0;
    } else {
      snprintf(expected, sizeof(expected), "\\x%02X", value);
    }
    ASSERT_TRUE(confirm_bytes_escape(&byte, 1, actual, sizeof(actual)));
    EXPECT_STREQ(expected, actual) << value;
  }
}

TEST(AppConfirm, PagesPreserveEveryEscapedByteIncludingHiddenSuffix) {
  kk_test_board_init();
  const std::string input = std::string(200, 'A') + "\n\t\\x00TAIL0199";
  char escaped[1024];
  ASSERT_TRUE(
      confirm_bytes_escape(reinterpret_cast<const uint8_t*>(input.data()),
                           input.size(), escaped, sizeof(escaped)));
  std::string joined;
  size_t offset = 0;
  unsigned pages = 0;
  while (offset < input.size()) {
    char page[128];
    size_t take = confirm_bytes_format_page(
        reinterpret_cast<const uint8_t*>(input.data() + offset),
        input.size() - offset, page, sizeof(page));
    ASSERT_GT(take, 0u);
    offset += take;
    joined += page;
    pages++;
  }
  EXPECT_GT(pages, 1u);
  EXPECT_EQ(escaped, joined);
  EXPECT_NE(std::string::npos, joined.find("TAIL0199"));
}
