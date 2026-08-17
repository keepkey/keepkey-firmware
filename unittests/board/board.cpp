#include "gtest/gtest.h"

#include <string>

extern "C" {
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/font.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/app_confirm.h"
}

TEST(Board, Shutdown) {
  EXPECT_EXIT(shutdown(), ::testing::ExitedWithCode(1), "");
}

// draw_string() stops once a glyph no longer fits the canvas and reports
// nothing, so a confirm body taller than BODY_ROWS was drawn in part with no
// indication at all. confirm_body_fits() is the measurement the confirm path
// now makes before it draws, so the cut can be announced.
TEST(Board, ConfirmBodyFits) {
  EXPECT_TRUE(confirm_body_fits(NULL, BODY_WIDTH));
  EXPECT_TRUE(confirm_body_fits("", BODY_WIDTH));
  EXPECT_TRUE(confirm_body_fits("one\ntwo\nthree", BODY_WIDTH));

  // The fourth row would land at y = 66, past KEEPKEY_DISPLAY_HEIGHT.
  EXPECT_FALSE(confirm_body_fits("one\ntwo\nthree\nfour", BODY_WIDTH));

  // confirm() first cuts the host's string into strbuf[BODY_CHAR_MAX], i.e.
  // to 351 characters. That cut cannot hide an overflow from this check: the
  // narrowest body glyph is 2px wide, so 351 of them are 702px, and three
  // rows hold at most 3 * BODY_WIDTH = 675px.
  EXPECT_FALSE(confirm_body_fits(std::string(351, 'i').c_str(), BODY_WIDTH));

  // The icon layout has LEFT_MARGIN_WITH_ICON less room for the same text.
  const std::string eighty_w(80, 'W');
  EXPECT_TRUE(confirm_body_fits(eighty_w.c_str(), BODY_WIDTH));
  EXPECT_FALSE(confirm_body_fits(eighty_w.c_str(), BODY_WIDTH_WITH_ICON));
}

// Regression: calc_str_line() accumulated into a uint8_t while returning
// uint32_t, so a body carrying 255 newlines wrapped the count back to 0 and
// confirm_body_fits() reported that it fitted. The 352-byte confirm buffer has
// room for a benign prefix, 255 newlines and a hidden suffix, so the "Cut Off"
// warning was skippable by a host that chose its whitespace.
//
// Every count here must exceed BODY_ROWS, including the ones that land on and
// around an 8-bit boundary.
TEST(Board, ConfirmBodyFitsLineCountDoesNotWrap) {
  for (size_t newlines : {(size_t)4, (size_t)254, (size_t)255, (size_t)256,
                          (size_t)257, (size_t)340}) {
    const std::string body(newlines, '\n');
    EXPECT_FALSE(confirm_body_fits(body.c_str(), BODY_WIDTH))
        << "a body of " << newlines << " newlines must not report as fitting";
  }

  // The shape an attacker would actually send: readable prefix, a wall of
  // newlines to wrap the counter, then the text that stays off screen.
  const std::string hidden =
      "Sign in to example.com" + std::string(255, '\n') + "APPROVE TRANSFER";
  EXPECT_FALSE(confirm_body_fits(hidden.c_str(), BODY_WIDTH));
}

static std::string FormatEveryPage(const std::string& input, size_t* pages) {
  std::string rendered;
  size_t offset = 0;
  *pages = 0;
  while (offset < input.size()) {
    char page[BODY_CHAR_MAX];
    const size_t take = confirm_bytes_format_page(
        reinterpret_cast<const uint8_t*>(input.data()) + offset,
        input.size() - offset, page, sizeof(page));
    EXPECT_GT(take, 0u);
    if (take == 0) break;
    EXPECT_LE(calc_str_line(get_body_font(), page, BODY_WIDTH), BODY_ROWS);
    rendered += page;
    offset += take;
    (*pages)++;
  }
  EXPECT_EQ(offset, input.size());
  return rendered;
}

TEST(Board, ExactBytePagesEscapeRendererWhitespaceAndNul) {
  static const char raw[] = " benign\nlogin\\\0authorization";
  const std::string payload(raw, sizeof(raw) - 1);
  size_t pages = 0;
  EXPECT_EQ(FormatEveryPage(payload, &pages),
            "\\x20benign\\x0Alogin\\x5C\\x00authorization");
  EXPECT_EQ(pages, 1u);
}

TEST(Board, ExactBytePagesNeverApproveOnlyAPrefix) {
  const std::string long_message =
      "Authorize transfer" + std::string(900, ' ') + "DENY";
  size_t pages = 0;
  const std::string rendered = FormatEveryPage(long_message, &pages);

  EXPECT_GT(pages, 1u);
  EXPECT_EQ(rendered.substr(0, 21), "Authorize\\x20transfer");
  EXPECT_EQ(rendered.substr(rendered.size() - 4), "DENY");
  EXPECT_EQ(rendered.size(), 21u + 900u * 4u + 4u);
}

// base_to_precision() previously used strlcpy(dst, src, n) to copy n DIGITS.
// strlcpy's third argument is the total destination size including the NUL, so
// it copied n-1 and dropped the last digit: a signed "1" rendered 0.00000 and
// "1234567" rendered 1.23456. It also terminated at dest[dest_len], one byte
// past a buffer whose supplied capacity is dest_len.
TEST(Board, BaseToPrecisionKeepsEveryDigit) {
  uint8_t out[64];

  // Fewer digits than the precision: zero-padded fraction, no digit lost.
  memset(out, 0xAA, sizeof(out));
  ASSERT_EQ(0, base_to_precision(out, (const uint8_t *)"1", sizeof(out), 1, 6));
  EXPECT_EQ(std::string((char *)out), "0.000001");

  // Exactly at the boundary.
  memset(out, 0xAA, sizeof(out));
  ASSERT_EQ(0, base_to_precision(out, (const uint8_t *)"123456", sizeof(out), 6, 6));
  EXPECT_EQ(std::string((char *)out), "0.123456");

  // One past the boundary: the last digit must survive.
  memset(out, 0xAA, sizeof(out));
  ASSERT_EQ(0, base_to_precision(out, (const uint8_t *)"1234567", sizeof(out), 7, 6));
  EXPECT_EQ(std::string((char *)out), "1.234567");

  memset(out, 0xAA, sizeof(out));
  ASSERT_EQ(0, base_to_precision(out, (const uint8_t *)"100000000", sizeof(out), 9, 6));
  EXPECT_EQ(std::string((char *)out), "100.000000");
}

// The NUL must land inside the supplied capacity, never at dest[dest_len].
TEST(Board, BaseToPrecisionRespectsCapacity) {
  uint8_t buf[16];

  // "1.234567" is 8 chars + NUL = 9; a capacity of 9 is exactly enough.
  memset(buf, 0xAA, sizeof(buf));
  ASSERT_EQ(0, base_to_precision(buf, (const uint8_t *)"1234567", 9, 7, 6));
  EXPECT_EQ(std::string((char *)buf), "1.234567");
  EXPECT_EQ(buf[9], 0xAA) << "wrote past the supplied capacity";

  // One byte short must be refused, not truncated.
  memset(buf, 0xAA, sizeof(buf));
  EXPECT_EQ(-1, base_to_precision(buf, (const uint8_t *)"1234567", 8, 7, 6));
  EXPECT_EQ(buf[0], 0xAA) << "buffer touched on the refusal path";

  EXPECT_EQ(-1, base_to_precision(NULL, (const uint8_t *)"1", 16, 1, 6));
  EXPECT_EQ(-1, base_to_precision(buf, NULL, 16, 1, 6));
}
