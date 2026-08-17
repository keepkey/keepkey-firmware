#include "gtest/gtest.h"

#include <string>

extern "C" {
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/font.h"
#include "keepkey/board/keepkey_board.h"
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
