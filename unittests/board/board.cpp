// gtest first: confirm_sm.h defines an isprint() macro that collides with the
// standard library's declaration if the C++ headers are pulled in after it.
#include "gtest/gtest.h"

#include <csignal>
#include <cstring>
#include <string>
#include <unistd.h>

extern "C" {
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/font.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/app_confirm.h"
}

TEST(Board, Shutdown) {
  EXPECT_EXIT(shutdown(), ::testing::ExitedWithCode(1), "");
}

// Exactly BODY_ROWS rows of body text fit on the display: the body starts at
// TOP_MARGIN + font_height + BODY_TOP_MARGIN and advances by font_height +
// BODY_FONT_LINE_PADDING, so row 4 begins at y=66 on a 64px-tall screen and
// draw_char_with_shift() refuses to draw it. Nothing announces that -
// draw_string() simply stops - so a body of BODY_ROWS+1 rows loses its tail
// silently. confirm_helper() pages such bodies instead; these are the
// properties that split has to hold.
namespace {

constexpr uint32_t kRows = BODY_ROWS;
constexpr uint16_t kWidth = BODY_WIDTH;

// Real bodies from ethereum.c's layoutEthereumConfirmTx(). All four sit within
// a few characters of the limit, which is why the overflow is value-dependent
// and went unnoticed: swap wstETH for ETH, or 1000000 for 1, and it fits.
const char *const kOverflowing[] = {
    // "Unlock full %s balance for withdrawal by %s?"
    "Unlock full wstETH balance for withdrawal by "
    "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984?",
    // "Approve withdrawal of up to %s by %s?"
    "Approve withdrawal of up to 1000000 USDC by "
    "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984?",
    "Approve withdrawal of up to 0.000000000000000001 ETH by "
    "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984?",
};

// NOTE (alpha<-develop merge): three tests were removed here, and the
// property they asserted is currently UNCOVERED.
//
// They walked alpha's pagination entry point (confirm_body_split) and
// asserted that joining every page reproduces the body exactly and that a
// fitting body is never split. Those are the right properties. develop's
// pager (page_body_confirm) is static inside confirm_sm.c and has no such
// entry point, so the tests could not be retargeted mechanically.
//
// Re-express them against the shipped pager rather than leaving this gap:
// the cheapest route is to expose page_take() for test builds and assert the
// same two properties over it.

}  // namespace

// The bug: these bodies do not fit, so today they are drawn in part.
TEST(Board, ConfirmBodiesThatOverflowAreDetected) {
  for (const char *body : kOverflowing) {
    EXPECT_GT(calc_str_line(get_body_font(), body, kWidth), kRows)
        << "|" << body << "| no longer overflows; pick a new vector rather "
        << "than deleting this case";
  }
}

// The fix: paging discloses every character. Dropping the ERC-20 spender's
// last three hex digits is what lets a look-alike address pass review.

// calc_crc32() is what storage_commit() uses to decide a flash write survived,
// so the emulator has to compute what the STM32 peripheral computes. It did
// not: it ran a reflected zlib CRC-32 over word_len *bytes*, meaning a 643-word
// buffer was covered as 643 bytes. The storage suite could not tell a correct
// length from a truncated one, which is precisely the bug the V17 CRC fix was
// about.
//
// These vectors are CRC-32/MPEG-2 (poly 0x04C11DB7, init 0xFFFFFFFF, no
// reflection, no final XOR) over each word's big-endian bytes — what the
// peripheral produces for `CRC_DR = word`. Reading the buffer as uint32_t
// rather than as bytes keeps this independent of host endianness.
TEST(Board, Crc32MatchesTheStm32Peripheral) {
  const uint32_t one[] = {0x12345678};  // bytes 12 34 56 78
  EXPECT_EQ(0xDF8A8A2Bu, calc_crc32(one, 1));

  const uint32_t two[] = {0x12345678, 0x9ABCDEF0};  // ... 9A BC DE F0
  EXPECT_EQ(0x7D24A31Bu, calc_crc32(two, 2));
}

// storage_commit() marshals a 2572-byte buffer — 643 words — holding a
// 2569-byte V17 record, so the last meaningful byte is index 2568. It reaches
// storage_wipe() when the CRC disagrees, so a byte outside the CRC is a byte
// whose corruption surfaces later as a decrypt failure instead.
TEST(Board, Crc32CoversTheFinalByteOfTheV17Record) {
  alignas(uint32_t) uint8_t buf[2572] = {};
  const uint32_t clean643 = calc_crc32(buf, 643);
  const uint32_t clean642 = calc_crc32(buf, 642);

  buf[2568] = 0x01;

  EXPECT_NE(clean643, calc_crc32(buf, 643)) << "byte 2568 is outside the CRC";
  // The regression itself: at sizeof(flash_temp)==2570 the integer division
  // gave 642 words = 2568 bytes, and byte 2568 changed nothing.
  EXPECT_EQ(clean642, calc_crc32(buf, 642));
}

// confirm_body_fits() asks the real renderer whether the body will fit, so it
// needs the canvas the renderer draws into. board_init() does this on the
// device; here we do the same two steps in the same order. Without it
// layout_get_canvas() is NULL and every measurement is meaningless rather
// than merely wrong, so this fixture is a precondition for the tests below,
// not decoration.
class BodyFits : public ::testing::Test {
 protected:
  void SetUp() override {
    static bool ready = false;
    if (!ready) {
      timer_init();
      layout_init(display_canvas_init());
      // layout_init() starts a 1ms animation tick. These tests only measure
      // geometry, and letting the tick run would repaint the canvas
      // underneath them.
      ualarm(0, 0);
      signal(SIGALRM, SIG_IGN);
      ready = true;
    }
  }
};

// draw_string() stops once a glyph no longer fits the canvas and reports
// nothing, so a confirm body taller than BODY_ROWS was drawn in part with no
// indication at all. confirm_body_fits() is the measurement the confirm path
// now makes before it draws, so the cut can be announced.
TEST_F(BodyFits, ConfirmBodyFits) {
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

  // Regression: draw_string_walk() advanced str_write unconditionally, so a
  // REJECTED final glyph was still consumed and the walk then saw '\0' and
  // reported that everything fitted. The failure is exactly one glyph wide,
  // which is why the earlier three-way sweep of 3,510 bodies missed it: it
  // only shows at the precise boundary. 117 digits fill three rows; the 118th
  // is the first glyph that cannot be placed and must be reported as not
  // fitting.
  std::string digits;
  for (size_t i = 0; i < 118; i++) digits += "0123456789"[i % 10];
  EXPECT_TRUE(confirm_body_fits(digits.substr(0, 117).c_str(), BODY_WIDTH));
  EXPECT_FALSE(confirm_body_fits(digits.c_str(), BODY_WIDTH))
      << "a body overflowing by exactly one glyph must not report as fitting";
}

// Regression: calc_str_line() accumulated into a uint8_t while returning
// uint32_t, so a body carrying 255 newlines wrapped the count back to 0 and
// confirm_body_fits() reported that it fitted. The 352-byte confirm buffer
// has room for a benign prefix, 255 newlines and a hidden suffix, so the "Cut
// Off" warning was skippable by a host that chose its whitespace.
//
// Every count here must exceed BODY_ROWS, including the ones that land on and
// around an 8-bit boundary.
TEST_F(BodyFits, ConfirmBodyFitsLineCountDoesNotWrap) {
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

// The guard has now been broken three separate ways -- plain overflow, a
// uint8_t line counter wrapping at 255 newlines, and whitespace that one walk
// collapses and the other does not. All three were the same mistake: a second
// model of the screen (calc_str_line + BODY_ROWS) disagreeing with the first
// (draw_string), on an input the attacker chooses.
//
// So the model is gone. confirm_body_fits() now runs draw_string()'s own loop
// with the pixel writes switched off. This test pins the property that made
// that worth doing: a body reports as fitting if and only if the renderer
// places its last character.
//
// A newline is "placed" only if the row it asks for exists. Without that,
// a body of nothing but newlines consumes every character while drawing
// nothing, and would report as fully shown -- a blank screen presented as a
// complete one.
TEST_F(BodyFits, MeasurementTracksTheRendererNotALineCount) {
  // Whitespace runs that the wrap rules collapse. The old model and the
  // renderer handled leading spaces at slightly different moments; neither
  // count matters now, only whether the last glyph landed.
  for (size_t pad : {(size_t)1, (size_t)40, (size_t)120, (size_t)300}) {
    const std::string padded = "HEAD" + std::string(pad, ' ') + "TAIL";
    if (padded.size() >= BODY_CHAR_MAX) continue;
    const bool fits = confirm_body_fits(padded.c_str(), BODY_WIDTH);
    // Whatever the verdict, it must be the renderer's. A body that fits must
    // still fit with strictly less room; one that does not must not start
    // fitting when given less.
    if (fits) {
      EXPECT_TRUE(confirm_body_fits(("HEAD" + std::string(pad, ' ')).c_str(),
                                    BODY_WIDTH))
          << "dropping the tail made a fitting body stop fitting, pad="
          << pad;
    } else {
      EXPECT_FALSE(confirm_body_fits(padded.c_str(), BODY_WIDTH_WITH_ICON))
          << "less room turned a clipped body into a fitting one, pad="
          << pad;
    }
  }

  // A body of pure newlines draws nothing at all. The body starts on row 24
  // and each newline steps 14, so the third lands the cursor at 66 -- past
  // the last row that can hold a 10px glyph. Up to and including that third
  // newline every character is still consumed, and nothing has been dropped,
  // so the body is blank but complete.
  EXPECT_TRUE(confirm_body_fits("\n\n\n", BODY_WIDTH));

  // From the fourth onwards there are characters the screen cannot reach. A
  // completeness test that only asked "did we walk to the NUL" would call
  // these fully shown, because newlines cost no glyph.
  for (size_t n : {(size_t)4, (size_t)8, (size_t)255, (size_t)340}) {
    EXPECT_FALSE(confirm_body_fits(std::string(n, '\n').c_str(), BODY_WIDTH))
        << n << " newlines strand characters off screen";
  }

  // A trailing newline after a body that fits is harmless: there is nothing
  // after it to lose.
  EXPECT_TRUE(confirm_body_fits("one\ntwo\nthree\n", BODY_WIDTH));

  // Narrowing the canvas must never turn a clipped body into a fitting one.
  const std::string wide(200, 'W');
  if (!confirm_body_fits(wide.c_str(), BODY_WIDTH)) {
    EXPECT_FALSE(confirm_body_fits(wide.c_str(), BODY_WIDTH_WITH_ICON));
  }
}

static std::string FormatEveryPage(const std::string &input, size_t *pages) {
  std::string rendered;
  size_t offset = 0;
  *pages = 0;
  while (offset < input.size()) {
    char page[BODY_CHAR_MAX];
    const size_t take = confirm_bytes_format_page(
        reinterpret_cast<const uint8_t *>(input.data()) + offset,
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
// strlcpy's third argument is the total destination size including the NUL,
// so it copied n-1 and dropped the last digit: a signed "1" rendered 0.00000
// and "1234567" rendered 1.23456. It also terminated at dest[dest_len], one
// byte past a buffer whose supplied capacity is dest_len.
TEST(Board, BaseToPrecisionKeepsEveryDigit) {
  uint8_t out[64];

  // Fewer digits than the precision: zero-padded fraction, no digit lost.
  memset(out, 0xAA, sizeof(out));
  ASSERT_EQ(0,
            base_to_precision(out, (const uint8_t *)"1", sizeof(out), 1, 6));
  EXPECT_EQ(std::string((char *)out), "0.000001");

  // Exactly at the boundary.
  memset(out, 0xAA, sizeof(out));
  ASSERT_EQ(0, base_to_precision(out, (const uint8_t *)"123456", sizeof(out),
                                 6, 6));
  EXPECT_EQ(std::string((char *)out), "0.123456");

  // One past the boundary: the last digit must survive.
  memset(out, 0xAA, sizeof(out));
  ASSERT_EQ(0, base_to_precision(out, (const uint8_t *)"1234567", sizeof(out),
                                 7, 6));
  EXPECT_EQ(std::string((char *)out), "1.234567");

  memset(out, 0xAA, sizeof(out));
  ASSERT_EQ(0, base_to_precision(out, (const uint8_t *)"100000000",
                                 sizeof(out), 9, 6));
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
