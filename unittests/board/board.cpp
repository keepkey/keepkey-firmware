#include "gtest/gtest.h"

#include <csignal>
#include <unistd.h>

#include <string>

extern "C" {
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/font.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/util.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/firmware/app_confirm.h"
}

TEST(Board, Shutdown) {
  EXPECT_EXIT(shutdown(), ::testing::ExitedWithCode(1), "");
}

TEST(Board, MonochromeEvidencePreservesGrayscaleForeground) {
  for (uint16_t y = 0; y < 4; y++) {
    for (uint16_t x = 0; x < 4; x++) {
      EXPECT_FALSE(display_mono_pixel_is_lit(0x00, x, y));
      EXPECT_TRUE(display_mono_pixel_is_lit(0xFF, x, y));
    }
  }
  EXPECT_TRUE(display_mono_pixel_is_lit(0x11, 0, 0));
  EXPECT_FALSE(display_mono_pixel_is_lit(0x11, 1, 0));
  EXPECT_FALSE(display_mono_pixel_is_lit(0x77, 1, 0));
  EXPECT_TRUE(display_mono_pixel_is_lit(0x99, 1, 0));
}

// confirm_body_fits() asks the real renderer whether the body will fit, so it
// needs the canvas the renderer draws into. board_init() does this on the
// device; here we do the same two steps in the same order. Without it
// layout_get_canvas() is NULL and every measurement is meaningless rather than
// merely wrong, so this fixture is a precondition for the tests below, not
// decoration.
class BodyFits : public ::testing::Test {
 protected:
  void SetUp() override {
    static bool ready = false;
    if (!ready) {
      timer_init();
      layout_init(display_canvas_init());
      // layout_init() starts a 1ms animation tick. These tests only measure
      // geometry, and letting the tick run would repaint the canvas underneath
      // them.
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
  // which is why the earlier three-way sweep of 3,510 bodies missed it: it only
  // shows at the precise boundary. 117 digits fill three rows; the 118th is the
  // first glyph that cannot be placed and must be reported as not fitting.
  std::string digits;
  for (size_t i = 0; i < 118; i++) digits += "0123456789"[i % 10];
  EXPECT_TRUE(confirm_body_fits(digits.substr(0, 117).c_str(), BODY_WIDTH));
  EXPECT_FALSE(confirm_body_fits(digits.c_str(), BODY_WIDTH))
      << "a body overflowing by exactly one glyph must not report as fitting";
}

TEST(Board, ConfirmationFormattingRefusesAnySourceLoss) {
  const std::string one_too_many(BODY_CHAR_MAX, 'A');

  // Source overflow must return before confirm() sends a ButtonRequest or
  // enters the interactive confirmation state machine.
  EXPECT_FALSE(confirm(ButtonRequestType_ButtonRequest_Other, "Overflow", "%s",
                       one_too_many.c_str()));

  // Expansion is measured after formatting, not from the format string or any
  // one argument. This is the shape used by multi-field confirmation bodies.
  const std::string left(175, 'L');
  const std::string right(175, 'R');
  EXPECT_FALSE(confirm(ButtonRequestType_ButtonRequest_Other, "Overflow",
                       "%s::%s", left.c_str(), right.c_str()));
}

TEST_F(BodyFits, ConstantPowerSeedRowsAreCompleteAndPagedAtRowBoundaries) {
  EXPECT_EQ(CONSTANT_POWER_BODY_WIDTH,
            KEEPKEY_DISPLAY_WIDTH - (128 + LEFT_MARGIN));
  EXPECT_EQ(CONSTANT_POWER_BODY_WIDTH, 124);

  static const char group[] =
      "   1.mushroom   2.mushroom\n"
      "   3.mushroom   4.mushroom\n"
      "   5.mushroom   6.mushroom\n";
  std::string reassembled;
  const char* p = group;
  size_t pages = 0;
  while (*p) {
    const size_t take = confirm_constant_power_subpage_take(p);
    ASSERT_GT(take, 0u);
    ASSERT_LE(take, strlen(p));
    const std::string page(p, take);
    EXPECT_TRUE(page.back() == '\n' || take == strlen(p));
    EXPECT_TRUE(confirm_body_fits_constant_power(page.c_str(),
                                                 CONSTANT_POWER_BODY_WIDTH));
    reassembled += page;
    p += take;
    ASSERT_LT(++pages, 32u);
  }
  EXPECT_EQ(reassembled, std::string(group));
  EXPECT_GT(pages, 1u);

  const std::string unsplittable =
      "   1.mushroom   2.mushroom   3.mushroom   4.mushroom\n";
  EXPECT_FALSE(confirm_body_fits_constant_power(unsplittable.c_str(),
                                                CONSTANT_POWER_BODY_WIDTH));
  EXPECT_EQ(confirm_constant_power_subpage_take(unsplittable.c_str()), 0u);
}

// Regression: calc_str_line() accumulated into a uint8_t while returning
// uint32_t, so a body carrying 255 newlines wrapped the count back to 0 and
// confirm_body_fits() reported that it fitted. The 352-byte confirm buffer has
// room for a benign prefix, 255 newlines and a hidden suffix, so the "Cut Off"
// warning was skippable by a host that chose its whitespace.
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
          << "dropping the tail made a fitting body stop fitting, pad=" << pad;
    } else {
      EXPECT_FALSE(confirm_body_fits(padded.c_str(), BODY_WIDTH_WITH_ICON))
          << "less room turned a clipped body into a fitting one, pad=" << pad;
    }
  }

  // A body of pure newlines draws nothing at all. The body starts on row 24
  // and each newline steps 14, so the third lands the cursor at 66 -- past the
  // last row that can hold a 10px glyph. Up to and including that third
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

TEST_F(BodyFits, PagerCanExceedItsOwnPageCap) {
  // page_body_confirm() refuses a body needing more than 99 pages rather than
  // stopping the count there, because a truncated count makes page 100 the
  // "last" page and puts the approving hold on a prefix.
  //
  // That bound is reachable, which is the point of this test: page_take() sizes
  // a page by the largest prefix confirm_body_fits() accepts, and for newlines
  // that is three -- they consume rows without drawing a glyph. A body filling
  // BODY_CHAR_MAX therefore needs ceil(351 / 3) = 117 pages.
  //
  // The refusal itself cannot be asserted here: page_body_confirm() is static
  // and reaching it means driving real confirm screens, which this binary has
  // no canvas or input for. What is asserted is the arithmetic the cap depends
  // on, so that a future change to BODY_ROWS or BODY_CHAR_MAX that quietly
  // moves the bound fails here rather than in the field.
  EXPECT_TRUE(confirm_body_fits(std::string(3, '\n').c_str(), BODY_WIDTH));
  EXPECT_FALSE(confirm_body_fits(std::string(4, '\n').c_str(), BODY_WIDTH));

  const size_t chars_per_page = 3;
  const size_t worst_case_body = BODY_CHAR_MAX - 1;
  const size_t pages_needed =
      (worst_case_body + chars_per_page - 1) / chars_per_page;
  EXPECT_GT(pages_needed, 99u)
      << "the 99-page cap is unreachable, so the refusal is dead code";
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

TEST(Board, EscapeMakesLeadingWhitespaceVisible) {
  // The passphrase screen used "%51s", which right-pads to 51 columns, and the
  // renderer drops spaces at the start of a wrapped line. "secret" and
  // " secret" could therefore draw the same pixels while deriving DIFFERENT
  // wallets. confirm_bytes_escape() is what removes that ambiguity, so the two
  // must not be able to produce the same string.
  char a[64], b[64];
  ASSERT_TRUE(confirm_bytes_escape(reinterpret_cast<const uint8_t*>("secret"),
                                   6, a, sizeof(a)));
  ASSERT_TRUE(confirm_bytes_escape(reinterpret_cast<const uint8_t*>(" secret"),
                                   7, b, sizeof(b)));
  EXPECT_STREQ(a, "secret");
  EXPECT_STREQ(b, "\\x20secret");
  EXPECT_STRNE(a, b);

  // Trailing whitespace is equally invisible on screen and equally load-bearing
  // in the derivation.
  ASSERT_TRUE(confirm_bytes_escape(reinterpret_cast<const uint8_t*>("secret "),
                                   7, b, sizeof(b)));
  EXPECT_STREQ(b, "secret\\x20");
  EXPECT_STRNE(a, b);

  // A backslash is escaped too, so an escape sequence typed INTO the
  // passphrase cannot impersonate one this function produced. The four input
  // bytes are 0x5C 'x' '2' '0', spelled out rather than written as a C
  // literal so the test cannot be read two ways.
  static const uint8_t kFakeEscape[] = {0x5C, 'x', '2', '0'};
  ASSERT_TRUE(
      confirm_bytes_escape(kFakeEscape, sizeof(kFakeEscape), b, sizeof(b)));
  EXPECT_STREQ(b, "\\x5Cx20");

  // Zero bytes are inside the declared length and must show, not terminate.
  ASSERT_TRUE(confirm_bytes_escape(reinterpret_cast<const uint8_t*>("a\0b"), 3,
                                   b, sizeof(b)));
  EXPECT_STREQ(b, "a\\x00b");

  // Empty input is a valid, empty escape -- the caller decides how to say so.
  ASSERT_TRUE(confirm_bytes_escape(nullptr, 0, b, sizeof(b)));
  EXPECT_STREQ(b, "");

  // Fails rather than truncating: half a secret is the ambiguity all over
  // again. Four bytes of output hold one escape and its NUL, never two.
  char small[5];
  EXPECT_TRUE(confirm_bytes_escape(reinterpret_cast<const uint8_t*>(" "), 1,
                                   small, sizeof(small)));
  EXPECT_STREQ(small, "\\x20");
  EXPECT_FALSE(confirm_bytes_escape(reinterpret_cast<const uint8_t*>("  "), 2,
                                    small, sizeof(small)));
  EXPECT_STREQ(small, "");

  // The production buffer must hold the longest possible passphrase: 50
  // visible characters, every one of them escaped.
  const std::string worst(50, ' ');
  char full[4 * 50 + 1];
  ASSERT_TRUE(
      confirm_bytes_escape(reinterpret_cast<const uint8_t*>(worst.data()),
                           worst.size(), full, sizeof(full)));
  EXPECT_EQ(strlen(full), 200u);
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

TEST(Board, PostPreviewMutationChangesExactByteReview) {
  std::string payload_a(160, 'A');
  std::string payload_b = payload_a;
  payload_b[96] = 'B';

  ASSERT_EQ(payload_a.size(), payload_b.size());
  ASSERT_EQ(0, memcmp(payload_a.data(), payload_b.data(), 32));

  size_t pages_a = 0;
  size_t pages_b = 0;
  const std::string review_a = FormatEveryPage(payload_a, &pages_a);
  const std::string review_b = FormatEveryPage(payload_b, &pages_b);

  EXPECT_EQ(pages_a, pages_b);
  EXPECT_GT(pages_a, 1u);
  EXPECT_NE(review_a, review_b)
      << "a byte after the old 32-byte Solana preview must change a page";
}

TEST(Board, IdentityKeySelectionDisclosesEveryKeySelector) {
  IdentityType identity{};
  identity.has_index = true;
  identity.index = UINT32_MAX;
  identity.has_path = true;
  memset(identity.path, 'p', sizeof(identity.path) - 1);

  char selection[CONFIRM_SIGN_IDENTITY_KEY];
  ASSERT_TRUE(format_sign_identity_key_selection(&identity, "ed25519",
                                                 selection, sizeof(selection)));
  EXPECT_STREQ(selection,
               "Index: 4294967295\nCurve: ed25519\nPath: shown next");

  // The production path uses confirm_bytes(), whose page formatter must retain
  // the complete maximum-size path rather than a BODY_CHAR_MAX prefix.
  size_t pages = 0;
  const std::string path(identity.path);
  EXPECT_EQ(FormatEveryPage(path, &pages), path);
  EXPECT_EQ(path.size(), sizeof(identity.path) - 1);
  EXPECT_GT(pages, 1u);

  identity.has_path = false;
  ASSERT_TRUE(format_sign_identity_key_selection(&identity, "secp256k1",
                                                 selection, sizeof(selection)));
  EXPECT_STREQ(selection, "Index: 4294967295\nCurve: secp256k1\nPath: none");
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
  ASSERT_EQ(0, base_to_precision(out, (const uint8_t*)"1", sizeof(out), 1, 6));
  EXPECT_EQ(std::string((char*)out), "0.000001");

  // Exactly at the boundary.
  memset(out, 0xAA, sizeof(out));
  ASSERT_EQ(
      0, base_to_precision(out, (const uint8_t*)"123456", sizeof(out), 6, 6));
  EXPECT_EQ(std::string((char*)out), "0.123456");

  // One past the boundary: the last digit must survive.
  memset(out, 0xAA, sizeof(out));
  ASSERT_EQ(
      0, base_to_precision(out, (const uint8_t*)"1234567", sizeof(out), 7, 6));
  EXPECT_EQ(std::string((char*)out), "1.234567");

  memset(out, 0xAA, sizeof(out));
  ASSERT_EQ(0, base_to_precision(out, (const uint8_t*)"100000000", sizeof(out),
                                 9, 6));
  EXPECT_EQ(std::string((char*)out), "100.000000");
}

// The NUL must land inside the supplied capacity, never at dest[dest_len].
TEST(Board, BaseToPrecisionRespectsCapacity) {
  uint8_t buf[16];

  // "1.234567" is 8 chars + NUL = 9; a capacity of 9 is exactly enough.
  memset(buf, 0xAA, sizeof(buf));
  ASSERT_EQ(0, base_to_precision(buf, (const uint8_t*)"1234567", 9, 7, 6));
  EXPECT_EQ(std::string((char*)buf), "1.234567");
  EXPECT_EQ(buf[9], 0xAA) << "wrote past the supplied capacity";

  // One byte short must be refused, not truncated.
  memset(buf, 0xAA, sizeof(buf));
  EXPECT_EQ(-1, base_to_precision(buf, (const uint8_t*)"1234567", 8, 7, 6));
  EXPECT_EQ(buf[0], 0xAA) << "buffer touched on the refusal path";

  EXPECT_EQ(-1, base_to_precision(NULL, (const uint8_t*)"1", 16, 1, 6));
  EXPECT_EQ(-1, base_to_precision(buf, NULL, 16, 1, 6));
}
