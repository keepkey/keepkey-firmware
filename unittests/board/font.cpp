extern "C" {
#include "keepkey/board/font.h"
}

#include "gtest/gtest.h"
#include <array>
#include <map>
#include <string>

namespace {
void expectDistinctShortStrings(const Font* font) {
  std::map<std::array<uint32_t, 10>, std::string> seen;
  const auto check = [&](const std::string& text) {
    std::array<uint32_t, 10> pixels = {};
    size_t left = 0;
    for (const char c : text) {
      const CharacterImage* glyph = font_get_char(font, c);
      ASSERT_NE(nullptr, glyph);
      ASSERT_EQ(pixels.size(), glyph->height);
      ASSERT_LE(left + glyph->width, 32u);
      for (size_t y = 0; y < glyph->height; ++y)
        for (size_t x = 0; x < glyph->width; ++x)
          if (glyph->data[y * glyph->width + x] == 0)
            pixels[y] |= uint32_t(1) << (left + x);
      left += glyph->width;
    }
    // Trailing blank columns are invisible when a reviewed value ends here.
    const auto inserted = seen.emplace(pixels, text);
    EXPECT_TRUE(inserted.second)
        << "Review strings [" << inserted.first->second << "] and [" << text
        << "] have identical pixels";
  };
  // Signed text escapes whitespace. Compare every visible ASCII character
  // and every pair: distinct individual glyphs alone miss quote collisions.
  for (int first = 0x21; first <= 0x7e; ++first) {
    const std::string prefix(1, static_cast<char>(first));
    check(prefix);
    for (int second = 0x21; second <= 0x7e; ++second) {
      check(prefix + static_cast<char>(second));
    }
  }
}
}  // namespace

TEST(FontDisclosure, BodyDistinguishesShortPrintableStrings) {
  expectDistinctShortStrings(get_body_font());
}

TEST(FontDisclosure, TitleDistinguishesShortPrintableStrings) {
  expectDistinctShortStrings(get_title_font());
}
