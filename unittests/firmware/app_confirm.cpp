extern "C" {
#include "keepkey/firmware/app_confirm.h"
}

#include "gtest/gtest.h"

TEST(AppConfirm, MultilineAsciiMessageUsesTextMode) {
  static const char message[] =
      "Welcome to DegenQuest!\n"
      "\n"
      "Sign this message to authenticate your wallet.\n"
      "\n"
      "This request will not trigger a blockchain transaction or cost any gas "
      "fees.\n"
      "\n"
      "Nonce: d2d8d32b-a7fc-4129-a60b-e0664f0b2169";

  ASSERT_EQ(193U, sizeof(message) - 1);
  EXPECT_TRUE(confirm_bytes_is_text(reinterpret_cast<const uint8_t*>(message),
                                    sizeof(message) - 1));
}

TEST(AppConfirm, UnsafeControlsAndBinaryBytesUseHexMode) {
  static const uint8_t spaces[] = {' ', ' ', ' '};
  static const uint8_t blank_lines[] = {'\n', '\n'};
  static const uint8_t nul[] = {'a', 0x00, 'b'};
  static const uint8_t tab[] = {'a', '\t', 'b'};
  static const uint8_t carriage_return[] = {'a', '\r', 'b'};
  static const uint8_t escape[] = {'a', 0x1b, 'b'};
  static const uint8_t del[] = {'a', 0x7f, 'b'};
  static const uint8_t utf8[] = {0xc3, 0xa9};

  EXPECT_FALSE(confirm_bytes_is_text(spaces, sizeof(spaces)));
  EXPECT_FALSE(confirm_bytes_is_text(blank_lines, sizeof(blank_lines)));
  EXPECT_FALSE(confirm_bytes_is_text(nul, sizeof(nul)));
  EXPECT_FALSE(confirm_bytes_is_text(tab, sizeof(tab)));
  EXPECT_FALSE(confirm_bytes_is_text(carriage_return, sizeof(carriage_return)));
  EXPECT_FALSE(confirm_bytes_is_text(escape, sizeof(escape)));
  EXPECT_FALSE(confirm_bytes_is_text(del, sizeof(del)));
  EXPECT_FALSE(confirm_bytes_is_text(utf8, sizeof(utf8)));
  EXPECT_FALSE(confirm_bytes_is_text(nullptr, 1));
}
