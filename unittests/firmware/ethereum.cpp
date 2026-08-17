extern "C" {
#include "keepkey/firmware/eip712.h"
#include "trezor/crypto/address.h"
}

#include "gtest/gtest.h"

#include <string>

static uint8_t bin_from_ascii(char c) {
  if ('a' <= c && c <= 'f') return c - 'a' + 0xa;

  if ('A' <= c && c <= 'F') return c - 'A' + 0xA;

  if ('0' <= c && c <= '9') return c - '0' + 0x0;

  __builtin_unreachable();
}

static void test_checksum(const std::string &addr) {
  uint8_t addr_bin[20];
  for (size_t i = 0; i < addr.size(); i += 2) {
    addr_bin[i / 2] = bin_from_ascii(addr[i + 1]) | bin_from_ascii(addr[i])
                                                        << 4;
  }

  char formatted[41];
  ethereum_address_checksum(addr_bin, formatted, false, 0);

  ASSERT_EQ(formatted[40], '\0') << "Must be null terminated";

  ASSERT_EQ(addr, std::string(formatted)) << "Checksum mismatch";
}

TEST(Ethereum, AddressChecksum) {
  // Testcases from: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
  test_checksum("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
  test_checksum("fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");
  test_checksum("dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB");
  test_checksum("D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb");
}

TEST(Ethereum, Eip712AddressRequiresCanonicalTwentyByteHex) {
  uint8_t encoded[32] = {0};
  ASSERT_EQ(SUCCESS,
            encAddress("0x00112233445566778899aabbccddeeff00112233", encoded));
  for (size_t i = 0; i < 12; i++) EXPECT_EQ(0, encoded[i]);
  EXPECT_EQ(0x00, encoded[12]);
  EXPECT_EQ(0x11, encoded[13]);
  EXPECT_EQ(0x33, encoded[31]);

  EXPECT_NE(SUCCESS, encAddress("0x112233", encoded));
  EXPECT_NE(SUCCESS,
            encAddress("00112233445566778899aabbccddeeff00112233", encoded));
  EXPECT_NE(SUCCESS,
            encAddress("0x00112233445566778899aabbccddeeff0011223g", encoded));
  EXPECT_NE(SUCCESS, encAddress(
                         "0x00112233445566778899aabbccddeeff0011223344",
                         encoded));
}

// Every EIP-712 field screen used to be a review(), which calls
// confirm_helper() and then returns true unconditionally, so a host that
// answered each screen with a protocol Cancel still got a hash back. The
// screens are confirm() now and refusal reaches ethereum.c as USER_CANCELLED.
//
// That code has to stay outside failMsgReturn[]. ethereum.c sizes the table
// LAST_ERROR - 2 and indexes it err - 3, so a cancellation code at or below
// LAST_ERROR would shift every message already in the table and would make
// failMessage() report a refusal as a parse error instead of an
// ActionCancelled. It also must not collide with the two non-error codes.
TEST(Ethereum, Eip712UserCancelledIsOutsideTheFailMessageTable) {
  EXPECT_GT(USER_CANCELLED, LAST_ERROR);
  EXPECT_NE(USER_CANCELLED, SUCCESS);
  EXPECT_NE(USER_CANCELLED, NULL_MSG_HASH);
}
