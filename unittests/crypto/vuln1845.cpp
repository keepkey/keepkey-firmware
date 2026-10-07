#include <cstddef>

extern "C" {
#include "trezor/crypto/segwit_addr.h"
#include "trezor/crypto/base58.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/cash_addr.h"
}

#include "gtest/gtest.h"

#include <cinttypes>
#include <string>
#include <vector>

TEST(Vuln1845, Base58RejectsOversizedAndNegativeLengths) {
  uint8_t data[257] = {0};
  char encoded[512] = {0};
  size_t encoded_len = sizeof(encoded);
  size_t decoded_len = sizeof(data);

  EXPECT_FALSE(b58enc(encoded, &encoded_len, data, sizeof(data)));
  EXPECT_FALSE(b58tobin(data, &decoded_len, "1"));
  EXPECT_EQ(0, base58_encode_check(data, -1, HASHER_SHA2D, encoded,
                                   sizeof(encoded)));
  EXPECT_EQ(0, base58_decode_check("1", HASHER_SHA2D, data, -1));
}

TEST(Vuln1845, Bech32Decode) {
  std::string input =
      "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrst"
      "uvwxyzabcdefg";
  std::vector<char> hrp(input.size() - 6);
  std::vector<uint8_t> data(input.size() - 8);

  size_t data_len;
  ASSERT_NE(1, bech32_decode(&hrp[0], &data[0], &data_len, input.c_str()));
}

TEST(Vuln1845, CashAddrDecode) {
  std::vector<uint8_t> addr_raw(MAX_ADDR_RAW_SIZE);
  size_t len;

  ASSERT_FALSE(cash_addr_decode(
      &addr_raw[0], &len, "bitcoincash:",
      "\x53\x74\x32\x63\x74\x79\x70\x63\x45\x74\x53\x49\x3a\x4d\x63\x4e"
      "\x53\x74\x36\x63\x74\x65\x63\x43\x43\x43\x43\x43\x43\x4a\x43\x43"
      "\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43"
      "\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43"
      "\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43"
      "\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43"
      "\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43"
      "\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x61\x00\x61\x61"
      "\x28"));
}
