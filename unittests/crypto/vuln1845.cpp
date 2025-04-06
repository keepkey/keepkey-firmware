#include <cstddef>

extern "C" {
#include "hwcrypto/crypto/segwit_addr.h"
#include "hwcrypto/crypto/ecdsa.h"
#include "hwcrypto/crypto/cash_addr.h"
}

#include "gtest/gtest.h"

#include <cinttypes>
#include <string>
#include <vector>

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
