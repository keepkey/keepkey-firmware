extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/nano.h"
}

#include "gtest/gtest.h"
#include <cstring>

static void test_truncateAddress(const CoinType *coin, const std::string &addr,
                                 const std::string &expected) {
  char value[100];
  strncpy(value, addr.c_str(), sizeof(value));
  value[sizeof(value) - 1] = '\0';

  nano_truncateAddress(coin, value);

  ASSERT_EQ(expected, std::string(value));
}

TEST(Nano, GetKnownRepName) {
  EXPECT_EQ(
      std::string("Official Rep 1 "),
      nano_getKnownRepName(
          "xrb_3arg3asgtigae3xckabaaewkx3bzsh7nwz7jkmjos79ihyaxwphhm6qgjps4"));
  EXPECT_EQ(nullptr, nano_getKnownRepName("xrb_notarealrepresentative"));
}

TEST(Nano, TruncateAddress) {
  CoinType coin;
  memcpy(&coin, coinByName("Nano"), sizeof(coin));

  strcpy(coin.nanoaddr_prefix, "xrb_");
  test_truncateAddress(
      &coin, "xrb_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
      "xrb_3t6k3..uohr3");
  test_truncateAddress(&coin, "xrb_3t6k35gi95", "xrb_3t6k35gi95");
  test_truncateAddress(&coin, "", "");

  strcpy(coin.nanoaddr_prefix, "nano_");
  test_truncateAddress(
      &coin,
      "nano_1nanode8ngaakzbck8smq6ru9bethqwyehomf79sae1k7xd47dkidjqzffeg",
      "nano_1nano..zffeg");
}

static std::string bytes_to_hex(const uint8_t *buf, const size_t size) {
  static const char *ALPHABET = "0123456789ABCDEF";
  std::string hex;
  hex.reserve(2 * size);
  for (size_t i = 0; i < size; i++) {
    const uint8_t b = buf[i];
    hex.push_back(ALPHABET[b >> 4]);
    hex.push_back(ALPHABET[b & 15]);
  }
  return hex;
}

static uint8_t byte_from_hex_char(const unsigned char c) {
  if ('0' <= c && c <= '9') {
    return c - '0';
  } else if ('a' <= c && c <= 'f') {
    return c - 'a' + 10;
  } else if ('A' <= c && c <= 'F') {
    return c - 'A' + 10;
  } else {
    return 0;
  }
}

static void bytes_from_hex(uint8_t *buf, const std::string &hex,
                           const size_t buf_size) {
  for (size_t i = 0; i < buf_size; i++) {
    if (2 * i + 1 < hex.size()) {
      buf[i] = (byte_from_hex_char(hex[2 * i]) << 4);
      buf[i] |= byte_from_hex_char(hex[2 * i + 1]);
    } else {
      buf[i] = 0;
    }
  }
}

#define BYTES_FROM_HEX(buf_name, buf_size) \
  uint8_t buf_name[buf_size];              \
  bytes_from_hex(buf_name, buf_name##_hex, buf_size);

static void test_block_hashing(const std::string &account_pk_hex,
                               const std::string &parent_hash_hex,
                               const std::string &link_hex,
                               const std::string &representative_pk_hex,
                               const std::string &balance_hex,
                               const std::string &expected_hash_hex) {
  BYTES_FROM_HEX(account_pk, 32);
  BYTES_FROM_HEX(parent_hash, 32);
  BYTES_FROM_HEX(link, 32);
  BYTES_FROM_HEX(representative_pk, 32);
  BYTES_FROM_HEX(balance, 16);

  uint8_t hash[32];
  nano_hash_block_data(account_pk, parent_hash, link, representative_pk,
                       balance, hash);

  ASSERT_EQ(expected_hash_hex, bytes_to_hex(hash, sizeof(hash)));
}

TEST(Nano, BlockHashing) {
  test_block_hashing(
      "C798CFF4F1131204F65C4D22C3E6316F26F380EE0616AADBABEA1268FD75FB05",
      "50DE35601F5BD5B0AAEAD0BCCFE028A98BD1DA4B2022ABD77DD7889DBFFCCEC1",
      "7DD26DF85B130A7B55B1130F4DF04366542CE588D98524D4519713E0A0FCBED4",
      "C798CFF4F1131204F65C4D22C3E6316F26F380EE0616AADBABEA1268FD75FB05",
      "03572D26B79A28EBB63E62EBB6B011D6",
      "F8FBAD162C5911405364035D620B0AEDB4F7D882513F8DD4BC47637C594F7CD0");
}

TEST(Nano, Bip32ToString) {
  const CoinType *coin = coinByName("Nano");

  struct {
    uint32_t address_n[5];
    uint32_t address_n_count;
    bool expected_ok;
    const char *expected_string;
  } vec[] = {
      {{0x80000000 | 44, 0x80000000 | 165, 0x80000000 | 12},
       3,
       true,
       "Nano Account #12"},
      {{0x80000000 | 44, 0x80000000 | 100, 0x80000000 | 12}, 3, false, ""},
      {{0x80000000 | 44, 0x80000000 | 165, 0x80000000 | 0, 0x80000000 | 12},
       4,
       false,
       ""},
  };

  for (const auto &v : vec) {
    char out_string[200];
    memset(out_string, 0, sizeof(out_string));

    bool ok = nano_bip32_to_string(out_string, sizeof(out_string), coin,
                                   v.address_n, v.address_n_count);

    ASSERT_EQ(v.expected_ok, ok) << "Unexpected success value";
    ASSERT_EQ(v.expected_string, std::string(out_string))
        << "Unexpected string result";
  }
}
