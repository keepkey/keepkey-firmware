extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/ripple.h"
#include "keepkey/firmware/ripple_base58.h"
#include "hwcrypto/crypto/hasher.h"
}

#include "gtest/gtest.h"
#include <cstring>
#include <string>

TEST(Ripple, AddressEncodeDecode) {
  // https://xrpl.org/accounts.html#address-encoding
  uint8_t public_key[33 + 1] =
      "\xED\x94\x34\x79\x92\x26\x37\x49\x26\xED"
      "\xA3\xB5\x4B\x1B\x46\x1B\x4A\xBF\x72\x37"
      "\x96\x2E\xAE\x18\x52\x8F\xEA\x67\x59\x53"
      "\x97\xFA\x32";

  uint8_t buff[64];
  memset(buff, 0, sizeof(buff));

  Hasher hasher;
  hasher_Init(&hasher, HASHER_SHA2_RIPEMD);
  hasher_Update(&hasher, public_key, 33);
  hasher_Final(&hasher, buff + 1);

  EXPECT_TRUE(memcmp(buff,
                     "\x00\x88\xa5\xa5\x7c\x82\x9f\x40\xf2\x5e"
                     "\xa8\x33\x85\xbb\xde\x6c\x3d\x8b\x4c\xa0\x82",
                     21) == 0);

  char address[56];
  ASSERT_TRUE(
      ripple_encode_check(buff, 21, HASHER_SHA2D, address, MAX_ADDR_SIZE));

  EXPECT_EQ(std::string(address), "rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN");

  uint8_t addr_raw[MAX_ADDR_RAW_SIZE];
  memset(addr_raw, 0, sizeof(addr_raw));
  uint32_t addr_raw_len =
      ripple_decode_check(address, HASHER_SHA2D, addr_raw, MAX_ADDR_RAW_SIZE);
  EXPECT_EQ(addr_raw_len, 21);

  EXPECT_TRUE(memcmp(buff, addr_raw, 21) == 0);

  EXPECT_TRUE(memcmp(addr_raw,
                     "\x00\x88\xa5\xa5\x7c\x82\x9f\x40\xf2\x5e"
                     "\xa8\x33\x85\xbb\xde\x6c\x3d\x8b\x4c\xa0\x82",
                     21) == 0);
}

TEST(Ripple, SerializeAddress) {
  uint8_t buffer[22];
  memset(buffer, 0, sizeof(buffer));

  uint8_t *buf = buffer;
  bool ok = true;
  ripple_serializeAddress(&ok, &buf, buf + sizeof(buffer), &RFM_account,
                          "rNaqKtKrMSwpwZSzRckPf7S96DkimjkF4H");

  ASSERT_TRUE(ok);

  EXPECT_TRUE(memcmp(buffer,
                     "\x81\x14\x8f\xb4\x0e\x1f\xfa\x5d\x55\x7c\xe9"
                     "\x85\x1a\x53\x5a\xf9\x49\x65\xe0\xdd\x09\x88",
                     22) == 0);
}

TEST(Ripple, Serialize) {
  RippleSignTx tx;
  memset(&tx, 0, sizeof(tx));

  tx.address_n_count = 0;

  tx.has_fee = true;
  tx.fee = 100000;

  tx.has_flags = true;
  tx.flags = 0x80000000;

  tx.has_sequence = true;
  tx.sequence = 25;

  tx.has_payment = true;
  tx.payment.has_amount = true;
  tx.payment.amount = 100000000ULL;
  tx.payment.has_destination = true;
  strcpy(tx.payment.destination, "rBKz5MC2iXdoS3XgnNSYmF69K1Yo4NS3Ws");

  uint8_t serialized[183];
  memset(serialized, 0, sizeof(serialized));

  const uint8_t *public_key = (const uint8_t*)
        "\x02\x13\x1f\xac\xd1\xea\xb7\x48\xd6\xcd\xdc\x49\x2f\x54\xb0\x4e"
        "\x8c\x35\x65\x88\x94\xf4\xad\xd2\x23\x2e\xbc\x5a\xfe\x75\x21\xdb\xe4";

  const size_t sig_len = 71;
  const uint8_t *sig = (const uint8_t*)
        "\x30" // DER Type
        "\x45" // Length of rest of payload
        "\x02" // r value Marker
        "\x21" // r value Length
        "\x00\xe2\x43\xef\x62\x36\x75\xee\xeb\x95\x96" // r value
        "\x5c\x35\xc3\xe0\x6d\x63\xa9\xfc\x68\xbb\x37"
        "\xe1\x7d\xc8\x7a\xf9\xc0\xaf\x83\xec\x05\x7e"
        "\x02" // s value Marker
        "\x20" // s value Length
        "\x6c\xa8\xaa\x5e\xaa\xb8\x39\x63\x97\xae\xf6\xd3\x8d\x25\x71\x04" // s value
        "\x41\xfa\xf7\xc7\x9d\x29\x2e\xe1\xd6\x27\xdf\x15\xad\x93\x46\xc0";

  uint8_t *buf = serialized;
  EXPECT_TRUE(ripple_serialize(&buf, buf + sizeof(serialized), &tx,
                               "rNaqKtKrMSwpwZSzRckPf7S96DkimjkF4H", public_key,
                               sig, sig_len));

  const uint8_t *expected = (const uint8_t*)
        "\x12\x00\x00\x22\x80\x00\x00\x00\x24\x00\x00\x00\x19\x61\x40\x00\x00\x00\x05\xf5"
        "\xe1\x00\x68\x40\x00\x00\x00\x00\x01\x86\xa0\x73\x21\x02\x13\x1f\xac\xd1\xea\xb7"
        "\x48\xd6\xcd\xdc\x49\x2f\x54\xb0\x4e\x8c\x35\x65\x88\x94\xf4\xad\xd2\x23\x2e\xbc"
        "\x5a\xfe\x75\x21\xdb\xe4\x74\x47\x30\x45\x02\x21\x00\xe2\x43\xef\x62\x36\x75\xee"
        "\xeb\x95\x96\x5c\x35\xc3\xe0\x6d\x63\xa9\xfc\x68\xbb\x37\xe1\x7d\xc8\x7a\xf9\xc0"
        "\xaf\x83\xec\x05\x7e\x02\x20\x6c\xa8\xaa\x5e\xaa\xb8\x39\x63\x97\xae\xf6\xd3\x8d"
        "\x25\x71\x04\x41\xfa\xf7\xc7\x9d\x29\x2e\xe1\xd6\x27\xdf\x15\xad\x93\x46\xc0\x81"
        "\x14\x8f\xb4\x0e\x1f\xfa\x5d\x55\x7c\xe9\x85\x1a\x53\x5a\xf9\x49\x65\xe0\xdd\x09"
        "\x88\x83\x14\x71\x48\xeb\xeb\xf7\x30\x4c\xcd\xf1\x67\x6f\xef\xcf\x97\x34\xcf\x1e"
        "\x78\x08\x26";

  ASSERT_TRUE(memcmp(serialized, expected, sizeof(serialized)) == 0);
}
