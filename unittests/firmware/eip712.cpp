extern "C" {
#include "keepkey/firmware/eip712.h"
}

#include "gtest/gtest.h"

#include <cstdio>
#include <cstring>

TEST(EIP712, AddressRequiresCanonicalTwentyByteHex) {
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
  EXPECT_NE(SUCCESS, encAddress("0x00112233445566778899aabbccddeeff0011223344",
                                encoded));
}

TEST(EIP712, DynamicBytesRequireCompleteHexOctets) {
  uint8_t encoded[32] = {0};
  EXPECT_EQ(SUCCESS, encodeBytes("0x", encoded));
  EXPECT_EQ(SUCCESS, encodeBytes("0x00a1FF", encoded));
  EXPECT_NE(SUCCESS, encodeBytes("00a1", encoded));
  EXPECT_NE(SUCCESS, encodeBytes("0x0", encoded));
  EXPECT_NE(SUCCESS, encodeBytes("0x0z", encoded));
}

TEST(EIP712, FixedBytesRequireExactDeclaredLength) {
  uint8_t encoded[32];
  memset(encoded, 0xa5, sizeof(encoded));
  ASSERT_EQ(SUCCESS, encodeBytesN("bytes4", "0x0011aAff", encoded));
  EXPECT_EQ(0x00, encoded[0]);
  EXPECT_EQ(0x11, encoded[1]);
  EXPECT_EQ(0xaa, encoded[2]);
  EXPECT_EQ(0xff, encoded[3]);
  for (size_t i = 4; i < sizeof(encoded); i++) EXPECT_EQ(0, encoded[i]);

  EXPECT_NE(SUCCESS, encodeBytesN("bytes4", "0x0011aa", encoded));
  EXPECT_NE(SUCCESS, encodeBytesN("bytes4", "0x0011aaff00", encoded));
  EXPECT_NE(SUCCESS, encodeBytesN("bytes0", "0x", encoded));
  EXPECT_NE(SUCCESS, encodeBytesN("bytes33", "0x", encoded));
  EXPECT_NE(SUCCESS, encodeBytesN("bytes4294967297", "0x00", encoded));
  EXPECT_NE(SUCCESS, encodeBytesN("bytes4x", "0x0011aaff", encoded));
}

TEST(EIP712, IntegerWidthsCannotWrapIntoValidTypes) {
  char types_json[] =
      "{\"types\":{\"Test\":[{\"name\":\"value\","
      "\"type\":\"uint4294967552\"}]}}";
  char values_json[] = "{\"message\":{\"value\":\"1\"}}";
  json_t type_nodes[12] = {};
  json_t value_nodes[8] = {};
  const json_t* types = json_create(types_json, type_nodes, 12);
  const json_t* values = json_create(values_json, value_nodes, 8);
  ASSERT_NE(nullptr, types);
  ASSERT_NE(nullptr, values);

  uint8_t hash[32] = {};
  EXPECT_NE(SUCCESS, encode(types, values, "Test", hash));
}

TEST(EIP712, FixedStructArraysRequireExactCardinality) {
  char types_json[] =
      "{\"types\":{"
      "\"Person\":[{\"name\":\"name\",\"type\":\"string\"}],"
      "\"Group\":[{\"name\":\"members\",\"type\":\"Person[2]\"}]}}";
  char too_few_json[] = "{\"message\":{\"members\":[{\"name\":\"Alice\"}]}}";
  char too_many_json[] =
      "{\"message\":{\"members\":[{\"name\":\"Alice\"},"
      "{\"name\":\"Bob\"},{\"name\":\"Carol\"}]}}";
  json_t type_nodes[24] = {};
  json_t too_few_nodes[12] = {};
  json_t too_many_nodes[20] = {};
  const json_t* types = json_create(types_json, type_nodes, 24);
  const json_t* too_few = json_create(too_few_json, too_few_nodes, 12);
  const json_t* too_many = json_create(too_many_json, too_many_nodes, 20);
  ASSERT_NE(nullptr, types);
  ASSERT_NE(nullptr, too_few);
  ASSERT_NE(nullptr, too_many);

  uint8_t hash[32] = {};
  EXPECT_NE(SUCCESS, encode(types, too_few, "Group", hash));
  EXPECT_NE(SUCCESS, encode(types, too_many, "Group", hash));
}

TEST(EIP712, MissingTypedValueFailsWithoutDereferencingNull) {
  char types_json[] =
      "{\"types\":{\"Mail\":[{\"name\":\"from\",\"type\":\"address\"},"
      "{\"name\":\"note\",\"type\":\"string\"}]}}";
  char values_json[] = "{\"message\":{\"note\":\"hello\"}}";
  json_t type_nodes[16] = {};
  json_t value_nodes[8] = {};
  const json_t* types = json_create(types_json, type_nodes, 16);
  const json_t* values = json_create(values_json, value_nodes, 8);
  ASSERT_NE(nullptr, types);
  ASSERT_NE(nullptr, values);

  uint8_t hash[32] = {};
  EXPECT_EQ(JSON_TYPE_WNOVAL, encode(types, values, "Mail", hash));
}

// Shared emulator confirmation driver from thorchain.cpp.
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

/* Chain IDs above 2^32 are legal and in production (Palm is 11297108109). The
 * domain separator's chainId is only ever DISPLAYED -- dsConfirm() prints the
 * host's string and nothing consumes a numeric value -- so a uint32 parse must
 * not be what decides whether the domain can be signed at all. This domain
 * used to fail with GENERAL_ERROR before a single screen was drawn, making
 * EIP-712 signing impossible on those chains. */
TEST(EIP712, DomainAcceptsChainIdAboveThirtyTwoBits) {
  char types_json[] =
      "{\"types\":{\"EIP712Domain\":["
      "{\"name\":\"name\",\"type\":\"string\"},"
      "{\"name\":\"chainId\",\"type\":\"uint256\"}]}}";
  char values_json[] =
      "{\"domain\":{\"name\":\"Palm\",\"chainId\":\"11297108109\"}}";
  json_t type_nodes[24] = {};
  json_t value_nodes[12] = {};
  const json_t* types = json_create(types_json, type_nodes, 24);
  const json_t* values = json_create(values_json, value_nodes, 12);
  ASSERT_NE(nullptr, types);
  ASSERT_NE(nullptr, values);

  uint8_t hash[32] = {};
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_EQ(SUCCESS, encode(types, values, "EIP712Domain", hash));
  EXPECT_EQ(0, kkconfirm_drain());
}

/* The canonical-decimal shape is still enforced: parseVals() hashes the value
 * with a base-10 parse, so a string the screen would print differently from
 * what was hashed ("0x1" encodes as 0) fails closed. No screen is drawn on
 * this path, so nothing is preloaded. */
TEST(EIP712, DomainRejectsNonCanonicalChainId) {
  char types_json[] =
      "{\"types\":{\"EIP712Domain\":["
      "{\"name\":\"chainId\",\"type\":\"uint256\"}]}}";
  char values_json[] = "{\"domain\":{\"chainId\":\"007\"}}";
  json_t type_nodes[16] = {};
  json_t value_nodes[8] = {};
  const json_t* types = json_create(types_json, type_nodes, 16);
  const json_t* values = json_create(values_json, value_nodes, 8);
  ASSERT_NE(nullptr, types);
  ASSERT_NE(nullptr, values);

  uint8_t hash[32] = {};
  EXPECT_EQ(GENERAL_ERROR, encode(types, values, "EIP712Domain", hash));
}

/* "-0" is zero. Sign extension keyed on the '-' character, not on the parsed
 * value, filled the top 24 bytes with 0xFF and encoded -2^64 while
 * confirmValue() printed "-0" -- a screen the user reads as nothing over a
 * word 18 quintillion away from it. The "-1" leg is the control: it must still
 * hash differently, or a build that encoded every integer alike would pass the
 * first comparison for the wrong reason. */
static int eip712_hash_int256(const char* value, uint8_t out[32]) {
  char types_json[] =
      "{\"types\":{\"Test\":[{\"name\":\"v\",\"type\":\"int256\"}]}}";
  char values_json[96];
  snprintf(values_json, sizeof(values_json), "{\"message\":{\"v\":\"%s\"}}",
           value);
  json_t type_nodes[16] = {};
  json_t value_nodes[8] = {};
  const json_t* types = json_create(types_json, type_nodes, 16);
  const json_t* values = json_create(values_json, value_nodes, 8);
  if (!types || !values) return GENERAL_ERROR;
  if (!kkconfirm_preload(1, 0)) return GENERAL_ERROR;
  const int rc = encode(types, values, "Test", out);
  kkconfirm_drain();
  return rc;
}

TEST(EIP712, NegativeZeroHashesAsZero) {
  uint8_t zero[32] = {}, neg_zero[32] = {}, neg_one[32] = {};
  ASSERT_EQ(SUCCESS, eip712_hash_int256("0", zero));
  ASSERT_EQ(SUCCESS, eip712_hash_int256("-0", neg_zero));
  ASSERT_EQ(SUCCESS, eip712_hash_int256("-1", neg_one));
  EXPECT_EQ(0, memcmp(zero, neg_zero, 32));
  EXPECT_NE(0, memcmp(zero, neg_one, 32));
}
