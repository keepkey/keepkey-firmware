extern "C" {
#include "keepkey/firmware/ctap2/cbor.h"
}

#include "gtest/gtest.h"

#include <cstring>

static bool cbor_validate(const uint8_t* buffer, size_t length) {
  CborDecoder decoder;
  cbor_decoder_init(&decoder, buffer, length);
  return cbor_skip_value(&decoder) && decoder.offset == length;
}

TEST(CTAP2CBOR, CanonicalRoundTrip) {
  uint8_t buffer[64];
  CborEncoder encoder;
  cbor_encoder_init(&encoder, buffer, sizeof(buffer));
  ASSERT_TRUE(cbor_encode_map(&encoder, 2));
  ASSERT_TRUE(cbor_encode_uint(&encoder, 1));
  ASSERT_TRUE(cbor_encode_text(&encoder, "ok", 2));
  ASSERT_TRUE(cbor_encode_uint(&encoder, 2));
  ASSERT_TRUE(
      cbor_encode_bytes(&encoder, reinterpret_cast<const uint8_t*>("abc"), 3));

  CborValue value;
  ASSERT_TRUE(cbor_map_find(buffer, cbor_encoder_size(&encoder), NULL, 1,
                            &value, NULL, NULL));
  ASSERT_EQ(value.type, CBOR_TYPE_TEXT);
  ASSERT_EQ(value.length, 2u);
  ASSERT_EQ(0, memcmp(value.data, "ok", 2));
  ASSERT_TRUE(cbor_map_find(buffer, cbor_encoder_size(&encoder), NULL, 2,
                            &value, NULL, NULL));
  ASSERT_EQ(value.type, CBOR_TYPE_BYTES);
  ASSERT_EQ(value.length, 3u);
}

TEST(CTAP2CBOR, RejectsIndefiniteAndNonCanonicalValues) {
  const uint8_t indefinite[] = {0x9f, 0xff};
  const uint8_t noncanonical[] = {0x18, 0x17};
  CborDecoder decoder;
  CborValue value;
  cbor_decoder_init(&decoder, indefinite, sizeof(indefinite));
  ASSERT_FALSE(cbor_decode_value(&decoder, &value));
  cbor_decoder_init(&decoder, noncanonical, sizeof(noncanonical));
  ASSERT_FALSE(cbor_decode_value(&decoder, &value));
}

TEST(CTAP2CBOR, RejectsTrailingInvalidUtf8AndExcessiveNesting) {
  const uint8_t trailing[] = {0xa0, 0x00};
  const uint8_t invalid_utf8[] = {0x62, 0xc0, 0x80};
  uint8_t nested[18];
  memset(nested, 0x81, sizeof(nested));
  nested[sizeof(nested) - 1] = 0x00;
  ASSERT_FALSE(cbor_validate(trailing, sizeof(trailing)));
  ASSERT_FALSE(cbor_validate(invalid_utf8, sizeof(invalid_utf8)));
  ASSERT_FALSE(cbor_validate(nested, sizeof(nested)));
}

TEST(CTAP2CBOR, EncoderReportsOverflow) {
  uint8_t buffer[2];
  CborEncoder encoder;
  cbor_encoder_init(&encoder, buffer, sizeof(buffer));
  ASSERT_FALSE(cbor_encode_text(&encoder, "passkey", 7));
  ASSERT_EQ(cbor_encoder_size(&encoder), 0u);
}

TEST(CTAP2CBOR, NestedMapsMustBeCanonicallyOrdered) {
  const uint8_t ordered[] = {0xa1, 0x01, 0xa2, 0x01, 0x00, 0x02, 0x00};
  const uint8_t duplicate[] = {0xa1, 0x01, 0xa2, 0x01, 0x00, 0x01, 0x00};
  const uint8_t reversed[] = {0xa1, 0x01, 0xa2, 0x61, 'b',
                              0x00, 0x61, 'a',  0x00};
  const uint8_t shorter_first[] = {0xa1, 0x01, 0xa2, 0x61, 'z',
                                   0x00, 0x62, 'a',  'a',  0x00};
  EXPECT_TRUE(cbor_validate(ordered, sizeof(ordered)));
  EXPECT_TRUE(cbor_validate(shorter_first, sizeof(shorter_first)));
  EXPECT_FALSE(cbor_validate(duplicate, sizeof(duplicate)));
  EXPECT_FALSE(cbor_validate(reversed, sizeof(reversed)));
  // Major type first: unsigned 24 (2 bytes) sorts before negative -1.
  const uint8_t mixed[] = {0xa2, 0x18, 0x18, 0x00, 0x20, 0x00};
  const uint8_t mixed_reversed[] = {0xa2, 0x20, 0x00, 0x18, 0x18, 0x00};
  EXPECT_TRUE(cbor_validate(mixed, sizeof(mixed)));
  EXPECT_FALSE(cbor_validate(mixed_reversed, sizeof(mixed_reversed)));
}

TEST(CTAP2CBOR, CountsUtf8Codepoints) {
  const uint8_t ascii[] = {'1', '2', '3', '4'};
  const uint8_t two_e_acute[] = {0xc3, 0xa9, 0xc3, 0xa9};
  const uint8_t invalid[] = {'1', '2', '3', 0xff};
  EXPECT_EQ(cbor_utf8_codepoints(ascii, sizeof(ascii)), 4u);
  EXPECT_EQ(cbor_utf8_codepoints(two_e_acute, sizeof(two_e_acute)), 2u);
  EXPECT_EQ(cbor_utf8_codepoints(invalid, sizeof(invalid)), SIZE_MAX);
}
