extern "C" {
#include "pb_decode.h"
#include "messages-hive.pb.h"
#include "types.pb.h"
}

#include "gtest/gtest.h"

#include <cstring>

TEST(NanopbBounds, OddSizedBytesAcceptsDeclaredMaximum) {
  uint8_t wire[2 + 73] = {0x12, 73};  // signatures field, length-delimited
  memset(wire + 2, 0xA5, sizeof(wire) - 2);

  MultisigRedeemScriptType message = MultisigRedeemScriptType_init_zero;
  pb_istream_t stream = pb_istream_from_buffer(wire, sizeof(wire));
  ASSERT_TRUE(pb_decode(&stream, MultisigRedeemScriptType_fields, &message));
  ASSERT_EQ(1u, message.signatures_count);
  EXPECT_EQ(73u, message.signatures[0].size);
}

TEST(NanopbBounds, OddSizedBytesRejectsAlignmentPaddingByte) {
  uint8_t wire[2 + 74] = {0x12, 74};  // one byte beyond max_size:73
  memset(wire + 2, 0xA5, sizeof(wire) - 2);

  MultisigRedeemScriptType message = MultisigRedeemScriptType_init_zero;
  pb_istream_t stream = pb_istream_from_buffer(wire, sizeof(wire));
  EXPECT_FALSE(pb_decode(&stream, MultisigRedeemScriptType_fields, &message));
}

TEST(NanopbBounds, DescriptorKeepsCapacitySeparateFromAlignedStride) {
  const pb_field_t &signatures = MultisigRedeemScriptType_fields[1];
  EXPECT_EQ(73u, signatures.bytes_capacity);
  EXPECT_EQ(sizeof(MultisigRedeemScriptType_signatures_t),
            signatures.data_size);
  EXPECT_GT(signatures.data_size,
            PB_BYTES_ARRAY_T_ALLOCSIZE(signatures.bytes_capacity));
}

/* Hive account names are up to 16 characters, and hive_account_name_valid()
   accepts exactly that. nanopb's max_size counts the NUL, so the field has to
   be 17 bytes: at 16 a legal 16-character account was refused at decode,
   before any handler could see it. Decoding one is the assertion -- a size
   constant compared against itself would pass at either bound. */
TEST(NanopbBounds, HiveAccountNameHoldsSixteenCharacters) {
  const char kName[] = "abcdefghijklmnop";  // 16 chars, the Hive maximum
  ASSERT_EQ(16u, strlen(kName));

  // field 6 (`from` in messages-hive.proto), wire type 2, length 16, then the
  // name.
  uint8_t wire[2 + 16];
  wire[0] = (6 << 3) | 2;
  wire[1] = 16;
  memcpy(wire + 2, kName, 16);

  HiveSignTx message = HiveSignTx_init_zero;
  pb_istream_t stream = pb_istream_from_buffer(wire, sizeof(wire));
  ASSERT_TRUE(pb_decode(&stream, HiveSignTx_fields, &message))
      << "a legal 16-character account must survive decode";
  EXPECT_STREQ(kName, message.from);
}
