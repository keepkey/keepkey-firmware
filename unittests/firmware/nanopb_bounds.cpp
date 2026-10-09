extern "C" {
#include "pb_decode.h"
#include "types.pb.h"
}

#include "gtest/gtest.h"

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
