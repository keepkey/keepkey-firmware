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

namespace {

// No current message has a oneof or a fixed-count array, so their descriptor
// macros are instantiated here.
typedef PB_BYTES_ARRAY_T(5) OneofBytes5;
typedef PB_BYTES_ARRAY_T(7) OneofBytes7;

struct DescriptorShapes {
  pb_size_t which_named;
  union {
    OneofBytes5 raw;
    uint32_t number;
  } named;
  pb_size_t which_plain;
  union {
    OneofBytes7 blob;
    uint32_t count;
  };
  uint32_t fixed[3];
};

// Stands in for a default value or submessage descriptor. Not an address: a
// relocation may not sit unaligned in the packed descriptor on every host.
const void *const kPtr = (const void *)0x55;

const pb_field_t kShapeFields[] = {
    PB_ONEOF_FIELD(named, 1, BYTES, ONEOF, STATIC, FIRST, DescriptorShapes, raw,
                   raw, 0),
    PB_ONEOF_FIELD(named, 2, UINT32, ONEOF, STATIC, UNION, DescriptorShapes,
                   number, number, kPtr),
    PB_ANONYMOUS_ONEOF_FIELD(plain, 3, BYTES, ONEOF, STATIC, OTHER,
                             DescriptorShapes, blob, named.number, 0),
    PB_ANONYMOUS_ONEOF_FIELD(plain, 4, UINT32, ONEOF, STATIC, UNION,
                             DescriptorShapes, count, count, kPtr),
    PB_REPEATED_FIXED_COUNT(5, UINT32, OTHER, DescriptorShapes, fixed, count,
                            kPtr),
    PB_LAST_FIELD};

}  // namespace

// Each initializer value must land in its own member: a value short, and the
// array size and pointer slide into the members before them.
TEST(NanopbBounds, OneofAndFixedCountDescriptorsFillEveryMember) {
  const pb_field_t &raw = kShapeFields[0];
  EXPECT_EQ(sizeof(OneofBytes5), raw.data_size);
  EXPECT_EQ(5u, raw.bytes_capacity);
  EXPECT_EQ(0u, raw.array_size);
  EXPECT_EQ(nullptr, raw.ptr);

  const pb_field_t &number = kShapeFields[1];
  EXPECT_EQ(0u, number.bytes_capacity);
  EXPECT_EQ(0u, number.array_size);
  EXPECT_EQ(kPtr, number.ptr);

  const pb_field_t &blob = kShapeFields[2];
  EXPECT_EQ(7u, blob.bytes_capacity);
  EXPECT_EQ(0u, blob.array_size);
  EXPECT_EQ(nullptr, blob.ptr);

  const pb_field_t &count = kShapeFields[3];
  EXPECT_EQ(0u, count.bytes_capacity);
  EXPECT_EQ(0u, count.array_size);
  EXPECT_EQ(kPtr, count.ptr);

  const pb_field_t &fixed = kShapeFields[4];
  EXPECT_EQ(sizeof(uint32_t), fixed.data_size);
  EXPECT_EQ(0u, fixed.bytes_capacity);
  EXPECT_EQ(3u, fixed.array_size);
  EXPECT_EQ(kPtr, fixed.ptr);
}
