#include <gtest/gtest.h>

extern "C" {
#include "keepkey/firmware/erc7730_abi_stream.h"
}

#include <algorithm>
#include <vector>

namespace {

void word(std::vector<uint8_t>& out, uint64_t value) {
  const size_t start = out.size();
  out.resize(start + 32);
  for (size_t i = 0; i < 8; i++)
    out[start + 31 - i] = static_cast<uint8_t>(value >> (8 * i));
}

void dynamicBytes(std::vector<uint8_t>& out,
                  const std::vector<uint8_t>& value) {
  word(out, value.size());
  out.insert(out.end(), value.begin(), value.end());
  out.resize((out.size() + 31) & ~size_t(31));
}

Erc7730AbiResult stream(const Erc7730AbiProgram* program,
                        const std::vector<uint8_t>& encoded,
                        size_t chunk_size) {
  Erc7730AbiStream state{};
  Erc7730AbiResult result =
      erc7730_abi_stream_begin(&state, program, encoded.size());
  for (size_t offset = 0;
       result == ERC7730_ABI_OK && offset < encoded.size();) {
    const size_t length = std::min(chunk_size, encoded.size() - offset);
    result = erc7730_abi_stream_feed(&state, offset, encoded.data() + offset,
                                     length);
    offset += length;
  }
  if (result == ERC7730_ABI_OK) result = erc7730_abi_stream_finish(&state);
  erc7730_abi_stream_clear(&state);
  return result;
}

TEST(Erc7730AbiStream, AcceptsAtomicArgumentsAtEveryChunkBoundary) {
  const Erc7730AbiNode nodes[] = {
      {ERC7730_ABI_TUPLE, 0, 1, 3, 0},
      {ERC7730_ABI_ADDRESS, 0, 0, 0, 0},
      {ERC7730_ABI_UINT, 16, 0, 0, 0},
      {ERC7730_ABI_BOOL, 0, 0, 0, 0},
  };
  const Erc7730AbiProgram program{nodes, 4, 0};
  std::vector<uint8_t> encoded;
  word(encoded, 0x1234);
  word(encoded, 65535);
  word(encoded, 1);
  ASSERT_EQ(erc7730_abi_validate(&program, encoded.data(), encoded.size()),
            ERC7730_ABI_OK);
  for (size_t chunk :
       {size_t{1}, size_t{7}, size_t{31}, size_t{32}, size_t{65}})
    EXPECT_EQ(stream(&program, encoded, chunk), ERC7730_ABI_OK);

  encoded[0] = 1;
  EXPECT_EQ(stream(&program, encoded, 13), ERC7730_ABI_NON_CANONICAL);
}

TEST(Erc7730AbiStream, AcceptsCanonicalRecursiveDynamicValues) {
  const Erc7730AbiNode nodes[] = {
      {ERC7730_ABI_TUPLE, 0, 1, 2, 0},
      {ERC7730_ABI_STRING, 0, 0, 0, 0},
      {ERC7730_ABI_ARRAY, 0, 3, 1, ERC7730_ABI_DYNAMIC_ARRAY},
      {ERC7730_ABI_UINT, 256, 0, 0, 0},
  };
  const Erc7730AbiProgram program{nodes, 4, 0};
  std::vector<uint8_t> encoded;
  word(encoded, 64);
  word(encoded, 128);
  dynamicBytes(encoded, {'a', 'b', 'c'});
  word(encoded, 2);
  word(encoded, 7);
  word(encoded, 9);
  ASSERT_EQ(erc7730_abi_validate(&program, encoded.data(), encoded.size()),
            ERC7730_ABI_OK);
  for (size_t chunk : {size_t{1}, size_t{7}, size_t{31}, size_t{64}})
    EXPECT_EQ(stream(&program, encoded, chunk), ERC7730_ABI_OK);

  auto gap = encoded;
  gap[63] = 160;
  EXPECT_EQ(stream(&program, gap, 17), ERC7730_ABI_NON_CANONICAL);
}

TEST(Erc7730AbiStream, CapturesAuthenticatedArrayLength) {
  const Erc7730AbiNode nodes[] = {
      {ERC7730_ABI_TUPLE, 0, 1, 1, 0},
      {ERC7730_ABI_ARRAY, 0, 2, 1, ERC7730_ABI_DYNAMIC_ARRAY},
      {ERC7730_ABI_UINT, 256, 0, 0, 0},
  };
  const Erc7730AbiProgram program{nodes, 3, 0};
  std::vector<uint8_t> encoded;
  word(encoded, 32);
  word(encoded, 3);
  word(encoded, 7);
  word(encoded, 8);
  word(encoded, 9);

  Erc7730AbiStream state{};
  ASSERT_EQ(erc7730_abi_stream_begin(&state, &program, encoded.size()),
            ERC7730_ABI_OK);
  const int32_t path[] = {0};
  ASSERT_EQ(erc7730_abi_stream_capture_array_path(&state, path, 1),
            ERC7730_ABI_OK);
  for (size_t offset = 0; offset < encoded.size();) {
    const size_t length = std::min(size_t{5}, encoded.size() - offset);
    ASSERT_EQ(erc7730_abi_stream_feed(&state, offset, encoded.data() + offset,
                                      length),
              ERC7730_ABI_OK);
    offset += length;
  }
  ASSERT_EQ(erc7730_abi_stream_finish(&state), ERC7730_ABI_OK);
  Erc7730AbiCapture capture{};
  ASSERT_TRUE(erc7730_abi_stream_captured(&state, &capture));
  EXPECT_EQ(capture.node, 1u);
  ASSERT_EQ(capture.length, 32u);
  EXPECT_EQ(capture.data[31], 3u);
}

TEST(Erc7730AbiStream, RejectsInvalidUtf8PaddingAndTruncation) {
  const Erc7730AbiNode nodes[] = {
      {ERC7730_ABI_TUPLE, 0, 1, 1, 0},
      {ERC7730_ABI_STRING, 0, 0, 0, 0},
  };
  const Erc7730AbiProgram program{nodes, 2, 0};
  std::vector<uint8_t> encoded;
  word(encoded, 32);
  dynamicBytes(encoded, {0xe2, 0x82, 0xac});
  EXPECT_EQ(stream(&program, encoded, 5), ERC7730_ABI_OK);

  auto invalid = encoded;
  invalid[65] = 0x28;
  EXPECT_EQ(stream(&program, invalid, 9), ERC7730_ABI_NON_CANONICAL);
  auto dirty = encoded;
  dirty.back() = 1;
  EXPECT_EQ(stream(&program, dirty, 11), ERC7730_ABI_NON_CANONICAL);
  encoded.pop_back();
  EXPECT_EQ(stream(&program, encoded, 3), ERC7730_ABI_NON_CANONICAL);
}

TEST(Erc7730AbiStream, RejectsResourceExhaustionAndDiscontinuousInput) {
  const Erc7730AbiNode nodes[] = {
      {ERC7730_ABI_TUPLE, 0, 1, 1, 0},
      {ERC7730_ABI_ARRAY, 0, 2, 1, ERC7730_ABI_DYNAMIC_ARRAY},
      {ERC7730_ABI_UINT, 256, 0, 0, 0},
  };
  const Erc7730AbiProgram program{nodes, 3, 0};
  std::vector<uint8_t> encoded;
  word(encoded, 32);
  word(encoded, ERC7730_ABI_MAX_ARRAY_ELEMENTS + 1);
  EXPECT_EQ(stream(&program, encoded, 32), ERC7730_ABI_RESOURCE_LIMIT);

  Erc7730AbiStream state{};
  ASSERT_EQ(erc7730_abi_stream_begin(&state, &program, encoded.size()),
            ERC7730_ABI_OK);
  EXPECT_EQ(erc7730_abi_stream_feed(&state, 1, encoded.data(), 1),
            ERC7730_ABI_BOUNDS);
  EXPECT_EQ(erc7730_abi_stream_feed(&state, 0, encoded.data(), 1),
            ERC7730_ABI_BOUNDS);
}

TEST(Erc7730AbiStream, CapturesNestedDynamicValueByNegativeArrayIndex) {
  const Erc7730AbiNode nodes[] = {
      {ERC7730_ABI_TUPLE, 0, 1, 1, 0},
      {ERC7730_ABI_ARRAY, 0, 2, 1, ERC7730_ABI_DYNAMIC_ARRAY},
      {ERC7730_ABI_TUPLE, 0, 3, 2, 0},
      {ERC7730_ABI_UINT, 256, 0, 0, 0},
      {ERC7730_ABI_STRING, 0, 0, 0, 0},
  };
  const Erc7730AbiProgram program{nodes, 5, 0};
  std::vector<uint8_t> encoded;
  word(encoded, 32);   // root -> array
  word(encoded, 2);    // array count
  word(encoded, 64);   // tuple 0
  word(encoded, 192);  // tuple 1
  word(encoded, 7);
  word(encoded, 64);
  dynamicBytes(encoded, {'a'});
  word(encoded, 9);
  word(encoded, 64);
  dynamicBytes(encoded, {'b', 'e', 't', 'a'});

  ASSERT_EQ(erc7730_abi_validate(&program, encoded.data(), encoded.size()),
            ERC7730_ABI_OK);

  Erc7730AbiStream state{};
  ASSERT_EQ(erc7730_abi_stream_begin(&state, &program, encoded.size()),
            ERC7730_ABI_OK);
  const int32_t path[] = {0, -1, 1};
  ASSERT_EQ(erc7730_abi_stream_capture_path(&state, path, 3), ERC7730_ABI_OK);
  for (size_t offset = 0; offset < encoded.size();) {
    SCOPED_TRACE(offset);
    const size_t length = std::min(size_t{7}, encoded.size() - offset);
    ASSERT_EQ(erc7730_abi_stream_feed(&state, offset, encoded.data() + offset,
                                      length),
              ERC7730_ABI_OK);
    offset += length;
  }
  ASSERT_EQ(erc7730_abi_stream_finish(&state), ERC7730_ABI_OK);
  Erc7730AbiCapture capture{};
  ASSERT_TRUE(erc7730_abi_stream_captured(&state, &capture));
  EXPECT_EQ(capture.node, 4u);
  ASSERT_EQ(capture.length, 4u);
  EXPECT_EQ(memcmp(capture.data, "beta", 4), 0);
}

TEST(Erc7730AbiStream, CapturesAtomicWordAndRejectsMissingOrLargeTargets) {
  const Erc7730AbiNode atomic_nodes[] = {
      {ERC7730_ABI_TUPLE, 0, 1, 1, 0},
      {ERC7730_ABI_UINT, 256, 0, 0, 0},
  };
  const Erc7730AbiProgram atomic{atomic_nodes, 2, 0};
  std::vector<uint8_t> encoded;
  word(encoded, 42);
  Erc7730AbiStream state{};
  ASSERT_EQ(erc7730_abi_stream_begin(&state, &atomic, encoded.size()),
            ERC7730_ABI_OK);
  const int32_t zero[] = {0};
  ASSERT_EQ(erc7730_abi_stream_capture_path(&state, zero, 1), ERC7730_ABI_OK);
  ASSERT_EQ(erc7730_abi_stream_feed(&state, 0, encoded.data(), encoded.size()),
            ERC7730_ABI_OK);
  ASSERT_EQ(erc7730_abi_stream_finish(&state), ERC7730_ABI_OK);
  Erc7730AbiCapture capture{};
  ASSERT_TRUE(erc7730_abi_stream_captured(&state, &capture));
  EXPECT_EQ(capture.data[31], 42u);

  ASSERT_EQ(erc7730_abi_stream_begin(&state, &atomic, encoded.size()),
            ERC7730_ABI_OK);
  const int32_t missing[] = {1};
  ASSERT_EQ(erc7730_abi_stream_capture_path(&state, missing, 1),
            ERC7730_ABI_OK);
  ASSERT_EQ(erc7730_abi_stream_feed(&state, 0, encoded.data(), encoded.size()),
            ERC7730_ABI_OK);
  EXPECT_EQ(erc7730_abi_stream_finish(&state), ERC7730_ABI_BAD_PATH);

  const Erc7730AbiNode bytes_nodes[] = {
      {ERC7730_ABI_TUPLE, 0, 1, 1, 0},
      {ERC7730_ABI_BYTES, 0, 0, 0, 0},
  };
  const Erc7730AbiProgram bytes_program{bytes_nodes, 2, 0};
  encoded.clear();
  word(encoded, 32);
  word(encoded, ERC7730_ABI_CAPTURE_MAX + 1);
  encoded.resize(encoded.size() + 160);
  ASSERT_EQ(erc7730_abi_stream_begin(&state, &bytes_program, encoded.size()),
            ERC7730_ABI_OK);
  ASSERT_EQ(erc7730_abi_stream_capture_path(&state, zero, 1), ERC7730_ABI_OK);
  EXPECT_EQ(erc7730_abi_stream_feed(&state, 0, encoded.data(), encoded.size()),
            ERC7730_ABI_RESOURCE_LIMIT);
}

}  // namespace
