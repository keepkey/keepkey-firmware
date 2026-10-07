#include <gtest/gtest.h>

extern "C" {
#include "keepkey/firmware/erc7730_abi.h"
#include "keepkey/firmware/erc7730_abi_stream.h"
}

#include <algorithm>
#include <string>
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
  for (size_t chunk : {size_t{1}, size_t{7}, size_t{31}, size_t{64}})
    EXPECT_EQ(stream(&program, encoded, chunk), ERC7730_ABI_OK);

  auto gap = encoded;
  gap[63] = 160;
  EXPECT_EQ(stream(&program, gap, 17), ERC7730_ABI_NON_CANONICAL);
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

  // A surrogate is refused; calldata may carry ASCII controls (escaped later).
  std::vector<uint8_t> surrogate, control;
  word(surrogate, 32);
  dynamicBytes(surrogate, {0xed, 0xa0, 0x80});
  EXPECT_EQ(stream(&program, surrogate, 5), ERC7730_ABI_NON_CANONICAL);
  word(control, 32);
  dynamicBytes(control, {0x0a});
  EXPECT_EQ(stream(&program, control, 5), ERC7730_ABI_OK);
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
  // Longer than the capture buffer: the value is not copied, only its length
  // is kept, so the device can show it blind instead of failing mid-review.
  ASSERT_EQ(erc7730_abi_stream_feed(&state, 0, encoded.data(), encoded.size()),
            ERC7730_ABI_OK);
  ASSERT_EQ(erc7730_abi_stream_finish(&state), ERC7730_ABI_OK);
  EXPECT_TRUE(state.capture_overflow);
  EXPECT_EQ(state.located_length, (size_t)ERC7730_ABI_CAPTURE_MAX + 1u);
  Erc7730AbiCapture captured;
  ASSERT_TRUE(erc7730_abi_stream_captured(&state, &captured));
  EXPECT_EQ(captured.length, 0u);
}

TEST(Erc7730AbiStream, ExtremeNegativeIndexFailsWithoutArithmeticWrap) {
  const Erc7730AbiNode nodes[] = {{ERC7730_ABI_TUPLE, 0, 1, 1, 0},
                                  {ERC7730_ABI_ARRAY, 0, 2, 1, 1},
                                  {ERC7730_ABI_UINT, 256, 0, 0, 0}};
  Erc7730AbiProgram program{nodes, 3, 0};
  Erc7730AbiStream state{};
  ASSERT_EQ(erc7730_abi_stream_begin(&state, &program, 32), ERC7730_ABI_OK);
  // The stream owns its program view even if the caller reuses the temporary.
  program = {};
  const int32_t path[] = {0, INT32_MIN};
  ASSERT_EQ(erc7730_abi_stream_capture_path(&state, path, 2), ERC7730_ABI_OK);
  uint8_t word[32] = {0};
  ASSERT_EQ(erc7730_abi_stream_feed(&state, 0, word, sizeof(word)),
            ERC7730_ABI_OK);
  EXPECT_EQ(erc7730_abi_stream_finish(&state), ERC7730_ABI_BAD_PATH);
}

}  // namespace

namespace {

std::vector<uint8_t> filled(uint8_t fill, uint8_t last) {
  std::vector<uint8_t> out(32, fill);
  out[31] = last;
  return out;
}

std::vector<uint8_t> cat(std::initializer_list<std::vector<uint8_t>> parts) {
  std::vector<uint8_t> out;
  for (const auto& part : parts)
    out.insert(out.end(), part.begin(), part.end());
  return out;
}

std::vector<uint8_t> w(uint64_t value) {
  std::vector<uint8_t> out;
  word(out, value);
  return out;
}

std::vector<uint8_t> dyn(const std::string& value) {
  std::vector<uint8_t> out;
  dynamicBytes(out, std::vector<uint8_t>(value.begin(), value.end()));
  return out;
}

const Erc7730AbiNode kInt8[] = {{ERC7730_ABI_TUPLE, 0, 1, 1, 0},
                                {ERC7730_ABI_INT, 8, 0, 0, 0}};
const Erc7730AbiNode kBool[] = {{ERC7730_ABI_TUPLE, 0, 1, 1, 0},
                                {ERC7730_ABI_BOOL, 0, 0, 0, 0}};
const Erc7730AbiNode kBytes4[] = {{ERC7730_ABI_TUPLE, 0, 1, 1, 0},
                                  {ERC7730_ABI_FIXED_BYTES, 4, 0, 0, 0}};
const Erc7730AbiNode kTwoBytes[] = {{ERC7730_ABI_TUPLE, 0, 1, 2, 0},
                                    {ERC7730_ABI_BYTES, 0, 0, 0, 0},
                                    {ERC7730_ABI_BYTES, 0, 0, 0, 0}};
// (tuple(uint256, bytes)): a dynamic tuple encoded in the root's tail.
const Erc7730AbiNode kDynamicTuple[] = {{ERC7730_ABI_TUPLE, 0, 1, 1, 0},
                                        {ERC7730_ABI_TUPLE, 0, 2, 2, 0},
                                        {ERC7730_ABI_UINT, 256, 0, 0, 0},
                                        {ERC7730_ABI_BYTES, 0, 0, 0, 0}};
// (string[2]): a fixed-length array of a dynamic type.
const Erc7730AbiNode kStringPair[] = {{ERC7730_ABI_TUPLE, 0, 1, 1, 0},
                                      {ERC7730_ABI_ARRAY, 0, 2, 1, 2},
                                      {ERC7730_ABI_STRING, 0, 0, 0, 0}};

struct AbiCase {
  const char* name;
  const Erc7730AbiNode* nodes;
  uint16_t node_count;
  std::vector<uint8_t> encoded;
  bool accepted;
};

std::vector<AbiCase> abiCases() {
  const auto two = cat({w(64), w(128), dyn("a"), dyn("b")});
  auto high_offset = two;
  high_offset[27] = 1;  // offset word bit 32 set: 64 + 2^32
  auto truncated = two;
  truncated.pop_back();
  auto dirty_bytes4 = cat({{0xde, 0xad, 0xbe, 0xef}, std::vector<uint8_t>(28)});
  auto clean_bytes4 = dirty_bytes4;
  dirty_bytes4[4] = 1;
  return {
      {"int8 127", kInt8, 2, w(0x7f), true},
      {"int8 -128", kInt8, 2, filled(0xff, 0x80), true},
      {"int8 0x00..0080 not sign-extended", kInt8, 2, w(0x80), false},
      {"int8 0xff..ff7f not sign-extended", kInt8, 2, filled(0xff, 0x7f),
       false},
      {"bool 1", kBool, 2, w(1), true},
      {"bool 2", kBool, 2, w(2), false},
      {"bytes4 clean", kBytes4, 2, clean_bytes4, true},
      {"bytes4 dirty tail", kBytes4, 2, dirty_bytes4, false},
      {"two dynamic canonical", kTwoBytes, 3, two, true},
      {"two dynamic reordered", kTwoBytes, 3,
       cat({w(128), w(64), dyn("b"), dyn("a")}), false},
      {"two dynamic aliased", kTwoBytes, 3, cat({w(64), w(64), dyn("a")}),
       false},
      {"two dynamic backward into head", kTwoBytes, 3,
       cat({w(64), w(32), dyn("a")}), false},
      {"two dynamic gap", kTwoBytes, 3,
       cat({w(64), w(160), dyn("a"), w(0), dyn("b")}), false},
      {"trailing word after root", kTwoBytes, 3, cat({two, w(0)}), false},
      {"offset above 32 bits", kTwoBytes, 3, high_offset, false},
      {"length not a multiple of 32", kTwoBytes, 3, truncated, false},
      {"dynamic tuple in tail", kDynamicTuple, 4,
       cat({w(32), w(7), w(64), dyn("a")}), true},
      {"dynamic tuple inner gap", kDynamicTuple, 4,
       cat({w(32), w(7), w(96), w(0), dyn("a")}), false},
      {"dynamic tuple inner backward", kDynamicTuple, 4,
       cat({w(32), w(7), w(32), dyn("a")}), false},
      {"string[2] canonical", kStringPair, 3,
       cat({w(32), w(64), w(128), dyn("a"), dyn("b")}), true},
      {"string[2] aliased elements", kStringPair, 3,
       cat({w(32), w(64), w(64), dyn("a")}), false},
      {"string[2] reordered elements", kStringPair, 3,
       cat({w(32), w(128), w(64), dyn("b"), dyn("a")}), false},
  };
}

}  // namespace

TEST(Erc7730AbiStream, RejectsNonCanonicalEncodings) {
  for (const auto& c : abiCases()) {
    SCOPED_TRACE(c.name);
    const Erc7730AbiProgram program{c.nodes, c.node_count, 0};
    ASSERT_EQ(erc7730_abi_validate_program(&program), ERC7730_ABI_OK);
    for (size_t chunk : {size_t{1}, size_t{31}, size_t{32}, size_t{1024}}) {
      const bool streamed =
          stream(&program, c.encoded, chunk) == ERC7730_ABI_OK;
      EXPECT_EQ(streamed, c.accepted) << chunk;
    }
  }
}

namespace {

// (uint256,bytes)[] with `count` elements, as the tail of its parent.
std::vector<uint8_t> dynamicTupleArray(size_t count) {
  std::vector<uint8_t> out = w(count);
  for (size_t i = 0; i < count; i++) word(out, count * 32 + i * 128);
  for (size_t i = 0; i < count; i++) out = cat({out, w(i), w(64), dyn("x")});
  return out;
}

}  // namespace

TEST(Erc7730AbiStream, FullDynamicTupleArrayDecodes) {
  // (T[]) and (T[], bytes) with T = (uint256, bytes): every element holds a
  // pending offset of its own while the array's later offsets are pending.
  const Erc7730AbiNode array_only[] = {
      {ERC7730_ABI_TUPLE, 0, 1, 1, 0},
      {ERC7730_ABI_ARRAY, 0, 2, 1, ERC7730_ABI_DYNAMIC_ARRAY},
      {ERC7730_ABI_TUPLE, 0, 3, 2, 0},
      {ERC7730_ABI_UINT, 256, 0, 0, 0},
      {ERC7730_ABI_BYTES, 0, 0, 0, 0}};
  const Erc7730AbiNode array_then_bytes[] = {
      {ERC7730_ABI_TUPLE, 0, 1, 2, 0},
      {ERC7730_ABI_ARRAY, 0, 3, 1, ERC7730_ABI_DYNAMIC_ARRAY},
      {ERC7730_ABI_BYTES, 0, 0, 0, 0},
      {ERC7730_ABI_TUPLE, 0, 4, 2, 0},
      {ERC7730_ABI_UINT, 256, 0, 0, 0},
      {ERC7730_ABI_BYTES, 0, 0, 0, 0}};
  const Erc7730AbiProgram one{array_only, 5, 0};
  const Erc7730AbiProgram two{array_then_bytes, 6, 0};
  const auto full = dynamicTupleArray(ERC7730_ABI_MAX_ARRAY_ELEMENTS);
  const auto short_by_one =
      dynamicTupleArray(ERC7730_ABI_MAX_ARRAY_ELEMENTS - 1);
  const struct {
    const Erc7730AbiProgram* program;
    std::vector<uint8_t> encoded;
    Erc7730AbiResult expected;
  } cases[] = {
      {&one, cat({w(32), full}), ERC7730_ABI_OK},
      {&two, cat({w(64), w(64 + short_by_one.size()), short_by_one, dyn("b")}),
       ERC7730_ABI_OK},
      // One offset more than the decoder can hold: both refuse it alike.
      {&two, cat({w(64), w(64 + full.size()), full, dyn("b")}),
       ERC7730_ABI_RESOURCE_LIMIT},
  };
  for (const auto& c : cases) {
    SCOPED_TRACE(c.encoded.size());
    for (size_t chunk : {size_t{1}, size_t{32}, size_t{4096}})
      EXPECT_EQ(stream(c.program, c.encoded, chunk), c.expected) << chunk;
  }
}
