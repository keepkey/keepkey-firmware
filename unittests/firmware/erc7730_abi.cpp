#include <gtest/gtest.h>

extern "C" {
#include "keepkey/firmware/erc7730_abi.h"
}

#include <array>
#include <cstring>
#include <vector>

namespace {

void word(std::vector<uint8_t>& out, uint64_t value) {
  size_t start = out.size();
  out.resize(start + 32);
  for (size_t i = 0; i < 8; i++) {
    out[start + 31 - i] = static_cast<uint8_t>(value >> (8 * i));
  }
}

void bytes(std::vector<uint8_t>& out, const char* value) {
  size_t len = strlen(value);
  word(out, len);
  out.insert(out.end(), value, value + len);
  out.resize((out.size() + 31) & ~size_t(31));
}

TEST(Erc7730Abi, RecursivelyDecodesTupleDynamicArrayAndString) {
  const Erc7730AbiNode nodes[] = {
      {ERC7730_ABI_TUPLE, 0, 1, 2, 0},
      {ERC7730_ABI_ADDRESS, 0, 0, 0, 0},
      {ERC7730_ABI_ARRAY, 0, 3, 1, ERC7730_ABI_DYNAMIC_ARRAY},
      {ERC7730_ABI_TUPLE, 0, 4, 2, 0},
      {ERC7730_ABI_UINT, 16, 0, 0, 0},
      {ERC7730_ABI_STRING, 0, 0, 0, 0},
  };
  Erc7730AbiProgram p{nodes, 6, 0};
  std::vector<uint8_t> encoded;
  word(encoded, 0x1234);  // address
  word(encoded, 64);      // array tail
  word(encoded, 2);       // array length
  word(encoded, 64);
  word(encoded, 192);  // dynamic tuple offsets
  word(encoded, 7);
  word(encoded, 64);  // tuple 0 head
  bytes(encoded, "alpha");
  word(encoded, 9);
  word(encoded, 64);  // tuple 1 head
  bytes(encoded, "beta");
  ASSERT_EQ(erc7730_abi_validate(&p, encoded.data(), encoded.size()),
            ERC7730_ABI_OK);

  const int32_t path[] = {1, -1, 1};
  Erc7730AbiValue value{};
  ASSERT_EQ(
      erc7730_abi_resolve(&p, encoded.data(), encoded.size(), path, 3, &value),
      ERC7730_ABI_OK);
  ASSERT_EQ(value.data_len, 4u);
  EXPECT_EQ(memcmp(value.data, "beta", 4), 0);
}

TEST(Erc7730Abi, RejectsNonCanonicalOffsetOverlapGapAndTrailingData) {
  const Erc7730AbiNode nodes[] = {
      {ERC7730_ABI_TUPLE, 0, 1, 2, 0},
      {ERC7730_ABI_BYTES, 0, 0, 0, 0},
      {ERC7730_ABI_BYTES, 0, 0, 0, 0},
  };
  Erc7730AbiProgram p{nodes, 3, 0};
  std::vector<uint8_t> good;
  word(good, 64);
  word(good, 128);
  bytes(good, "one");
  bytes(good, "two");
  EXPECT_EQ(erc7730_abi_validate(&p, good.data(), good.size()), ERC7730_ABI_OK);
  for (uint8_t bad_offset : {uint8_t{64}, uint8_t{160}}) {
    auto bad = good;
    bad[63] = bad_offset;
    EXPECT_EQ(erc7730_abi_validate(&p, bad.data(), bad.size()),
              ERC7730_ABI_NON_CANONICAL);
  }
  auto trailing = good;
  trailing.resize(trailing.size() + 32);
  EXPECT_EQ(erc7730_abi_validate(&p, trailing.data(), trailing.size()),
            ERC7730_ABI_NON_CANONICAL);
}

TEST(Erc7730Abi, RejectsDirtyAtomicAndDynamicPadding) {
  const Erc7730AbiNode nodes[] = {
      {ERC7730_ABI_TUPLE, 0, 1, 3, 0},
      {ERC7730_ABI_UINT, 8, 0, 0, 0},
      {ERC7730_ABI_BOOL, 0, 0, 0, 0},
      {ERC7730_ABI_BYTES, 0, 0, 0, 0},
  };
  Erc7730AbiProgram p{nodes, 4, 0};
  std::vector<uint8_t> good;
  word(good, 255);
  word(good, 1);
  word(good, 96);
  bytes(good, "x");
  ASSERT_EQ(erc7730_abi_validate(&p, good.data(), good.size()), ERC7730_ABI_OK);
  auto dirty_uint = good;
  dirty_uint[0] = 1;
  EXPECT_EQ(erc7730_abi_validate(&p, dirty_uint.data(), dirty_uint.size()),
            ERC7730_ABI_NON_CANONICAL);
  auto bad_bool = good;
  bad_bool[63] = 2;
  EXPECT_EQ(erc7730_abi_validate(&p, bad_bool.data(), bad_bool.size()),
            ERC7730_ABI_NON_CANONICAL);
  auto dirty_bytes = good;
  dirty_bytes.back() = 1;
  EXPECT_EQ(erc7730_abi_validate(&p, dirty_bytes.data(), dirty_bytes.size()),
            ERC7730_ABI_NON_CANONICAL);
}

TEST(Erc7730Abi, RejectsBadProgramsAndResourceExhaustion) {
  Erc7730AbiNode cycle[] = {
      {ERC7730_ABI_ARRAY, 0, 0, 1, 1},
  };
  Erc7730AbiProgram bad{cycle, 1, 0};
  std::array<uint8_t, 32> data{};
  EXPECT_EQ(erc7730_abi_validate(&bad, data.data(), data.size()),
            ERC7730_ABI_BAD_PROGRAM);

  const Erc7730AbiNode nodes[] = {
      {ERC7730_ABI_TUPLE, 0, 1, 1, 0},
      {ERC7730_ABI_ARRAY, 0, 2, 1, ERC7730_ABI_DYNAMIC_ARRAY},
      {ERC7730_ABI_UINT, 256, 0, 0, 0},
  };
  Erc7730AbiProgram p{nodes, 3, 0};
  std::vector<uint8_t> oversized;
  word(oversized, 32);
  word(oversized, ERC7730_ABI_MAX_ARRAY_ELEMENTS + 1);
  EXPECT_EQ(erc7730_abi_validate(&p, oversized.data(), oversized.size()),
            ERC7730_ABI_RESOURCE_LIMIT);
}

TEST(Erc7730Abi, ProgramMustBeAnExactForwardTree) {
  const Erc7730AbiNode unreachable[] = {
      {ERC7730_ABI_TUPLE, 0, 1, 1, 0},
      {ERC7730_ABI_UINT, 256, 0, 0, 0},
      {ERC7730_ABI_ADDRESS, 0, 0, 0, 0},
  };
  Erc7730AbiProgram p{unreachable, 3, 0};
  EXPECT_EQ(erc7730_abi_validate_program(&p), ERC7730_ABI_BAD_PROGRAM);

  const Erc7730AbiNode shared[] = {
      {ERC7730_ABI_TUPLE, 0, 1, 2, 0},
      {ERC7730_ABI_ARRAY, 0, 3, 1, 1},
      {ERC7730_ABI_ARRAY, 0, 3, 1, 1},
      {ERC7730_ABI_UINT, 256, 0, 0, 0},
  };
  p = {shared, 4, 0};
  EXPECT_EQ(erc7730_abi_validate_program(&p), ERC7730_ABI_BAD_PROGRAM);

  const Erc7730AbiNode wrong_root[] = {
      {ERC7730_ABI_ARRAY, 0, 1, 1, 1},
      {ERC7730_ABI_UINT, 256, 0, 0, 0},
  };
  p = {wrong_root, 2, 0};
  EXPECT_EQ(erc7730_abi_validate_program(&p), ERC7730_ABI_BAD_PROGRAM);
}

}  // namespace
