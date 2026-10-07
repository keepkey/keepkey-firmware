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
