#include <gtest/gtest.h>

extern "C" {
#include "keepkey/firmware/erc7730_condition.h"
}

#include <cstring>

namespace {

const Erc7730AbiNode kNodes[] = {
    {ERC7730_ABI_TUPLE, 0, 1, 3, 0},
    {ERC7730_ABI_UINT, 256, 0, 0, 0},
    {ERC7730_ABI_BYTES, 0, 0, 0, 0},
    {ERC7730_ABI_ADDRESS, 0, 0, 0, 0},
};
const Erc7730AbiProgram kProgram{kNodes, 4, 0};

}  // namespace

TEST(Erc7730Condition, EvaluatesAlwaysNeverAndEmptiness) {
  Erc7730Condition condition{1, UINT16_MAX, UINT16_MAX, 0};
  bool visible = false;
  EXPECT_TRUE(
      erc7730_condition_evaluate_basic(&condition, nullptr, nullptr, &visible));
  EXPECT_TRUE(visible);
  condition.opcode = 2;
  EXPECT_TRUE(
      erc7730_condition_evaluate_basic(&condition, nullptr, nullptr, &visible));
  EXPECT_FALSE(visible);

  Erc7730AbiCapture capture{};
  capture.node = 2;
  condition = {4, 0, UINT16_MAX, 0};
  EXPECT_TRUE(erc7730_condition_evaluate_basic(&condition, &kProgram, &capture,
                                               &visible));
  EXPECT_TRUE(visible);
  capture.length = 1;
  capture.data[0] = 1;
  condition.opcode = 5;
  EXPECT_TRUE(erc7730_condition_evaluate_basic(&condition, &kProgram, &capture,
                                               &visible));
  EXPECT_TRUE(visible);
}

TEST(Erc7730Condition, ComparesCapturedValuesToTypedLiterals) {
  Erc7730AbiCapture capture{};
  capture.node = 1;
  capture.length = 32;
  capture.data[31] = 7;
  Erc7730Literal literal{};
  literal.kind = 1;
  literal.length = 1;
  literal.value[0] = 7;
  EXPECT_TRUE(erc7730_capture_equals_literal(&kProgram, &capture, &literal));
  literal.value[0] = 8;
  EXPECT_FALSE(erc7730_capture_equals_literal(&kProgram, &capture, &literal));

  capture.node = 3;
  memset(capture.data, 0, sizeof(capture.data));
  for (size_t i = 0; i < 20; i++) capture.data[12 + i] = i;
  literal.kind = 5;
  literal.length = 20;
  for (size_t i = 0; i < 20; i++) literal.value[i] = i;
  EXPECT_TRUE(erc7730_capture_equals_literal(&kProgram, &capture, &literal));
}

TEST(Erc7730Condition, RejectsMembershipWithoutAuthenticatedSet) {
  Erc7730Condition condition{6, 0, 0, 0};
  Erc7730AbiCapture capture{};
  capture.node = 1;
  capture.length = 32;
  bool visible = true;
  EXPECT_FALSE(erc7730_condition_evaluate_basic(&condition, &kProgram, &capture,
                                                &visible));
}
