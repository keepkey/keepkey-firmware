#include <gtest/gtest.h>

extern "C" {
#include "keepkey/firmware/erc7730_workflow.h"
}

static void prepareTypedUintWorkflow(Erc7730Workflow* workflow) {
  workflow->typed_data = true;
  workflow->current_formatter_kind = 1;
  workflow->phase = ERC7730_WORKFLOW_READY;
  workflow->loader.abi_started = true;
  workflow->loader.index.complete = true;
  workflow->loader.abi.complete = true;
  workflow->loader.abi.node_count = 2;
  workflow->loader.abi.nodes[0].kind = ERC7730_ABI_TUPLE;
  workflow->loader.abi.nodes[0].first_child = 1;
  workflow->loader.abi.nodes[0].child_count = 1;
  workflow->loader.abi.nodes[1].kind = ERC7730_ABI_UINT;
  workflow->loader.abi.nodes[1].size = 256;
}

TEST(Erc7730Workflow, RejectsUnbackedAndMalformedStarts) {
  erc7730_catalog_clear_preload();
  Erc7730Workflow workflow{};
  Erc7730CatalogIdentity identity{};
  identity.kind = ERC7730_DEFINITION_CALLDATA;
  EthereumSignTx tx{};
  tx.has_data_length = true;
  tx.data_length = 36;
  tx.has_data_initial_chunk = true;
  tx.data_initial_chunk.size = 4;
  EXPECT_FALSE(erc7730_workflow_begin(&workflow, &identity, &tx));
  EXPECT_EQ(workflow.phase, ERC7730_WORKFLOW_FAILED);

  identity.kind = ERC7730_DEFINITION_EIP712;
  EXPECT_FALSE(erc7730_workflow_begin(&workflow, &identity, &tx));
  EXPECT_EQ(workflow.phase, ERC7730_WORKFLOW_FAILED);
}

TEST(Erc7730Workflow, RefusesDataOutsideAuthenticatedLifecycle) {
  Erc7730Workflow workflow{};
  const uint8_t byte = 0;
  EXPECT_EQ(erc7730_workflow_calldata_feed(&workflow, &byte, 1),
            ERC7730_ABI_BOUNDS);
  EXPECT_EQ(workflow.phase, ERC7730_WORKFLOW_FAILED);
  EXPECT_EQ(erc7730_workflow_calldata_finish(&workflow), ERC7730_ABI_BOUNDS);
  EXPECT_FALSE(erc7730_workflow_active(&workflow));
  EXPECT_FALSE(erc7730_workflow_complete(&workflow));
}

TEST(Erc7730Workflow, StateIsBoundedIndependentlyOfDescriptorSize) {
  EXPECT_LE(sizeof(Erc7730Workflow), 4096u);
}

TEST(Erc7730Workflow, ReportsOnlyUnvalidatedCalldataAsWaiting) {
  Erc7730Workflow workflow{};
  size_t remaining = 99;
  EXPECT_FALSE(erc7730_workflow_calldata_waiting(&workflow, &remaining));
  workflow.phase = ERC7730_WORKFLOW_CALLDATA;
  workflow.calldata.total_length = 96;
  workflow.calldata.received = 32;
  ASSERT_TRUE(erc7730_workflow_calldata_waiting(&workflow, &remaining));
  EXPECT_EQ(remaining, 64u);
  workflow.calldata.received = 96;
  EXPECT_FALSE(erc7730_workflow_calldata_waiting(&workflow, &remaining));
  EXPECT_EQ(remaining, 0u);
  workflow.calldata.received = 97;
  EXPECT_FALSE(erc7730_workflow_calldata_waiting(&workflow, &remaining));
}

TEST(Erc7730Workflow, CapturesAndFormatsExactTypedDataLeaf) {
  Erc7730Workflow workflow{};
  prepareTypedUintWorkflow(&workflow);
  Erc7730Path path{};
  path.source = 1;
  path.step_count = 1;
  path.source_index = UINT16_MAX;
  path.steps[0].opcode = 1;
  path.steps[0].first = 0;
  ASSERT_TRUE(erc7730_workflow_start_eip712_capture(&workflow, &path));

  const uint32_t member_path[2] = {1, 0};
  uint8_t value[32] = {0};
  value[31] = 42;
  ASSERT_TRUE(erc7730_workflow_eip712_observe(&workflow, member_path, 2, value,
                                              sizeof(value)));
  EXPECT_FALSE(erc7730_workflow_eip712_observe(&workflow, member_path, 2, value,
                                               sizeof(value)));
  ASSERT_TRUE(erc7730_workflow_eip712_finish(&workflow));
  char formatted[16];
  ASSERT_TRUE(erc7730_workflow_format_captured_raw(&workflow, formatted,
                                                   sizeof(formatted)));
  EXPECT_STREQ(formatted, "42");
}

TEST(Erc7730Workflow, FormatsAuthenticatedMainnetNativeAmountExactly) {
  Erc7730Workflow workflow{};
  prepareTypedUintWorkflow(&workflow);
  workflow.identity.chain_id = 1;
  workflow.current_formatter_kind = 2;
  Erc7730Path path{};
  path.source = 1;
  path.step_count = 1;
  path.source_index = UINT16_MAX;
  path.steps[0].opcode = 1;
  path.steps[0].first = 0;
  ASSERT_TRUE(erc7730_workflow_start_eip712_capture(&workflow, &path));
  const uint32_t member_path[2] = {1, 0};
  uint8_t value[32] = {0};
  value[24] = 0x0d;
  value[25] = 0xe0;
  value[26] = 0xb6;
  value[27] = 0xb3;
  value[28] = 0xa7;
  value[29] = 0x64;
  value[30] = 0x00;
  value[31] = 0x00;  // 1 ETH
  ASSERT_TRUE(erc7730_workflow_eip712_observe(&workflow, member_path, 2, value,
                                              sizeof(value)));
  ASSERT_TRUE(erc7730_workflow_eip712_finish(&workflow));
  char formatted[32];
  ASSERT_TRUE(erc7730_workflow_format_captured_raw(&workflow, formatted,
                                                   sizeof(formatted)));
  EXPECT_STREQ(formatted, "1 ETH");
}

TEST(Erc7730Workflow, FormatsCapturedDurationExactly) {
  Erc7730Workflow workflow{};
  prepareTypedUintWorkflow(&workflow);
  workflow.current_formatter_kind = 6;
  Erc7730Path path{};
  path.source = 1;
  path.step_count = 1;
  path.source_index = UINT16_MAX;
  path.steps[0].opcode = 1;
  path.steps[0].first = 0;
  ASSERT_TRUE(erc7730_workflow_start_eip712_capture(&workflow, &path));
  const uint32_t member_path[2] = {1, 0};
  uint8_t value[32] = {0};
  value[30] = 0x20;
  value[31] = 0x3a;
  ASSERT_TRUE(erc7730_workflow_eip712_observe(&workflow, member_path, 2, value,
                                              sizeof(value)));
  ASSERT_TRUE(erc7730_workflow_eip712_finish(&workflow));
  char formatted[16];
  ASSERT_TRUE(erc7730_workflow_format_captured_raw(&workflow, formatted,
                                                   sizeof(formatted)));
  EXPECT_STREQ(formatted, "02:17:30");
}

TEST(Erc7730Workflow, FormatsCapturedTimestampExactly) {
  Erc7730Workflow workflow{};
  prepareTypedUintWorkflow(&workflow);
  workflow.current_formatter_kind = 5;
  Erc7730Path path{};
  path.source = 1;
  path.step_count = 1;
  path.source_index = UINT16_MAX;
  path.steps[0].opcode = 1;
  path.steps[0].first = 0;
  ASSERT_TRUE(erc7730_workflow_start_eip712_capture(&workflow, &path));
  const uint32_t member_path[2] = {1, 0};
  uint8_t value[32] = {0};
  value[28] = 0x65;
  value[29] = 0xe0;
  value[30] = 0x31;
  value[31] = 0xd0;
  ASSERT_TRUE(erc7730_workflow_eip712_observe(&workflow, member_path, 2, value,
                                              sizeof(value)));
  ASSERT_TRUE(erc7730_workflow_eip712_finish(&workflow));
  char formatted[32];
  ASSERT_TRUE(erc7730_workflow_format_captured_raw(&workflow, formatted,
                                                   sizeof(formatted)));
  EXPECT_STREQ(formatted, "2024-02-29T07:27:12Z");
}

TEST(Erc7730Workflow, FormatsCapturedUnitFromAuthenticatedParameters) {
  Erc7730Workflow workflow{};
  prepareTypedUintWorkflow(&workflow);
  workflow.current_formatter_kind = 7;
  strcpy(workflow.value_scratch.formatter_parameters.base, "s");
  workflow.value_scratch.formatter_parameters.prefix = true;
  Erc7730Path path{};
  path.source = 1;
  path.step_count = 1;
  path.source_index = UINT16_MAX;
  path.steps[0].opcode = 1;
  path.steps[0].first = 0;
  ASSERT_TRUE(erc7730_workflow_start_eip712_capture(&workflow, &path));
  const uint32_t member_path[2] = {1, 0};
  uint8_t value[32] = {0};
  value[30] = 0x8c;
  value[31] = 0xa0;
  ASSERT_TRUE(erc7730_workflow_eip712_observe(&workflow, member_path, 2, value,
                                              sizeof(value)));
  ASSERT_TRUE(erc7730_workflow_eip712_finish(&workflow));
  char formatted[16];
  ASSERT_TRUE(erc7730_workflow_format_captured_raw(&workflow, formatted,
                                                   sizeof(formatted)));
  EXPECT_STREQ(formatted, "36ks");
}

TEST(Erc7730Workflow, TypedDataCaptureFailsClosedOnMissingOrWrongWidthValue) {
  Erc7730Workflow workflow{};
  prepareTypedUintWorkflow(&workflow);
  Erc7730Path path{};
  path.source = 1;
  path.step_count = 1;
  path.source_index = UINT16_MAX;
  path.steps[0].opcode = 1;
  path.steps[0].first = 0;
  ASSERT_TRUE(erc7730_workflow_start_eip712_capture(&workflow, &path));
  const uint32_t other_path[2] = {1, 1};
  uint8_t value[32] = {0};
  EXPECT_TRUE(erc7730_workflow_eip712_observe(&workflow, other_path, 2, value,
                                              sizeof(value)));
  EXPECT_FALSE(erc7730_workflow_eip712_finish(&workflow));
  const uint32_t target_path[2] = {1, 0};
  EXPECT_FALSE(erc7730_workflow_eip712_observe(&workflow, target_path, 2, value,
                                               sizeof(value) - 1));
}

TEST(Erc7730Workflow, ResolvesNegativeTypedArrayIndexFromStreamedLength) {
  Erc7730Workflow workflow{};
  workflow.typed_data = true;
  workflow.phase = ERC7730_WORKFLOW_READY;
  workflow.loader.abi_started = true;
  workflow.loader.index.complete = true;
  workflow.loader.abi.complete = true;
  workflow.loader.abi.node_count = 3;
  workflow.loader.abi.nodes[0].kind = ERC7730_ABI_TUPLE;
  workflow.loader.abi.nodes[0].first_child = 1;
  workflow.loader.abi.nodes[0].child_count = 1;
  workflow.loader.abi.nodes[1].kind = ERC7730_ABI_ARRAY;
  workflow.loader.abi.nodes[1].first_child = 2;
  workflow.loader.abi.nodes[1].child_count = 1;
  workflow.loader.abi.nodes[1].array_length = ERC7730_ABI_DYNAMIC_ARRAY;
  workflow.loader.abi.nodes[2].kind = ERC7730_ABI_UINT;
  workflow.loader.abi.nodes[2].size = 256;

  Erc7730Path path{};
  path.source = 1;
  path.step_count = 2;
  path.source_index = UINT16_MAX;
  path.steps[0].opcode = 1;
  path.steps[0].first = 0;
  path.steps[1].opcode = 1;
  path.steps[1].first = -1;
  ASSERT_TRUE(erc7730_workflow_start_eip712_capture(&workflow, &path));

  const uint32_t array_path[2] = {1, 0};
  const uint8_t length[2] = {0, 3};
  ASSERT_TRUE(erc7730_workflow_eip712_observe(&workflow, array_path, 2, length,
                                              sizeof(length)));
  const uint32_t last_element_path[3] = {1, 0, 2};
  uint8_t value[32] = {0};
  value[31] = 7;
  ASSERT_TRUE(erc7730_workflow_eip712_observe(&workflow, last_element_path, 3,
                                              value, sizeof(value)));
  EXPECT_TRUE(erc7730_workflow_eip712_finish(&workflow));
}

TEST(Erc7730Workflow, CapturesDeviceOwnedTransactionContainerFacts) {
  Erc7730Workflow workflow{};
  workflow.phase = ERC7730_WORKFLOW_READY;
  workflow.current_formatter_kind = 9;
  EthereumSignTx tx{};
  tx.has_chain_id = true;
  tx.chain_id = 8453;
  tx.has_to = true;
  tx.to.size = 20;
  memset(tx.to.bytes, 0x11, tx.to.size);
  tx.has_data_length = true;
  tx.data_length = 4;
  tx.has_data_initial_chunk = true;
  tx.data_initial_chunk.size = 4;
  ASSERT_TRUE(erc7730_tx_continuation_capture(&workflow.continuation, &tx));

  Erc7730Path path{};
  path.source = 2;
  path.source_index = 4;
  EthereumSignTx restored{};
  ASSERT_TRUE(erc7730_workflow_capture_tx_container(&workflow, &path, &restored,
                                                    nullptr));
  EXPECT_EQ(restored.chain_id, 8453u);
  char formatted[16];
  ASSERT_TRUE(erc7730_workflow_format_captured_raw(&workflow, formatted,
                                                   sizeof(formatted)));
  EXPECT_STREQ(formatted, "8453");
}

TEST(Erc7730Workflow, RefusesUnavailableOrMalformedContainerFacts) {
  Erc7730Workflow workflow{};
  workflow.phase = ERC7730_WORKFLOW_READY;
  EthereumSignTx tx{};
  tx.has_chain_id = true;
  tx.chain_id = 1;
  tx.has_data_length = true;
  tx.data_length = 4;
  tx.has_data_initial_chunk = true;
  tx.data_initial_chunk.size = 4;
  ASSERT_TRUE(erc7730_tx_continuation_capture(&workflow.continuation, &tx));
  Erc7730Path path{};
  path.source = 2;
  path.source_index = 1;
  EthereumSignTx restored{};
  EXPECT_FALSE(erc7730_workflow_capture_tx_container(&workflow, &path,
                                                     &restored, nullptr));
  uint8_t sender[20];
  memset(sender, 0x22, sizeof(sender));
  ASSERT_TRUE(erc7730_workflow_capture_tx_container(&workflow, &path, &restored,
                                                    sender));
  char formatted[43];
  workflow.current_formatter_kind = 1;
  ASSERT_TRUE(erc7730_workflow_format_captured_raw(&workflow, formatted,
                                                   sizeof(formatted)));
  EXPECT_STREQ(formatted, "0x2222222222222222222222222222222222222222");
  workflow.phase = ERC7730_WORKFLOW_READY;
  path.source_index = 2;  // missing recipient
  EXPECT_FALSE(erc7730_workflow_capture_tx_container(&workflow, &path,
                                                     &restored, nullptr));
}

TEST(Erc7730Workflow, FormatsOnlyDeviceProvidedEip712HashFacts) {
  Erc7730Workflow workflow{};
  workflow.typed_data = true;
  workflow.phase = ERC7730_WORKFLOW_READY;
  workflow.current_formatter_kind = 1;
  Erc7730Path path{};
  path.source = 2;
  path.source_index = 5;
  uint8_t hash[32];
  memset(hash, 0xab, sizeof(hash));
  ASSERT_TRUE(
      erc7730_workflow_capture_eip712_container(&workflow, &path, hash));
  char formatted[67];
  ASSERT_TRUE(erc7730_workflow_format_captured_raw(&workflow, formatted,
                                                   sizeof(formatted)));
  EXPECT_EQ(strlen(formatted), 66u);
  EXPECT_STREQ(
      formatted,
      "0xabababababababababababababababababababababababababababababababab");

  workflow.phase = ERC7730_WORKFLOW_READY;
  path.source_index = 4;
  EXPECT_FALSE(
      erc7730_workflow_capture_eip712_container(&workflow, &path, hash));
}

TEST(Erc7730Workflow, EvaluatesVisibilityFromDeviceCapturedContainerValue) {
  Erc7730Workflow workflow{};
  workflow.phase = ERC7730_WORKFLOW_READY;
  EthereumSignTx tx{};
  tx.has_chain_id = true;
  tx.chain_id = 1;
  tx.has_data_length = true;
  tx.data_length = 4;
  tx.has_data_initial_chunk = true;
  tx.data_initial_chunk.size = 4;
  ASSERT_TRUE(erc7730_tx_continuation_capture(&workflow.continuation, &tx));

  Erc7730Condition condition{4, 0, UINT16_MAX, 0};
  ASSERT_TRUE(
      erc7730_workflow_begin_condition_capture(&workflow, &condition));
  EXPECT_TRUE(erc7730_workflow_condition_capture_pending(&workflow));
  Erc7730Path value_path{};
  value_path.source = 2;
  value_path.source_index = 3;
  EthereumSignTx restored{};
  ASSERT_TRUE(erc7730_workflow_capture_tx_container(
      &workflow, &value_path, &restored, nullptr));
  bool visible = false;
  ASSERT_TRUE(
      erc7730_workflow_resolve_captured_condition(&workflow, &visible));
  EXPECT_TRUE(visible);
  EXPECT_FALSE(erc7730_workflow_condition_capture_pending(&workflow));
  EXPECT_EQ(workflow.phase, ERC7730_WORKFLOW_READY);

  tx.has_value = true;
  tx.value.size = 1;
  tx.value.bytes[0] = 1;
  ASSERT_TRUE(erc7730_tx_continuation_capture(&workflow.continuation, &tx));
  condition.opcode = 5;
  ASSERT_TRUE(
      erc7730_workflow_begin_condition_capture(&workflow, &condition));
  ASSERT_TRUE(erc7730_workflow_capture_tx_container(
      &workflow, &value_path, &restored, nullptr));
  ASSERT_TRUE(
      erc7730_workflow_resolve_captured_condition(&workflow, &visible));
  EXPECT_TRUE(visible);
}

TEST(Erc7730Workflow, RefusesConditionCaptureWithoutSupportedLifecycle) {
  Erc7730Workflow workflow{};
  workflow.phase = ERC7730_WORKFLOW_READY;
  Erc7730Condition condition{6, 0, UINT16_MAX, 0};
  EXPECT_FALSE(
      erc7730_workflow_begin_condition_capture(&workflow, &condition));
  condition = {4, 0, UINT16_MAX, 0};
  workflow.typed_data = true;
  EXPECT_FALSE(
      erc7730_workflow_begin_condition_capture(&workflow, &condition));
}

TEST(Erc7730Workflow, EvaluatesAuthenticatedMembershipAndMustMatch) {
  Erc7730Workflow workflow{};
  workflow.phase = ERC7730_WORKFLOW_READY;
  EthereumSignTx tx{};
  tx.has_chain_id = true;
  tx.chain_id = 1;
  tx.has_value = true;
  tx.value.size = 1;
  tx.value.bytes[0] = 7;
  tx.has_data_length = true;
  tx.data_length = 4;
  tx.has_data_initial_chunk = true;
  tx.data_initial_chunk.size = 4;
  ASSERT_TRUE(erc7730_tx_continuation_capture(&workflow.continuation, &tx));
  Erc7730Condition condition{6, 0, 9, 0};
  ASSERT_TRUE(
      erc7730_workflow_begin_condition_capture(&workflow, &condition));
  Erc7730Path value_path{};
  value_path.source = 2;
  value_path.source_index = 3;
  EthereumSignTx restored{};
  ASSERT_TRUE(erc7730_workflow_capture_tx_container(
      &workflow, &value_path, &restored, nullptr));
  uint16_t set_index = UINT16_MAX;
  ASSERT_TRUE(erc7730_workflow_prepare_captured_membership(&workflow,
                                                           &set_index));
  EXPECT_EQ(set_index, 9u);

  Erc7730Literal set{};
  set.kind = 9;
  set.length = 6;
  const uint8_t encoded_set[] = {0, 2, 0, 1, 0, 4};
  memcpy(set.value, encoded_set, sizeof(encoded_set));
  uint16_t literal_index = UINT16_MAX;
  ASSERT_TRUE(erc7730_workflow_load_membership_set(&workflow, &set,
                                                   &literal_index));
  EXPECT_EQ(literal_index, 1u);
  Erc7730Literal literal{};
  literal.kind = 1;
  literal.length = 1;
  literal.value[0] = 6;
  bool complete = false;
  bool visible = false;
  ASSERT_TRUE(erc7730_workflow_observe_membership_literal(
      &workflow, &literal, &complete, &visible, &literal_index));
  EXPECT_FALSE(complete);
  EXPECT_EQ(literal_index, 4u);
  literal.value[0] = 7;
  ASSERT_TRUE(erc7730_workflow_observe_membership_literal(
      &workflow, &literal, &complete, &visible, &literal_index));
  EXPECT_TRUE(complete);
  EXPECT_TRUE(visible);

  workflow.phase = ERC7730_WORKFLOW_READY;
  ASSERT_TRUE(erc7730_tx_continuation_capture(&workflow.continuation, &tx));
  condition.opcode = 8;
  ASSERT_TRUE(
      erc7730_workflow_begin_condition_capture(&workflow, &condition));
  ASSERT_TRUE(erc7730_workflow_capture_tx_container(
      &workflow, &value_path, &restored, nullptr));
  ASSERT_TRUE(erc7730_workflow_prepare_captured_membership(&workflow,
                                                           &set_index));
  set.length = 4;
  const uint8_t nonmatching_set[] = {0, 1, 0, 2};
  memcpy(set.value, nonmatching_set, sizeof(nonmatching_set));
  ASSERT_TRUE(erc7730_workflow_load_membership_set(&workflow, &set,
                                                   &literal_index));
  literal.value[0] = 8;
  EXPECT_FALSE(erc7730_workflow_observe_membership_literal(
      &workflow, &literal, &complete, &visible, &literal_index));
}

TEST(Erc7730Workflow, HandlesCanonicalEmptyMembershipSets) {
  Erc7730Workflow workflow{};
  workflow.phase = ERC7730_WORKFLOW_READY;
  workflow.condition_capture = true;
  workflow.pending_condition = {7, 0, 1, 0};
  Erc7730Literal empty_set{};
  empty_set.kind = 9;
  empty_set.length = 2;
  uint16_t first_literal = 0;
  ASSERT_TRUE(erc7730_workflow_load_membership_set(
      &workflow, &empty_set, &first_literal));
  EXPECT_EQ(first_literal, UINT16_MAX);
  bool visible = false;
  ASSERT_TRUE(
      erc7730_workflow_finish_empty_membership(&workflow, &visible));
  EXPECT_TRUE(visible);
}
