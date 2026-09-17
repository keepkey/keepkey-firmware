#include <gtest/gtest.h>

extern "C" {
#include "keepkey/firmware/erc7730_workflow.h"
}

static void prepareTypedUintWorkflow(Erc7730Workflow* workflow) {
  workflow->typed_data = true;
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
