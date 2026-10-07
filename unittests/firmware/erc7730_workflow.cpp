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

TEST(Erc7730Workflow,
     SigningReplayMustMatchReviewedBytesAcrossChunkBoundaries) {
  for (bool change_value : {false, true}) {
    Erc7730Workflow workflow{};
    prepareTypedUintWorkflow(&workflow);
    workflow.typed_data = false;
    EthereumSignTx tx{};
    tx.has_data_length = true;
    tx.data_length = 36;
    tx.has_data_initial_chunk = true;
    tx.data_initial_chunk.size = 4;
    tx.data_initial_chunk.bytes[0] = 0xaa;
    ASSERT_TRUE(erc7730_tx_continuation_capture(&workflow.continuation, &tx));
    ASSERT_TRUE(erc7730_workflow_restore_and_start_calldata(&workflow, &tx));
    uint8_t value[32] = {0};
    value[31] = 42;
    ASSERT_EQ(erc7730_workflow_calldata_feed(&workflow, value, 32),
              ERC7730_ABI_OK);
    ASSERT_EQ(erc7730_workflow_calldata_finish(&workflow), ERC7730_ABI_OK);
    ASSERT_TRUE(erc7730_workflow_start_signing(&workflow, &tx));
    EXPECT_FALSE(erc7730_workflow_complete(&workflow));
    if (change_value) value[31] = 43;
    ASSERT_EQ(erc7730_workflow_calldata_feed(&workflow, value, 7),
              ERC7730_ABI_OK);
    ASSERT_EQ(erc7730_workflow_calldata_feed(&workflow, value + 7, 25),
              ERC7730_ABI_OK);
    EXPECT_EQ(erc7730_workflow_calldata_finish(&workflow),
              change_value ? ERC7730_ABI_NON_CANONICAL : ERC7730_ABI_OK);
    EXPECT_EQ(erc7730_workflow_complete(&workflow), !change_value);
  }
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
  // Host (64-bit) layout; tools/check_sram_budget.py is the real (ARM) gate.
  EXPECT_LE(sizeof(Erc7730Workflow), 4352u);
}

TEST(Erc7730Workflow, ReportsOnlyUnvalidatedCalldataAsWaiting) {
  Erc7730Workflow workflow{};
  size_t remaining = 99;
  EXPECT_FALSE(erc7730_workflow_calldata_waiting(&workflow, &remaining));
  workflow.phase = ERC7730_WORKFLOW_CALLDATA;
  // Every pass replays the whole outer calldata, also while an inner call's
  // bytes are the only ones decoded.
  workflow.outer_total = 96;
  workflow.outer_received = 32;
  ASSERT_TRUE(erc7730_workflow_calldata_waiting(&workflow, &remaining));
  EXPECT_EQ(remaining, 64u);
  workflow.outer_received = 96;
  EXPECT_FALSE(erc7730_workflow_calldata_waiting(&workflow, &remaining));
  EXPECT_EQ(remaining, 0u);
  workflow.outer_received = 97;
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

TEST(Erc7730Workflow, TypedDataReplayBindsBothDomainAndMessageHashes) {
  for (bool change_domain : {false, true}) {
    Erc7730Workflow workflow{};
    workflow.typed_data = true;
    workflow.phase = ERC7730_WORKFLOW_COMPLETE;
    uint8_t domain[32] = {1};
    uint8_t message[32] = {2};
    ASSERT_TRUE(erc7730_workflow_eip712_commit(&workflow, domain, message));
    EXPECT_TRUE(erc7730_workflow_eip712_commit(&workflow, domain, message));
    if (change_domain)
      domain[31] ^= 1;
    else
      message[31] ^= 1;
    EXPECT_FALSE(erc7730_workflow_eip712_commit(&workflow, domain, message));
    EXPECT_EQ(workflow.phase, ERC7730_WORKFLOW_FAILED);
  }
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
