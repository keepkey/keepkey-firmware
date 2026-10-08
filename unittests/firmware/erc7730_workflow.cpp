#include <gtest/gtest.h>

#include <cstring>
#include <vector>

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

// f(address to, bytes data) with the embedded call `inner` as data: run the
// pass that locates it, as a calldata formatter's first argument does.
static bool locateEmbedded(Erc7730Workflow* workflow,
                           const std::vector<uint8_t>& inner) {
  *workflow = Erc7730Workflow{};
  workflow->phase = ERC7730_WORKFLOW_READY;
  workflow->loader.abi_started = true;
  workflow->loader.index.complete = true;
  workflow->loader.abi.complete = true;
  workflow->loader.abi.node_count = 3;
  workflow->loader.abi.nodes[0].kind = ERC7730_ABI_TUPLE;
  workflow->loader.abi.nodes[0].first_child = 1;
  workflow->loader.abi.nodes[0].child_count = 2;
  workflow->loader.abi.nodes[1].kind = ERC7730_ABI_ADDRESS;
  workflow->loader.abi.nodes[2].kind = ERC7730_ABI_BYTES;
  workflow->field.kind = 13;
  workflow->field.pending_role = 1;

  std::vector<uint8_t> args(64 + 32, 0);
  args[31] = 0x11;  // to
  args[63] = 64;    // data offset
  args[94] = (uint8_t)(inner.size() >> 8);
  args[95] = (uint8_t)inner.size();
  args.insert(args.end(), inner.begin(), inner.end());
  args.resize(args.size() + (32 - inner.size() % 32) % 32, 0);

  EthereumSignTx tx{};
  tx.has_data_length = true;
  tx.data_length = 4 + args.size();
  tx.has_data_initial_chunk = true;
  tx.data_initial_chunk.size = 4;
  if (!erc7730_tx_continuation_capture(&workflow->continuation, &tx))
    return false;
  Erc7730Path path{};
  path.source = 1;
  path.step_count = 1;
  path.source_index = UINT16_MAX;
  path.steps[0].opcode = 1;
  path.steps[0].first = 1;
  return erc7730_workflow_restore_and_start_capture(workflow, &tx, &path) &&
         erc7730_workflow_calldata_feed(workflow, args.data(), args.size()) ==
             ERC7730_ABI_OK &&
         erc7730_workflow_calldata_finish(workflow) == ERC7730_ABI_OK &&
         erc7730_workflow_field_embedded(workflow);
}

static std::vector<uint8_t> innerApprove(uint8_t amount_byte) {
  std::vector<uint8_t> call = {0x09, 0x5e, 0xa7, 0xb3};
  call.resize(68, 0);
  for (size_t i = 16; i < 36; i++) call[i] = 0x22;  // spender
  for (size_t i = 36; i < 68; i++) call[i] = amount_byte;
  return call;
}

// An embedded approve() gets the top-level policy: 2^256-1 is flagged for
// the UNLIMITED warning with its full spender, a finite amount is not, and a
// dirty spender word is refused.
TEST(Erc7730Workflow, EmbeddedApproveIsClassifiedLikeATopLevelOne) {
  Erc7730Workflow workflow{};
  ASSERT_TRUE(locateEmbedded(&workflow, innerApprove(0xff)));
  EXPECT_TRUE(workflow.field.unlimited_approve);
  const uint8_t spender[20] = {0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                               0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                               0x22, 0x22, 0x22, 0x22, 0x22, 0x22};
  EXPECT_EQ(0, memcmp(workflow.field.approve_spender, spender, 20));
  EXPECT_EQ(workflow.field.inner_selector_length, 4u);
  EXPECT_EQ(workflow.field.inner_length, 68u);

  auto almost = innerApprove(0xff);
  almost[67] = 0xfe;
  ASSERT_TRUE(locateEmbedded(&workflow, almost));
  EXPECT_FALSE(workflow.field.unlimited_approve);
  ASSERT_TRUE(locateEmbedded(&workflow, innerApprove(0x01)));
  EXPECT_FALSE(workflow.field.unlimited_approve);

  // Trailing bytes do not hide it, as they do not at the top level.
  auto longer = innerApprove(0xff);
  longer.resize(100, 0xab);
  ASSERT_TRUE(locateEmbedded(&workflow, longer));
  EXPECT_TRUE(workflow.field.unlimited_approve);
  EXPECT_EQ(workflow.field.inner_length, 100u);

  auto dirty = innerApprove(0xff);
  dirty[15] = 1;  // pre-0.8 tokens mask it and still grant the allowance
  EXPECT_FALSE(locateEmbedded(&workflow, dirty));

  // Another call keeps only its selector.
  auto transfer = innerApprove(0xff);
  transfer[0] = 0xa9;
  ASSERT_TRUE(locateEmbedded(&workflow, transfer));
  EXPECT_FALSE(workflow.field.unlimited_approve);
  EXPECT_EQ(workflow.field.inner_selector[0], 0xa9);
}
