#include "keepkey/firmware/erc7730_workflow.h"

#include <string.h>

#include "memzero.h"

static Erc7730Workflow active_workflow;

Erc7730Workflow* erc7730_workflow_state(void) { return &active_workflow; }

static void fail(Erc7730Workflow* workflow) {
  if (!workflow) return;
  erc7730_catalog_clear_preload();
  erc7730_tx_continuation_clear(&workflow->continuation);
  erc7730_program_loader_clear(&workflow->loader);
  erc7730_abi_stream_clear(&workflow->calldata);
  memzero(&workflow->identity, sizeof(workflow->identity));
  workflow->envelope_length = 0;
  workflow->phase = ERC7730_WORKFLOW_FAILED;
}

bool erc7730_workflow_begin(Erc7730Workflow* workflow,
                            const Erc7730CatalogIdentity* identity,
                            const EthereumSignTx* tx) {
  if (!workflow || !identity || !tx) return false;
  memzero(workflow, sizeof(*workflow));
  if (identity->kind != ERC7730_DEFINITION_CALLDATA ||
      !erc7730_tx_continuation_capture(&workflow->continuation, tx)) {
    fail(workflow);
    return false;
  }
  memcpy(&workflow->identity, identity, sizeof(*identity));
  uint8_t definition_id[32];
  uint32_t total_length = 0;
  if (!erc7730_catalog_preloaded_replay_begin(definition_id, &total_length) ||
      memcmp(definition_id, identity->definition_id, 32) != 0 ||
      total_length != identity->envelope_length) {
    memzero(definition_id, sizeof(definition_id));
    fail(workflow);
    return false;
  }
  memzero(definition_id, sizeof(definition_id));
  workflow->envelope_length = total_length;
  erc7730_program_loader_begin(&workflow->loader, identity->program_length);
  if (workflow->loader.failed) {
    fail(workflow);
    return false;
  }
  workflow->phase = ERC7730_WORKFLOW_REPLAY;
  return true;
}

bool erc7730_workflow_waiting(const Erc7730Workflow* workflow,
                              uint8_t definition_id[32], uint32_t* offset,
                              uint32_t* total_length) {
  return workflow && workflow->phase == ERC7730_WORKFLOW_REPLAY &&
         erc7730_catalog_preloaded_replay_waiting(definition_id, offset,
                                                  total_length);
}

Erc7730CatalogResult erc7730_workflow_replay_feed(
    Erc7730Workflow* workflow, const EthereumClearSignDefinitionChunk* chunk,
    bool* complete) {
  if (complete) *complete = false;
  if (!workflow || !chunk || !complete ||
      workflow->phase != ERC7730_WORKFLOW_REPLAY ||
      chunk->definition_id.size != 32 || chunk->data.size == 0 ||
      chunk->data.size > ERC7730_TRANSPORT_CHUNK_MAX) {
    fail(workflow);
    return ERC7730_CATALOG_BAD_SEQUENCE;
  }
  uint32_t next_offset = 0;
  uint32_t program_offset = 0;
  const uint8_t* program_data = NULL;
  size_t program_data_len = 0;
  const Erc7730CatalogResult result = erc7730_catalog_preloaded_replay_feed(
      chunk->definition_id.bytes, chunk->offset, chunk->total_length,
      chunk->data.bytes, chunk->data.size, &next_offset, complete,
      &program_offset, &program_data, &program_data_len);
  (void)next_offset;
  if ((result != ERC7730_CATALOG_MORE && result != ERC7730_CATALOG_COMPLETE) ||
      (program_data_len != 0 &&
       !erc7730_program_loader_feed(&workflow->loader, program_offset,
                                    program_data, program_data_len))) {
    fail(workflow);
    return result == ERC7730_CATALOG_MORE || result == ERC7730_CATALOG_COMPLETE
               ? ERC7730_CATALOG_BAD_PROGRAM
               : result;
  }
  if (result == ERC7730_CATALOG_COMPLETE) {
    Erc7730AbiProgram program;
    Erc7730CatalogIdentity replayed;
    if (!*complete ||
        !erc7730_program_loader_complete(&workflow->loader, &program) ||
        !erc7730_catalog_preloaded(&replayed) ||
        memcmp(&replayed, &workflow->identity, sizeof(replayed)) != 0) {
      memzero(&replayed, sizeof(replayed));
      fail(workflow);
      return ERC7730_CATALOG_BAD_PROGRAM;
    }
    memzero(&replayed, sizeof(replayed));
    workflow->phase = ERC7730_WORKFLOW_READY;
  }
  return result;
}

bool erc7730_workflow_restore_and_start_calldata(Erc7730Workflow* workflow,
                                                 EthereumSignTx* tx) {
  if (!workflow || !tx || workflow->phase != ERC7730_WORKFLOW_READY ||
      !erc7730_tx_continuation_restore(&workflow->continuation, tx)) {
    fail(workflow);
    return false;
  }
  Erc7730AbiProgram program;
  if (tx->data_length < 4 ||
      !erc7730_program_loader_complete(&workflow->loader, &program) ||
      erc7730_abi_stream_begin(&workflow->calldata, &program,
                               tx->data_length - 4u) != ERC7730_ABI_OK) {
    fail(workflow);
    return false;
  }
  erc7730_tx_continuation_clear(&workflow->continuation);
  workflow->phase = ERC7730_WORKFLOW_CALLDATA;
  return true;
}

Erc7730AbiResult erc7730_workflow_calldata_feed(Erc7730Workflow* workflow,
                                                const uint8_t* data,
                                                size_t data_len) {
  if (!workflow || workflow->phase != ERC7730_WORKFLOW_CALLDATA || !data ||
      data_len == 0) {
    fail(workflow);
    return ERC7730_ABI_BOUNDS;
  }
  const Erc7730AbiResult result = erc7730_abi_stream_feed(
      &workflow->calldata, workflow->calldata.received, data, data_len);
  if (result != ERC7730_ABI_OK) fail(workflow);
  return result;
}

Erc7730AbiResult erc7730_workflow_calldata_finish(Erc7730Workflow* workflow) {
  if (!workflow || workflow->phase != ERC7730_WORKFLOW_CALLDATA) {
    fail(workflow);
    return ERC7730_ABI_BOUNDS;
  }
  const Erc7730AbiResult result =
      erc7730_abi_stream_finish(&workflow->calldata);
  if (result != ERC7730_ABI_OK) {
    fail(workflow);
    return result;
  }
  workflow->phase = ERC7730_WORKFLOW_COMPLETE;
  return ERC7730_ABI_OK;
}

bool erc7730_workflow_active(const Erc7730Workflow* workflow) {
  return workflow && (workflow->phase == ERC7730_WORKFLOW_REPLAY ||
                      workflow->phase == ERC7730_WORKFLOW_READY ||
                      workflow->phase == ERC7730_WORKFLOW_CALLDATA);
}

bool erc7730_workflow_complete(const Erc7730Workflow* workflow) {
  return workflow && workflow->phase == ERC7730_WORKFLOW_COMPLETE;
}

const Erc7730CatalogIdentity* erc7730_workflow_identity(
    const Erc7730Workflow* workflow) {
  if (!erc7730_workflow_active(workflow) &&
      !erc7730_workflow_complete(workflow))
    return NULL;
  return &workflow->identity;
}

void erc7730_workflow_abort(Erc7730Workflow* workflow) {
  if (!workflow) return;
  if (workflow->phase != ERC7730_WORKFLOW_IDLE) erc7730_catalog_clear_preload();
  memzero(workflow, sizeof(*workflow));
}
