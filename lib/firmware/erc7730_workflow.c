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
  workflow->phase = ERC7730_WORKFLOW_FAILED;
}

static bool begin_replay(Erc7730Workflow* workflow,
                         const Erc7730CatalogIdentity* identity) {
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
  erc7730_program_loader_begin(&workflow->loader, identity->program_length);
  if (workflow->loader.failed) {
    fail(workflow);
    return false;
  }
  workflow->phase = ERC7730_WORKFLOW_REPLAY;
  return true;
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
  return begin_replay(workflow, identity);
}

bool erc7730_workflow_begin_eip712(Erc7730Workflow* workflow,
                                   const Erc7730CatalogIdentity* identity) {
  if (!workflow || !identity) return false;
  memzero(workflow, sizeof(*workflow));
  if (identity->kind != ERC7730_DEFINITION_EIP712) {
    fail(workflow);
    return false;
  }
  workflow->typed_data = true;
  return begin_replay(workflow, identity);
}

bool erc7730_workflow_waiting(const Erc7730Workflow* workflow,
                              uint8_t definition_id[32], uint32_t* offset,
                              uint32_t* total_length) {
  return workflow &&
         (workflow->phase == ERC7730_WORKFLOW_REPLAY ||
          workflow->phase == ERC7730_WORKFLOW_SELECT) &&
         erc7730_catalog_preloaded_replay_waiting(definition_id, offset,
                                                  total_length);
}

static bool begin_selection_replay(Erc7730Workflow* workflow,
                                   uint8_t selection_kind) {
  if (!workflow || workflow->phase != ERC7730_WORKFLOW_READY ||
      selection_kind == ERC7730_SELECTION_NONE)
    return false;
  uint8_t definition_id[32];
  uint32_t total_length = 0;
  if (!erc7730_catalog_preloaded_replay_begin(definition_id, &total_length) ||
      memcmp(definition_id, workflow->identity.definition_id, 32) != 0 ||
      total_length != workflow->identity.envelope_length) {
    memzero(definition_id, sizeof(definition_id));
    fail(workflow);
    return false;
  }
  memzero(definition_id, sizeof(definition_id));
  workflow->selection_kind = selection_kind;
  workflow->phase = ERC7730_WORKFLOW_SELECT;
  return true;
}

bool erc7730_workflow_select_display(Erc7730Workflow* workflow,
                                     uint16_t instruction_index) {
  Erc7730ProgramSection section;
  if (!workflow || workflow->phase != ERC7730_WORKFLOW_READY ||
      !erc7730_program_index_section(&workflow->loader.index, 7, &section))
    return false;
  memzero(&workflow->selection, sizeof(workflow->selection));
  erc7730_program_display_begin(&workflow->selection.display, section.length,
                                instruction_index);
  if (workflow->selection.display.failed) return false;
  return begin_selection_replay(workflow, ERC7730_SELECTION_DISPLAY);
}

bool erc7730_workflow_select_string(Erc7730Workflow* workflow,
                                    uint16_t string_index) {
  Erc7730ProgramSection section;
  if (!workflow || workflow->phase != ERC7730_WORKFLOW_READY ||
      !erc7730_program_index_section(&workflow->loader.index, 1, &section))
    return false;
  memzero(&workflow->selection, sizeof(workflow->selection));
  erc7730_program_string_begin(&workflow->selection.string, section.length,
                               string_index);
  if (workflow->selection.string.failed) return false;
  return begin_selection_replay(workflow, ERC7730_SELECTION_STRING);
}

bool erc7730_workflow_select_formatter(Erc7730Workflow* workflow,
                                       uint16_t formatter_index) {
  Erc7730ProgramSection section;
  if (!workflow || workflow->phase != ERC7730_WORKFLOW_READY ||
      !erc7730_program_index_section(&workflow->loader.index, 6, &section))
    return false;
  memzero(&workflow->selection, sizeof(workflow->selection));
  erc7730_program_formatter_begin(&workflow->selection.formatter,
                                  section.length, formatter_index);
  if (workflow->selection.formatter.failed) return false;
  return begin_selection_replay(workflow, ERC7730_SELECTION_FORMATTER);
}

bool erc7730_workflow_select_path(Erc7730Workflow* workflow,
                                  uint16_t path_index) {
  Erc7730ProgramSection section;
  if (!workflow || workflow->phase != ERC7730_WORKFLOW_READY ||
      !erc7730_program_index_section(&workflow->loader.index, 3, &section))
    return false;
  memzero(&workflow->selection, sizeof(workflow->selection));
  erc7730_program_path_begin(&workflow->selection.path, section.length,
                             path_index);
  if (workflow->selection.path.failed) return false;
  return begin_selection_replay(workflow, ERC7730_SELECTION_PATH);
}

static bool feed_selection_program(Erc7730Workflow* workflow,
                                   uint32_t program_offset,
                                   const uint8_t* program_data,
                                   size_t program_data_len) {
  if (program_data_len == 0) return true;
  uint8_t section_type = 0;
  switch (workflow->selection_kind) {
    case ERC7730_SELECTION_DISPLAY:
      section_type = 7;
      break;
    case ERC7730_SELECTION_STRING:
      section_type = 1;
      break;
    case ERC7730_SELECTION_FORMATTER:
      section_type = 6;
      break;
    case ERC7730_SELECTION_PATH:
      section_type = 3;
      break;
    default:
      return false;
  }
  Erc7730ProgramSection section;
  if (!erc7730_program_index_section(&workflow->loader.index, section_type,
                                     &section) ||
      program_data_len > UINT32_MAX - program_offset)
    return false;
  const uint32_t chunk_end = program_offset + (uint32_t)program_data_len;
  const uint32_t section_end = section.offset + section.length;
  const uint32_t overlap_start =
      program_offset > section.offset ? program_offset : section.offset;
  const uint32_t overlap_end =
      chunk_end < section_end ? chunk_end : section_end;
  if (overlap_start >= overlap_end) return true;
  const uint8_t* overlap_data = program_data + (overlap_start - program_offset);
  const size_t overlap_length = overlap_end - overlap_start;
  const uint32_t section_offset = overlap_start - section.offset;
  if (workflow->selection_kind == ERC7730_SELECTION_DISPLAY)
    return erc7730_program_display_feed(&workflow->selection.display,
                                        section_offset, overlap_data,
                                        overlap_length);
  if (workflow->selection_kind == ERC7730_SELECTION_STRING)
    return erc7730_program_string_feed(&workflow->selection.string,
                                       section_offset, overlap_data,
                                       overlap_length);
  if (workflow->selection_kind == ERC7730_SELECTION_FORMATTER)
    return erc7730_program_formatter_feed(&workflow->selection.formatter,
                                          section_offset, overlap_data,
                                          overlap_length);
  if (workflow->selection_kind == ERC7730_SELECTION_PATH)
    return erc7730_program_path_feed(&workflow->selection.path, section_offset,
                                     overlap_data, overlap_length);
  return false;
}

Erc7730CatalogResult erc7730_workflow_selection_feed(
    Erc7730Workflow* workflow, const EthereumClearSignDefinitionChunk* chunk,
    bool* complete) {
  if (complete) *complete = false;
  if (!workflow || !chunk || !complete ||
      workflow->phase != ERC7730_WORKFLOW_SELECT ||
      chunk->definition_id.size != 32 || chunk->data.size == 0 ||
      chunk->data.size > ERC7730_TRANSPORT_CHUNK_MAX) {
    fail(workflow);
    return ERC7730_CATALOG_BAD_SEQUENCE;
  }
  uint32_t next_offset = 0, program_offset = 0;
  const uint8_t* program_data = NULL;
  size_t program_data_len = 0;
  const Erc7730CatalogResult result = erc7730_catalog_preloaded_replay_feed(
      chunk->definition_id.bytes, chunk->offset, chunk->total_length,
      chunk->data.bytes, chunk->data.size, &next_offset, complete,
      &program_offset, &program_data, &program_data_len);
  (void)next_offset;
  if ((result != ERC7730_CATALOG_MORE && result != ERC7730_CATALOG_COMPLETE) ||
      !feed_selection_program(workflow, program_offset, program_data,
                              program_data_len)) {
    fail(workflow);
    return result == ERC7730_CATALOG_MORE || result == ERC7730_CATALOG_COMPLETE
               ? ERC7730_CATALOG_BAD_PROGRAM
               : result;
  }
  if (result == ERC7730_CATALOG_COMPLETE) {
    Erc7730CatalogIdentity replayed;
    bool selection_complete = false;
    switch (workflow->selection_kind) {
      case ERC7730_SELECTION_DISPLAY:
        selection_complete = workflow->selection.display.complete &&
                             !workflow->selection.display.failed;
        break;
      case ERC7730_SELECTION_STRING:
        selection_complete = workflow->selection.string.complete &&
                             !workflow->selection.string.failed;
        break;
      case ERC7730_SELECTION_FORMATTER:
        selection_complete = workflow->selection.formatter.complete &&
                             !workflow->selection.formatter.failed;
        break;
      case ERC7730_SELECTION_PATH:
        selection_complete = workflow->selection.path.complete &&
                             !workflow->selection.path.failed;
        break;
      default:
        break;
    }
    if (!*complete || !selection_complete ||
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

bool erc7730_workflow_selected_display(const Erc7730Workflow* workflow,
                                       Erc7730DisplayInstruction* instruction,
                                       uint16_t* instruction_count) {
  return workflow && workflow->phase != ERC7730_WORKFLOW_IDLE &&
         workflow->phase != ERC7730_WORKFLOW_FAILED &&
         workflow->selection_kind == ERC7730_SELECTION_DISPLAY &&
         erc7730_program_display_complete(&workflow->selection.display,
                                          instruction, instruction_count);
}

bool erc7730_workflow_selected_string(const Erc7730Workflow* workflow,
                                      const char** value, size_t* value_len) {
  return workflow && workflow->phase != ERC7730_WORKFLOW_IDLE &&
         workflow->phase != ERC7730_WORKFLOW_FAILED &&
         workflow->selection_kind == ERC7730_SELECTION_STRING &&
         erc7730_program_string_complete(&workflow->selection.string, value,
                                         value_len);
}

bool erc7730_workflow_selected_formatter(const Erc7730Workflow* workflow,
                                         Erc7730Formatter* formatter) {
  return workflow && workflow->phase != ERC7730_WORKFLOW_IDLE &&
         workflow->phase != ERC7730_WORKFLOW_FAILED &&
         workflow->selection_kind == ERC7730_SELECTION_FORMATTER &&
         erc7730_program_formatter_complete(&workflow->selection.formatter,
                                            formatter);
}

bool erc7730_workflow_selected_path(const Erc7730Workflow* workflow,
                                    Erc7730Path* path) {
  return workflow && workflow->phase != ERC7730_WORKFLOW_IDLE &&
         workflow->phase != ERC7730_WORKFLOW_FAILED &&
         workflow->selection_kind == ERC7730_SELECTION_PATH &&
         erc7730_program_path_complete(&workflow->selection.path, path);
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
  workflow->phase = ERC7730_WORKFLOW_CALLDATA;
  return true;
}

bool erc7730_workflow_restore_and_start_capture(Erc7730Workflow* workflow,
                                                EthereumSignTx* tx,
                                                const Erc7730Path* path) {
  if (!workflow || !tx || !path || path->source != 1 || path->step_count == 0 ||
      path->step_count >= ERC7730_ABI_MAX_DEPTH)
    return false;
  int32_t components[ERC7730_ABI_MAX_DEPTH];
  for (uint8_t i = 0; i < path->step_count; i++) {
    if (path->steps[i].opcode != 1) return false;
    components[i] = path->steps[i].first;
  }
  if (!erc7730_workflow_restore_and_start_calldata(workflow, tx)) {
    memzero(components, sizeof(components));
    return false;
  }
  const Erc7730AbiResult result = erc7730_abi_stream_capture_path(
      &workflow->calldata, components, path->step_count);
  memzero(components, sizeof(components));
  if (result != ERC7730_ABI_OK) {
    fail(workflow);
    return false;
  }
  return true;
}

bool erc7730_workflow_start_eip712_capture(Erc7730Workflow* workflow,
                                           const Erc7730Path* path) {
  if (!workflow || !path || !workflow->typed_data ||
      workflow->phase != ERC7730_WORKFLOW_READY || path->source != 1 ||
      path->step_count == 0 || path->step_count >= ERC7730_ABI_MAX_DEPTH)
    return false;
  Erc7730AbiProgram program;
  if (!erc7730_program_loader_complete(&workflow->loader, &program))
    return false;
  uint16_t node = program.root;
  memzero(&workflow->calldata, sizeof(workflow->calldata));
  for (uint8_t i = 0; i < path->step_count; i++) {
    if (path->steps[i].opcode != 1 || node >= program.node_count) return false;
    const Erc7730AbiNode* parent = &program.nodes[node];
    const int32_t requested = path->steps[i].first;
    if (parent->kind == ERC7730_ABI_TUPLE) {
      if (requested < 0 || (uint32_t)requested >= parent->child_count)
        return false;
      node = (uint16_t)(parent->first_child + (uint32_t)requested);
    } else if (parent->kind == ERC7730_ABI_ARRAY) {
      if (parent->child_count != 1 ||
          (parent->array_length != ERC7730_ABI_DYNAMIC_ARRAY &&
           ((requested >= 0 && (uint32_t)requested >= parent->array_length) ||
            (requested < 0 &&
             (uint32_t)(-(int64_t)requested) > parent->array_length))))
        return false;
      node = parent->first_child;
    } else {
      return false;
    }
    workflow->calldata.capture_path[i] = path->steps[i].first;
  }
  if (node >= program.node_count ||
      program.nodes[node].kind > ERC7730_ABI_STRING)
    return false;
  workflow->calldata.capture_path_count = path->step_count;
  workflow->calldata.capture.node = node;
  workflow->calldata.capture_enabled = true;
  workflow->phase = ERC7730_WORKFLOW_TYPED_DATA;
  return true;
}

static bool normalize_eip712_capture(const Erc7730AbiNode* node,
                                     const uint8_t* value, size_t value_len,
                                     Erc7730AbiCapture* capture) {
  if (!node || (!value && value_len != 0) || !capture) return false;
  capture->length = 32;
  if (node->kind == ERC7730_ABI_UINT || node->kind == ERC7730_ABI_INT) {
    const size_t width = node->size / 8u;
    if (width == 0 || width > 32 || value_len != width) return false;
    memset(capture->data,
           node->kind == ERC7730_ABI_INT && (value[0] & 0x80u) ? 0xff : 0,
           32 - width);
    memcpy(capture->data + 32 - width, value, width);
    return true;
  }
  if (node->kind == ERC7730_ABI_ADDRESS) {
    if (value_len != 20) return false;
    memzero(capture->data, 12);
    memcpy(capture->data + 12, value, 20);
    return true;
  }
  if (node->kind == ERC7730_ABI_BOOL) {
    if (value_len != 1 || value[0] > 1) return false;
    memzero(capture->data, 31);
    capture->data[31] = value[0];
    return true;
  }
  if (node->kind == ERC7730_ABI_FIXED_BYTES) {
    if (node->size == 0 || node->size > 32 || value_len != node->size)
      return false;
    memcpy(capture->data, value, value_len);
    memzero(capture->data + value_len, 32 - value_len);
    return true;
  }
  if (node->kind == ERC7730_ABI_BYTES || node->kind == ERC7730_ABI_STRING) {
    if (value_len > sizeof(capture->data)) return false;
    memcpy(capture->data, value, value_len);
    capture->length = value_len;
    return true;
  }
  return false;
}

bool erc7730_workflow_eip712_observe(Erc7730Workflow* workflow,
                                     const uint32_t* member_path,
                                     size_t member_path_count,
                                     const uint8_t* value, size_t value_len) {
  if (!workflow || !member_path || !value ||
      workflow->phase != ERC7730_WORKFLOW_TYPED_DATA ||
      !workflow->calldata.capture_enabled || member_path_count < 2 ||
      member_path[0] != 1)
    return false;
  /* Array lengths are streamed at the array's own path before its elements.
   * Resolve a signed negative component from that device-validated length,
   * then compare subsequent element paths using the resulting absolute index.
   */
  for (size_t i = 0; i < workflow->calldata.capture_path_count; i++) {
    const int32_t wanted = workflow->calldata.capture_path[i];
    if (wanted >= 0 || member_path_count != i + 1u) continue;
    bool prefix_matches = true;
    for (size_t j = 0; j < i; j++)
      prefix_matches &=
          member_path[j + 1u] == (uint32_t)workflow->calldata.capture_path[j];
    if (!prefix_matches) continue;
    if (value_len != 2) return false;
    const uint16_t length = (uint16_t)((value[0] << 8) | value[1]);
    const int64_t resolved = (int64_t)length + wanted;
    if (resolved < 0 || resolved >= length) return false;
    workflow->calldata.capture_path[i] = (int32_t)resolved;
    return true;
  }
  if (member_path_count != workflow->calldata.capture_path_count + 1u)
    return true;
  for (size_t i = 0; i < workflow->calldata.capture_path_count; i++)
    if (member_path[i + 1u] != (uint32_t)workflow->calldata.capture_path[i])
      return true;
  if (workflow->calldata.capture_found) return false;
  Erc7730AbiProgram program;
  if (!erc7730_program_loader_complete(&workflow->loader, &program) ||
      workflow->calldata.capture.node >= program.node_count ||
      !normalize_eip712_capture(&program.nodes[workflow->calldata.capture.node],
                                value, value_len, &workflow->calldata.capture))
    return false;
  workflow->calldata.capture_found = true;
  return true;
}

bool erc7730_workflow_eip712_finish(Erc7730Workflow* workflow) {
  if (!workflow || workflow->phase != ERC7730_WORKFLOW_TYPED_DATA ||
      !workflow->calldata.capture_enabled || !workflow->calldata.capture_found)
    return false;
  workflow->calldata.complete = true;
  workflow->phase = ERC7730_WORKFLOW_COMPLETE;
  return true;
}

bool erc7730_workflow_restore_complete(const Erc7730Workflow* workflow,
                                       EthereumSignTx* tx) {
  return workflow && tx && workflow->phase == ERC7730_WORKFLOW_COMPLETE &&
         erc7730_tx_continuation_restore(&workflow->continuation, tx);
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
                      workflow->phase == ERC7730_WORKFLOW_SELECT ||
                      workflow->phase == ERC7730_WORKFLOW_READY ||
                      workflow->phase == ERC7730_WORKFLOW_CALLDATA ||
                      workflow->phase == ERC7730_WORKFLOW_TYPED_DATA);
}

bool erc7730_workflow_complete(const Erc7730Workflow* workflow) {
  return workflow && workflow->phase == ERC7730_WORKFLOW_COMPLETE;
}

bool erc7730_workflow_calldata_waiting(const Erc7730Workflow* workflow,
                                       size_t* remaining) {
  if (!workflow || !remaining || workflow->phase != ERC7730_WORKFLOW_CALLDATA ||
      workflow->calldata.received > workflow->calldata.total_length)
    return false;
  *remaining = workflow->calldata.total_length - workflow->calldata.received;
  return *remaining != 0;
}

const Erc7730CatalogIdentity* erc7730_workflow_identity(
    const Erc7730Workflow* workflow) {
  if (!erc7730_workflow_active(workflow) &&
      !erc7730_workflow_complete(workflow))
    return NULL;
  return &workflow->identity;
}

bool erc7730_workflow_preserve_selected_string(Erc7730Workflow* workflow,
                                               bool intent) {
  const char* value = NULL;
  size_t length = 0;
  if (!erc7730_workflow_selected_string(workflow, &value, &length) ||
      length == 0 || length > ERC7730_PROGRAM_MAX_STRING_LENGTH)
    return false;
  char* destination = intent ? workflow->intent : workflow->label;
  memcpy(destination, value, length);
  destination[length] = '\0';
  return true;
}

bool erc7730_workflow_format_captured_raw(const Erc7730Workflow* workflow,
                                          char* output, size_t output_size) {
  Erc7730AbiProgram program;
  Erc7730AbiCapture capture;
  if (!workflow || !output || output_size == 0 ||
      workflow->phase != ERC7730_WORKFLOW_COMPLETE ||
      !erc7730_program_loader_complete(&workflow->loader, &program) ||
      !erc7730_abi_stream_captured(&workflow->calldata, &capture))
    return false;
  const bool result =
      erc7730_format_raw(&program, &capture, output, output_size);
  memzero(&capture, sizeof(capture));
  return result;
}

void erc7730_workflow_abort(Erc7730Workflow* workflow) {
  if (!workflow) return;
  if (workflow->phase != ERC7730_WORKFLOW_IDLE) erc7730_catalog_clear_preload();
  memzero(workflow, sizeof(*workflow));
}
