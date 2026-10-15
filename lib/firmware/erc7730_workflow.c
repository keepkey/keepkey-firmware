#include "keepkey/firmware/erc7730_workflow.h"

#include <string.h>

#include "keepkey/firmware/eip712_stream.h"
#include "keepkey/firmware/erc7730_capabilities.h"
#include "trezor/crypto/memzero.h"

static Erc7730Workflow active_workflow;

Erc7730Workflow* erc7730_workflow_state(void) { return &active_workflow; }

static void fail(Erc7730Workflow* workflow) {
  if (!workflow) return;
  erc7730_catalog_clear_preload();
  erc7730_tx_continuation_clear(&workflow->continuation);
  erc7730_program_loader_clear(&workflow->loader);
  erc7730_abi_stream_clear(&workflow->calldata);
  memzero(&workflow->identity, sizeof(workflow->identity));
  memzero(&workflow->calldata_hash, sizeof(workflow->calldata_hash));
  memzero(workflow->reviewed_digest, sizeof(workflow->reviewed_digest));
  workflow->reviewed_digest_set = false;
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
  /* A replay loads a whole program: clear any pending selection. */
  workflow->selection_kind = ERC7730_SELECTION_NONE;
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
  if (!begin_replay(workflow, identity)) return false;
  /* The definition applies only at a signed deployment on the typed data's
   * own chain; the loader refuses the replay unless one lists it. */
  Eip712DomainFacts facts;
  const bool bound =
      eip712_stream_domain_facts(&facts) && facts.has_chain_id &&
      facts.has_verifying_contract && facts.chain_id == identity->chain_id &&
      erc7730_program_loader_require_deployment(
          &workflow->loader, facts.chain_id, facts.verifying_contract);
  memzero(&facts, sizeof(facts));
  if (!bound) {
    fail(workflow);
    return false;
  }
  return true;
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

/* Clears the selection and returns the length of program section `type`. */
static bool selection_section(Erc7730Workflow* workflow, uint8_t type,
                              uint32_t* length) {
  Erc7730ProgramSection section;
  if (!workflow || workflow->phase != ERC7730_WORKFLOW_READY ||
      !erc7730_program_index_section(&workflow->loader.index, type, &section))
    return false;
  memzero(&workflow->selection, sizeof(workflow->selection));
  *length = section.length;
  return true;
}

bool erc7730_workflow_select_display(Erc7730Workflow* workflow,
                                     uint16_t instruction_index) {
  uint32_t length;
  if (!selection_section(workflow, 7, &length)) return false;
  erc7730_program_display_begin(&workflow->selection.display, length,
                                instruction_index);
  return !workflow->selection.display.failed &&
         begin_selection_replay(workflow, ERC7730_SELECTION_DISPLAY);
}

bool erc7730_workflow_select_string(Erc7730Workflow* workflow,
                                    uint16_t string_index) {
  uint32_t length;
  if (!selection_section(workflow, 1, &length)) return false;
  erc7730_program_string_begin(&workflow->selection.string, length,
                               string_index);
  return !workflow->selection.string.failed &&
         begin_selection_replay(workflow, ERC7730_SELECTION_STRING);
}

bool erc7730_workflow_select_formatter(Erc7730Workflow* workflow,
                                       uint16_t formatter_index) {
  uint32_t length;
  if (!selection_section(workflow, 6, &length)) return false;
  erc7730_program_formatter_begin(&workflow->selection.formatter, length,
                                  formatter_index);
  return !workflow->selection.formatter.failed &&
         begin_selection_replay(workflow, ERC7730_SELECTION_FORMATTER);
}

bool erc7730_workflow_select_path(Erc7730Workflow* workflow,
                                  uint16_t path_index) {
  uint32_t length;
  if (!selection_section(workflow, 3, &length)) return false;
  erc7730_program_path_begin(&workflow->selection.path, length, path_index);
  return !workflow->selection.path.failed &&
         begin_selection_replay(workflow, ERC7730_SELECTION_PATH);
}

bool erc7730_workflow_select_literal(Erc7730Workflow* workflow,
                                     uint16_t literal_index) {
  uint32_t length;
  if (!selection_section(workflow, 4, &length)) return false;
  erc7730_program_literal_begin(&workflow->selection.literal, length,
                                literal_index);
  return !workflow->selection.literal.failed &&
         begin_selection_replay(workflow, ERC7730_SELECTION_LITERAL);
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
    case ERC7730_SELECTION_LITERAL:
      section_type = 4;
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
  if (workflow->selection_kind == ERC7730_SELECTION_LITERAL)
    return erc7730_program_literal_feed(&workflow->selection.literal,
                                        section_offset, overlap_data,
                                        overlap_length);
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
      case ERC7730_SELECTION_LITERAL:
        selection_complete = workflow->selection.literal.complete &&
                             !workflow->selection.literal.failed;
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

static bool selected(const Erc7730Workflow* workflow, uint8_t kind) {
  return workflow && workflow->phase != ERC7730_WORKFLOW_IDLE &&
         workflow->phase != ERC7730_WORKFLOW_FAILED &&
         workflow->selection_kind == kind;
}

bool erc7730_workflow_selected_display(const Erc7730Workflow* workflow,
                                       Erc7730DisplayInstruction* instruction,
                                       uint16_t* instruction_count) {
  return selected(workflow, ERC7730_SELECTION_DISPLAY) &&
         erc7730_program_display_complete(&workflow->selection.display,
                                          instruction, instruction_count);
}

bool erc7730_workflow_selected_string(const Erc7730Workflow* workflow,
                                      const char** value, size_t* value_len) {
  return selected(workflow, ERC7730_SELECTION_STRING) &&
         erc7730_program_string_complete(&workflow->selection.string, value,
                                         value_len);
}

bool erc7730_workflow_selected_formatter(const Erc7730Workflow* workflow,
                                         Erc7730Formatter* formatter) {
  return selected(workflow, ERC7730_SELECTION_FORMATTER) &&
         erc7730_program_formatter_complete(&workflow->selection.formatter,
                                            formatter);
}

bool erc7730_workflow_selected_path(const Erc7730Workflow* workflow,
                                    Erc7730Path* path) {
  return selected(workflow, ERC7730_SELECTION_PATH) &&
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
  /* At depth 1 the stream decodes only the inner call's arguments, located
   * inside the outer arguments that are replayed and hashed in full. */
  const uint32_t outer = tx->data_length >= 4 ? tx->data_length - 4u : 0;
  const bool inner = workflow->depth == 1;
  if (tx->data_length < 4 ||
      (inner && (workflow->inner_length < 4 || workflow->inner_offset > outer ||
                 workflow->inner_length > outer - workflow->inner_offset)) ||
      !erc7730_program_loader_complete(&workflow->loader, &program) ||
      erc7730_abi_stream_begin(&workflow->calldata, &program,
                               inner ? workflow->inner_length - 4u : outer) !=
          ERC7730_ABI_OK) {
    fail(workflow);
    return false;
  }
  workflow->outer_total = outer;
  workflow->outer_received = 0;
  workflow->phase = ERC7730_WORKFLOW_CALLDATA;
  sha256_Init(&workflow->calldata_hash);
  sha256_Update(&workflow->calldata_hash, tx->data_initial_chunk.bytes,
                tx->data_initial_chunk.size);
  return true;
}

bool erc7730_workflow_restore_and_start_capture(Erc7730Workflow* workflow,
                                                EthereumSignTx* tx,
                                                const Erc7730Path* path) {
  if (!workflow || !tx || !path || path->source != 1 || !erc7730_cap_path(path))
    return false;
  int32_t components[ERC7730_ABI_MAX_DEPTH];
  for (uint8_t i = 0; i < path->step_count; i++) {
    if (path->steps[i].opcode == 2 && workflow->iterating) {
      /* "every element": the iteration's current element */
      components[i] = workflow->iteration_index;
    } else if (path->steps[i].opcode == 1) {
      components[i] = path->steps[i].first;
    } else {
      return false;
    }
  }
  if (!erc7730_workflow_restore_and_start_calldata(workflow, tx)) {
    memzero(components, sizeof(components));
    return false;
  }
  const Erc7730AbiResult result = erc7730_abi_stream_capture_path(
      &workflow->calldata, components, path->step_count);
  /* Embedded calldata is located, not captured: it may be any length. */
  workflow->calldata.capture_locate =
      workflow->field.kind == 13 && workflow->field.pending_role == 1;
  memzero(components, sizeof(components));
  if (result != ERC7730_ABI_OK) {
    fail(workflow);
    return false;
  }
  return true;
}

bool erc7730_workflow_restore_and_start_length(Erc7730Workflow* workflow,
                                               EthereumSignTx* tx,
                                               const Erc7730Path* path) {
  if (!workflow || !tx || !path || workflow->iterating || path->source != 1 ||
      path->step_count < 2 || !erc7730_cap_path(path) ||
      path->steps[path->step_count - 1u].opcode != 2)
    return false;
  Erc7730Path array = *path;
  array.step_count--;
  for (uint8_t i = 0; i < array.step_count; i++)
    if (array.steps[i].opcode != 1) return false;
  return erc7730_workflow_restore_and_start_capture(workflow, tx, &array);
}

bool erc7730_workflow_start_eip712_capture(Erc7730Workflow* workflow,
                                           const Erc7730Path* path) {
  if (!workflow || !path || !workflow->typed_data ||
      workflow->phase != ERC7730_WORKFLOW_READY || path->source != 1 ||
      !erc7730_cap_path(path))
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
                                     const uint8_t* value, size_t value_len,
                                     size_t whole_len, bool continuation) {
  if (!workflow || !member_path || !value || whole_len < value_len ||
      workflow->phase != ERC7730_WORKFLOW_TYPED_DATA ||
      !workflow->calldata.capture_enabled || member_path_count < 2 ||
      member_path[0] != 1)
    return false;
  /* Resolve a negative index from the device-validated array length, which
   * is streamed before the elements. */
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
  /* A long value is observed once, at its first chunk. The later chunks only
   * have to continue a value that was too long to capture. */
  if (continuation)
    return workflow->calldata.capture_found &&
           workflow->calldata.capture_overflow;
  if (workflow->calldata.capture_found) return false;
  Erc7730AbiProgram program;
  if (!erc7730_program_loader_complete(&workflow->loader, &program) ||
      workflow->calldata.capture.node >= program.node_count)
    return false;
  const Erc7730AbiNode* leaf = &program.nodes[workflow->calldata.capture.node];
  if ((leaf->kind == ERC7730_ABI_BYTES || leaf->kind == ERC7730_ABI_STRING) &&
      whole_len > sizeof(workflow->calldata.capture.data)) {
    /* Too long to capture: keep only its length, as a calldata pass does. */
    workflow->calldata.capture_overflow = true;
    workflow->calldata.located_length = whole_len;
    workflow->calldata.capture.length = 0;
  } else if (whole_len != value_len ||
             !normalize_eip712_capture(leaf, value, value_len,
                                       &workflow->calldata.capture)) {
    return false;
  }
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

bool erc7730_workflow_eip712_commit(Erc7730Workflow* workflow,
                                    const uint8_t domain[32],
                                    const uint8_t message[32]) {
  if (!workflow || !domain || !message || !workflow->typed_data ||
      workflow->phase != ERC7730_WORKFLOW_COMPLETE)
    return false;
  uint8_t digest[32];
  sha256_Init(&workflow->calldata_hash);
  sha256_Update(&workflow->calldata_hash, domain, 32);
  sha256_Update(&workflow->calldata_hash, message, 32);
  sha256_Final(&workflow->calldata_hash, digest);
  const bool matches = !workflow->reviewed_digest_set ||
                       memcmp(workflow->reviewed_digest, digest, 32) == 0;
  if (matches) {
    memcpy(workflow->reviewed_digest, digest, 32);
    workflow->reviewed_digest_set = true;
  } else {
    fail(workflow);
  }
  memzero(digest, sizeof(digest));
  return matches;
}

bool erc7730_workflow_restore_complete(const Erc7730Workflow* workflow,
                                       EthereumSignTx* tx) {
  return workflow && tx && workflow->phase == ERC7730_WORKFLOW_COMPLETE &&
         erc7730_tx_continuation_restore(&workflow->continuation, tx);
}

bool erc7730_workflow_start_signing(Erc7730Workflow* workflow,
                                    EthereumSignTx* tx) {
  /* READY: the display program ended after a field that captured nothing. */
  if (!workflow || workflow->typed_data ||
      (workflow->phase != ERC7730_WORKFLOW_COMPLETE &&
       workflow->phase != ERC7730_WORKFLOW_READY) ||
      !workflow->reviewed_digest_set) {
    fail(workflow);
    return false;
  }
  workflow->phase = ERC7730_WORKFLOW_READY;
  if (!erc7730_workflow_restore_and_start_calldata(workflow, tx)) return false;
  workflow->signing_pass = true;
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
  if (data_len > workflow->outer_total - workflow->outer_received) {
    fail(workflow);
    return ERC7730_ABI_BOUNDS;
  }
  Erc7730AbiResult result = ERC7730_ABI_OK;
  if (workflow->depth == 0) {
    result = erc7730_abi_stream_feed(
        &workflow->calldata, workflow->calldata.received, data, data_len);
  } else {
    /* Feed only the inner call's arguments (after its selector). */
    const uint32_t start = workflow->inner_offset + 4u;
    const uint32_t end = workflow->inner_offset + workflow->inner_length;
    const uint32_t from = workflow->outer_received;
    const uint32_t to = from + (uint32_t)data_len;
    const uint32_t lo = from > start ? from : start;
    const uint32_t hi = to < end ? to : end;
    if (lo < hi)
      result = erc7730_abi_stream_feed(&workflow->calldata, lo - start,
                                       data + (lo - from), hi - lo);
  }
  if (result != ERC7730_ABI_OK) {
    fail(workflow);
  } else {
    sha256_Update(&workflow->calldata_hash, data, data_len);
    workflow->outer_received += (uint32_t)data_len;
  }
  return result;
}

Erc7730AbiResult erc7730_workflow_calldata_finish(Erc7730Workflow* workflow) {
  if (!workflow || workflow->phase != ERC7730_WORKFLOW_CALLDATA) {
    fail(workflow);
    return ERC7730_ABI_BOUNDS;
  }
  const Erc7730AbiResult result =
      workflow->outer_received != workflow->outer_total
          ? ERC7730_ABI_BOUNDS
          : erc7730_abi_stream_finish(&workflow->calldata);
  if (result != ERC7730_ABI_OK) {
    fail(workflow);
    return result;
  }
  uint8_t digest[32];
  sha256_Final(&workflow->calldata_hash, digest);
  const bool matches = !workflow->reviewed_digest_set ||
                       memcmp(workflow->reviewed_digest, digest, 32) == 0;
  if (matches && !workflow->reviewed_digest_set) {
    memcpy(workflow->reviewed_digest, digest, 32);
    workflow->reviewed_digest_set = true;
  }
  memzero(digest, sizeof(digest));
  if (!matches) {
    fail(workflow);
    return ERC7730_ABI_NON_CANONICAL;
  }
  workflow->phase = ERC7730_WORKFLOW_COMPLETE;
  return ERC7730_ABI_OK;
}

bool erc7730_workflow_active(const Erc7730Workflow* workflow) {
  return workflow && (workflow->phase == ERC7730_WORKFLOW_REPLAY ||
                      workflow->phase == ERC7730_WORKFLOW_SELECT ||
                      workflow->phase == ERC7730_WORKFLOW_READY ||
                      workflow->phase == ERC7730_WORKFLOW_CALLDATA ||
                      workflow->phase == ERC7730_WORKFLOW_TYPED_DATA ||
                      workflow->phase == ERC7730_WORKFLOW_FETCH);
}

bool erc7730_workflow_complete(const Erc7730Workflow* workflow) {
  return workflow && workflow->phase == ERC7730_WORKFLOW_COMPLETE;
}

bool erc7730_workflow_calldata_waiting(const Erc7730Workflow* workflow,
                                       size_t* remaining) {
  if (!workflow || !remaining || workflow->phase != ERC7730_WORKFLOW_CALLDATA ||
      workflow->outer_received > workflow->outer_total)
    return false;
  *remaining = workflow->outer_total - workflow->outer_received;
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

bool erc7730_workflow_advance_display(Erc7730Workflow* workflow) {
  /* READY: the field showed a literal or container and captured nothing. */
  if (!workflow ||
      (workflow->phase != ERC7730_WORKFLOW_COMPLETE &&
       workflow->phase != ERC7730_WORKFLOW_READY) ||
      workflow->display_index == UINT16_MAX)
    return false;
  memzero(workflow->label, sizeof(workflow->label));
  memzero(&workflow->field, sizeof(workflow->field));
  workflow->intent_part = 0;
  workflow->intent_parts = 0;
  workflow->intent_value = false;
  erc7730_abi_stream_clear(&workflow->calldata);
  workflow->phase = ERC7730_WORKFLOW_READY;
  workflow->display_stage = ERC7730_DISPLAY_INSTRUCTION;
  workflow->display_index++;
  return erc7730_workflow_select_display(workflow, workflow->display_index);
}

bool erc7730_workflow_field_begin(Erc7730Workflow* workflow,
                                  const Erc7730Formatter* formatter) {
  if (!workflow || !formatter || !erc7730_cap_formatter(formatter) ||
      formatter->argument_count > ERC7730_FIELD_MAX_ARGUMENTS)
    return false;
  memzero(&workflow->field, sizeof(workflow->field));
  workflow->field.kind = formatter->kind;
  workflow->field.argument_count = formatter->argument_count;
  memcpy(workflow->field.arguments, formatter->arguments,
         formatter->argument_count * sizeof(formatter->arguments[0]));
  return true;
}

bool erc7730_workflow_captured(const Erc7730Workflow* workflow,
                               Erc7730AbiCapture* capture, uint8_t* cls) {
  Erc7730AbiProgram program;
  if (!workflow || !capture || !cls ||
      workflow->phase != ERC7730_WORKFLOW_COMPLETE ||
      !erc7730_program_loader_complete(&workflow->loader, &program) ||
      !erc7730_abi_stream_captured(&workflow->calldata, capture) ||
      capture->node >= program.node_count)
    return false;
  *cls = program.nodes[capture->node].kind;
  return true;
}

bool erc7730_workflow_begin_fetch(Erc7730Workflow* workflow, uint8_t depth) {
  if (!workflow || workflow->typed_data || depth > 1 ||
      workflow->phase != ERC7730_WORKFLOW_READY ||
      (depth == 1 && (workflow->depth != 0 || !workflow->field.has_inner ||
                      !workflow->field.has_address ||
                      workflow->field.inner_selector_length != 4)) ||
      (depth == 0 && workflow->depth != 1))
    return false;
  if (depth == 1) {
    /* What restores the outer program, whichever way the inner call ends. */
    memcpy(workflow->outer_definition_id, workflow->identity.definition_id, 32);
    workflow->outer_resume = workflow->display_index;
    workflow->outer_identity_confirmed = workflow->identity_confirmed;
    workflow->outer_intent_confirmed = workflow->intent_confirmed;
  }
  workflow->fetch_depth = depth;
  workflow->fetch_offset = 0;
  workflow->fetch_total = 0;
  workflow->phase = ERC7730_WORKFLOW_FETCH;
  return true;
}

Erc7730CatalogResult erc7730_workflow_fetch_feed(
    Erc7730Workflow* workflow, const EthereumClearSignDefinitionChunk* chunk,
    bool* complete, bool* none) {
  if (complete) *complete = false;
  if (none) *none = false;
  if (!workflow || !chunk || !complete || !none ||
      workflow->phase != ERC7730_WORKFLOW_FETCH ||
      chunk->definition_id.size != 32 ||
      chunk->offset != workflow->fetch_offset ||
      chunk->data.size > ERC7730_TRANSPORT_CHUNK_MAX) {
    fail(workflow);
    return ERC7730_CATALOG_BAD_SEQUENCE;
  }
  if (chunk->offset == 0 && chunk->total_length == 0 && chunk->data.size == 0 &&
      workflow->fetch_depth == 1) {
    /* Nothing streamed: the outer definition is still loaded. */
    *none = true;
    workflow->phase = ERC7730_WORKFLOW_READY;
    return ERC7730_CATALOG_COMPLETE;
  }
  /* The outer definition must come back byte for byte: same id. */
  if (chunk->data.size == 0 ||
      (workflow->fetch_depth == 0 &&
       memcmp(chunk->definition_id.bytes, workflow->outer_definition_id, 32) !=
           0) ||
      (workflow->fetch_total != 0 &&
       chunk->total_length != workflow->fetch_total)) {
    fail(workflow);
    return ERC7730_CATALOG_BAD_SEQUENCE;
  }
  uint32_t next_offset = 0;
  const Erc7730CatalogResult result = erc7730_catalog_preload_chunk(
      chunk->definition_id.bytes, chunk->offset, chunk->total_length,
      chunk->data.bytes, chunk->data.size, &next_offset, complete);
  /* An inner definition that shows @.value needs the value from the signed
   * calldata; with no amountPath there is none to show, only a default. */
  const bool unsourced_value = result == ERC7730_CATALOG_COMPLETE &&
                               !workflow->field.has_value &&
                               erc7730_catalog_preloaded_reads_value();
  if (workflow->fetch_depth == 1 &&
      (result == ERC7730_CATALOG_BAD_PROGRAM ||
       result == ERC7730_CATALOG_UNTRUSTED || unsourced_value)) {
    /* The device cannot clear-sign this inner call: restore the outer
     * definition (the slot now holds nothing) and show the call blind. */
    erc7730_catalog_clear_preload();
    if (complete) *complete = false;
    workflow->inner_refused = true;
    workflow->fetch_depth = 0;
    workflow->fetch_offset = 0;
    workflow->fetch_total = 0;
    return ERC7730_CATALOG_MORE;
  }
  if (result != ERC7730_CATALOG_MORE && result != ERC7730_CATALOG_COMPLETE) {
    fail(workflow);
    return result;
  }
  workflow->fetch_total = chunk->total_length;
  workflow->fetch_offset = next_offset;
  return result;
}

bool erc7730_workflow_fetch_complete(Erc7730Workflow* workflow) {
  Erc7730CatalogIdentity identity;
  if (!workflow || workflow->phase != ERC7730_WORKFLOW_FETCH ||
      !erc7730_catalog_preloaded(&identity)) {
    memzero(&identity, sizeof(identity));
    fail(workflow);
    return false;
  }
  bool bound;
  if (workflow->fetch_depth == 1) {
    /* H8: the inner definition is for this chain, this callee and this
     * selector, all read from the signed calldata. */
    bound = erc7730_catalog_matches_calldata(
        &identity, workflow->identity.chain_id, workflow->field.address,
        workflow->field.inner_selector);
    if (bound) {
      workflow->inner_offset = workflow->field.inner_offset;
      workflow->inner_length = workflow->field.inner_length;
      memcpy(workflow->inner_to, workflow->field.address, 20);
      memzero(workflow->inner_value, sizeof(workflow->inner_value));
      if (workflow->field.has_value)
        memcpy(workflow->inner_value, workflow->field.value, 32);
      memcpy(workflow->inner_from,
             workflow->field.has_spender ? workflow->field.spender
                                         : workflow->identity.contract_address,
             20);
      workflow->depth = 1;
      workflow->identity_confirmed = false;
      workflow->intent_confirmed = false;
      workflow->calldata_validated = false;
      workflow->resuming = false;
    }
  } else {
    bound =
        memcmp(identity.definition_id, workflow->outer_definition_id, 32) == 0;
    if (bound) {
      /* Resume after the embedded field, or re-run it blind when its inner
       * definition was refused (outer_resume >= 1: never the intent). */
      workflow->display_index = workflow->inner_refused
                                    ? (uint16_t)(workflow->outer_resume - 1u)
                                    : workflow->outer_resume;
      workflow->depth = 0;
      workflow->identity_confirmed = workflow->outer_identity_confirmed;
      workflow->intent_confirmed = workflow->outer_intent_confirmed;
      workflow->calldata_validated = true;
      workflow->resuming = true;
      workflow->inner_offset = 0;
      workflow->inner_length = 0;
      memzero(workflow->inner_to, sizeof(workflow->inner_to));
      memzero(workflow->inner_value, sizeof(workflow->inner_value));
      memzero(workflow->inner_from, sizeof(workflow->inner_from));
    }
  }
  if (!bound) {
    memzero(&identity, sizeof(identity));
    fail(workflow);
    return false;
  }
  memzero(&workflow->field, sizeof(workflow->field));
  memzero(workflow->label, sizeof(workflow->label));
  memzero(workflow->intent, sizeof(workflow->intent));
  workflow->display_stage = ERC7730_DISPLAY_NONE;
  const bool started = begin_replay(workflow, &identity);
  memzero(&identity, sizeof(identity));
  return started;
}

bool erc7730_workflow_field_embedded(Erc7730Workflow* workflow) {
  Erc7730AbiCapture capture;
  uint8_t cls = 0;
  if (!workflow || workflow->field.kind != 13 ||
      workflow->field.pending_role != 1 || workflow->field.has_inner ||
      !workflow->calldata.capture_locate ||
      !erc7730_workflow_captured(workflow, &capture, &cls) ||
      cls != ERC7730_CLASS_BYTES ||
      capture.length > ERC7730_ABI_LOCATE_PREFIX ||
      workflow->calldata.located_length > UINT32_MAX ||
      workflow->calldata.located_offset > UINT32_MAX) {
    memzero(&capture, sizeof(capture));
    return false;
  }
  Erc7730Field* field = &workflow->field;
  /* An inner approve() or increaseAllowance() gets the top-level policy
   * (ethereum.c): a dirty spender word is refused, and 2^256-1 signs only
   * after the UNLIMITED warning. */
  if (capture.length == ERC7730_ABI_LOCATE_PREFIX &&
      (memcmp(capture.data, "\x09\x5e\xa7\xb3", 4) == 0 ||
       memcmp(capture.data, "\x39\x50\x93\x51", 4) == 0)) {
    bool unlimited = true;
    for (size_t i = 4; i < 68; i++) {
      if (i < 16 && capture.data[i] != 0) {
        memzero(&capture, sizeof(capture));
        return false;
      }
      if (i >= 36) unlimited &= capture.data[i] == 0xff;
    }
    field->unlimited_approve = unlimited;
    if (unlimited) memcpy(field->approve_spender, capture.data + 16, 20);
  }
  const size_t selector_length = capture.length < 4 ? capture.length : 4;
  memcpy(field->inner_selector, capture.data, selector_length);
  field->inner_selector_length = (uint8_t)selector_length;
  field->inner_length = (uint32_t)workflow->calldata.located_length;
  field->inner_offset = (uint32_t)workflow->calldata.located_offset;
  field->has_inner = true;
  memzero(&capture, sizeof(capture));
  return true;
}

bool erc7730_workflow_field_value(Erc7730Workflow* workflow, uint8_t cls,
                                  const uint8_t* value, size_t value_len) {
  if (!workflow || !value) return false;
  Erc7730Field* field = &workflow->field;
  const uint8_t role = field->pending_role;
  if (field->kind == 1 || field->kind == 10 ||
      !erc7730_cap_value(field->kind, role, cls))
    return false;
  if (field->kind == 13) {
    /* callee, value and authority of an embedded call */
    if (role == 17) {
      if (value_len != 32 || field->has_value) return false;
      memcpy(field->value, value, 32);
      field->has_value = true;
      return true;
    }
    uint8_t* out = role == 15 ? field->address : field->spender;
    bool* has = role == 15 ? &field->has_address : &field->has_spender;
    if (*has || (value_len != 20 && value_len != 32)) return false;
    if (value_len == 32) {
      for (size_t i = 0; i < 12; i++)
        if (value[i] != 0) return false;
      value += 12;
    }
    memcpy(out, value, 20);
    *has = true;
    return true;
  }
  switch (role) {
    case 1: /* the value: a 32-byte word */
      if (value_len != 32 || field->has_value) return false;
      memcpy(field->value, value, 32);
      field->value_class = cls;
      field->has_value = true;
      return true;
    case 2: /* tokenAmount token */
    case 3: /* nftName collection: a word from calldata, or 20 bytes */
      if (field->has_address || (value_len != 20 && value_len != 32))
        return false;
      if (value_len == 32) {
        for (size_t i = 0; i < 12; i++)
          if (value[i] != 0) return false;
        value += 12;
      }
      memcpy(field->address, value, 20);
      field->has_address = true;
      return true;
    case 4: /* unit decimals: one byte */
      if (value_len != 1) return false;
      field->decimals = value[0];
      return true;
    case 6: /* unit prefix: shown exactly either way */
      return value_len == 1;
    case 7: { /* the threshold: a minimal big-endian literal */
      if (!field->has_value || value_len == 0 || value_len > 32) return false;
      uint8_t threshold[32] = {0};
      memcpy(threshold + 32 - value_len, value, value_len);
      field->threshold_reached = memcmp(field->value, threshold, 32) >= 0;
      memzero(threshold, sizeof(threshold));
      return true;
    }
    default:
      return false;
  }
}

uint16_t erc7730_workflow_intent_parts(const Erc7730Workflow* workflow) {
  return workflow && workflow->selection_kind == ERC7730_SELECTION_DISPLAY &&
                 workflow->selection.display.complete
             ? workflow->selection.display.intent_parts
             : 0;
}

bool erc7730_workflow_resume_field(Erc7730Workflow* workflow) {
  if (!workflow || workflow->phase != ERC7730_WORKFLOW_COMPLETE) return false;
  erc7730_abi_stream_clear(&workflow->calldata);
  workflow->phase = ERC7730_WORKFLOW_READY;
  return true;
}

void erc7730_workflow_abort(Erc7730Workflow* workflow) {
  if (!workflow) return;
  if (workflow->phase != ERC7730_WORKFLOW_IDLE) erc7730_catalog_clear_preload();
  memzero(workflow, sizeof(*workflow));
}
