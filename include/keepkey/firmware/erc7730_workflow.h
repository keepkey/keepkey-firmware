#ifndef KEEPKEY_FIRMWARE_ERC7730_WORKFLOW_H
#define KEEPKEY_FIRMWARE_ERC7730_WORKFLOW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keepkey/firmware/erc7730_abi_stream.h"
#include "keepkey/firmware/erc7730_format.h"
#include "keepkey/firmware/erc7730_program.h"
#include "keepkey/firmware/erc7730_tx.h"

typedef enum {
  ERC7730_WORKFLOW_IDLE = 0,
  ERC7730_WORKFLOW_REPLAY,
  ERC7730_WORKFLOW_SELECT,
  ERC7730_WORKFLOW_READY,
  ERC7730_WORKFLOW_CALLDATA,
  ERC7730_WORKFLOW_TYPED_DATA,
  ERC7730_WORKFLOW_COMPLETE,
  ERC7730_WORKFLOW_FAILED,
} Erc7730WorkflowPhase;

typedef enum {
  ERC7730_SELECTION_NONE = 0,
  ERC7730_SELECTION_DISPLAY,
  ERC7730_SELECTION_STRING,
  ERC7730_SELECTION_FORMATTER,
  ERC7730_SELECTION_PATH,
  ERC7730_SELECTION_CONDITION,
  ERC7730_SELECTION_LITERAL,
} Erc7730SelectionKind;

typedef enum {
  ERC7730_DISPLAY_NONE = 0,
  ERC7730_DISPLAY_INTENT_STRING,
  ERC7730_DISPLAY_INSTRUCTION,
  ERC7730_DISPLAY_LABEL,
  ERC7730_DISPLAY_FORMATTER,
  ERC7730_DISPLAY_PATH,
  ERC7730_DISPLAY_CONDITION,
  ERC7730_DISPLAY_CONDITION_SET,
  ERC7730_DISPLAY_CONDITION_LITERAL,
  ERC7730_DISPLAY_FORMATTER_ARGUMENT,
} Erc7730DisplayStage;

/* The workflow owns every pointer-bearing interpreter object. No pointer into
 * a protobuf transport buffer survives a handler return. */
typedef struct {
  Erc7730CatalogIdentity identity;
  Erc7730TxContinuation continuation;
  Erc7730ProgramLoader loader;
  /* Signed-table selection precedes value streaming, so their bounded state
   * never coexists. This overlay leaves room for the largest literal/set
   * entry without increasing the workflow's fixed SRAM ceiling. */
  union {
    Erc7730AbiStream calldata;
    union {
      Erc7730ProgramDisplay display;
      Erc7730ProgramString string;
      Erc7730ProgramFormatter formatter;
      Erc7730ProgramPath path;
      Erc7730ProgramCondition condition;
      Erc7730ProgramLiteral literal;
    } selection;
  };
  char intent[ERC7730_PROGRAM_MAX_STRING_LENGTH + 1u];
  char label[ERC7730_PROGRAM_MAX_STRING_LENGTH + 1u];
  uint16_t display_index;
  uint16_t current_formatter;
  uint8_t phase;
  uint8_t selection_kind : 4;
  uint8_t display_stage : 4;
  uint8_t current_formatter_kind;
  uint8_t container_source;
  Erc7730Condition pending_condition;
  Erc7730AbiCapture condition_value;
  /* Format 1 admits at most 64 literals, so authenticated set references fit
   * in bytes and do not spend another 64 bytes of signing SRAM. */
  uint8_t condition_literals[64];
  union {
    uint16_t condition_literal_count;
    uint16_t formatter_auxiliary;
  };
  union {
    uint16_t condition_literal_position;
    uint16_t formatter_value_path;
  };
  bool typed_data;
  bool intent_confirmed;
  bool condition_capture;
  bool condition_matched;
} Erc7730Workflow;

/* One Ethereum workflow exists at a time. Keeping ownership here ensures FSM
 * definition replies and ethereum.c calldata chunks operate on the same state.
 */
Erc7730Workflow* erc7730_workflow_state(void);

bool erc7730_workflow_begin(Erc7730Workflow* workflow,
                            const Erc7730CatalogIdentity* identity,
                            const EthereumSignTx* tx);
bool erc7730_workflow_begin_eip712(Erc7730Workflow* workflow,
                                   const Erc7730CatalogIdentity* identity);
bool erc7730_workflow_waiting(const Erc7730Workflow* workflow,
                              uint8_t definition_id[32], uint32_t* offset,
                              uint32_t* total_length);
Erc7730CatalogResult erc7730_workflow_replay_feed(
    Erc7730Workflow* workflow, const EthereumClearSignDefinitionChunk* chunk,
    bool* complete);
bool erc7730_workflow_select_display(Erc7730Workflow* workflow,
                                     uint16_t instruction_index);
bool erc7730_workflow_select_string(Erc7730Workflow* workflow,
                                    uint16_t string_index);
bool erc7730_workflow_select_formatter(Erc7730Workflow* workflow,
                                       uint16_t formatter_index);
bool erc7730_workflow_select_path(Erc7730Workflow* workflow,
                                  uint16_t path_index);
bool erc7730_workflow_select_condition(Erc7730Workflow* workflow,
                                       uint16_t condition_index);
bool erc7730_workflow_select_literal(Erc7730Workflow* workflow,
                                     uint16_t literal_index);
Erc7730CatalogResult erc7730_workflow_selection_feed(
    Erc7730Workflow* workflow, const EthereumClearSignDefinitionChunk* chunk,
    bool* complete);
bool erc7730_workflow_selected_display(const Erc7730Workflow* workflow,
                                       Erc7730DisplayInstruction* instruction,
                                       uint16_t* instruction_count);
bool erc7730_workflow_selected_string(const Erc7730Workflow* workflow,
                                      const char** value, size_t* value_len);
bool erc7730_workflow_selected_formatter(const Erc7730Workflow* workflow,
                                         Erc7730Formatter* formatter);
bool erc7730_workflow_selected_path(const Erc7730Workflow* workflow,
                                    Erc7730Path* path);
bool erc7730_workflow_selected_condition(const Erc7730Workflow* workflow,
                                         Erc7730Condition* condition);
bool erc7730_workflow_selected_literal(const Erc7730Workflow* workflow,
                                       Erc7730Literal* literal);
bool erc7730_workflow_restore_and_start_calldata(Erc7730Workflow* workflow,
                                                 EthereumSignTx* tx);
bool erc7730_workflow_restore_and_start_capture(Erc7730Workflow* workflow,
                                                EthereumSignTx* tx,
                                                const Erc7730Path* path);
bool erc7730_workflow_capture_tx_container(Erc7730Workflow* workflow,
                                           const Erc7730Path* path,
                                           EthereumSignTx* tx,
                                           const uint8_t* sender_address);
bool erc7730_workflow_capture_eip712_container(Erc7730Workflow* workflow,
                                               const Erc7730Path* path,
                                               const uint8_t value[32]);
bool erc7730_workflow_begin_condition_capture(
    Erc7730Workflow* workflow, const Erc7730Condition* condition);
bool erc7730_workflow_condition_capture_pending(
    const Erc7730Workflow* workflow);
bool erc7730_workflow_resolve_captured_condition(Erc7730Workflow* workflow,
                                                 bool* visible);
bool erc7730_workflow_prepare_captured_membership(
    Erc7730Workflow* workflow, uint16_t* literal_set);
bool erc7730_workflow_load_membership_set(Erc7730Workflow* workflow,
                                          const Erc7730Literal* set,
                                          uint16_t* first_literal);
bool erc7730_workflow_finish_empty_membership(Erc7730Workflow* workflow,
                                              bool* visible);
bool erc7730_workflow_observe_membership_literal(
    Erc7730Workflow* workflow, const Erc7730Literal* literal, bool* complete,
    bool* visible, uint16_t* next_literal);
bool erc7730_workflow_start_eip712_capture(Erc7730Workflow* workflow,
                                           const Erc7730Path* path);
bool erc7730_workflow_eip712_observe(Erc7730Workflow* workflow,
                                     const uint32_t* member_path,
                                     size_t member_path_count,
                                     const uint8_t* value, size_t value_len);
bool erc7730_workflow_eip712_finish(Erc7730Workflow* workflow);
bool erc7730_workflow_restore_complete(const Erc7730Workflow* workflow,
                                       EthereumSignTx* tx);
Erc7730AbiResult erc7730_workflow_calldata_feed(Erc7730Workflow* workflow,
                                                const uint8_t* data,
                                                size_t data_len);
Erc7730AbiResult erc7730_workflow_calldata_finish(Erc7730Workflow* workflow);
bool erc7730_workflow_active(const Erc7730Workflow* workflow);
bool erc7730_workflow_complete(const Erc7730Workflow* workflow);
bool erc7730_workflow_calldata_waiting(const Erc7730Workflow* workflow,
                                       size_t* remaining);
const Erc7730CatalogIdentity* erc7730_workflow_identity(
    const Erc7730Workflow* workflow);
bool erc7730_workflow_preserve_selected_string(Erc7730Workflow* workflow,
                                               bool intent);
bool erc7730_workflow_format_captured_raw(const Erc7730Workflow* workflow,
                                          char* output, size_t output_size);
bool erc7730_workflow_advance_display(Erc7730Workflow* workflow);
bool erc7730_workflow_skip_display(Erc7730Workflow* workflow);
void erc7730_workflow_abort(Erc7730Workflow* workflow);

#endif
