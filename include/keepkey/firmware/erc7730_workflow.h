#ifndef KEEPKEY_FIRMWARE_ERC7730_WORKFLOW_H
#define KEEPKEY_FIRMWARE_ERC7730_WORKFLOW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keepkey/firmware/erc7730_abi_stream.h"
#include "keepkey/firmware/erc7730_program.h"
#include "keepkey/firmware/erc7730_tx.h"

typedef enum {
  ERC7730_WORKFLOW_IDLE = 0,
  ERC7730_WORKFLOW_REPLAY,
  ERC7730_WORKFLOW_SELECT,
  ERC7730_WORKFLOW_READY,
  ERC7730_WORKFLOW_CALLDATA,
  ERC7730_WORKFLOW_COMPLETE,
  ERC7730_WORKFLOW_FAILED,
} Erc7730WorkflowPhase;

typedef enum {
  ERC7730_SELECTION_NONE = 0,
  ERC7730_SELECTION_DISPLAY,
  ERC7730_SELECTION_STRING,
} Erc7730SelectionKind;

/* The workflow owns every pointer-bearing interpreter object. No pointer into
 * a protobuf transport buffer survives a handler return. */
typedef struct {
  Erc7730CatalogIdentity identity;
  Erc7730TxContinuation continuation;
  Erc7730ProgramLoader loader;
  union {
    Erc7730ProgramDisplay display;
    Erc7730ProgramString string;
  } selection;
  Erc7730AbiStream calldata;
  uint32_t envelope_length;
  uint8_t phase;
  uint8_t selection_kind;
} Erc7730Workflow;

/* One Ethereum workflow exists at a time. Keeping ownership here ensures FSM
 * definition replies and ethereum.c calldata chunks operate on the same state.
 */
Erc7730Workflow* erc7730_workflow_state(void);

bool erc7730_workflow_begin(Erc7730Workflow* workflow,
                            const Erc7730CatalogIdentity* identity,
                            const EthereumSignTx* tx);
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
Erc7730CatalogResult erc7730_workflow_selection_feed(
    Erc7730Workflow* workflow, const EthereumClearSignDefinitionChunk* chunk,
    bool* complete);
bool erc7730_workflow_selected_display(const Erc7730Workflow* workflow,
                                       Erc7730DisplayInstruction* instruction,
                                       uint16_t* instruction_count);
bool erc7730_workflow_selected_string(const Erc7730Workflow* workflow,
                                      const char** value, size_t* value_len);
bool erc7730_workflow_restore_and_start_calldata(Erc7730Workflow* workflow,
                                                 EthereumSignTx* tx);
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
void erc7730_workflow_abort(Erc7730Workflow* workflow);

#endif
