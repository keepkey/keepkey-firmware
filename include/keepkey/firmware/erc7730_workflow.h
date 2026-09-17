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
  ERC7730_WORKFLOW_READY,
  ERC7730_WORKFLOW_CALLDATA,
  ERC7730_WORKFLOW_COMPLETE,
  ERC7730_WORKFLOW_FAILED,
} Erc7730WorkflowPhase;

/* The workflow owns every pointer-bearing interpreter object. No pointer into
 * a protobuf transport buffer survives a handler return. */
typedef struct {
  Erc7730CatalogIdentity identity;
  Erc7730TxContinuation continuation;
  Erc7730ProgramLoader loader;
  Erc7730AbiStream calldata;
  uint32_t envelope_length;
  uint8_t phase;
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
bool erc7730_workflow_restore_and_start_calldata(Erc7730Workflow* workflow,
                                                 EthereumSignTx* tx);
Erc7730AbiResult erc7730_workflow_calldata_feed(Erc7730Workflow* workflow,
                                                const uint8_t* data,
                                                size_t data_len);
Erc7730AbiResult erc7730_workflow_calldata_finish(Erc7730Workflow* workflow);
bool erc7730_workflow_active(const Erc7730Workflow* workflow);
bool erc7730_workflow_complete(const Erc7730Workflow* workflow);
const Erc7730CatalogIdentity* erc7730_workflow_identity(
    const Erc7730Workflow* workflow);
void erc7730_workflow_abort(Erc7730Workflow* workflow);

#endif
