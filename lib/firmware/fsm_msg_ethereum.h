
#include "keepkey/firmware/erc7730_workflow.h"
#include "keepkey/firmware/erc7730_condition.h"

/*
 * This file is part of the Keepkey project
 *
 * Copyright (C) 2022 markrypto
 * Copyright (C) 2018 keepkey
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

static int process_ethereum_xfer(const CoinType* coin, EthereumSignTx* msg) {
  if (!ethereum_isStandardERC20Transfer(msg) && msg->data_length != 0)
    return TXOUT_COMPILE_ERROR;

  char node_str[NODE_STRING_LENGTH];
  if (!bip32_node_to_string(node_str, sizeof(node_str), coin, msg->to_address_n,
                            msg->to_address_n_count, /*whole_account=*/false,
                            /*show_addridx=*/false))
    return TXOUT_COMPILE_ERROR;

  char amount_str[128 + sizeof(msg->token_shortcut) + 3];
  if (!ethereumFormatTransferAmount(msg, amount_str, sizeof(amount_str)))
    return TXOUT_COMPILE_ERROR;

  if (!confirm_transfer_output(
          ButtonRequestType_ButtonRequest_ConfirmTransferToAccount, amount_str,
          node_str))
    return TXOUT_CANCEL;

  /* `node` is the shared fsm_derived_node scratch, scrubbed only by the NEXT
   * derivation or by fsm_abort_workflows(). Neither runs on the error paths
   * below: fsm_msgEthereumSignTx answers a compile error with
   * ethereum_signing_abort(), which scrubs ethereum.c's own privkey and
   * nothing else. So every exit past this point has to scrub the node itself,
   * exactly as fsm_msgEthereumSignTypedHash does. */
  const HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->to_address_n,
                                          msg->to_address_n_count, NULL);
  if (!node) return TXOUT_COMPILE_ERROR;

  uint8_t to_bytes[20];
  if (!hdnode_get_ethereum_pubkeyhash(node, to_bytes)) {
    memzero((void*)node, sizeof(HDNode));
    return TXOUT_COMPILE_ERROR;
  }

  if (ethereum_isStandardERC20Transfer(msg)) {
    if (memcmp(msg->data_initial_chunk.bytes + 4 + (32 - 20), to_bytes, 20) !=
        0) {
      memzero((void*)node, sizeof(HDNode));
      return TXOUT_COMPILE_ERROR;
    }
  } else {
    msg->has_to = true;
    msg->to.size = 20;
    memcpy(msg->to.bytes, to_bytes, sizeof(to_bytes));
  }

  memzero((void*)node, sizeof(HDNode));
  return TXOUT_OK;
}

static int process_ethereum_msg(EthereumSignTx* msg, bool* needs_confirm) {
  const CoinType* coin = fsm_getCoin(true, ETHEREUM);
  if (!coin) return TXOUT_COMPILE_ERROR;

  switch (msg->address_type) {
    case OutputAddressType_TRANSFER: {
      // prep transfer type transaction
      *needs_confirm = false;
      return process_ethereum_xfer(coin, msg);
    }
    default:
      return TXOUT_OK;
  }
}

static void eip712_pump(void);

static void send_erc7730_definition_request(void) {
  Erc7730Workflow* workflow = erc7730_workflow_state();
  const Erc7730CatalogIdentity* identity = erc7730_workflow_identity(workflow);
  uint8_t definition_id[32];
  uint32_t offset = 0, total_length = 0;
  if (!identity ||
      !erc7730_workflow_waiting(workflow, definition_id, &offset,
                                &total_length) ||
      offset >= total_length) {
    memzero(definition_id, sizeof(definition_id));
    erc7730_workflow_abort(workflow);
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid ERC-7730 replay state"));
    layoutHome();
    return;
  }
  RESP_INIT(EthereumClearSignDefinitionRequest);
  resp->kind = identity->kind == ERC7730_DEFINITION_EIP712
                   ? EthereumClearSignDefinitionKind_ERC7730_EIP712
                   : EthereumClearSignDefinitionKind_ERC7730_CALLDATA;
  resp->chain_id = identity->chain_id;
  resp->has_contract_address = true;
  resp->contract_address.size = sizeof(identity->contract_address);
  memcpy(resp->contract_address.bytes, identity->contract_address,
         sizeof(identity->contract_address));
  resp->has_selector_or_type_hash = true;
  resp->selector_or_type_hash.size =
      identity->kind == ERC7730_DEFINITION_EIP712 ? 32 : 4;
  memcpy(resp->selector_or_type_hash.bytes, identity->selector_or_type_hash,
         resp->selector_or_type_hash.size);
  resp->has_definition_id = true;
  resp->definition_id.size = sizeof(definition_id);
  memcpy(resp->definition_id.bytes, definition_id, sizeof(definition_id));
  resp->offset = offset;
  const uint32_t remaining = total_length - offset;
  resp->length = remaining < ERC7730_TRANSPORT_CHUNK_MAX
                     ? remaining
                     : ERC7730_TRANSPORT_CHUNK_MAX;
  memzero(definition_id, sizeof(definition_id));
  msg_write(MessageType_MessageType_EthereumClearSignDefinitionRequest, resp);
}

static void send_erc7730_calldata_request(void) {
  size_t remaining = 0;
  if (!erc7730_workflow_calldata_waiting(erc7730_workflow_state(),
                                         &remaining)) {
    erc7730_workflow_abort(erc7730_workflow_state());
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid ERC-7730 calldata state"));
    layoutHome();
    return;
  }
  RESP_INIT(EthereumTxRequest);
  resp->has_data_length = true;
  resp->data_length = remaining < ERC7730_TRANSPORT_CHUNK_MAX
                          ? remaining
                          : ERC7730_TRANSPORT_CHUNK_MAX;
  msg_write(MessageType_MessageType_EthereumTxRequest, resp);
}

static void continue_ethereum_sign_tx(EthereumSignTx* msg) {
  bool needs_confirm = true;
  int msg_result = process_ethereum_msg(msg, &needs_confirm);

  if (msg_result < TXOUT_OK) {
    ethereum_signing_abort();
    erc7730_workflow_abort(erc7730_workflow_state());
    send_fsm_co_error_message(msg_result);
    layoutHome();
    return;
  }

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) {
    erc7730_workflow_abort(erc7730_workflow_state());
    return;
  }

  ethereum_signing_init(msg, node, needs_confirm);
  memzero(node, sizeof(*node));
}

static void confirm_erc7730_intent_and_continue(EthereumSignTx* tx) {
  Erc7730Workflow* workflow = erc7730_workflow_state();
  const bool typed_data = workflow->typed_data;
  if (workflow->intent[0] == '\0') {
    if (typed_data) eip712_stream_abort();
    erc7730_workflow_abort(workflow);
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid ERC-7730 intent"));
    layoutHome();
    return;
  }
  if (!workflow->intent_confirmed) {
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Contract action", "%s", workflow->intent)) {
      if (typed_data) eip712_stream_abort();
      erc7730_workflow_abort(workflow);
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled by user"));
      layoutHome();
      return;
    }
    workflow->intent_confirmed = true;
  }
  const bool had_field = workflow->label[0] != '\0';
  if (had_field) {
    char formatted[ERC7730_FORMATTED_VALUE_MAX + 1u];
    if (!erc7730_workflow_format_captured_raw(workflow, formatted,
                                              sizeof(formatted))) {
      if (typed_data) eip712_stream_abort();
      erc7730_workflow_abort(workflow);
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Unable to format ERC-7730 field"));
      layoutHome();
      return;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, workflow->label,
                 "%s", formatted)) {
      memzero(formatted, sizeof(formatted));
      if (typed_data) eip712_stream_abort();
      erc7730_workflow_abort(workflow);
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled by user"));
      layoutHome();
      return;
    }
    memzero(formatted, sizeof(formatted));
  }
  if (had_field) {
    if (!erc7730_workflow_advance_display(workflow)) {
      if (typed_data) eip712_stream_abort();
      erc7730_workflow_abort(workflow);
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Invalid ERC-7730 display continuation"));
      layoutHome();
      return;
    }
    send_erc7730_definition_request();
    return;
  }
  continue_ethereum_sign_tx(tx);
}

static void continue_erc7730_condition(void) {
  Erc7730Workflow* workflow = erc7730_workflow_state();
  bool visible = false;
  if (!erc7730_workflow_resolve_captured_condition(workflow, &visible)) {
    erc7730_workflow_abort(workflow);
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Unable to evaluate ERC-7730 condition"));
    layoutHome();
    return;
  }
  if (!visible) {
    if (!erc7730_workflow_skip_display(workflow)) {
      erc7730_workflow_abort(workflow);
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Invalid ERC-7730 condition jump"));
      layoutHome();
      return;
    }
    send_erc7730_definition_request();
    return;
  }
  const uint16_t label_index =
      (uint16_t)(((uint16_t)(uint8_t)workflow->label[0] << 8) |
                 (uint8_t)workflow->label[1]);
  memzero(workflow->label, sizeof(workflow->label));
  workflow->display_stage = ERC7730_DISPLAY_LABEL;
  if (!erc7730_workflow_select_string(workflow, label_index)) {
    erc7730_workflow_abort(workflow);
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid ERC-7730 conditioned field"));
    layoutHome();
    return;
  }
  send_erc7730_definition_request();
}

static void start_erc7730_calldata(Erc7730Workflow* workflow,
                                   const Erc7730Path* path) {
  EthereumSignTx tx;
  const bool started =
      path ? erc7730_workflow_restore_and_start_capture(workflow, &tx, path)
           : erc7730_workflow_restore_and_start_calldata(workflow, &tx);
  if (!started) {
    erc7730_workflow_abort(workflow);
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid ERC-7730 execution program"));
    layoutHome();
    return;
  }
  size_t remaining = 0;
  if (erc7730_workflow_calldata_waiting(workflow, &remaining)) {
    send_erc7730_calldata_request();
  } else if (erc7730_workflow_calldata_finish(workflow) == ERC7730_ABI_OK) {
    if (erc7730_workflow_condition_capture_pending(workflow))
      continue_erc7730_condition();
    else
      confirm_erc7730_intent_and_continue(&tx);
  } else {
    erc7730_workflow_abort(workflow);
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("ERC-7730 calldata does not match definition"));
    layoutHome();
  }
  memzero(&tx, sizeof(tx));
}

void fsm_msgEthereumSignTx(EthereumSignTx* msg) {
  /* A new start supersedes any old Ethereum stream before validation. */
  ethereum_signing_abort();
  erc7730_workflow_abort(erc7730_workflow_state());

  CHECK_INITIALIZED

  CHECK_PIN

  /* Validate the replay-protection domain before any transaction-specific
   * review. process_ethereum_msg() can draw a transfer-to-account screen, so
   * leaving this to ethereum_signing_init() meant OutputAddressType_TRANSFER
   * emitted a ButtonRequest before an omitted chain_id was refused. */
  if (!ethereum_chainIdIsValid(msg)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Chain Id out of bounds"));
    layoutHome();
    return;
  }

  /* A host that explicitly supplied a certified definition has selected the
   * clear-sign path. Bind it to the exact transaction before any review UI or
   * key derivation. A mismatch is an error, never permission to silently fall
   * back to blind signing. */
  Erc7730CatalogIdentity definition;
  if (erc7730_catalog_preloaded(&definition)) {
    const bool calldata_shape = msg->has_to && msg->to.size == 20 &&
                                msg->has_data_length && msg->data_length >= 4 &&
                                msg->has_data_initial_chunk &&
                                msg->data_initial_chunk.size == 4;
    const bool matches =
        calldata_shape && erc7730_catalog_matches_calldata(
                              &definition, msg->chain_id, msg->to.bytes,
                              msg->data_initial_chunk.bytes);
    if (!matches) {
      memzero(&definition, sizeof(definition));
      erc7730_catalog_clear_preload();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("ERC-7730 definition does not match transaction"));
      layoutHome();
      return;
    }
    if (!erc7730_workflow_begin(erc7730_workflow_state(), &definition, msg)) {
      memzero(&definition, sizeof(definition));
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Unable to start ERC-7730 verification"));
      layoutHome();
      return;
    }
    memzero(&definition, sizeof(definition));
    send_erc7730_definition_request();
    return;
  }
  memzero(&definition, sizeof(definition));
  continue_ethereum_sign_tx(msg);
}

void fsm_msgEthereumTxAck(EthereumTxAck* msg) {
  Erc7730Workflow* workflow = erc7730_workflow_state();
  if (workflow->phase != ERC7730_WORKFLOW_CALLDATA) {
    ethereum_signing_txack(msg);
    return;
  }
  size_t remaining = 0;
  if (!erc7730_workflow_calldata_waiting(workflow, &remaining) ||
      !msg->has_data_chunk || msg->data_chunk.size == 0 ||
      msg->data_chunk.size > remaining ||
      erc7730_workflow_calldata_feed(workflow, msg->data_chunk.bytes,
                                     msg->data_chunk.size) != ERC7730_ABI_OK) {
    erc7730_workflow_abort(workflow);
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("ERC-7730 calldata does not match definition"));
    layoutHome();
    return;
  }
  if (erc7730_workflow_calldata_waiting(workflow, &remaining)) {
    send_erc7730_calldata_request();
    return;
  }
  if (erc7730_workflow_calldata_finish(workflow) != ERC7730_ABI_OK) {
    erc7730_workflow_abort(workflow);
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("ERC-7730 calldata does not match definition"));
    layoutHome();
    return;
  }
  EthereumSignTx tx;
  if (!erc7730_workflow_restore_complete(workflow, &tx)) {
    erc7730_workflow_abort(workflow);
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Unable to resume ERC-7730 transaction"));
    layoutHome();
    return;
  }
  if (erc7730_workflow_condition_capture_pending(workflow))
    continue_erc7730_condition();
  else
    confirm_erc7730_intent_and_continue(&tx);
  memzero(&tx, sizeof(tx));
}

void fsm_msgEthereumClearSignDefinition(
    const EthereumClearSignDefinition* msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  if (ethereum_signing_isInProgress() ||
      eip712_stream_waiting() != EIP712_IDLE) {
    ethereum_signing_abort();
    eip712_stream_abort();
    erc7730_catalog_clear_preload();
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Definition not allowed during signing"));
    layoutHome();
    return;
  }
  if (msg->definition_id.size != 32 || msg->data.size == 0 ||
      msg->data.size > ERC7730_TRANSPORT_CHUNK_MAX) {
    erc7730_catalog_clear_preload();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid ERC-7730 definition chunk"));
    layoutHome();
    return;
  }

  uint32_t next_offset = 0;
  bool complete = false;
  const Erc7730CatalogResult result = erc7730_catalog_preload_chunk(
      msg->definition_id.bytes, msg->offset, msg->total_length, msg->data.bytes,
      msg->data.size, &next_offset, &complete);
  if (result != ERC7730_CATALOG_MORE && result != ERC7730_CATALOG_COMPLETE) {
    erc7730_catalog_clear_preload();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid certified ERC-7730 definition"));
    layoutHome();
    return;
  }

  RESP_INIT(EthereumClearSignDefinitionAck);
  resp->definition_id.size = 32;
  memcpy(resp->definition_id.bytes, msg->definition_id.bytes, 32);
  resp->next_offset = next_offset;
  resp->complete = complete;
  msg_write(MessageType_MessageType_EthereumClearSignDefinitionAck, resp);
}

void fsm_msgEthereumClearSignDefinitionChunk(
    const EthereumClearSignDefinitionChunk* msg) {
  Erc7730Workflow* workflow = erc7730_workflow_state();
  if (!erc7730_workflow_active(workflow)) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("No ERC-7730 definition requested"));
    layoutHome();
    return;
  }
  bool complete = false;
  const uint8_t selection_kind = workflow->selection_kind;
  const Erc7730CatalogResult result =
      workflow->phase == ERC7730_WORKFLOW_SELECT
          ? erc7730_workflow_selection_feed(workflow, msg, &complete)
          : erc7730_workflow_replay_feed(workflow, msg, &complete);
  if (result != ERC7730_CATALOG_MORE && result != ERC7730_CATALOG_COMPLETE) {
    ethereum_signing_abort();
    eip712_stream_abort();
    erc7730_workflow_abort(workflow);
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid certified ERC-7730 replay"));
    layoutHome();
    return;
  }
  if (!complete) {
    send_erc7730_definition_request();
    return;
  }
  if (selection_kind == ERC7730_SELECTION_NONE) {
    if (!erc7730_workflow_select_display(workflow, 0)) {
      erc7730_workflow_abort(workflow);
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Invalid ERC-7730 display program"));
      layoutHome();
      return;
    }
    send_erc7730_definition_request();
    return;
  }
  if (selection_kind == ERC7730_SELECTION_DISPLAY) {
    Erc7730DisplayInstruction instruction;
    uint16_t instruction_count = 0;
    if (!erc7730_workflow_selected_display(workflow, &instruction,
                                           &instruction_count) ||
        instruction_count == 0) {
      erc7730_workflow_abort(workflow);
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Invalid ERC-7730 display instruction"));
      layoutHome();
      return;
    }
    if (workflow->display_stage == ERC7730_DISPLAY_NONE) {
      if (instruction.opcode != 1 || instruction.flags != 0 ||
          instruction.a == UINT16_MAX || instruction.b != UINT16_MAX ||
          instruction.c != UINT16_MAX ||
          !erc7730_workflow_select_string(workflow, instruction.a)) {
        erc7730_workflow_abort(workflow);
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Invalid ERC-7730 intent instruction"));
        layoutHome();
        return;
      }
      workflow->display_stage = ERC7730_DISPLAY_INTENT_STRING;
      send_erc7730_definition_request();
      return;
    }
    if (workflow->display_stage == ERC7730_DISPLAY_INSTRUCTION &&
        instruction.opcode == 10 && instruction.flags == 0 &&
        instruction.a == UINT16_MAX && instruction.b == UINT16_MAX &&
        instruction.c == UINT16_MAX) {
      if (workflow->typed_data) {
        erc7730_workflow_abort(workflow);
        if (!eip712_stream_definition_accepted()) {
          eip712_stream_abort();
          fsm_sendFailure(FailureType_Failure_SyntaxError,
                          _("Unable to resume certified EIP-712"));
          layoutHome();
          return;
        }
        eip712_pump();
      } else {
        start_erc7730_calldata(workflow, NULL);
      }
      return;
    }
    if (workflow->display_stage != ERC7730_DISPLAY_INSTRUCTION ||
        instruction.opcode != 4 || instruction.flags != 0 ||
        instruction.a == UINT16_MAX || instruction.b == UINT16_MAX) {
      erc7730_workflow_abort(workflow);
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Unsupported ERC-7730 field instruction"));
      layoutHome();
      return;
    }
    if (instruction.c != UINT16_MAX) {
      workflow->label[0] = (char)(instruction.a >> 8);
      workflow->label[1] = (char)instruction.a;
      workflow->current_formatter = instruction.b;
      workflow->display_stage = ERC7730_DISPLAY_CONDITION;
      if (!erc7730_workflow_select_condition(workflow, instruction.c)) {
        erc7730_workflow_abort(workflow);
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Invalid ERC-7730 field condition"));
        layoutHome();
        return;
      }
      send_erc7730_definition_request();
      return;
    }
    workflow->current_formatter = instruction.b;
    if (!erc7730_workflow_select_string(workflow, instruction.a)) {
      erc7730_workflow_abort(workflow);
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Invalid ERC-7730 field label"));
      layoutHome();
      return;
    }
    workflow->display_stage = ERC7730_DISPLAY_LABEL;
    send_erc7730_definition_request();
    return;
  }
  if (selection_kind == ERC7730_SELECTION_CONDITION) {
    Erc7730Condition condition;
    bool visible = false;
    if (workflow->display_stage != ERC7730_DISPLAY_CONDITION ||
        !erc7730_workflow_selected_condition(workflow, &condition)) {
      memzero(&condition, sizeof(condition));
      erc7730_workflow_abort(workflow);
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Unsupported ERC-7730 field condition"));
      layoutHome();
      return;
    }
    if (condition.opcode == 4 || condition.opcode == 5) {
      const uint16_t condition_path = condition.path;
      if (!erc7730_workflow_begin_condition_capture(workflow, &condition) ||
          !erc7730_workflow_select_path(workflow, condition_path)) {
        memzero(&condition, sizeof(condition));
        erc7730_workflow_abort(workflow);
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Invalid ERC-7730 condition path"));
        layoutHome();
        return;
      }
      memzero(&condition, sizeof(condition));
      workflow->display_stage = ERC7730_DISPLAY_PATH;
      send_erc7730_definition_request();
      return;
    }
    if (!erc7730_condition_evaluate_basic(&condition, NULL, NULL, &visible)) {
      memzero(&condition, sizeof(condition));
      erc7730_workflow_abort(workflow);
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Unsupported ERC-7730 field condition"));
      layoutHome();
      return;
    }
    memzero(&condition, sizeof(condition));
    if (!visible) {
      if (!erc7730_workflow_skip_display(workflow)) {
        erc7730_workflow_abort(workflow);
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Invalid ERC-7730 condition jump"));
        layoutHome();
        return;
      }
      send_erc7730_definition_request();
      return;
    }
    const uint16_t label_index =
        (uint16_t)(((uint16_t)(uint8_t)workflow->label[0] << 8) |
                   (uint8_t)workflow->label[1]);
    memzero(workflow->label, sizeof(workflow->label));
    workflow->display_stage = ERC7730_DISPLAY_LABEL;
    if (!erc7730_workflow_select_string(workflow, label_index)) {
      erc7730_workflow_abort(workflow);
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Invalid ERC-7730 conditioned field"));
      layoutHome();
      return;
    }
    send_erc7730_definition_request();
    return;
  }
  if (selection_kind == ERC7730_SELECTION_STRING) {
    if (workflow->display_stage == ERC7730_DISPLAY_INTENT_STRING) {
      if (!erc7730_workflow_preserve_selected_string(workflow, true)) {
        erc7730_workflow_abort(workflow);
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Invalid ERC-7730 intent"));
        layoutHome();
        return;
      }
      workflow->display_stage = ERC7730_DISPLAY_INSTRUCTION;
      workflow->display_index = 1;
      if (!erc7730_workflow_select_display(workflow, 1)) {
        erc7730_workflow_abort(workflow);
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Missing ERC-7730 display instruction"));
        layoutHome();
        return;
      }
      send_erc7730_definition_request();
      return;
    }
    if (workflow->display_stage != ERC7730_DISPLAY_LABEL ||
        !erc7730_workflow_preserve_selected_string(workflow, false) ||
        !erc7730_workflow_select_formatter(workflow,
                                           workflow->current_formatter)) {
      erc7730_workflow_abort(workflow);
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Invalid ERC-7730 field formatter"));
      layoutHome();
      return;
    }
    workflow->display_stage = ERC7730_DISPLAY_FORMATTER;
    send_erc7730_definition_request();
    return;
  }
  if (selection_kind == ERC7730_SELECTION_FORMATTER) {
    Erc7730Formatter formatter;
    if (workflow->display_stage != ERC7730_DISPLAY_FORMATTER ||
        !erc7730_workflow_selected_formatter(workflow, &formatter) ||
        (formatter.kind != 1 && formatter.kind != 2 && formatter.kind != 9) ||
        formatter.flags != 0 || formatter.argument_count != 1 ||
        formatter.arguments[0].role != 1 ||
        formatter.arguments[0].source != 1 ||
        !erc7730_workflow_select_path(workflow, formatter.arguments[0].index)) {
      memzero(&formatter, sizeof(formatter));
      erc7730_workflow_abort(workflow);
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Unsupported ERC-7730 formatter"));
      layoutHome();
      return;
    }
    workflow->current_formatter_kind = formatter.kind;
    memzero(&formatter, sizeof(formatter));
    workflow->display_stage = ERC7730_DISPLAY_PATH;
    send_erc7730_definition_request();
    return;
  }
  if (selection_kind != ERC7730_SELECTION_PATH) {
    erc7730_workflow_abort(workflow);
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid ERC-7730 selection state"));
    layoutHome();
    return;
  }
  Erc7730Path path;
  if (workflow->display_stage != ERC7730_DISPLAY_PATH ||
      !erc7730_workflow_selected_path(workflow, &path)) {
    memzero(&path, sizeof(path));
    erc7730_workflow_abort(workflow);
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid ERC-7730 value path"));
    layoutHome();
    return;
  }
  if (!workflow->typed_data && path.source == 2) {
    EthereumSignTx tx;
    uint8_t sender_address[20];
    memzero(sender_address, sizeof(sender_address));
    const uint8_t* sender = NULL;
    if (path.source_index == 1) {
      if (!erc7730_tx_continuation_restore(&workflow->continuation, &tx)) {
        memzero(&path, sizeof(path));
        memzero(&tx, sizeof(tx));
        erc7730_workflow_abort(workflow);
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Invalid ERC-7730 sender path"));
        layoutHome();
        return;
      }
      HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, tx.address_n,
                                        tx.address_n_count, NULL);
      if (!node) {
        memzero(sender_address, sizeof(sender_address));
        memzero(&path, sizeof(path));
        memzero(&tx, sizeof(tx));
        erc7730_workflow_abort(workflow);
        layoutHome();
        return;
      }
      if (!hdnode_get_ethereum_pubkeyhash(node, sender_address)) {
        memzero(node, sizeof(*node));
        memzero(sender_address, sizeof(sender_address));
        memzero(&path, sizeof(path));
        memzero(&tx, sizeof(tx));
        erc7730_workflow_abort(workflow);
        fsm_sendFailure(FailureType_Failure_Other,
                        _("Ethereum sender derivation failed"));
        layoutHome();
        return;
      }
      memzero(node, sizeof(*node));
      sender = sender_address;
    }
    if (!erc7730_workflow_capture_tx_container(workflow, &path, &tx, sender)) {
      memzero(sender_address, sizeof(sender_address));
      memzero(&path, sizeof(path));
      memzero(&tx, sizeof(tx));
      erc7730_workflow_abort(workflow);
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Unsupported ERC-7730 transaction fact"));
      layoutHome();
      return;
    }
    memzero(sender_address, sizeof(sender_address));
    if (erc7730_workflow_condition_capture_pending(workflow))
      continue_erc7730_condition();
    else
      confirm_erc7730_intent_and_continue(&tx);
    memzero(&tx, sizeof(tx));
  } else if (workflow->typed_data && path.source == 2) {
    uint8_t value[32];
    EthereumSignTx unused_tx;
    memzero(value, sizeof(value));
    memzero(&unused_tx, sizeof(unused_tx));
    if (!eip712_stream_container_hash(path.source_index, value) ||
        !erc7730_workflow_capture_eip712_container(workflow, &path, value)) {
      memzero(value, sizeof(value));
      memzero(&path, sizeof(path));
      eip712_stream_abort();
      erc7730_workflow_abort(workflow);
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Unsupported ERC-7730 EIP-712 fact"));
      layoutHome();
      return;
    }
    memzero(value, sizeof(value));
    confirm_erc7730_intent_and_continue(&unused_tx);
    memzero(&unused_tx, sizeof(unused_tx));
  } else if (workflow->typed_data) {
    if (!erc7730_workflow_start_eip712_capture(workflow, &path) ||
        !eip712_stream_definition_accepted()) {
      memzero(&path, sizeof(path));
      eip712_stream_abort();
      erc7730_workflow_abort(workflow);
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Unsupported ERC-7730 typed-data path"));
      layoutHome();
      return;
    }
    eip712_pump();
  } else {
    start_erc7730_calldata(workflow, &path);
  }
  memzero(&path, sizeof(path));
}

void fsm_msgEthereumTxMetadata(const EthereumTxMetadata* msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  /* Metadata must arrive before signing starts. signed_metadata_process()
   * clears the binding on entry, so accepting metadata mid-signing would
   * drop the tx<->metadata binding without aborting: a host could approve a
   * benign decode (suppressing the blind-sign gate), then inject metadata to
   * clear the binding and stream attacker-chosen calldata for the rest.
   * Refuse and abort any in-progress signing session. */
  if (ethereum_signing_isInProgress()) {
    ethereum_signing_abort();
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Metadata not allowed during signing"));
    layoutHome();
    return;
  }

  CHECK_PARAM(!msg->has_key_id || msg->key_id <= 0xff,
              _("clearsign metadata key_id out of range"));

  /* Runtime/self-service signers remain behind AdvancedMode. A production v3
   * envelope is allowed through only when it uses the reserved delegate key
   * id and has enough bytes to contain a certificate plus inner payload. This
   * shape check grants no trust: signed_metadata_process() still verifies the
   * compiled root, certificate, delegate signature, and device-owned decode
   * before the metadata can affect signing or suppress raw review. */
  bool certified =
      msg->has_signed_payload && msg->has_key_id &&
      signed_metadata_is_certified_envelope(
          msg->signed_payload.bytes, msg->signed_payload.size, msg->key_id);
  CHECK_PARAM(storage_isPolicyEnabled("AdvancedMode") || certified,
              _("AdvancedMode required for uncertified clearsign metadata"));

  RESP_INIT(EthereumMetadataAck);

  MetadataClassification result = signed_metadata_process(
      msg->signed_payload.bytes, msg->signed_payload.size,
      msg->has_key_id ? (uint8_t)msg->key_id : 0);

  resp->classification = (uint32_t)result;
  resp->has_display_summary = true;

  switch (result) {
    case METADATA_VERIFIED:
      strlcpy(resp->display_summary, "Verified", sizeof(resp->display_summary));
      break;
    case METADATA_OPAQUE:
      strlcpy(resp->display_summary, "Unverified",
              sizeof(resp->display_summary));
      break;
    case METADATA_MALFORMED:
    default:
      strlcpy(resp->display_summary, "Invalid", sizeof(resp->display_summary));
      break;
  }

  msg_write(MessageType_MessageType_EthereumMetadataAck, resp);
}

void fsm_msgLoadClearsignSigner(const LoadClearsignSigner* msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  /* Same reasoning as fsm_msgEthereumTxMetadata above, and the same fix.
   * Storing a signer ends in signed_metadata_clear(), which drops the
   * tx<->metadata binding along with relied_on_metadata -- so loading a
   * signer mid-signing let a host approve a benign decode and then stream
   * different calldata, with signed_metadata_enforce() seeing relied=false
   * and passing. The guard was on the metadata message but not on its
   * sibling. */
  if (ethereum_signing_isInProgress()) {
    ethereum_signing_abort();
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Signer load not allowed during signing"));
    layoutHome();
    return;
  }

  CHECK_PARAM(storage_isPolicyEnabled("AdvancedMode"),
              _("AdvancedMode required for clearsign signers"));

  CHECK_PARAM(msg->has_key_id && msg->has_pubkey && msg->has_alias,
              _("key_id, pubkey and alias required"));
  /* Range-check as uint32 BEFORE narrowing: (uint8_t)256 would alias slot 0 */
  CHECK_PARAM(msg->key_id < METADATA_MAX_KEYS, _("key_id out of range"));
  CHECK_PARAM(
      signed_metadata_signer_valid((uint8_t)msg->key_id, msg->pubkey.bytes,
                                   msg->pubkey.size, msg->alias),
      _("Invalid clearsign signer"));

  /* Optional identity icon (1bpp mono RLE). The proto caps icon at 384 bytes;
   * bound the dims too so the render path never scans a bogus geometry. An icon
   * with zero/oversized dims is rejected rather than silently dropped so a
   * malformed upload is visible, not a mystery text-only identity. */
  const uint8_t* icon = NULL;
  uint16_t icon_len = 0;
  uint8_t icon_w = 0, icon_h = 0;
  if (msg->has_icon && msg->icon.size > 0) {
    CHECK_PARAM(msg->icon.size <= METADATA_ICON_MAX, _("icon too large"));
    /* Width is capped at the confirm screen's icon column
     * (LEFT_MARGIN_WITH_ICON = 40), NOT at the 64px height. Title/body text
     * begins at x=40 and the icon is drawn AFTER the text, so a wider
     * host-supplied icon would paint over the alias, fingerprint and the
     * "NOT verified by KeepKey" warning — on the very screen that exists to
     * carry that warning. This is the trust boundary for icons arriving on the
     * wire; signed_metadata_signer_icon() rechecks the session copy at use. */
    CHECK_PARAM(msg->has_icon_width && msg->has_icon_height &&
                    msg->icon_width > 0 &&
                    msg->icon_width <= LEFT_MARGIN_WITH_ICON &&
                    msg->icon_height > 0 && msg->icon_height <= 64,
                _("icon dimensions out of range"));
    /* Reject a malformed RLE stream HERE rather than discovering it at draw
     * time. The render path returns a bool that layout_add_icon() discards, so
     * an undecodable icon would otherwise show no logo while still returning
     * Success — the user would consent to an identity
     * whose logo silently does not exist. Validation is exact (every packet
     * well-formed, no run straddling the image, whole input consumed) and
     * side-effect-free.
     */
    CHECK_PARAM(draw_bitmap_mono_rle_valid(
                    msg->icon.bytes, (uint32_t)msg->icon.size,
                    (uint16_t)msg->icon_width, (uint16_t)msg->icon_height),
                _("invalid icon encoding"));
    icon = msg->icon.bytes;
    icon_len = (uint16_t)msg->icon.size;
    icon_w = (uint8_t)msg->icon_width;
    icon_h = (uint8_t)msg->icon_height;
  }
  bool persist = msg->has_persist && msg->persist;
  CHECK_PARAM(!persist, _("Persistent clearsign signers are disabled"));

  /* Mandatory on-device consent — leads with the identity's logo (if any) +
   * alias + fingerprint. The whole trust model hangs on this confirm; the same
   * fingerprint reappears on every per-tx identity screen. */
  char fingerprint[METADATA_FINGERPRINT_LEN];
  signed_metadata_pubkey_fingerprint(msg->pubkey.bytes, fingerprint);
  if (!signed_metadata_confirm_load(msg->alias, fingerprint, icon, icon_w,
                                    icon_h, icon_len)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Load clearsign signer cancelled"));
    layoutHome();
    return;
  }

  if (!signed_metadata_store_signer((uint8_t)msg->key_id, msg->pubkey.bytes,
                                    msg->alias, icon, icon_w, icon_h, icon_len,
                                    persist)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Clearsign signer could not be loaded"));
    layoutHome();
    return;
  }
  fsm_sendSuccess(_("Clearsign signer loaded"));
  layoutHome();
}

void fsm_msgEthereumGetAddress(EthereumGetAddress* msg) {
  RESP_INIT(EthereumAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  /* Build the whole answer in LOCALS and commit it to `resp` only after the
   * confirmation.
   *
   * `resp` aliases fsm.c's single msg_resp buffer, and confirm_* below runs a
   * message loop: every DebugLink request the emulator harness makes while a
   * screen is up is dispatched from inside it, and those handlers RESP_INIT
   * the same buffer. Anything staged in `resp` before the screen is therefore
   * live across an arbitrary number of foreign writes to it -- which is how
   * EthereumAddress.address_str reached the host as undecodable bytes.
   *
   * fsm_msgNanoGetAddress() already builds into a local and assigns after its
   * confirm; this handler was the one that staged first. */
  uint8_t pubkeyhash[20] = {0};

  if (!hdnode_get_ethereum_pubkeyhash(node, pubkeyhash)) {
    memzero(node, sizeof(*node));
    return;
  }

  const CoinType* coin = NULL;
  bool rskip60 = false;
  uint32_t chain_id = 0;

  if (msg->address_n_count == 5) {
    coin = coinBySlip44(msg->address_n[1]);
    uint32_t slip44 = msg->address_n[1] & 0x7fffffff;
    // constants from trezor-common/defs/ethereum/networks.json
    switch (slip44) {
      case 137:
        rskip60 = true;
        chain_id = 30;
        break;
      case 37310:
        rskip60 = true;
        chain_id = 31;
        break;
    }
  }

  char address[43] = {'0', 'x'};
  ethereum_address_checksum(pubkeyhash, address + 2, rskip60, chain_id);

  if (msg->has_show_display && msg->show_display) {
    char node_str[NODE_STRING_LENGTH];
    if (!(coin && isEthereumLike(coin->coin_name) &&
          bip32_node_to_string(node_str, sizeof(node_str), coin, msg->address_n,
                               msg->address_n_count,
                               /*whole_account=*/false,
                               /*show_addridx=*/false)) &&
        !bip32_path_to_string(node_str, sizeof(node_str), msg->address_n,
                              msg->address_n_count)) {
      memset(node_str, 0, sizeof(node_str));
    }

    if (!confirm_ethereum_address(node_str, address)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Show address cancelled"));
      layoutHome();
      return;
    }
  }

  memzero(node, sizeof(*node));

  /* Only now, with no further message loop between here and the write. */
  resp->address.size = sizeof(pubkeyhash);
  memcpy(resp->address.bytes, pubkeyhash, sizeof(pubkeyhash));
  resp->has_address_str = true;
  strlcpy(resp->address_str, address, sizeof(resp->address_str));

  msg_write(MessageType_MessageType_EthereumAddress, resp);
  layoutHome();
}

void fsm_msgEthereumSignMessage(EthereumSignMessage* msg) {
  RESP_INIT(EthereumMessageSignature);

  CHECK_INITIALIZED

  CHECK_PIN

  /* A zero-length message is not a message. confirm_bytes() renders size 0 as
     the literal "(empty)" and returns whatever the owner pressed, so without
     this the device would sign a payload no screen ever showed -- the same
     hole already closed on the TON and Solana paths. (`message` is a required
     field here, so nanopb rejects an omitted one during decode; only the empty
     case reaches this far.) */
  if (msg->message.size == 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Missing message"));
    layoutHome();
    return;
  }

  /* Merge note (#432 vs this branch): release/7.14.2 gated Ethereum message
   * signing behind AdvancedMode, which blocks every Sign-In-With-Ethereum flow
   * on a default device until the user explicitly enables blind signing.
   * AdvancedMode persists across power cycles until explicitly disabled.
   * confirm_bytes() paginates and displays EVERY signed byte, which is what
   * that gate was standing in for. Full disclosure is both the stronger
   * security property and the one that does not break default-configuration
   * signing, so the gate is dropped here in favour of it. */
  if (!confirm_bytes(ButtonRequestType_ButtonRequest_ProtectCall,
                     _("Sign Ethereum Message"), msg->message.bytes,
                     msg->message.size)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  ethereum_message_sign(msg, node, resp);
  memzero(node, sizeof(*node));
  layoutHome();
}

void fsm_msgEthereumVerifyMessage(const EthereumVerifyMessage* msg) {
  CHECK_PARAM(msg->has_address, _("No address provided"));
  CHECK_PARAM(msg->has_message, _("No message provided"));

  if (ethereum_message_verify(msg) != 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Invalid signature"));
    return;
  }

  char address[43] = {'0', 'x'};
  ethereum_address_checksum(msg->address.bytes, address + 2, false, 0);
  if (!confirm_address(_("Confirm Signer"), address)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  if (!confirm_bytes(ButtonRequestType_ButtonRequest_Other,
                     _("Ethereum Message Verified"), msg->message.bytes,
                     msg->message.size)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }
  fsm_sendSuccess(_("Message verified"));

  layoutHome();
}

void fsm_msgEthereumSignTypedHash(const EthereumSignTypedHash* msg) {
  RESP_INIT(EthereumTypedDataSignature);

  CHECK_INITIALIZED

  CHECK_PIN

  if (!ethereum_typed_hash_policy_allows(
          storage_isPolicyEnabled("AdvancedMode"))) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Enable AdvancedMode to blind-sign typed hashes"));
    layoutHome();
    return;
  }

  if (msg->domain_separator_hash.size != 32 ||
      (msg->has_message_hash && msg->message_hash.size != 32)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid EIP-712 hash length"));
    return;
  }

  if (!confirm(ButtonRequestType_ButtonRequest_Other, "EIP-712 Blind Sign",
               "Cannot verify these hashes. Trust the host?")) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  /* Not const: every exit past this point has to scrub the node.
   *
   * `node` is the shared fsm_derived_node scratch. A Cancel answered at any of
   * the confirmations below is consumed by confirm_screen() and returned as a
   * refusal -- it never reaches fsm_msgCancel(), so nothing else runs
   * fsm_abort_workflows() on the way out. Each early return here was therefore
   * leaving a derived private key resident, and so was the success path. */
  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  uint8_t pubkeyhash[20] = {0};
  if (!hdnode_get_ethereum_pubkeyhash(node, pubkeyhash)) {
    memzero(node, sizeof(*node));
    layoutHome();
    return;
  }

  resp->address[0] = '0';
  resp->address[1] = 'x';
  ethereum_address_checksum(pubkeyhash, resp->address + 2, false, 0);

  // No message hash when setting primaryType="EIP712Domain"
  // https://ethereum-magicians.org/t/eip-712-standards-clarification-primarytype-as-domaintype/3286
  char str[64 + 1];
  int ctr;

  if (!confirm(ButtonRequestType_ButtonRequest_Other, "Verify Address",
               "Confirm address: %s", resp->address)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  for (ctr = 0; ctr < 64 / 2; ctr++) {
    snprintf(&str[2 * ctr], 3, "%02x", msg->domain_separator_hash.bytes[ctr]);
  }
  if (!confirm(ButtonRequestType_ButtonRequest_Other, "Typed Data domain",
               "Confirm hash digest: %s", str)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  if (msg->has_message_hash) {
    for (ctr = 0; ctr < 64 / 2; ctr++) {
      snprintf(&str[2 * ctr], 3, "%02x", msg->message_hash.bytes[ctr]);
    }
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Typed Data message",
                 "Confirm hash digest: %s", str)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  } else {
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Typed Data message",
                 "Confirm: No message")) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  ethereum_typed_hash_sign(msg, node, resp);
  memzero(node, sizeof(*node));
  layoutHome();
}

void fsm_msgEthereum712TypesValues(Ethereum712TypesValues* msg) {
  RESP_INIT(EthereumTypedDataSignature);

  CHECK_INITIALIZED

  CHECK_PIN

  if (!ethereum_structured_eip712_enabled()) {
    fsm_sendFailure(
        FailureType_Failure_Other,
        _("Structured EIP-712 disabled pending canonical display hardening"));
    layoutHome();
    return;
  }

  if (strlen(msg->eip712types) == 0) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid EIP-712 types property string"));
    return;
  }

  /* Not const, for the same reason as fsm_msgEthereumSignTypedHash() above:
   * this is the shared fsm_derived_node scratch and every exit has to scrub
   * it. e712_types_values() runs its own confirmations, and a Cancel answered
   * there never reaches fsm_msgCancel(). */
  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  uint8_t pubkeyhash[20] = {0};
  if (!hdnode_get_ethereum_pubkeyhash(node, pubkeyhash)) {
    memzero(node, sizeof(*node));
    layoutHome();
    return;
  }

  resp->address[0] = '0';
  resp->address[1] = 'x';
  ethereum_address_checksum(pubkeyhash, resp->address + 2, false, 0);

  e712_types_values(msg, resp, node);
  memzero(node, sizeof(*node));

  layoutHome();
}

/* ── Structured EIP-712 ──────────────────────────────────────────────
 *
 * The walk in eip712_stream.c never writes a message. It describes what it
 * wants next and these three handlers emit it, because msg_resp and the HD
 * node live here. One pump serves all three so the wire behaviour has exactly
 * one definition.
 */
static void eip712_pump(void) {
  const Eip712Next* next = eip712_stream_next();

  switch (next->kind) {
    case EIP712_REQ_DEFINITION: {
      Eip712DomainFacts facts;
      Erc7730CatalogIdentity identity;
      if (!eip712_stream_domain_facts(&facts) || !facts.has_chain_id ||
          !facts.has_primary_type_hash ||
          !erc7730_catalog_preloaded(&identity) ||
          !erc7730_catalog_matches_eip712(
              &identity, facts.chain_id, facts.verifying_contract,
              facts.has_verifying_contract, facts.primary_type_hash) ||
          !erc7730_workflow_begin_eip712(erc7730_workflow_state(), &identity)) {
        memzero(&facts, sizeof(facts));
        memzero(&identity, sizeof(identity));
        eip712_stream_abort();
        erc7730_workflow_abort(erc7730_workflow_state());
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("ERC-7730 definition does not match typed data"));
        layout_home();
        return;
      }
      memzero(&facts, sizeof(facts));
      memzero(&identity, sizeof(identity));
      send_erc7730_definition_request();
      return;
    }
    case EIP712_REQ_STRUCT: {
      RESP_INIT(EthereumTypedDataStructRequest);
      strlcpy(resp->name, next->struct_name, sizeof(resp->name));
      msg_write(MessageType_MessageType_EthereumTypedDataStructRequest, resp);
      return;
    }
    case EIP712_REQ_VALUE: {
      RESP_INIT(EthereumTypedDataValueRequest);
      resp->member_path_count = next->member_path_len;
      memcpy(resp->member_path, next->member_path,
             next->member_path_len * sizeof(uint32_t));
      msg_write(MessageType_MessageType_EthereumTypedDataValueRequest, resp);
      return;
    }
    case EIP712_REQ_DONE: {
      Erc7730Workflow* workflow = erc7730_workflow_state();
      if (workflow->phase == ERC7730_WORKFLOW_TYPED_DATA) {
        char formatted[ERC7730_FORMATTED_VALUE_MAX + 1u];
        if (!erc7730_workflow_eip712_finish(workflow) ||
            !erc7730_workflow_format_captured_raw(workflow, formatted,
                                                  sizeof(formatted))) {
          memzero(formatted, sizeof(formatted));
          erc7730_workflow_abort(workflow);
          fsm_sendFailure(FailureType_Failure_SyntaxError,
                          _("Certified EIP-712 value was not found"));
          layout_home();
          return;
        }
        const bool confirmed =
            confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                    workflow->label, "%s", formatted);
        memzero(formatted, sizeof(formatted));
        erc7730_workflow_abort(workflow);
        if (!confirmed) {
          fsm_sendFailure(FailureType_Failure_ActionCancelled,
                          _("Signing cancelled by user"));
          layout_home();
          return;
        }
      }
      /* sign(keccak(0x19 || 0x01 || domainSeparator || hashStruct(message))) */
      uint8_t preimage[66];
      preimage[0] = 0x19;
      preimage[1] = 0x01;
      memcpy(preimage + 2, next->domain_separator, 32);
      memcpy(preimage + 34, next->message_hash, 32);
      uint8_t sighash[32];
      keccak_256(preimage, sizeof(preimage), sighash);

      /* Not const: node is the shared fsm_derived_node scratch and holds a
       * private key, so every exit below scrubs it (same rule as
       * process_ethereum_xfer(); 7.15 audit F059). */
      HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, next->address_n,
                                        next->address_n_count, NULL);
      if (!node) return;

      RESP_INIT(EthereumTypedDataSignature);
      uint8_t pubkeyhash[20];
      if (!hdnode_get_ethereum_pubkeyhash(node, pubkeyhash)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_Other,
                        _("Ethereum address derivation failed"));
        layout_home();
        return;
      }
      resp->address[0] = '0';
      resp->address[1] = 'x';
      ethereum_address_checksum(pubkeyhash, resp->address + 2, false, 0);

      uint8_t sig[64];
      uint8_t v = 0;
      if (ecdsa_sign_digest(&secp256k1, node->private_key, sighash, sig, &v,
                            NULL) != 0) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_Other, _("Signing failed"));
        layout_home();
        return;
      }
      memzero(node, sizeof(*node));
      resp->signature.size = 65;
      memcpy(resp->signature.bytes, sig, 64);
      resp->signature.bytes[64] = 27 + v;
      resp->has_domain_separator_hash = true;
      resp->domain_separator_hash.size = 32;
      memcpy(resp->domain_separator_hash.bytes, next->domain_separator, 32);
      resp->has_msg_hash = true;
      resp->has_message_hash = true;
      resp->message_hash.size = 32;
      memcpy(resp->message_hash.bytes, next->message_hash, 32);
      msg_write(MessageType_MessageType_EthereumTypedDataSignature, resp);
      layout_home();
      return;
    }
    case EIP712_REQ_CANCELLED:
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("EIP-712 cancelled"));
      layout_home();
      return;
    case EIP712_REQ_FAIL:
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      next->error ? next->error : "EIP-712 error");
      layout_home();
      return;
    default:
      fsm_sendFailure(FailureType_Failure_Other, _("EIP-712 internal state"));
      layout_home();
      return;
  }
}

void fsm_msgEthereumSignTypedData(const EthereumSignTypedData* msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  /* This is the canonical device-driven stream, not the withdrawn whole-JSON
   * parser and not the blind typed-hash endpoint. Every leaf is validated,
   * rendered and hashed from the same bytes, so AdvancedMode is neither needed
   * nor consulted. */
  if (!ethereum_streamed_eip712_enabled()) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Structured EIP-712 is unavailable"));
    layout_home();
    return;
  }

  Erc7730CatalogIdentity definition;
  const bool certified = erc7730_catalog_preloaded(&definition);
  memzero(&definition, sizeof(definition));
  eip712_stream_begin(msg, certified);
  eip712_pump();
}

void fsm_msgEthereumTypedDataStructAck(const EthereumTypedDataStructAck* msg) {
  CHECK_INITIALIZED
  eip712_stream_on_struct(msg);
  eip712_pump();
}

void fsm_msgEthereumTypedDataValueAck(const EthereumTypedDataValueAck* msg) {
  CHECK_INITIALIZED
  uint32_t member_path[EIP712_MAX_DEPTH + 2];
  size_t member_path_count = 0;
  const Eip712Next* requested = eip712_stream_next();
  if (requested->kind == EIP712_REQ_VALUE) {
    member_path_count = requested->member_path_len;
    memcpy(member_path, requested->member_path,
           member_path_count * sizeof(uint32_t));
  }
  if (!eip712_stream_on_value(msg)) {
    memzero(member_path, sizeof(member_path));
    eip712_pump();
    return;
  }
  Erc7730Workflow* workflow = erc7730_workflow_state();
  if (workflow->phase == ERC7730_WORKFLOW_TYPED_DATA &&
      !erc7730_workflow_eip712_observe(workflow, member_path, member_path_count,
                                       msg->value.bytes, msg->value.size)) {
    memzero(member_path, sizeof(member_path));
    eip712_stream_abort();
    erc7730_workflow_abort(workflow);
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("EIP-712 value does not match certified definition"));
    layout_home();
    return;
  }
  memzero(member_path, sizeof(member_path));
  eip712_pump();
}
