
#include "keepkey/firmware/erc7730_capabilities.h"
#include "keepkey/firmware/erc7730_field.h"
#include "keepkey/firmware/erc7730_workflow.h"

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

static int process_ethereum_xfer(const CoinType* coin, EthereumSignTx* msg,
                                 bool* needs_confirm) {
  /* Account routing accepts only a complete canonical ERC20 transfer. Check
   * the declared total too, so streaming a suffix cannot change the signing
   * classifier after the account confirmation has replaced output review. */
  if ((msg->data_length != 0 || msg->data_initial_chunk.size != 0) &&
      (msg->data_length != 68 || !ethereum_isStandardERC20Transfer(msg)))
    return TXOUT_COMPILE_ERROR;

  char node_str[NODE_STRING_LENGTH];
  if (!bip32_node_to_string(node_str, sizeof(node_str), coin, msg->to_address_n,
                            msg->to_address_n_count, /*whole_account=*/false,
                            /*show_addridx=*/false))
    return TXOUT_COMPILE_ERROR;

  char amount_str[128 + sizeof(msg->token_shortcut) + 3];
  const bool amount_is_reviewable =
      ethereumFormatTransferAmount(msg, amount_str, sizeof(amount_str));
  if (!amount_is_reviewable &&
      !(ethereum_isStandardERC20Transfer(msg) &&
        tokenByChainAddress(msg->chain_id, msg->to.bytes) == UnknownToken)) {
    return TXOUT_COMPILE_ERROR;
  }
  if (amount_is_reviewable) {
    if (!confirm_transfer_output(
            ButtonRequestType_ButtonRequest_ConfirmTransferToAccount,
            amount_str, node_str))
      return TXOUT_CANCEL;
    *needs_confirm = false;
  }

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
    fsm_clearDerivedNode();
    return TXOUT_COMPILE_ERROR;
  }

  if (ethereum_isStandardERC20Transfer(msg)) {
    if (memcmp(msg->data_initial_chunk.bytes + 4 + (32 - 20), to_bytes, 20) !=
        0) {
      fsm_clearDerivedNode();
      return TXOUT_COMPILE_ERROR;
    }
  } else {
    msg->has_to = true;
    msg->to.size = 20;
    memcpy(msg->to.bytes, to_bytes, sizeof(to_bytes));
  }

  fsm_clearDerivedNode();
  return TXOUT_OK;
}

static int process_ethereum_msg(EthereumSignTx* msg, bool* needs_confirm) {
  const CoinType* coin = fsm_getCoin(true, ETHEREUM);
  if (!coin) return TXOUT_COMPILE_ERROR;

  switch (msg->address_type) {
    case OutputAddressType_TRANSFER: {
      // prep transfer type transaction
      return process_ethereum_xfer(coin, msg, needs_confirm);
    }
    default:
      return TXOUT_OK;
  }
}

static void eip712_pump(void);
static void fail_erc7730_field(Erc7730Workflow* workflow, FailureType type,
                               const char* message);

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
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Invalid ERC-7730 replay state"));
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
  note_workflow_progress();
  msg_write(MessageType_MessageType_EthereumClearSignDefinitionRequest, resp);
}

/* Request the inner definition by the signed calldata's (chain, callee,
 * selector), or the outer one by id. An empty chunk means "none". */
static void send_erc7730_fetch_request(void) {
  Erc7730Workflow* workflow = erc7730_workflow_state();
  if (workflow->phase != ERC7730_WORKFLOW_FETCH ||
      (workflow->fetch_total != 0 &&
       workflow->fetch_offset >= workflow->fetch_total)) {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Invalid ERC-7730 replay state"));
    return;
  }
  RESP_INIT(EthereumClearSignDefinitionRequest);
  resp->kind = EthereumClearSignDefinitionKind_ERC7730_CALLDATA;
  resp->chain_id = workflow->identity.chain_id;
  if (workflow->fetch_depth == 1) {
    resp->has_contract_address = true;
    resp->contract_address.size = 20;
    memcpy(resp->contract_address.bytes, workflow->field.address, 20);
    resp->has_selector_or_type_hash = true;
    resp->selector_or_type_hash.size = 4;
    memcpy(resp->selector_or_type_hash.bytes, workflow->field.inner_selector,
           4);
    resp->has_recursion_depth = true;
    resp->recursion_depth = 1;
  } else {
    resp->has_definition_id = true;
    resp->definition_id.size = 32;
    memcpy(resp->definition_id.bytes, workflow->outer_definition_id, 32);
  }
  resp->offset = workflow->fetch_offset;
  const uint32_t remaining =
      workflow->fetch_total ? workflow->fetch_total - workflow->fetch_offset
                            : ERC7730_TRANSPORT_CHUNK_MAX;
  resp->length = remaining < ERC7730_TRANSPORT_CHUNK_MAX
                     ? remaining
                     : ERC7730_TRANSPORT_CHUNK_MAX;
  note_workflow_progress();
  msg_write(MessageType_MessageType_EthereumClearSignDefinitionRequest, resp);
}

static void send_erc7730_calldata_request(void) {
  size_t remaining = 0;
  if (!erc7730_workflow_calldata_waiting(erc7730_workflow_state(),
                                         &remaining)) {
    fail_erc7730_field(erc7730_workflow_state(),
                       FailureType_Failure_SyntaxError,
                       _("Invalid ERC-7730 calldata state"));
    return;
  }
  RESP_INIT(EthereumTxRequest);
  resp->has_data_length = true;
  resp->data_length = remaining < ERC7730_TRANSPORT_CHUNK_MAX
                          ? remaining
                          : ERC7730_TRANSPORT_CHUNK_MAX;
  note_workflow_progress();
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

typedef enum {
  ERC7730_UI_OK,
  ERC7730_UI_INVALID,
  ERC7730_UI_CANCELLED,
} Erc7730UiResult;

/* The end of the longest part of `value` starting at `offset` that fits
 * `budget` characters without cutting an erc7730_format_text() escape. */
static size_t erc7730_part_end(const char* value, size_t offset,
                               size_t budget) {
  size_t end = offset;
  while (value[end]) {
    const size_t step =
        value[end] != '\\' ? 1u : (value[end + 1] == 'x' ? 4u : 2u);
    if (end + step - offset > budget) break;
    end += step;
  }
  /* Split between lines when there is one: a number, an address or a token
   * name is never cut across two screens unless its own line is too long. */
  if (value[end]) {
    for (size_t i = end; i > offset + 1u; i--)
      if (value[i - 1u] == '\n') return i;
  }
  return end;
}

/* Escaped `text` under a device-owned title; over-long text is split across
 * numbered screens, each repeating the label and each confirmed. */
static bool confirm_erc7730_text(const char* title, const char* label,
                                 const char* text) {
  const size_t label_length = label ? strlen(label) + 2u : 0u; /* ":\n" */
  const size_t text_length = strlen(text);
  if ((label && label_length == 2u) || label_length + 1u + 4u >= BODY_CHAR_MAX)
    return false;
  const size_t budget = BODY_CHAR_MAX - 1u - label_length;
  if (text_length <= budget)
    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                   "%s%s%s", label ? label : "", label ? ":\n" : "", text);
  size_t parts = 0;
  for (size_t offset = 0; offset < text_length;
       offset = erc7730_part_end(text, offset, budget))
    parts++;
  if (parts > 999) return false;
  char numbered[TITLE_CHAR_MAX];
  size_t offset = 0;
  for (size_t i = 0; i < parts; i++) {
    const size_t end = erc7730_part_end(text, offset, budget);
    snprintf(numbered, sizeof(numbered), "%s (%u/%u)", title,
             (unsigned)(i + 1u), (unsigned)parts);
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, numbered,
                 "%s%s%.*s", label ? label : "", label ? ":\n" : "",
                 (int)(end - offset), text + offset))
      return false;
    offset = end;
  }
  return true;
}

/* Signer-authored strings are escaped as labels: raw text is not shown
 * one-to-one (non-ASCII glyphs, dropped edge spaces). */
static bool confirm_erc7730_escaped(const char* title, const char* label,
                                    const char* raw) {
  char text[ERC7730_FORMATTED_VALUE_MAX + 1u];
  const bool shown = erc7730_format_label((const uint8_t*)raw, strlen(raw),
                                          text, sizeof(text)) &&
                     confirm_erc7730_text(title, label, text);
  memzero(text, sizeof(text));
  return shown;
}

static Erc7730UiResult confirm_erc7730_source_and_intent(
    Erc7730Workflow* workflow) {
  if (!workflow ||
      (!workflow->intent_confirmed && workflow->intent[0] == '\0') ||
      workflow->identity.delegate_alias[0] == '\0' ||
      workflow->identity.delegate_fingerprint[0] == '\0')
    return ERC7730_UI_INVALID;
  const bool inner = workflow->depth != 0;
  if (!workflow->identity_confirmed) {
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 inner ? "Inner signer" : "Runtime signer", "%s (%s)",
                 workflow->identity.delegate_alias,
                 workflow->identity.delegate_fingerprint) ||
        !confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Unverified data", "NOT verified by KeepKey"))
      return ERC7730_UI_CANCELLED;
    workflow->identity_confirmed = true;
  }
  if (!workflow->intent_confirmed) {
    if (!confirm_erc7730_escaped(inner ? "Inner action" : "Contract action",
                                 NULL, workflow->intent))
      return ERC7730_UI_CANCELLED;
    workflow->intent_confirmed = true;
  }
  return ERC7730_UI_OK;
}

/* Device-owned title: a signer label there could imitate a firmware screen,
 * so the escaped label leads the body. `value` is already escaped. */
static bool confirm_erc7730_field(const char* title, const char* label,
                                  const char* value) {
  char escaped[ERC7730_FORMATTED_VALUE_MAX + 1u];
  const bool shown = erc7730_format_label((const uint8_t*)label, strlen(label),
                                          escaped, sizeof(escaped)) &&
                     confirm_erc7730_text(title, escaped, value);
  memzero(escaped, sizeof(escaped));
  return shown;
}

static void start_erc7730_calldata(Erc7730Workflow* workflow,
                                   const Erc7730Path* path);
static void resolve_erc7730_argument(Erc7730Workflow* workflow);

/* A failure while resolving a field ends the workflow, and with it any
 * typed-data review the field belongs to. */
static void fail_erc7730_field(Erc7730Workflow* workflow, FailureType type,
                               const char* message) {
  const bool typed = workflow->typed_data;
  erc7730_workflow_abort(workflow);
  if (typed) eip712_stream_abort();
  fsm_sendFailure(type, message);
  layoutHome();
}

/* A refused source/intent screen: invalid identity or a user decline. */
static void fail_erc7730_ui(Erc7730Workflow* workflow, Erc7730UiResult ui) {
  fail_erc7730_field(
      workflow,
      ui == ERC7730_UI_INVALID ? FailureType_Failure_SyntaxError
                               : FailureType_Failure_ActionCancelled,
      ui == ERC7730_UI_INVALID ? _("Invalid ERC-7730 signer or intent")
                               : _("Signing cancelled by user"));
}

typedef enum {
  ERC7730_SIGNER_OK,
  ERC7730_SIGNER_FAILED,
  ERC7730_SIGNER_REPORTED, /* fsm_getDerivedNode() already sent a Failure */
} Erc7730SignerResult;

/* The signing account's address, derived on device. The node is scrubbed
 * before returning, so no key material is held across a confirmation. */
static Erc7730SignerResult erc7730_signer_address(
    const Erc7730Workflow* workflow, uint8_t address[20]) {
  uint32_t address_n[8];
  size_t count = 0;
  if (workflow->typed_data) {
    if (!eip712_stream_signer_path(address_n, &count))
      return ERC7730_SIGNER_FAILED;
  } else {
    EthereumSignTx tx;
    const bool restored =
        erc7730_tx_continuation_restore(&workflow->continuation, &tx) &&
        tx.address_n_count <= sizeof(address_n) / sizeof(address_n[0]);
    if (restored) {
      count = tx.address_n_count;
      memcpy(address_n, tx.address_n, count * sizeof(address_n[0]));
    }
    memzero(&tx, sizeof(tx));
    if (!restored) return ERC7730_SIGNER_FAILED;
  }
  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, address_n, count, NULL);
  if (!node) return ERC7730_SIGNER_REPORTED;
  const bool derived = hdnode_get_ethereum_pubkeyhash(node, address);
  memzero(node, sizeof(*node));
  return derived ? ERC7730_SIGNER_OK : ERC7730_SIGNER_FAILED;
}

/* Show one fully resolved field, then move to the next display instruction.
 * `formatted` is already escaped. */
static void show_erc7730_field(Erc7730Workflow* workflow,
                               const char* formatted) {
  const Erc7730UiResult ui = confirm_erc7730_source_and_intent(workflow);
  if (ui != ERC7730_UI_OK) {
    fail_erc7730_ui(workflow, ui);
    return;
  }
  bool confirmed;
  if (workflow->intent_part != 0) {
    /* Interpolated intent part: device-owned "i of n" title (never the
     * pager's "i/n"), no label. */
    char title[TITLE_CHAR_MAX];
    snprintf(title, sizeof(title), "%s%s %u of %u",
             workflow->depth ? "Inner" : "Intent",
             workflow->intent_value ? " value" : " text",
             (unsigned)workflow->intent_part, (unsigned)workflow->intent_parts);
    confirmed = confirm_erc7730_text(title, NULL, formatted);
  } else if (workflow->iterating) {
    /* One screen per element of the array, numbered by the device. */
    char title[TITLE_CHAR_MAX];
    snprintf(title, sizeof(title),
             workflow->depth ? "Inner field %u of %u" : "Signer field %u of %u",
             (unsigned)workflow->iteration_index + 1u,
             (unsigned)workflow->iteration_count);
    confirmed = confirm_erc7730_field(title, workflow->label, formatted);
  } else {
    confirmed =
        confirm_erc7730_field(workflow->depth ? "Inner field" : "Signer field",
                              workflow->label, formatted);
  }
  if (!confirmed) {
    fail_erc7730_field(workflow, FailureType_Failure_ActionCancelled,
                       _("Signing cancelled by user"));
    return;
  }
  if (!erc7730_workflow_advance_display(workflow)) {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Invalid ERC-7730 display continuation"));
    return;
  }
  send_erc7730_definition_request();
}

/* A raw or addressName value that is an address. */
static void show_erc7730_address(Erc7730Workflow* workflow,
                                 const uint8_t address[20]) {
  bool this_wallet = false;
  if (workflow->field.kind == 10) {
    uint8_t signer[20];
    const Erc7730SignerResult result = erc7730_signer_address(workflow, signer);
    if (result != ERC7730_SIGNER_OK) {
      memzero(signer, sizeof(signer));
      if (result == ERC7730_SIGNER_REPORTED) {
        const bool typed = workflow->typed_data;
        erc7730_workflow_abort(workflow);
        if (typed) eip712_stream_abort();
      } else {
        fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                           _("Unable to derive the signing address"));
      }
      return;
    }
    this_wallet = memcmp(signer, address, 20) == 0;
    memzero(signer, sizeof(signer));
  }
  char formatted[64];
  if (!erc7730_format_address(address, this_wallet, formatted,
                              sizeof(formatted))) {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Unable to format ERC-7730 field"));
    return;
  }
  show_erc7730_field(workflow, formatted);
}

/* Render the field's value word as raw does, for an enum's value. */
static bool format_erc7730_word(const Erc7730Field* field, char* output,
                                size_t output_size) {
  const Erc7730AbiNode node = {field->value_class,
                               field->value_class == ERC7730_ABI_BOOL ? 0 : 256,
                               0, 0, 0};
  const Erc7730AbiProgram program = {&node, 1, 0};
  Erc7730AbiCapture word;
  memcpy(word.data, field->value, 32);
  word.length = 32;
  word.node = 0;
  const bool ok = erc7730_format_raw(&program, &word, output, output_size);
  memzero(&word, sizeof(word));
  return ok;
}

/* A multi-argument field; `text` is its one named program string
 * (unescaped) or NULL. */
static void show_erc7730_value(Erc7730Workflow* workflow, const char* text) {
  const Erc7730Field* field = &workflow->field;
  char escaped[ERC7730_FORMATTED_VALUE_MAX + 1u];
  char formatted[ERC7730_FORMATTED_VALUE_MAX + 1u];
  bool ok = field->has_value &&
            (!text || erc7730_format_label((const uint8_t*)text, strlen(text),
                                           escaped, sizeof(escaped)));
  const uint64_t chain_id = workflow->identity.chain_id;
  if (ok) {
    switch (field->kind) {
      case 2:
        ok = erc7730_format_native_amount(field->value, chain_id, formatted,
                                          sizeof(formatted));
        break;
      case 3:
        ok = field->has_address &&
             erc7730_format_token_amount(
                 field->value, field->address, field->token_native, chain_id,
                 text ? escaped : NULL, formatted, sizeof(formatted));
        break;
      case 4:
        ok = field->has_address &&
             erc7730_format_nft(field->value, field->address, formatted,
                                sizeof(formatted));
        break;
      case 5: {
        /* The verifier admitted only "timestamp" and "blockheight". */
        const bool block_height = text && strcmp(text, "blockheight") == 0;
        ok = (!text || block_height || strcmp(text, "timestamp") == 0) &&
             erc7730_format_date(field->value, block_height, formatted,
                                 sizeof(formatted));
        break;
      }
      case 6:
        ok =
            erc7730_format_duration(field->value, formatted, sizeof(formatted));
        break;
      case 7:
        ok = text && erc7730_format_unit(field->value, field->decimals, escaped,
                                         formatted, sizeof(formatted));
        break;
      case 8: {
        char
            value[80]; /* an integer or a boolean: at most 78 digits and sign */
        ok = format_erc7730_word(field, value, sizeof(value)) &&
             erc7730_format_enum(value, text ? escaped : NULL, formatted,
                                 sizeof(formatted));
        memzero(value, sizeof(value));
        break;
      }
      default:
        ok = false;
    }
  }
  memzero(escaped, sizeof(escaped));
  if (!ok) {
    memzero(formatted, sizeof(formatted));
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Unable to format ERC-7730 field"));
    return;
  }
  show_erc7730_field(workflow, formatted);
  memzero(formatted, sizeof(formatted));
}

/* An embedded call that cannot be clear-signed: 7.15 shows it under a
 * blind-sign warning. 7.16 must reject here (AdvancedMode hard gate). */
static void show_erc7730_embedded(Erc7730Workflow* workflow) {
  workflow->inner_refused = false; /* consumed: the next call may fetch */
  const Erc7730Field* field = &workflow->field;
  char formatted[ERC7730_FORMATTED_VALUE_MAX + 1u];
  if (!field->has_inner || !field->has_address ||
      !erc7730_format_embedded(
          field->address, field->inner_selector, field->inner_selector_length,
          field->inner_length, field->has_value ? field->value : NULL,
          workflow->identity.chain_id,
          field->has_spender ? field->spender : NULL, formatted,
          sizeof(formatted))) {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Unable to format ERC-7730 field"));
    return;
  }
  const Erc7730UiResult ui = confirm_erc7730_source_and_intent(workflow);
  if (ui != ERC7730_UI_OK) {
    memzero(formatted, sizeof(formatted));
    fail_erc7730_ui(workflow, ui);
    return;
  }
  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Blind signature",
               "The inner call is not clear-signed")) {
    memzero(formatted, sizeof(formatted));
    fail_erc7730_field(workflow, FailureType_Failure_ActionCancelled,
                       _("Signing cancelled by user"));
    return;
  }
  show_erc7730_field(workflow, formatted);
  memzero(formatted, sizeof(formatted));
}

/* A value longer than the device captures: 7.15 shows its length under a
 * blind-sign warning. 7.16 must reject here (AdvancedMode hard gate). */
static void show_erc7730_long_value(Erc7730Workflow* workflow, size_t length) {
  char formatted[48];
  const Erc7730UiResult ui = confirm_erc7730_source_and_intent(workflow);
  if (ui != ERC7730_UI_OK) {
    fail_erc7730_ui(workflow, ui);
    return;
  }
  /* Typed data: the walk that captured this value has just shown every leaf
   * in full, this one among them, so nothing is blind. */
  const bool typed = workflow->typed_data;
  if (!typed && !confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                         "Blind signature", "The value is too long to show")) {
    fail_erc7730_field(workflow, FailureType_Failure_ActionCancelled,
                       _("Signing cancelled by user"));
    return;
  }
  snprintf(formatted, sizeof(formatted),
           typed ? "Shown above in full: %lu bytes" : "Not shown: %lu bytes",
           (unsigned long)length);
  show_erc7730_field(workflow, formatted);
}

/* Record an argument's value and resolve the next argument. */
static void deliver_erc7730_argument(Erc7730Workflow* workflow, uint8_t cls,
                                     const uint8_t* value, size_t length) {
  if (!erc7730_workflow_field_value(workflow, cls, value, length)) {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Invalid ERC-7730 formatter argument"));
    return;
  }
  resolve_erc7730_argument(workflow);
}

/* A value captured from calldata or typed data has arrived. */
static void deliver_erc7730_capture(Erc7730Workflow* workflow) {
  Erc7730AbiCapture capture;
  uint8_t cls = 0;
  if (!erc7730_workflow_captured(workflow, &capture, &cls) ||
      !erc7730_cap_value(workflow->field.kind, workflow->field.pending_role,
                         cls)) {
    memzero(&capture, sizeof(capture));
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Unable to format ERC-7730 field"));
    return;
  }
  if (workflow->field.kind == 10) {
    /* An address word: twelve zero bytes, then the address. */
    bool clean = capture.length == 32;
    for (size_t i = 0; clean && i < 12; i++) clean = capture.data[i] == 0;
    if (!clean) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Unable to format ERC-7730 field"));
    } else {
      show_erc7730_address(workflow, capture.data + 12);
    }
  } else if (workflow->field.kind == 1 && workflow->calldata.capture_overflow) {
    show_erc7730_long_value(workflow, workflow->calldata.located_length);
  } else if (workflow->field.kind == 1) {
    char formatted[ERC7730_FORMATTED_VALUE_MAX + 1u];
    if (!erc7730_workflow_format_captured_raw(workflow, formatted,
                                              sizeof(formatted))) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Unable to format ERC-7730 field"));
    } else {
      show_erc7730_field(workflow, formatted);
    }
    memzero(formatted, sizeof(formatted));
  } else if (workflow->field.kind == 13 && workflow->field.pending_role == 1) {
    /* The inner call: located, never copied. */
    if (!erc7730_workflow_field_embedded(workflow) ||
        !erc7730_workflow_resume_field(workflow)) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Invalid ERC-7730 embedded call"));
    } else {
      resolve_erc7730_argument(workflow);
    }
  } else if (!erc7730_workflow_resume_field(workflow)) {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Invalid ERC-7730 display continuation"));
  } else {
    deliver_erc7730_argument(workflow, cls, capture.data, capture.length);
  }
  memzero(&capture, sizeof(capture));
}

/* Select the next literal of the field's list (native aliases or enum keys),
 * one replay each. */
static bool select_next_erc7730_list_item(Erc7730Workflow* workflow,
                                          uint8_t stage) {
  Erc7730Field* field = &workflow->field;
  const uint16_t literal = stage == ERC7730_DISPLAY_ARG_ALIAS
                               ? field->list.aliases[field->list_next]
                               : field->list.enum_entries[field->list_next][0];
  field->list_next++;
  if (!erc7730_workflow_select_literal(workflow, literal)) {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Invalid ERC-7730 formatter argument"));
    return false;
  }
  workflow->display_stage = stage;
  send_erc7730_definition_request();
  return true;
}

static void next_erc7730_alias(Erc7730Workflow* workflow) {
  const Erc7730Field* field = &workflow->field;
  if (field->token_native || field->list_next >= field->list_count) {
    resolve_erc7730_argument(workflow);
    return;
  }
  select_next_erc7730_list_item(workflow, ERC7730_DISPLAY_ARG_ALIAS);
}

static void next_erc7730_enum_key(Erc7730Workflow* workflow) {
  const Erc7730Field* field = &workflow->field;
  if (field->list_next >= field->list_count) {
    show_erc7730_value(workflow, NULL); /* unmapped */
    return;
  }
  select_next_erc7730_list_item(workflow, ERC7730_DISPLAY_ARG_ENUM_KEY);
}

/* Fetch one string an argument named, then show the field with it. */
static void fetch_erc7730_text(Erc7730Workflow* workflow, uint16_t index) {
  if (!erc7730_workflow_select_string(workflow, index)) {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Invalid ERC-7730 formatter argument"));
    return;
  }
  workflow->display_stage = ERC7730_DISPLAY_ARG_MESSAGE;
  send_erc7730_definition_request();
}

/* Fetch the next argument in role order (value first, string last; a
 * tokenAmount message only when the threshold is met). */
static void resolve_erc7730_argument(Erc7730Workflow* workflow) {
  Erc7730Field* field = &workflow->field;
  while (field->next_argument < field->argument_count) {
    const Erc7730FormatterArgument* argument =
        &field->arguments[field->next_argument++];
    field->pending_role = argument->role;
    if (argument->source == 3) {
      field->text = argument->index;
      field->has_text = true;
      continue;
    }
    bool selected = false;
    if (argument->source == 1) {
      selected = erc7730_workflow_select_path(workflow, argument->index);
      workflow->display_stage = ERC7730_DISPLAY_PATH;
    } else if (argument->source == 2) {
      selected = erc7730_workflow_select_literal(workflow, argument->index);
      workflow->display_stage = ERC7730_DISPLAY_ARG_LITERAL;
    }
    if (!selected) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Invalid ERC-7730 formatter argument"));
      return;
    }
    send_erc7730_definition_request();
    return;
  }
  if (field->kind == 13) {
    /* An inner approve(spender, 2^256-1) signs only after the device's own
     * UNLIMITED warning, before its inner or blind screens. */
    if (field->unlimited_approve && field->has_address) {
      const Erc7730UiResult ui = confirm_erc7730_source_and_intent(workflow);
      if (ui != ERC7730_UI_OK) {
        fail_erc7730_ui(workflow, ui);
        return;
      }
      if (!ethereum_confirmUnlimitedApproval(
              (uint32_t)workflow->identity.chain_id, field->approve_spender,
              field->address)) {
        fail_erc7730_field(workflow, FailureType_Failure_ActionCancelled,
                           _("Signing cancelled by user"));
        return;
      }
    }
    /* Clear-sign the inner call at depth 1, outside iterations, for whole ABI
     * words; otherwise it is shown blind (7.15). */
    const bool fetchable = workflow->depth == 0 && !workflow->iterating &&
                           !workflow->inner_refused && field->has_address &&
                           field->inner_selector_length == 4 &&
                           field->inner_length >= 4 &&
                           (field->inner_length - 4u) % 32u == 0;
    if (!fetchable) {
      show_erc7730_embedded(workflow);
      return;
    }
    /* The outer signer and intent come first: the fetch replaces the
     * preloaded definition. */
    const Erc7730UiResult ui = confirm_erc7730_source_and_intent(workflow);
    if (ui != ERC7730_UI_OK) {
      fail_erc7730_ui(workflow, ui);
      return;
    }
    if (!erc7730_workflow_begin_fetch(workflow, 1)) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Invalid ERC-7730 embedded call"));
      return;
    }
    send_erc7730_fetch_request();
  } else if (field->kind == 8) {
    field->list_next = 0;
    next_erc7730_enum_key(workflow);
  } else if (field->has_text &&
             (field->kind != 3 || field->threshold_reached)) {
    fetch_erc7730_text(workflow, field->text);
  } else if (field->kind == 7) {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Invalid ERC-7730 formatter argument"));
  } else {
    show_erc7730_value(workflow, NULL);
  }
}

/* A raw or addressName value that did not come from a capture. */
static void show_erc7730_single(Erc7730Workflow* workflow, uint8_t cls,
                                const uint8_t* value, size_t length) {
  if (cls == ERC7730_CLASS_ADDRESS && length == 20) {
    show_erc7730_address(workflow, value);
    return;
  }
  if (workflow->field.kind != 1 ||
      (cls != ERC7730_CLASS_UINT && cls != ERC7730_CLASS_UINT_SMALL) ||
      length > 32) {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Invalid ERC-7730 formatter argument"));
    return;
  }
  /* An integer: format it through a uint256 node, as a captured word. */
  static const Erc7730AbiNode uint256 = {ERC7730_ABI_UINT, 256, 0, 0, 0};
  const Erc7730AbiProgram program = {&uint256, 1, 0};
  Erc7730AbiCapture word = {{0}, 32, 0};
  memcpy(word.data + 32 - length, value, length);
  char formatted[80];
  if (erc7730_format_raw(&program, &word, formatted, sizeof(formatted))) {
    show_erc7730_field(workflow, formatted);
  } else {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Unable to format ERC-7730 field"));
  }
  memzero(&word, sizeof(word));
  memzero(formatted, sizeof(formatted));
}

/* A value path has been selected: capture it, read the container, or fetch
 * the literal it names. */
static void follow_erc7730_path(Erc7730Workflow* workflow,
                                const Erc7730Path* path) {
  if (!erc7730_cap_path(path)) {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Invalid ERC-7730 value path"));
    return;
  }
  if (path->source == 3) {
    if (!erc7730_workflow_select_literal(workflow, path->source_index)) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Invalid ERC-7730 value path"));
      return;
    }
    workflow->display_stage = ERC7730_DISPLAY_ARG_LITERAL;
    send_erc7730_definition_request();
    return;
  }
  if (path->source == 2) {
    /* Containers are calldata-only (refused at preload for typed data). */
    uint8_t value[32];
    size_t length = 0;
    uint8_t cls = ERC7730_CLASS_ADDRESS;
    if (workflow->typed_data) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Invalid ERC-7730 value path"));
      return;
    }
    if (workflow->depth == 1) {
      /* Inside an inner call its own context stands in for the transaction.
       */
      if (path->source_index == 3) {
        memcpy(value, workflow->inner_value, 32);
        length = 32;
        cls = ERC7730_CLASS_UINT;
      } else {
        memcpy(
            value,
            path->source_index == 1 ? workflow->inner_from : workflow->inner_to,
            20);
        length = 20;
      }
    } else if (path->source_index == 1) {
      const Erc7730SignerResult result =
          erc7730_signer_address(workflow, value);
      if (result == ERC7730_SIGNER_REPORTED) {
        erc7730_workflow_abort(workflow);
        return;
      }
      if (result != ERC7730_SIGNER_OK) {
        memzero(value, sizeof(value));
        fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                           _("Unable to derive the signing address"));
        return;
      }
      length = 20;
    } else {
      EthereumSignTx tx;
      bool restored =
          erc7730_tx_continuation_restore(&workflow->continuation, &tx);
      if (restored && path->source_index == 2) {
        restored = tx.has_to && tx.to.size == 20;
        if (restored) memcpy(value, tx.to.bytes, 20);
        length = 20;
      } else if (restored) { /* @.value: an unsigned word */
        restored = tx.value.size <= 32;
        if (restored) {
          memzero(value, sizeof(value));
          memcpy(value + 32 - tx.value.size, tx.value.bytes, tx.value.size);
        }
        length = 32;
        cls = ERC7730_CLASS_UINT;
      }
      memzero(&tx, sizeof(tx));
      if (!restored) {
        fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                           _("Invalid ERC-7730 value path"));
        return;
      }
    }
    if (workflow->field.kind == 1 || workflow->field.kind == 10) {
      show_erc7730_single(workflow, cls, value, length);
    } else {
      deliver_erc7730_argument(workflow, cls, value, length);
    }
    memzero(value, sizeof(value));
    return;
  }
  if (workflow->typed_data) {
    if (!erc7730_workflow_start_eip712_capture(workflow, path) ||
        !eip712_stream_resume_for_field()) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Unsupported ERC-7730 typed-data path"));
      return;
    }
    eip712_pump();
  } else {
    start_erc7730_calldata(workflow, path);
  }
}

/* A literal argument, or the literal a path names, has been selected. */
static void follow_erc7730_literal(Erc7730Workflow* workflow) {
  Erc7730Literal literal;
  if (!erc7730_program_literal_complete(&workflow->selection.literal,
                                        &literal)) {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Invalid ERC-7730 formatter argument"));
    return;
  }
  Erc7730Field* field = &workflow->field;
  const uint16_t count =
      (literal.kind == 8 || literal.kind == 9) && literal.length >= 2
          ? (uint16_t)((literal.value[0] << 8) | literal.value[1])
          : 0;
  const uint8_t cls = erc7730_cap_literal_class(
      literal.kind, literal.kind == 1 ? literal.length : count);
  const size_t stride = literal.kind == 8 ? 4u : 2u;
  if (!erc7730_cap_value(field->kind, field->pending_role, cls) ||
      ((cls == ERC7730_CLASS_ALIAS_SET || cls == ERC7730_CLASS_ENUM_MAP) &&
       literal.length != 2u + stride * count)) {
    memzero(&literal, sizeof(literal));
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Invalid ERC-7730 formatter argument"));
    return;
  }
  if (cls == ERC7730_CLASS_ALIAS_SET || cls == ERC7730_CLASS_ENUM_MAP) {
    field->list_count = (uint8_t)count;
    field->list_next = 0;
    for (uint16_t i = 0; i < count; i++) {
      const uint8_t* entry = literal.value + 2 + stride * i;
      if (cls == ERC7730_CLASS_ALIAS_SET) {
        field->list.aliases[i] = (uint16_t)((entry[0] << 8) | entry[1]);
      } else {
        field->list.enum_entries[i][0] = (uint16_t)((entry[0] << 8) | entry[1]);
        field->list.enum_entries[i][1] = (uint16_t)((entry[2] << 8) | entry[3]);
      }
    }
    memzero(&literal, sizeof(literal));
    if (cls == ERC7730_CLASS_ALIAS_SET) {
      next_erc7730_alias(workflow);
    } else {
      resolve_erc7730_argument(workflow);
    }
    return;
  }
  if (cls == ERC7730_CLASS_STRING_REF) { /* raw: a signed constant string */
    const bool well_formed = literal.length == 2;
    const uint16_t string_index =
        (uint16_t)((literal.value[0] << 8) | literal.value[1]);
    memzero(&literal, sizeof(literal));
    if (!well_formed ||
        !erc7730_workflow_select_string(workflow, string_index)) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Invalid ERC-7730 formatter argument"));
      return;
    }
    workflow->display_stage = ERC7730_DISPLAY_ARG_STRING;
    send_erc7730_definition_request();
    return;
  }
  if (field->kind == 1 || field->kind == 10) {
    show_erc7730_single(workflow, cls, literal.value, literal.length);
  } else {
    deliver_erc7730_argument(workflow, cls, literal.value, literal.length);
  }
  memzero(&literal, sizeof(literal));
}

/* An enum key's word: uint zero-extends, int sign-extends, bool is 0/1. */
static bool erc7730_enum_key_word(const Erc7730Literal* key, uint8_t word[32]) {
  if (key->length == 0 || key->length > 32 ||
      (key->kind != 1 && key->kind != 2 && key->kind != 6))
    return false;
  memset(word, key->kind == 2 && (key->value[0] & 0x80u) ? 0xff : 0, 32);
  memcpy(word + 32 - key->length, key->value, key->length);
  return true;
}

static void confirm_erc7730_intent_and_continue(EthereumSignTx* tx) {
  Erc7730Workflow* workflow = erc7730_workflow_state();
  if (!workflow->calldata_validated) {
    /* The first pass only checked the calldata and fixed its digest; every
     * later pass must match it. Now run the display program. */
    (void)tx;
    workflow->calldata_validated = true;
    if (!erc7730_workflow_resume_field(workflow) ||
        !erc7730_workflow_select_display(workflow, 0)) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Invalid ERC-7730 display program"));
      return;
    }
    send_erc7730_definition_request();
    return;
  }
  const Erc7730UiResult ui = confirm_erc7730_source_and_intent(workflow);
  if (ui != ERC7730_UI_OK) {
    fail_erc7730_ui(workflow, ui);
    return;
  }
  if (workflow->display_stage == ERC7730_DISPLAY_ITERATION) {
    /* The pass captured the array's element count. */
    Erc7730AbiCapture capture;
    uint8_t cls = 0;
    const bool counted = erc7730_workflow_captured(workflow, &capture, &cls) &&
                         cls == ERC7730_ABI_ARRAY && capture.length == 32;
    uint16_t count = 0;
    if (counted) count = (uint16_t)((capture.data[30] << 8) | capture.data[31]);
    memzero(&capture, sizeof(capture));
    if (!counted || count > ERC7730_ABI_MAX_ARRAY_ELEMENTS ||
        !erc7730_workflow_resume_field(workflow)) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Invalid ERC-7730 iteration"));
      return;
    }
    workflow->iteration_index = 0;
    workflow->iteration_count = (uint8_t)count;
    workflow->iterating = count != 0;
    /* An empty array shows nothing: continue after the iteration's end. */
    if (count == 0) workflow->display_index = workflow->iteration_end;
    if (!erc7730_workflow_advance_display(workflow)) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Invalid ERC-7730 display continuation"));
      return;
    }
    send_erc7730_definition_request();
    return;
  }
  /* A field or intent value in progress: this pass captured its argument. */
  if (workflow->field.kind == 0) {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Invalid ERC-7730 display continuation"));
    return;
  }
  deliver_erc7730_capture(workflow);
}

/* The display program has ended: sign, replaying the calldata once more
 * against the digest every earlier pass matched. */
static void finish_erc7730_calldata(Erc7730Workflow* workflow) {
  const Erc7730UiResult ui = confirm_erc7730_source_and_intent(workflow);
  if (ui == ERC7730_UI_OK && workflow->depth == 1) {
    /* The inner program ended: restore the outer definition by its id and
     * continue after the instruction that held the inner call. */
    if (!erc7730_workflow_begin_fetch(workflow, 0)) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Invalid ERC-7730 embedded call"));
      return;
    }
    send_erc7730_fetch_request();
    return;
  }
  if (ui != ERC7730_UI_OK) {
    fail_erc7730_ui(workflow, ui);
    return;
  }
  EthereumSignTx tx;
  if (!erc7730_workflow_start_signing(workflow, &tx)) {
    memzero(&tx, sizeof(tx));
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Invalid ERC-7730 signing replay"));
    return;
  }
  continue_ethereum_sign_tx(&tx);
  memzero(&tx, sizeof(tx));
}

static void start_erc7730_calldata(Erc7730Workflow* workflow,
                                   const Erc7730Path* path) {
  EthereumSignTx tx;
  const bool started =
      !path ? erc7730_workflow_restore_and_start_calldata(workflow, &tx)
      : workflow->display_stage == ERC7730_DISPLAY_ITERATION
          ? erc7730_workflow_restore_and_start_length(workflow, &tx, path)
          : erc7730_workflow_restore_and_start_capture(workflow, &tx, path);
  if (!started) {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Invalid ERC-7730 execution program"));
    return;
  }
  size_t remaining = 0;
  if (erc7730_workflow_calldata_waiting(workflow, &remaining)) {
    send_erc7730_calldata_request();
  } else if (erc7730_workflow_calldata_finish(workflow) == ERC7730_ABI_OK) {
    confirm_erc7730_intent_and_continue(&tx);
  } else {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("ERC-7730 calldata does not match definition"));
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

  /* A supplied definition binds to this exact tx before any UI or key
   * derivation; a mismatch is an error, never a fallback to blind signing. */
  Erc7730CatalogIdentity definition;
  if (erc7730_catalog_preloaded(&definition)) {
    if (!storage_isPolicyEnabled("AdvancedMode")) {
      memzero(&definition, sizeof(definition));
      erc7730_catalog_clear_preload();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("AdvancedMode required for ERC-7730"));
      layoutHome();
      return;
    }
    /* A definition describes an Ethereum call; a Wanchain transaction
     * (tx_type) names its value in WAN, which the review would call ETH. */
    const bool calldata_shape =
        msg->has_to && msg->to.size == 20 && msg->has_data_length &&
        msg->data_length >= 4 && msg->has_data_initial_chunk &&
        msg->data_initial_chunk.size == 4 && !msg->has_tx_type;
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
    /* approve() needs the full 68-byte prefix for the allowance guard, which
     * this path does not have. */
    if (memcmp(msg->data_initial_chunk.bytes, "\x09\x5e\xa7\xb3", 4) == 0) {
      memzero(&definition, sizeof(definition));
      erc7730_catalog_clear_preload();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("ERC-7730 approval not supported"));
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
  if (workflow->phase != ERC7730_WORKFLOW_CALLDATA || workflow->signing_pass) {
    ethereum_signing_txack(msg);
    return;
  }
  size_t remaining = 0;
  if (!erc7730_workflow_calldata_waiting(workflow, &remaining) ||
      !msg->has_data_chunk || msg->data_chunk.size == 0 ||
      msg->data_chunk.size > remaining ||
      erc7730_workflow_calldata_feed(workflow, msg->data_chunk.bytes,
                                     msg->data_chunk.size) != ERC7730_ABI_OK) {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("ERC-7730 calldata does not match definition"));
    return;
  }
  if (erc7730_workflow_calldata_waiting(workflow, &remaining)) {
    send_erc7730_calldata_request();
    return;
  }
  if (erc7730_workflow_calldata_finish(workflow) != ERC7730_ABI_OK) {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("ERC-7730 calldata does not match definition"));
    return;
  }
  EthereumSignTx tx;
  if (!erc7730_workflow_restore_complete(workflow, &tx)) {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Unable to resume ERC-7730 transaction"));
    return;
  }
  confirm_erc7730_intent_and_continue(&tx);
  memzero(&tx, sizeof(tx));
}

void fsm_msgEthereumClearSignDefinition(
    const EthereumClearSignDefinition* msg) {
  CHECK_INITIALIZED
  CHECK_PIN
  /* A refusal discards any partial preload, like the chunk refusals below. */
  if (!storage_isPolicyEnabled("AdvancedMode")) {
    erc7730_catalog_clear_preload();
    fsm_sendFailure(FailureType_Failure_Other,
                    _("AdvancedMode required for ERC-7730"));
    layoutHome();
    return;
  }

  /* Dispatch has already ended any signing session before this runs. */
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

static bool continue_erc7730_domain_checks(Erc7730Workflow* workflow) {
  while (workflow->domain_field < 5) {
    const uint8_t field = ++workflow->domain_field;
    const uint8_t operation = workflow->loader.domain.operations[field - 1];
    if (operation == 0) continue;
    if (operation == 2) {
      if (!eip712_stream_domain_matches(field, 0, NULL, 0, true)) return false;
      continue;
    }
    if (operation != 1 ||
        !erc7730_workflow_select_literal(
            workflow, workflow->loader.domain.literals[field - 1]))
      return false;
    send_erc7730_definition_request();
    return true;
  }
  workflow->display_stage = ERC7730_DISPLAY_NONE;
  if (!erc7730_workflow_select_display(workflow, 0)) return false;
  send_erc7730_definition_request();
  return true;
}

static void fail_erc7730_domain(void) {
  erc7730_workflow_abort(erc7730_workflow_state());
  eip712_stream_abort();
  fsm_sendFailure(FailureType_Failure_SyntaxError,
                  _("ERC-7730 domain constraint does not match"));
  layoutHome();
}

void fsm_msgEthereumClearSignDefinitionChunk(
    const EthereumClearSignDefinitionChunk* msg) {
  Erc7730Workflow* workflow = erc7730_workflow_state();
  if (!storage_isPolicyEnabled("AdvancedMode")) {
    /* Refuse as the SignTx-time gate does: end the workflow, its typed-data
     * stream and the preload, never leave them armed behind a Failure. */
    erc7730_catalog_clear_preload();
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("AdvancedMode required for ERC-7730"));
    return;
  }
  if (!erc7730_workflow_active(workflow)) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("No ERC-7730 definition requested"));
    layoutHome();
    return;
  }
  bool complete = false;
  if (workflow->phase == ERC7730_WORKFLOW_FETCH) {
    bool none = false;
    const uint8_t fetch_depth = workflow->fetch_depth;
    const Erc7730CatalogResult fetched =
        erc7730_workflow_fetch_feed(workflow, msg, &complete, &none);
    if (fetched != ERC7730_CATALOG_MORE &&
        fetched != ERC7730_CATALOG_COMPLETE) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Invalid certified ERC-7730 definition"));
      return;
    }
    if (none) {
      show_erc7730_embedded(workflow); /* no inner definition: blind */
      return;
    }
    if (!complete) {
      send_erc7730_fetch_request();
      return;
    }
    if (fetch_depth == 1) {
      /* Bound before any inner screen; then the call's context, which the
       * inner program does not show. */
      char formatted[ERC7730_FORMATTED_VALUE_MAX + 1u];
      const Erc7730Field* field = &workflow->field;
      Erc7730CatalogIdentity inner;
      const bool shown =
          erc7730_catalog_preloaded(&inner) &&
          erc7730_catalog_matches_calldata(&inner, workflow->identity.chain_id,
                                           field->address,
                                           field->inner_selector) &&
          erc7730_format_embedded(field->address, field->inner_selector, 4,
                                  field->inner_length,
                                  field->has_value ? field->value : NULL,
                                  workflow->identity.chain_id,
                                  field->has_spender ? field->spender : NULL,
                                  formatted, sizeof(formatted));
      memzero(&inner, sizeof(inner));
      if (!shown) {
        memzero(formatted, sizeof(formatted));
        fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                           _("ERC-7730 inner definition does not match"));
        return;
      }
      const bool confirmed =
          confirm_erc7730_field("Signer field", workflow->label, formatted);
      memzero(formatted, sizeof(formatted));
      if (!confirmed) {
        fail_erc7730_field(workflow, FailureType_Failure_ActionCancelled,
                           _("Signing cancelled by user"));
        return;
      }
    }
    if (!erc7730_workflow_fetch_complete(workflow)) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("ERC-7730 inner definition does not match"));
      return;
    }
    send_erc7730_definition_request();
    return;
  }
  const uint8_t selection_kind = workflow->selection_kind;
  const Erc7730CatalogResult result =
      workflow->phase == ERC7730_WORKFLOW_SELECT
          ? erc7730_workflow_selection_feed(workflow, msg, &complete)
          : erc7730_workflow_replay_feed(workflow, msg, &complete);
  if (result != ERC7730_CATALOG_MORE && result != ERC7730_CATALOG_COMPLETE) {
    ethereum_signing_abort();
    eip712_stream_abort();
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Invalid certified ERC-7730 replay"));
    return;
  }
  if (!complete) {
    send_erc7730_definition_request();
    return;
  }
  if (selection_kind == ERC7730_SELECTION_NONE) {
    if (workflow->typed_data) {
      if (!continue_erc7730_domain_checks(workflow)) fail_erc7730_domain();
      return;
    }
    if (workflow->resuming) {
      /* Back from an inner call: continue after the instruction that held
       * it. The calldata was validated and its digest fixed long ago. */
      workflow->resuming = false;
      if (!erc7730_workflow_advance_display(workflow)) {
        fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                           _("Invalid ERC-7730 display continuation"));
        return;
      }
      send_erc7730_definition_request();
      return;
    }
    /* Validate all calldata against the ABI before the first screen. */
    start_erc7730_calldata(workflow, NULL);
    return;
  }
  if (selection_kind == ERC7730_SELECTION_LITERAL &&
      workflow->display_stage == ERC7730_DISPLAY_ARG_LITERAL) {
    follow_erc7730_literal(workflow);
    return;
  }
  if (selection_kind == ERC7730_SELECTION_LITERAL &&
      (workflow->display_stage == ERC7730_DISPLAY_ARG_ALIAS ||
       workflow->display_stage == ERC7730_DISPLAY_ARG_ENUM_KEY)) {
    Erc7730Literal item;
    if (!erc7730_program_literal_complete(&workflow->selection.literal,
                                          &item)) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Invalid ERC-7730 formatter argument"));
      return;
    }
    Erc7730Field* field = &workflow->field;
    if (workflow->display_stage == ERC7730_DISPLAY_ARG_ALIAS) {
      /* A member that is not an address simply does not match. */
      field->token_native = item.kind == 5 && item.length == 20 &&
                            memcmp(item.value, field->address, 20) == 0;
      memzero(&item, sizeof(item));
      next_erc7730_alias(workflow);
      return;
    }
    uint8_t word[32];
    const bool match = erc7730_enum_key_word(&item, word) &&
                       memcmp(word, field->value, 32) == 0;
    memzero(word, sizeof(word));
    memzero(&item, sizeof(item));
    if (match) {
      fetch_erc7730_text(workflow,
                         field->list.enum_entries[field->list_next - 1u][1]);
    } else {
      next_erc7730_enum_key(workflow);
    }
    return;
  }
  if (selection_kind == ERC7730_SELECTION_LITERAL) {
    Erc7730Literal literal;
    if (!erc7730_program_literal_complete(&workflow->selection.literal,
                                          &literal)) {
      fail_erc7730_domain();
      return;
    }
    if (workflow->domain_field <= 2 && literal.kind == 4 &&
        literal.length == 2) {
      const uint16_t string_index =
          (uint16_t)((literal.value[0] << 8) | literal.value[1]);
      if (!erc7730_workflow_select_string(workflow, string_index)) {
        fail_erc7730_domain();
        return;
      }
      workflow->display_stage = ERC7730_DISPLAY_DOMAIN_STRING;
      send_erc7730_definition_request();
      return;
    }
    if (!eip712_stream_domain_matches(workflow->domain_field, literal.kind,
                                      literal.value, literal.length, false) ||
        !continue_erc7730_domain_checks(workflow))
      fail_erc7730_domain();
    return;
  }
  if (selection_kind == ERC7730_SELECTION_STRING &&
      workflow->display_stage == ERC7730_DISPLAY_DOMAIN_STRING) {
    const char* value;
    size_t length;
    if (!erc7730_workflow_selected_string(workflow, &value, &length) ||
        !eip712_stream_domain_matches(workflow->domain_field, 4,
                                      (const uint8_t*)value, length, false) ||
        !continue_erc7730_domain_checks(workflow))
      fail_erc7730_domain();
    return;
  }
  if (selection_kind == ERC7730_SELECTION_DISPLAY) {
    Erc7730DisplayInstruction instruction;
    uint16_t instruction_count = 0;
    if (!erc7730_workflow_selected_display(workflow, &instruction,
                                           &instruction_count) ||
        instruction_count == 0) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Invalid ERC-7730 display instruction"));
      return;
    }
    if (workflow->display_stage == ERC7730_DISPLAY_NONE) {
      if (instruction.opcode != 1 || !erc7730_cap_display(&instruction, 0) ||
          !erc7730_workflow_select_string(workflow, instruction.a)) {
        fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                           _("Invalid ERC-7730 intent instruction"));
        return;
      }
      workflow->display_stage = ERC7730_DISPLAY_INTENT_STRING;
      send_erc7730_definition_request();
      return;
    }
    const bool executable =
        erc7730_cap_display(&instruction, workflow->display_index);
    if (workflow->display_stage == ERC7730_DISPLAY_INSTRUCTION &&
        instruction.opcode == 10 && executable) {
      if (workflow->typed_data) {
        const Erc7730UiResult ui = confirm_erc7730_source_and_intent(workflow);
        if (ui != ERC7730_UI_OK) {
          fail_erc7730_ui(workflow, ui);
          return;
        }
        erc7730_workflow_abort(workflow);
        if (eip712_stream_next()->kind != EIP712_REQ_DONE &&
            !eip712_stream_definition_accepted()) {
          eip712_stream_abort();
          fsm_sendFailure(FailureType_Failure_SyntaxError,
                          _("Unable to resume certified EIP-712"));
          layoutHome();
          return;
        }
        eip712_pump();
      } else {
        finish_erc7730_calldata(workflow);
      }
      return;
    }
    if (workflow->display_stage == ERC7730_DISPLAY_INSTRUCTION &&
        (instruction.opcode == 2 || instruction.opcode == 3) && executable) {
      const uint16_t parts = erc7730_workflow_intent_parts(workflow);
      if (workflow->display_index > parts || parts > UINT8_MAX) {
        fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                           _("Invalid ERC-7730 intent instruction"));
        return;
      }
      workflow->intent_part = (uint8_t)workflow->display_index;
      workflow->intent_parts = (uint8_t)parts;
      workflow->intent_value = instruction.opcode == 3;
      bool selected;
      if (instruction.opcode == 2) {
        selected = erc7730_workflow_select_string(workflow, instruction.a);
        workflow->display_stage = ERC7730_DISPLAY_ARG_STRING;
      } else {
        workflow->current_formatter = instruction.a;
        selected = erc7730_workflow_select_formatter(workflow, instruction.a);
        workflow->display_stage = ERC7730_DISPLAY_FORMATTER;
      }
      if (!selected) {
        fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                           _("Invalid ERC-7730 intent instruction"));
        return;
      }
      send_erc7730_definition_request();
      return;
    }
    if (workflow->display_stage == ERC7730_DISPLAY_INSTRUCTION && executable &&
        instruction.opcode >= 5 && instruction.opcode <= 8) {
      bool ok = true;
      if (instruction.opcode == 7) {
        /* Count the array first; the verifier refused nesting. */
        ok = !workflow->iterating &&
             erc7730_workflow_select_path(workflow, instruction.a);
        if (ok) {
          workflow->iteration_begin = workflow->display_index;
          workflow->iteration_end = instruction.c;
          workflow->display_stage = ERC7730_DISPLAY_ITERATION;
          send_erc7730_definition_request();
          return;
        }
      } else if (instruction.opcode == 8) {
        ok = workflow->iterating && instruction.a == workflow->iteration_begin;
        if (ok && ++workflow->iteration_index < workflow->iteration_count) {
          workflow->display_index = workflow->iteration_begin;
        } else {
          workflow->iterating = false;
        }
      }
      /* Groups only group: their fields show their own labels. */
      if (!ok || !erc7730_workflow_advance_display(workflow)) {
        fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                           _("Invalid ERC-7730 display instruction"));
        return;
      }
      send_erc7730_definition_request();
      return;
    }
    if (workflow->display_stage != ERC7730_DISPLAY_INSTRUCTION ||
        instruction.opcode != 4 || !executable) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Unsupported ERC-7730 field instruction"));
      return;
    }
    workflow->current_formatter = instruction.b;
    if (!erc7730_workflow_select_string(workflow, instruction.a)) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Invalid ERC-7730 field label"));
      return;
    }
    workflow->display_stage = ERC7730_DISPLAY_LABEL;
    send_erc7730_definition_request();
    return;
  }
  if (selection_kind == ERC7730_SELECTION_STRING) {
    if (workflow->display_stage == ERC7730_DISPLAY_INTENT_STRING) {
      if (!erc7730_workflow_preserve_selected_string(workflow, true)) {
        fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                           _("Invalid ERC-7730 intent"));
        return;
      }
      workflow->display_stage = ERC7730_DISPLAY_INSTRUCTION;
      workflow->display_index = 1;
      if (!erc7730_workflow_select_display(workflow, 1)) {
        fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                           _("Missing ERC-7730 display instruction"));
        return;
      }
      send_erc7730_definition_request();
      return;
    }
    if (workflow->display_stage == ERC7730_DISPLAY_ARG_STRING ||
        workflow->display_stage == ERC7730_DISPLAY_ARG_MESSAGE) {
      const char* value = NULL;
      size_t length = 0;
      char text[ERC7730_PROGRAM_MAX_STRING_LENGTH + 1u];
      if (!erc7730_workflow_selected_string(workflow, &value, &length) ||
          length == 0 || length >= sizeof(text)) {
        fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                           _("Invalid ERC-7730 formatter argument"));
        return;
      }
      memcpy(text, value, length);
      text[length] = '\0';
      if (workflow->display_stage == ERC7730_DISPLAY_ARG_MESSAGE) {
        show_erc7730_value(workflow, text);
      } else {
        char escaped[ERC7730_FORMATTED_VALUE_MAX + 1u];
        /* A signed constant or an intent text part: signer-authored. */
        if (erc7730_format_label((const uint8_t*)text, length, escaped,
                                 sizeof(escaped))) {
          show_erc7730_field(workflow, escaped);
        } else {
          fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                             _("Unable to format ERC-7730 field"));
        }
        memzero(escaped, sizeof(escaped));
      }
      memzero(text, sizeof(text));
      return;
    }
    if (workflow->display_stage != ERC7730_DISPLAY_LABEL ||
        !erc7730_workflow_preserve_selected_string(workflow, false) ||
        !erc7730_workflow_select_formatter(workflow,
                                           workflow->current_formatter)) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Invalid ERC-7730 field formatter"));
      return;
    }
    workflow->display_stage = ERC7730_DISPLAY_FORMATTER;
    send_erc7730_definition_request();
    return;
  }
  if (selection_kind == ERC7730_SELECTION_FORMATTER) {
    Erc7730Formatter formatter;
    const bool begun =
        workflow->display_stage == ERC7730_DISPLAY_FORMATTER &&
        erc7730_workflow_selected_formatter(workflow, &formatter) &&
        erc7730_workflow_field_begin(workflow, &formatter);
    memzero(&formatter, sizeof(formatter));
    if (!begun) {
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Unsupported ERC-7730 formatter"));
      return;
    }
    resolve_erc7730_argument(workflow);
    return;
  }
  if (selection_kind != ERC7730_SELECTION_PATH) {
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Invalid ERC-7730 selection state"));
    return;
  }
  Erc7730Path path;
  if ((workflow->display_stage != ERC7730_DISPLAY_PATH &&
       workflow->display_stage != ERC7730_DISPLAY_ITERATION) ||
      !erc7730_workflow_selected_path(workflow, &path)) {
    memzero(&path, sizeof(path));
    fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                       _("Invalid ERC-7730 value path"));
    return;
  }
  if (workflow->display_stage == ERC7730_DISPLAY_ITERATION) {
    if (workflow->typed_data) { /* refused at preload */
      memzero(&path, sizeof(path));
      fail_erc7730_field(workflow, FailureType_Failure_SyntaxError,
                         _("Invalid ERC-7730 iteration"));
      return;
    }
    start_erc7730_calldata(workflow, &path);
  } else {
    follow_erc7730_path(workflow, &path);
  }
  memzero(&path, sizeof(path));
}

void fsm_msgEthereumTxMetadata(const EthereumTxMetadata* msg) {
  CHECK_INITIALIZED
  if (!storage_isPolicyEnabled("AdvancedMode")) {
    ethereum_signing_abort();
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("AdvancedMode required for clearsign metadata"));
    layoutHome();
    return;
  }
  CHECK_PIN

  /* Metadata during signing never reaches here: the dispatch hook refuses
   * it (see keepkey_before_message_dispatch()). */

  /* Range-check the uint32 wire value against the slot count BEFORE it is
   * narrowed to the uint8 slot index below: (uint8_t)256 would alias slot 0.
   * A slot that cannot exist is a malformed request, not an "Invalid"
   * classification. */
  CHECK_PARAM(!msg->has_key_id || msg->key_id < METADATA_MAX_KEYS,
              _("clearsign metadata key_id out of range"));

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

  /* A signer load during signing never reaches here: the dispatch hook
   * refuses it (see keepkey_before_message_dispatch()). */

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

// cppcheck-suppress constParameterPointer -- protobuf dispatcher ABI is mutable
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
   * AdvancedMode is session-scoped and is cleared on lock.
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
        erc7730_catalog_clear_preload();
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
      note_workflow_progress();
      msg_write(MessageType_MessageType_EthereumTypedDataStructRequest, resp);
      return;
    }
    case EIP712_REQ_VALUE: {
      RESP_INIT(EthereumTypedDataValueRequest);
      resp->member_path_count = next->member_path_len;
      memcpy(resp->member_path, next->member_path,
             next->member_path_len * sizeof(uint32_t));
      resp->has_value_offset = next->has_value_offset;
      resp->value_offset = next->value_offset;
      note_workflow_progress();
      msg_write(MessageType_MessageType_EthereumTypedDataValueRequest, resp);
      return;
    }
    case EIP712_REQ_DONE: {
      Erc7730Workflow* workflow = erc7730_workflow_state();
      if (workflow->phase == ERC7730_WORKFLOW_TYPED_DATA) {
        if (!erc7730_workflow_eip712_finish(workflow) ||
            !erc7730_workflow_eip712_commit(workflow, next->domain_separator,
                                            next->message_hash)) {
          erc7730_workflow_abort(workflow);
          eip712_stream_abort();
          fsm_sendFailure(FailureType_Failure_SyntaxError,
                          _("Certified EIP-712 value was not found"));
          layout_home();
          return;
        }
        const Erc7730UiResult ui = confirm_erc7730_source_and_intent(workflow);
        if (ui != ERC7730_UI_OK) {
          erc7730_workflow_abort(workflow);
          eip712_stream_abort();
          fsm_sendFailure(
              ui == ERC7730_UI_INVALID ? FailureType_Failure_SyntaxError
                                       : FailureType_Failure_ActionCancelled,
              ui == ERC7730_UI_INVALID ? _("Invalid ERC-7730 signer or intent")
                                       : _("Signing cancelled by user"));
          layout_home();
          return;
        }
        deliver_erc7730_capture(workflow);
        return;
      }
      /* The walk has finished; keep only its result. */
      const Eip712Next done = *next;
      eip712_stream_abort();
      /* sign(keccak(0x19 || 0x01 || domainSeparator || hashStruct(message))),
       * or keccak(0x19 || 0x01 || domainSeparator) for a domain-only type. */
      uint8_t preimage[66];
      preimage[0] = 0x19;
      preimage[1] = 0x01;
      memcpy(preimage + 2, done.domain_separator, 32);
      memcpy(preimage + 34, done.message_hash, 32);
      uint8_t sighash[32];
      keccak_256(preimage, done.domain_only ? 34 : sizeof(preimage), sighash);

      /* Not const: node is the shared fsm_derived_node scratch and holds a
       * private key, so every exit below scrubs it (same rule as
       * process_ethereum_xfer(); 7.15 audit F059). Neither the node nor the
       * msg_resp arena is held across the confirmation below: a DebugLink
       * request answered during it reuses the arena, and dispatch clears the
       * derived node. The address is kept in a local and the key is derived
       * again only after approval. */
      HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, done.address_n,
                                        done.address_n_count, NULL);
      if (!node) return;
      uint8_t pubkeyhash[20];
      const bool derived = hdnode_get_ethereum_pubkeyhash(node, pubkeyhash);
      memzero(node, sizeof(*node));
      if (!derived) {
        fsm_sendFailure(FailureType_Failure_Other,
                        _("Ethereum address derivation failed"));
        layout_home();
        return;
      }
      char address[2 + 40 + 1];
      address[0] = '0';
      address[1] = 'x';
      ethereum_address_checksum(pubkeyhash, address + 2, false, 0);

      /* The one screen that names the action being authorised and the
       * account authorising it; every leaf before it was part of the review. */
      if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Sign Typed Data",
                   "Sign %s%s%s\nfrom %s?",
                   done.message_empty && !done.domain_only ? "EMPTY " : "",
                   done.primary_type, done.domain_only ? " (domain only)" : "",
                   address)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        _("Signing cancelled by user"));
        layout_home();
        return;
      }

      node = fsm_getDerivedNode(SECP256K1_NAME, done.address_n,
                                done.address_n_count, NULL);
      if (!node) return;
      uint8_t sig[64];
      uint8_t v = 0;
      const int signed_rc = ecdsa_sign_digest(&secp256k1, node->private_key,
                                              sighash, sig, &v, NULL);
      memzero(node, sizeof(*node));
      if (signed_rc != 0) {
        fsm_sendFailure(FailureType_Failure_Other, _("Signing failed"));
        layout_home();
        return;
      }
      RESP_INIT(EthereumTypedDataSignature);
      memcpy(resp->address, address, sizeof(address));
      resp->signature.size = 65;
      memcpy(resp->signature.bytes, sig, 64);
      resp->signature.bytes[64] = 27 + v;
      resp->has_domain_separator_hash = true;
      resp->domain_separator_hash.size = 32;
      memcpy(resp->domain_separator_hash.bytes, done.domain_separator, 32);
      resp->has_msg_hash = !done.domain_only;
      resp->has_message_hash = !done.domain_only;
      resp->message_hash.size = done.domain_only ? 0 : 32;
      memcpy(resp->message_hash.bytes, done.message_hash, 32);
      msg_write(MessageType_MessageType_EthereumTypedDataSignature, resp);
      layout_home();
      return;
    }
    case EIP712_REQ_CANCELLED:
      erc7730_workflow_abort(erc7730_workflow_state());
      erc7730_catalog_clear_preload();
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("EIP-712 cancelled"));
      layout_home();
      return;
    case EIP712_REQ_FAIL:
      erc7730_workflow_abort(erc7730_workflow_state());
      erc7730_catalog_clear_preload();
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
  if (certified && !storage_isPolicyEnabled("AdvancedMode")) {
    memzero(&definition, sizeof(definition));
    erc7730_catalog_clear_preload();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("AdvancedMode required for ERC-7730"));
    layout_home();
    return;
  }
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
