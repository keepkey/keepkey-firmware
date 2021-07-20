/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2021 Reid Rankin <reid.ran@shapeshift.io>
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

#include "keepkey/firmware/eip712.h"

#include "keepkey/firmware/fsm.h"

EIP712EncodingSession eip712Session = { 0 };
#if DEBUG_LINK
const char* eip712FailureFile = NULL;
uint32_t eip712FailureLine = 0;
#endif

static void fsm_sendEIP712Failure(void) {
#if DEBUG_LINK
  char strbuf[256] = { 0 };
  if (eip712FailureFile) {
    snprintf(strbuf, sizeof(strbuf), "%s:%ld", eip712FailureFile, eip712FailureLine);
  }
  fsm_sendFailure(FailureType_Failure_Other, strbuf);
#else
  fsm_sendFailure(FailureType_Failure_Other, NULL);
#endif
  layoutHome();
}

void fsm_msgEIP712Init(const EIP712Init *msg) {
  (void)msg; // Currently unused

#if DEBUG_LINK
  // Reset failure reason
  eip712FailureFile = NULL;
  eip712FailureLine = 0;
#endif

  eip712_assert(eip712_init(&eip712Session));

  RESP_INIT(EIP712ContextInfo);

  resp->has_stack_depth_limit = true;
  resp->stack_depth_limit = EIP712_STACK_DEPTH_LIMIT;
  resp->has_type_length_limit = true;
  resp->type_length_limit = EIP712_TYPE_LENGTH_LIMIT;
  resp->has_name_length_limit = true;
  resp->name_length_limit = EIP712_NAME_LENGTH_LIMIT;
  resp->has_dynamic_data_limit = true;
  resp->dynamic_data_limit = EIP712_DYNAMIC_DATA_LIMIT;
  resp->has_field_limit = true;
  resp->field_limit = EIP712_FIELD_LIMIT;

  msg_write(MessageType_MessageType_EIP712ContextInfo, resp);

  return;

abort:
  fsm_sendEIP712Failure();
  return;
}

void fsm_msgEIP712Sign(const EIP712Sign *msg) {
  RESP_INIT(EthereumMessageSignature);

  const uint8_t* hash = eip712_finalize(&eip712Session);
  eip712_assert(hash);

  CHECK_INITIALIZED

  char hash_str[65];
  data2hex(hash, 32, hash_str);
  kk_strlwr(hash_str);
  CHECK_CONFIRM(
    confirm(
      ButtonRequestType_ButtonRequest_ProtectCall,
      "Sign Typed Data",
      "%.8s %.8s %.8s %.8s\n"
      "%.8s %.8s %.8s %.8s",
      hash_str, hash_str + 8, hash_str + 16, hash_str + 24, hash_str + 32,
      hash_str + 40, hash_str + 48, hash_str + 56),
    NULL);

  CHECK_PIN

  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n, msg->address_n_count, NULL);
  CHECK_PARAM(node, NULL);

  eip712_sign(msg, node, resp, &eip712Session);
  memzero(node, sizeof(*node));
  layoutHome();

abort:
  fsm_sendEIP712Failure();
  return;
}

void fsm_msgEIP712Verify(const EIP712Verify *msg) {
  CHECK_PARAM(msg->has_address, _("No address provided"));

  if (eip712_verify(msg, &eip712Session) != 0) {
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
  if (!confirm(ButtonRequestType_ButtonRequest_Other, _("Message Verified"),
               "(EIP-712, shown already)")) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }
  fsm_sendSuccess(_("Message verified"));

  layoutHome();
}

void fsm_msgEIP712PushFrame(const EIP712PushFrame *msg) {
  eip712_assert(eip712_pushFrame(
    &eip712Session,
    msg->frameType,
    msg->encodedType,
    strlen(msg->encodedType),
    (msg->has_fieldName ? msg->fieldName : NULL),
    (msg->has_fieldName ? strlen(msg->fieldName) : 0)
  ));
  fsm_sendSuccess(NULL);

  return;

abort:
  fsm_sendEIP712Failure();
  return;
}

void fsm_msgEIP712PopFrame(const EIP712PopFrame *msg) {
  (void)msg; // Currently unused

  eip712_assert(eip712_popFrame(&eip712Session));
  fsm_sendSuccess(NULL);

  return;

abort:
  fsm_sendEIP712Failure();
  return;
}

void fsm_msgEIP712AppendAtomicField(const EIP712AppendAtomicField *msg) {
  eip712_assert(eip712_appendAtomicField(&eip712Session, msg->encodedType, strlen(msg->encodedType), msg->fieldName, strlen(msg->fieldName), msg->data.bytes, msg->data.size));
  fsm_sendSuccess(NULL);

  return;

abort:
  fsm_sendEIP712Failure();
  return;
}

void fsm_msgEIP712AppendDynamicData(const EIP712AppendDynamicData *msg) {
  eip712_assert(eip712_appendDynamicData(&eip712Session, msg->data.bytes, msg->data.size));
  fsm_sendSuccess(NULL);

  return;

abort:
  fsm_sendEIP712Failure();
  return;
}
