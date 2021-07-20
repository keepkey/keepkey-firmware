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

#include <stdio.h>

bool eip712_isFrameType(const EIP712Frame* frame, EIP712FrameType expectedFrameType) {
  if (!frame) return false;
  return frame->frameType == expectedFrameType;
}

bool eip712_frameOk(const EIP712Frame* frame) {
  return !eip712_isFrameType(frame, EIP712FrameType_Invalid);
}

bool eip712_initFrame(EIP712EncodingSession* session, EIP712Frame* frame, const char* encodedType, size_t encodedTypeLen, const char* fieldName, size_t fieldNameLen) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));
  
  bool stackEmpty = eip712_getParentFrame(session, frame) == NULL;
  if (stackEmpty) {
    eip712_assert(fieldName == NULL);
    eip712_assert(fieldNameLen == 0);
  }

  // Update state
  eip712_assert(fieldNameLen < sizeof(frame->fieldName));
  memcpy(frame->fieldName, fieldName, fieldNameLen);

  switch (frame->frameType) {
  case EIP712FrameType_Struct:
    eip712_assert(eip712_initStructFrame(session, frame, encodedType, encodedTypeLen, fieldName, fieldNameLen));
    break;
  case EIP712FrameType_DynamicData:
    eip712_assert(eip712_initDynamicDataFrame(session, frame, encodedType, encodedTypeLen, fieldName, fieldNameLen));
    break;
  case EIP712FrameType_Array:
    eip712_assert(eip712_initArrayFrame(session, frame, encodedType, encodedTypeLen, fieldName, fieldNameLen));
    break;
  default:
    // All other types of frame are unrecognized and must hard-fail
    eip712_assert(false);
  }

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_finalizeFrame(EIP712EncodingSession* session, EIP712Frame* frame) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));

  // Update state
  switch (frame->frameType) {
  case EIP712FrameType_Struct:
    eip712_assert(eip712_finalizeStructFrame(session, frame));
    break;
  case EIP712FrameType_DynamicData:
    eip712_assert(eip712_finalizeDynamicDataFrame(session, frame));
    break;
  case EIP712FrameType_Array:
    eip712_assert(eip712_finalizeArrayFrame(session, frame));
    break;
  default:
    // All other types of frame are unrecognized and must hard-fail
    eip712_assert(false);
  }

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_updateFrameHash(EIP712EncodingSession* session, EIP712Frame* frame, const void* buf, size_t len) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));

  eip712_keccak_update(&frame->hash, buf, len);

  return true;
  
abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_extendFrameExtendedHash(EIP712EncodingSession* session, EIP712Frame* frame, const void* buf, size_t len) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));

  // Update state
  switch (frame->frameType) {
  case EIP712FrameType_Struct:
    eip712_assert(eip712_extendStructFrameExtendedHash(session, frame, buf, len));
    break;
  case EIP712FrameType_DynamicData:
    eip712_assert(eip712_extendDynamicDataFrameExtendedHash(session, frame, buf, len));
    break;
  case EIP712FrameType_Array:
    eip712_assert(eip712_extendArrayFrameExtendedHash(session, frame, buf, len));
    break;
  default:
    // All other types of frame are unrecognized and must hard-fail
    eip712_assert(false);
  }

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_extendFrameExtendedHashWithEncodedType(EIP712EncodingSession* session, EIP712Frame* frame, const char* encodedType, size_t encodedTypeLen) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));

  // Update state
  switch (frame->frameType) {
  case EIP712FrameType_Struct:
    eip712_assert(eip712_extendStructFrameExtendedHashWithEncodedType(session, frame, encodedType, encodedTypeLen));
    break;
  case EIP712FrameType_DynamicData:
    eip712_assert(eip712_extendDynamicDataFrameExtendedHashWithEncodedType(session, frame, encodedType, encodedTypeLen));
    break;
  case EIP712FrameType_Array:
    eip712_assert(eip712_extendArrayFrameExtendedHashWithEncodedType(session, frame, encodedType, encodedTypeLen));
    break;
  default:
    // All other types of frame are unrecognized and must hard-fail
    eip712_assert(false);
  }

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_nextFrameField(EIP712EncodingSession* session, EIP712Frame* frame, const char* fieldName, size_t fieldNameLen) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));

  // Update state
  switch (frame->frameType) {
  case EIP712FrameType_Struct:
    eip712_assert(eip712_nextStructFrameField(session, frame, fieldName, fieldNameLen));
    break;
  case EIP712FrameType_DynamicData:
    eip712_assert(eip712_nextDynamicDataFrameField(session, frame, fieldName, fieldNameLen));
    break;
  case EIP712FrameType_Array:
    eip712_assert(eip712_nextArrayFrameField(session, frame, fieldName, fieldNameLen));
    break;
  default:
    // All other types of frame are unrecognized and must hard-fail
    eip712_assert(false);
  }

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_appendFrameAtomicField(EIP712EncodingSession* session, EIP712Frame* frame, const char* encodedType, size_t encodedTypeLen, const char* name, size_t nameLen, const uint8_t* value, size_t valueLen) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));

  int8_t padLen = 0;
  eip712_assert(eip712_isAtomicType(encodedType, encodedTypeLen, &padLen));
  eip712_assert(valueLen <= 32);
  eip712_assert((signed)valueLen == 32 - (padLen >= 0 ? padLen : -padLen));

  if (padLen == 31 && encodedTypeLen == 4 && memcmp(encodedType, "bool", 4) == 0) {
    eip712_assert(value[0] <= 0x01);
  }

  // Update state
  eip712_assert(eip712_nextFrameField(session, frame, name, nameLen));

  eip712_assert(eip712_extendFrameExtendedHash(session, frame, encodedType, encodedTypeLen));

  bool isNegative = encodedTypeLen >= 3 && memcmp(encodedType, "int", 3) == 0 && valueLen > 0 && (value[0] & 0x80);
  for (int i = 0; i < padLen; i++) eip712_assert(eip712_updateFrameHash(session, frame, (isNegative ? "\xff" : "\x00"), 1));
  eip712_assert(eip712_updateFrameHash(session, frame, value, valueLen));
  for (int i = 0; i < -padLen; i++) eip712_assert(eip712_updateFrameHash(session, frame, "\x00", 1));

  // Confirm action
  eip712_assert(eip712_displayAtomicField(session, name, nameLen, encodedType, encodedTypeLen, value, valueLen));

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_appendFrameDynamicData(EIP712EncodingSession* session, EIP712Frame* frame, const uint8_t* data, size_t len) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));

  // Update state
  switch (frame->frameType) {
  case EIP712FrameType_Struct:
    eip712_assert(eip712_appendStructFrameDynamicData(session, frame, data, len));
    break;
  case EIP712FrameType_DynamicData:
    eip712_assert(eip712_appendDynamicDataFrameDynamicData(session, frame, data, len));
    break;
  case EIP712FrameType_Array:
    eip712_assert(eip712_appendArrayFrameDynamicData(session, frame, data, len));
    break;
  default:
    // All other types of frame are unrecognized and must hard-fail
    eip712_assert(false);
  }

  return true;

abort:
  eip712_abortSession(session);
  return false;
}
