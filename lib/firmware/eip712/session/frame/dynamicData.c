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

bool eip712_initDynamicDataFrame(EIP712EncodingSession* session, EIP712Frame* frame, const char* encodedType, size_t encodedTypeLen, const char* fieldName, size_t fieldNameLen) {
  (void)fieldName;
  (void)fieldNameLen;
  
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));
  eip712_assert(eip712_isFrameType(frame, EIP712FrameType_DynamicData));
  eip712_assert(eip712_isDynamicType(encodedType, encodedTypeLen));

  // Update state
  eip712_assert(encodedTypeLen < sizeof(frame->typeName));
  memcpy(frame->typeName, encodedType, encodedTypeLen);

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_finalizeDynamicDataFrame(EIP712EncodingSession* session, EIP712Frame* frame) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));
  eip712_assert(eip712_isFrameType(frame, EIP712FrameType_DynamicData));

  EIP712Frame* lastFrame = eip712_getCurrentFrame(session);
  eip712_assert(eip712_frameOk(lastFrame));

  // Update state
  eip712_keccak_finalize(&frame->hash);
  eip712_assert(eip712_extendFrameExtendedHash(session, lastFrame, frame->typeName, strlen(frame->typeName)));

  // Confirm action
  eip712_assert(eip712_displayDynamicField(session, frame->fieldName, strlen(frame->fieldName), frame->typeName, strlen(frame->typeName), frame->info.dynamicDataInfo.data, eip712_getDynamicDataLen(frame), frame->info.dynamicDataInfo.totalDataLen));

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_nextDynamicDataFrameField(EIP712EncodingSession* session, EIP712Frame* frame, const char* fieldName, size_t fieldNameLen) {
  (void)frame;
  (void)fieldName;
  (void)fieldNameLen;

  // Can't add fields to dynamic data
  eip712_abortSession(session);
  return false;
}

bool eip712_extendDynamicDataFrameExtendedHash(EIP712EncodingSession* session, EIP712Frame* frame, const void* buf, size_t len) {
  (void)frame;
  (void)buf;
  (void)len;

  // Dynamic data frames don't have an extended hash
  eip712_abortSession(session);
  return false;
}

bool eip712_extendDynamicDataFrameExtendedHashWithEncodedType(EIP712EncodingSession* session, EIP712Frame* frame, const char* encodedType, size_t encodedTypeLen) {
  (void)frame;
  (void)encodedType;
  (void)encodedTypeLen;

  // Dynamic data frames don't have an extended hash
  eip712_abortSession(session);
  return false;
}

bool eip712_appendDynamicDataFrameDynamicData(EIP712EncodingSession* session, EIP712Frame* frame, const uint8_t* data, size_t len) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));
  eip712_assert(eip712_isFrameType(frame, EIP712FrameType_DynamicData));

  // Update state
  size_t dynamicDataLen = eip712_getDynamicDataLen(frame);
  if (sizeof(frame->info.dynamicDataInfo.data) > dynamicDataLen) {
    size_t bufBytesLeft = sizeof(frame->info.dynamicDataInfo.data) - dynamicDataLen;
    if (bufBytesLeft > 0) {
      size_t bytesToCopy = len < bufBytesLeft ? len : bufBytesLeft;
      memcpy(&frame->info.dynamicDataInfo.data[dynamicDataLen], data, bytesToCopy);
    }
  }
  eip712_assert(frame->info.dynamicDataInfo.totalDataLen + len >= frame->info.dynamicDataInfo.totalDataLen);
  frame->info.dynamicDataInfo.totalDataLen += len;

  eip712_assert(eip712_updateFrameHash(session, frame, data, len));

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

size_t eip712_getDynamicDataLen(const EIP712Frame* frame) {
  // Assert invariants
  eip712_assert(eip712_frameOk(frame))
  eip712_assert(eip712_isFrameType(frame, EIP712FrameType_DynamicData));

  // Inspect state
  return sizeof(frame->info.dynamicDataInfo.data) < frame->info.dynamicDataInfo.totalDataLen ? sizeof(frame->info.dynamicDataInfo.data) : frame->info.dynamicDataInfo.totalDataLen;

abort:
  return 0;
}
