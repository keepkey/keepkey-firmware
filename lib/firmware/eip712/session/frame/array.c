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

bool eip712_initArrayFrame(EIP712EncodingSession* session, EIP712Frame* frame, const char* encodedType, size_t encodedTypeLen, const char* fieldName, size_t fieldNameLen) {
  (void)fieldName;
  (void)fieldNameLen;

  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));
  eip712_assert(eip712_isFrameType(frame, EIP712FrameType_Array));

  EIP712Frame* lastFrame = eip712_getParentFrame(session, frame);
  eip712_assert(eip712_frameOk(lastFrame));

  const char* typeName = NULL;
  size_t typeNameLen = 0;
  eip712_assert(eip712_findStructTypeInEncodedType(encodedType, encodedTypeLen, NULL, 0, &typeName, &typeNameLen, NULL, NULL, NULL));

  // Update state
  eip712_assert(typeNameLen < sizeof(frame->typeName));
  memcpy(frame->typeName, typeName, typeNameLen);

  eip712_assert(eip712_extendExtendedHashWithEncodedType(frame->info.arrayInfo.expectedElementExtendedTypeHash, encodedType, encodedTypeLen));
  eip712_assert(eip712_extendFrameExtendedHashWithEncodedType(session, lastFrame, encodedType, encodedTypeLen));

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_finalizeArrayFrame(EIP712EncodingSession* session, EIP712Frame* frame) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));
  eip712_assert(eip712_isFrameType(frame, EIP712FrameType_Array));

  if (frame->info.arrayInfo.expectedElementCount != UINT32_MAX) {
    eip712_assert(frame->info.arrayInfo.elementCount == frame->info.arrayInfo.expectedElementCount);
  }

  if (frame->info.arrayInfo.elementCount > 0) {
    eip712_assert(memcmp(frame->info.arrayInfo.elementExtendedTypeHash, frame->info.arrayInfo.expectedElementExtendedTypeHash, sizeof(frame->info.arrayInfo.expectedElementExtendedTypeHash)) == 0);
  }

  // Update state
  eip712_keccak_finalize(&frame->hash);

  // Confirm action
  if (frame->info.arrayInfo.elementCount == 0) {
    eip712_assert(eip712_displayEmptyArray(session, frame->fieldName, strlen(frame->fieldName), frame->typeName, strlen(frame->typeName)));
  }

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_nextArrayFrameField(EIP712EncodingSession* session, EIP712Frame* frame, const char* fieldName, size_t fieldNameLen) {
  (void)fieldName;

  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));
  eip712_assert(eip712_isFrameType(frame, EIP712FrameType_Array));
  eip712_assert(fieldNameLen == 0);

  if (frame->info.arrayInfo.elementCount > 0) {
    eip712_assert(memcmp(frame->info.arrayInfo.elementExtendedTypeHash, frame->info.arrayInfo.expectedElementExtendedTypeHash, sizeof(frame->info.arrayInfo.expectedElementExtendedTypeHash)) == 0);
  }

  // Update state
  frame->info.arrayInfo.elementCount += 1;
  eip712_assert(frame->info.arrayInfo.elementCount > 0);
  eip712_assert(frame->info.arrayInfo.elementCount < frame->info.arrayInfo.expectedElementCount);

  memset(frame->info.arrayInfo.elementExtendedTypeHash, 0, sizeof(frame->info.arrayInfo.elementExtendedTypeHash));

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_extendArrayFrameExtendedHash(EIP712EncodingSession* session, EIP712Frame* frame, const void* buf, size_t len) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));
  eip712_assert(eip712_isFrameType(frame, EIP712FrameType_Array));

  // Update state
  eip712_extendExtendedHash(frame->info.arrayInfo.elementExtendedTypeHash, buf, len);

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_extendArrayFrameExtendedHashWithEncodedType(EIP712EncodingSession* session, EIP712Frame* frame, const char* encodedType, size_t encodedTypeLen) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));
  eip712_assert(eip712_isFrameType(frame, EIP712FrameType_Array));

  EIP712Frame* lastFrame = eip712_getParentFrame(session, frame);
  if (lastFrame) eip712_assert(eip712_frameOk(lastFrame));

  // Update state
  eip712_assert(eip712_extendExtendedHashWithEncodedType(frame->info.arrayInfo.elementExtendedTypeHash, encodedType, encodedTypeLen));
  if (lastFrame) eip712_assert(eip712_extendFrameExtendedHashWithEncodedType(session, lastFrame, encodedType, encodedTypeLen));

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_appendArrayFrameDynamicData(EIP712EncodingSession* session, EIP712Frame* frame, const uint8_t* data, size_t len) {
  (void)session;
  (void)frame;
  (void)data;
  (void)len;

  // Array frames don't accept dynamic data
  return false;
}
