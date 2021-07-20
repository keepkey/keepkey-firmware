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

bool eip712_initStructFrame(EIP712EncodingSession* session, EIP712Frame* frame, const char* encodedType, size_t encodedTypeLen, const char* fieldName, size_t fieldNameLen) {
  (void)fieldName;
  (void)fieldNameLen;

  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));
  eip712_assert(eip712_isFrameType(frame, EIP712FrameType_Struct));

  const char* typeName = NULL;
  size_t typeNameLen = 0;
  eip712_assert(eip712_findStructTypeInEncodedType(encodedType, encodedTypeLen, NULL, 0, &typeName, &typeNameLen, NULL, NULL, NULL));

  // Update state
  eip712_assert(typeNameLen < sizeof(frame->typeName));
  memcpy(frame->typeName, typeName, typeNameLen);

  EIP712KeccakHash typeHash;
  eip712_keccak_init(&typeHash);
  eip712_keccak_update(&typeHash, encodedType, encodedTypeLen);
  eip712_keccak_finalize(&typeHash);
  eip712_keccak_update(&frame->hash, typeHash.digest, sizeof(typeHash.digest));

  eip712_assert(eip712_extendExtendedHashWithEncodedType(frame->info.structInfo.expectedExtendedTypeHash, encodedType, encodedTypeLen));

  eip712_assert(eip712_extendFrameExtendedHash(session, frame, typeName, typeNameLen));
  eip712_assert(eip712_extendFrameExtendedHash(session, frame, "(", 1));

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_finalizeStructFrame(EIP712EncodingSession* session, EIP712Frame* frame) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));
  eip712_assert(eip712_isFrameType(frame, EIP712FrameType_Struct));

  EIP712Frame* lastFrame = eip712_getCurrentFrame(session);
  if (lastFrame) eip712_assert(eip712_frameOk(lastFrame));

  // Finalize state
  eip712_keccak_finalize(&frame->hash);
  eip712_assert(eip712_extendStructFrameExtendedHash(session, frame, ")", 1));
  if (lastFrame) eip712_assert(eip712_extendFrameExtendedHash(session, lastFrame, ")", 1));

  // Assert more invariants
  eip712_assert(memcmp(frame->info.structInfo.extendedTypeHash, frame->info.structInfo.expectedExtendedTypeHash, sizeof(frame->info.structInfo.extendedTypeHash)) == 0);

  // Confirm action
  if (frame->info.structInfo.fieldCount == 0) {
    eip712_assert(eip712_displayEmptyStruct(session, frame->fieldName, strlen(frame->fieldName), frame->typeName, strlen(frame->typeName)));
  }

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_nextStructFrameField(EIP712EncodingSession* session, EIP712Frame* frame, const char* fieldName, size_t fieldNameLen) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));
  eip712_assert(eip712_isFrameType(frame, EIP712FrameType_Struct));
  eip712_assert(eip712_isValidIdentifier(fieldName, fieldNameLen));

  // Update state
  if (frame->info.structInfo.fieldCount > 0) eip712_assert(eip712_extendFrameExtendedHash(session, frame, ",", 1));
  eip712_assert(eip712_extendFrameExtendedHash(session, frame, fieldName, fieldNameLen));
  eip712_assert(eip712_extendFrameExtendedHash(session, frame, " ", 1));

  frame->info.structInfo.fieldCount += 1;
  eip712_assert(frame->info.structInfo.fieldCount > 0);

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_extendStructFrameExtendedHash(EIP712EncodingSession* session, EIP712Frame* frame, const void* buf, size_t len) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));
  eip712_assert(eip712_isFrameType(frame, EIP712FrameType_Struct));

  EIP712Frame* lastFrame = eip712_getParentFrame(session, frame);
  if (lastFrame) eip712_assert(eip712_frameOk(lastFrame));

  // Update state
  eip712_extendExtendedHash(frame->info.structInfo.extendedTypeHash, buf, len);
  if (lastFrame) eip712_assert(eip712_extendFrameExtendedHash(session, lastFrame, buf, len));

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_extendStructFrameExtendedHashWithEncodedType(EIP712EncodingSession* session, EIP712Frame* frame, const char* encodedType, size_t encodedTypeLen) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));
  eip712_assert(eip712_isFrameType(frame, EIP712FrameType_Struct));

  EIP712Frame* lastFrame = eip712_getParentFrame(session, frame);
  if (lastFrame) eip712_assert(eip712_frameOk(lastFrame));

  // Update state
  eip712_assert(eip712_extendExtendedHashWithEncodedType(frame->info.structInfo.extendedTypeHash, encodedType, encodedTypeLen));
  if (lastFrame) eip712_assert(eip712_extendFrameExtendedHashWithEncodedType(session, lastFrame, encodedType, encodedTypeLen));

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_appendStructFrameDynamicData(EIP712EncodingSession* session, EIP712Frame* frame, const uint8_t* data, size_t len) {
  (void)session;
  (void)frame;
  (void)data;
  (void)len;

  // Struct frames don't accept dynamic data
  return false;
}
