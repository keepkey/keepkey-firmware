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

void eip712_abortSession(EIP712EncodingSession* session) {
  if (!session) return;
  session->state = EIP712EncodingSessionState_Invalid;
}

bool eip712_isSessionState(const EIP712EncodingSession* session, EIP712EncodingSessionState expectedState) {
  if (!session) return false;
  return session->state == expectedState;
}

bool eip712_sessionOk(const EIP712EncodingSession* session) {
  // Assert invariants
  eip712_assert(eip712_isSessionState(session, EIP712EncodingSessionState_OK));

  for (size_t i = 0; i < session->numFrames; i++) eip712_assert(eip712_frameOk(&session->frames[i]));

  return true;

abort:
  return false;
}

bool eip712_stackEmpty(const EIP712EncodingSession* session) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));

  // Inspect state
  return session->numFrames == 0;

abort:
  return false;
}

EIP712Frame* eip712_getCurrentFrame(EIP712EncodingSession* session) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));

  // Inspect state
  if (eip712_stackEmpty(session)) return NULL;
  return &session->frames[session->numFrames - 1];

abort:
  return NULL;
}

EIP712Frame* eip712_getParentFrame(EIP712EncodingSession* session, const EIP712Frame* frame) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_frameOk(frame));

  // Inspect state
  for (size_t i = session->numFrames; i > 1; i--) {
    if (&session->frames[i - 1] == frame) return &session->frames[i - 2];
  }

  return NULL;

abort:
  return NULL;
}


bool eip712_init(EIP712EncodingSession* session) {
  // Assert invariants
  eip712_assert(session);

  // Update state
  memset(session, 0, sizeof(*session));
  session->state = EIP712EncodingSessionState_OK;
  session->numFrames = 0;

  eip712_keccak_init(&session->hash);
  eip712_keccak_update(&session->hash, "\x19\x01", 2);

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

const uint8_t* eip712_finalize(EIP712EncodingSession* session) {
  // Bypass finalization if already complete
  if (eip712_isSessionState(session, EIP712EncodingSessionState_Done)) {
    return eip712_getHash(session);
  }

  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(eip712_stackEmpty(session));
  eip712_assert(session->hashUpdates == 2);

  // Update state
  eip712_keccak_finalize(&session->hash);
  session->state = EIP712EncodingSessionState_Done;

  return eip712_getHash(session);

abort:
  eip712_abortSession(session);
  return NULL;
}

const uint8_t* eip712_getHash(const EIP712EncodingSession* session) {
  // Assert invariants
  eip712_assert(eip712_isSessionState(session, EIP712EncodingSessionState_Done));

  // Inspect state
  return (const uint8_t*)session->hash.digest;

abort:
  return NULL;
}

bool eip712_popFrame(EIP712EncodingSession* session) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(!eip712_stackEmpty(session));

  EIP712Frame* frame = eip712_getCurrentFrame(session);
  eip712_assert(eip712_frameOk(frame));

  // Update state
  session->numFrames -= 1;
  eip712_assert(eip712_finalizeFrame(session, frame));

  EIP712Frame* lastFrame = eip712_getCurrentFrame(session);
  if (lastFrame) {
    eip712_assert(eip712_frameOk(lastFrame));
    eip712_assert(eip712_updateFrameHash(session, lastFrame, frame->hash.digest, sizeof(frame->hash.digest)));
  } else {
    eip712_keccak_update(&session->hash, frame->hash.digest, sizeof(frame->hash.digest));
    session->hashUpdates += 1;
    eip712_assert(session->hashUpdates > 0);

    switch(session->hashUpdates) {
      case 1:
        eip712_assert(eip712_isFrameType(frame, EIP712FrameType_Struct));
        eip712_assert(memcmp(frame->typeName, "EIP712Domain", sizeof("EIP712Domain")) == 0);
        break;
      case 2:
        eip712_assert(eip712_isFrameType(frame, EIP712FrameType_Struct));
        break;
      default:
        // The spec calls for exactly encode() to contain exactly two sub-hashes.
        eip712_assert(false);
        break;
    }
  }

  frame->frameType = EIP712FrameType_Invalid;

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

EIP712Frame* eip712_pushFrame(EIP712EncodingSession* session, EIP712FrameType frameType, const char* encodedType, size_t encodedTypeLen, const char* fieldName, size_t fieldNameLen) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));
  eip712_assert(frameType != EIP712FrameType_Invalid);

  EIP712Frame* lastFrame = eip712_getCurrentFrame(session);
  if (lastFrame) {
    eip712_assert(eip712_frameOk(lastFrame));
  } else {
    eip712_assert(fieldNameLen == 0);
  }

  // Update state
  if (lastFrame) eip712_assert(eip712_nextFrameField(session, lastFrame, fieldName, fieldNameLen));

  session->numFrames += 1;
  eip712_assert(session->numFrames > 0);
  eip712_assert(session->numFrames <= EIP712_STACK_DEPTH_LIMIT);

  EIP712Frame* frame = &session->frames[session->numFrames - 1];
  memset(frame, 0, sizeof(*frame));
  frame->frameType = frameType;
  eip712_keccak_init(&frame->hash);

  eip712_assert(eip712_initFrame(session, frame, encodedType, encodedTypeLen, fieldName, fieldNameLen));
  eip712_assert(eip712_frameOk(frame));

  return frame;

abort:
  eip712_abortSession(session);
  return NULL;
}

bool eip712_appendAtomicField(EIP712EncodingSession* session, const char* type, size_t typeLen, const char* name, size_t nameLen, const uint8_t* value, size_t valueLen) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));

  EIP712Frame* frame = eip712_getCurrentFrame(session);
  eip712_assert(eip712_frameOk(frame));

  // Update state
  eip712_assert(eip712_appendFrameAtomicField(session, frame, type, typeLen, name, nameLen, value, valueLen));

  return true;

abort:
  eip712_abortSession(session);
  return NULL;
}

bool eip712_appendDynamicData(EIP712EncodingSession* session, const uint8_t* data, size_t len) {
  // Assert invariants
  eip712_assert(eip712_sessionOk(session));

  EIP712Frame* frame = eip712_getCurrentFrame(session);
  eip712_assert(eip712_frameOk(frame));

  // Update state
  eip712_assert(eip712_appendFrameDynamicData(session, frame, data, len));

  return true;

abort:
  eip712_abortSession(session);
  return NULL;
}
