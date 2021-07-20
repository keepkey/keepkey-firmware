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

#ifndef LIB_FIRMWARE_EIP712_EIP712_H
#define LIB_FIRMWARE_EIP712_EIP712_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "keepkey/firmware/ethereum.h"
#include "keepkey/transport/interface.h"
#include "trezor/crypto/sha3.h"

#if !defined(__GNUC__) || (__GNUC__ < 3) || \
    (__GNUC__ == 3 && __GNUC_MINOR__ < 4)
#define checkreturn
#else
#define checkreturn __attribute__((warn_unused_result))
#endif

#if DEBUG_LINK
  #define eip712_assert(X) {          \
    if (!(X)) {                       \
      if (!eip712FailureFile) {       \
        eip712FailureFile = __FILE__; \
        eip712FailureLine = __LINE__; \
      }                               \
      goto abort;                     \
    }                                 \
  }
#else
  #define eip712_assert(X) {          \
    if (!(X)) {                       \
      goto abort;                     \
    }                                 \
  }
#endif

#define EIP712_STACK_DEPTH_LIMIT 8
#define EIP712_TYPE_LENGTH_LIMIT 63
#define EIP712_NAME_LENGTH_LIMIT 63
#define EIP712_DYNAMIC_DATA_LIMIT (SHA3_256_DIGEST_LENGTH * 2)
#define EIP712_FIELD_LIMIT_BITFIELD_SIZE 32
#define EIP712_FIELD_LIMIT (EIP712_FIELD_LIMIT_BITFIELD_SIZE * 8)

typedef struct _EIP712Init EIP712Init;
typedef struct _EIP712Sign EIP712Sign;
typedef struct _EIP712Verify EIP712Verify;
typedef struct _EIP712PushFrame EIP712PushFrame;
typedef struct _EIP712PopFrame EIP712PopFrame;
typedef struct _EIP712AppendAtomicField EIP712AppendAtomicField;
typedef struct _EIP712AppendDynamicData EIP712AppendDynamicData;

typedef union EIP712KeccakHash {
    SHA3_CTX ctx;
    uint8_t digest[SHA3_256_DIGEST_LENGTH];
} EIP712KeccakHash;

typedef enum EIP712EncodingSessionState {
  EIP712EncodingSessionState_Invalid = 0,
  EIP712EncodingSessionState_OK = 1,
  EIP712EncodingSessionState_Done = 2,
} EIP712EncodingSessionState;

typedef struct EIP712Frame {
  EIP712FrameType frameType;
  char typeName[EIP712_TYPE_LENGTH_LIMIT + 1];
  char fieldName[EIP712_NAME_LENGTH_LIMIT + 1];
  EIP712KeccakHash hash;
  union {
    struct {
      uint32_t fieldCount;
      uint8_t expectedExtendedTypeHash[SHA3_256_DIGEST_LENGTH];
      uint8_t extendedTypeHash[SHA3_256_DIGEST_LENGTH];
    } structInfo;
    struct {
      size_t totalDataLen;
      uint8_t data[EIP712_DYNAMIC_DATA_LIMIT];
    } dynamicDataInfo;
    struct {
      uint32_t elementCount;
      uint32_t expectedElementCount;
      uint8_t expectedElementExtendedTypeHash[SHA3_256_DIGEST_LENGTH];
      uint8_t elementExtendedTypeHash[SHA3_256_DIGEST_LENGTH];
    } arrayInfo;
  } info;
} EIP712Frame;

typedef struct EIP712EncodingSession {
  EIP712EncodingSessionState state;
  uint32_t hashUpdates;
  EIP712KeccakHash hash;
  size_t numFrames;
  EIP712Frame frames[EIP712_STACK_DEPTH_LIMIT];
} EIP712EncodingSession;

extern EIP712EncodingSession eip712Session;
#if DEBUG_LINK
extern const char* eip712FailureFile;
extern uint32_t eip712FailureLine;
#endif

// util.c
bool eip712_isValidIdentifier(const char* name, size_t len);
bool eip712_isAtomicType(const char* type, size_t typeLen, int8_t* padLen);
bool eip712_isDynamicType(const char* type, size_t typeLen);
bool eip712_isArrayType(
  const char* type,
  size_t typeLen,
  const char** elementTypeOut,
  size_t* elementTypeLenOut,
  uint32_t* numElementsOut,
  const char** numElementsAsciiOut,
  size_t* numElementsAsciiLenOut
);
void eip712_keccak_init(EIP712KeccakHash* x);
void eip712_keccak_update(EIP712KeccakHash* x, const void* buf, size_t len);
void eip712_keccak_finalize(EIP712KeccakHash* x);

// encoded_types.c
bool checkreturn eip712_findStructTypeInEncodedType(
  const char* encodedType,
  size_t encodedTypeLen,
  const char* target,
  size_t targetLen,
  const char** typeNameOut,
  size_t* typeNameOutLen,
  const char** typeOut,
  size_t* typeOutLen,
  size_t* indexOut
);
bool checkreturn eip712_countTypesInEncodedType(const char* encodedType, size_t encodedTypeLen, size_t* typeCountOut);

// extended_types.c
void eip712_extendExtendedHash(uint8_t hashBuf[SHA3_256_DIGEST_LENGTH], const char* buf, size_t len);
bool checkreturn eip712_extendExtendedHashWithEncodedType(uint8_t extendedTypeHash[SHA3_256_DIGEST_LENGTH], const char* encodedType, size_t encodedTypeLen);

// session/session.c
void eip712_abortSession(EIP712EncodingSession* session);
bool checkreturn eip712_isSessionState(const EIP712EncodingSession* session, EIP712EncodingSessionState expectedState);
bool checkreturn eip712_sessionOk(const EIP712EncodingSession* session);
bool checkreturn eip712_stackEmpty(const EIP712EncodingSession* session);
EIP712Frame* checkreturn eip712_getCurrentFrame(EIP712EncodingSession* session);
EIP712Frame* checkreturn eip712_getParentFrame(EIP712EncodingSession* session, const EIP712Frame* frame);
bool checkreturn eip712_init(EIP712EncodingSession* session);
const uint8_t* eip712_finalize(EIP712EncodingSession* session);
const uint8_t* checkreturn eip712_getHash(const EIP712EncodingSession* session);
bool checkreturn eip712_popFrame(EIP712EncodingSession* session);
EIP712Frame* checkreturn eip712_pushFrame(EIP712EncodingSession* session, EIP712FrameType frameType, const char* encodedType, size_t encodedTypeLen, const char* fieldName, size_t fieldNameLen);
bool checkreturn eip712_appendAtomicField(EIP712EncodingSession* session, const char* type, size_t typeLen, const char* name, size_t nameLen, const uint8_t* value, size_t valueLen);
bool checkreturn eip712_appendDynamicData(EIP712EncodingSession* session, const uint8_t* data, size_t len);

// session/frame.c
bool checkreturn eip712_isFrameType(const EIP712Frame* frame, EIP712FrameType expectedFrameType);
bool checkreturn eip712_frameOk(const EIP712Frame* frame);
bool checkreturn eip712_initFrame(EIP712EncodingSession* session, EIP712Frame* frame, const char* encodedType, size_t encodedTypeLen, const char* fieldName, size_t fieldNameLen);
bool checkreturn eip712_finalizeFrame(EIP712EncodingSession* session, EIP712Frame* frame);
bool checkreturn eip712_updateFrameHash(EIP712EncodingSession* session, EIP712Frame* frame, const void* buf, size_t len);
bool checkreturn eip712_extendFrameExtendedHash(EIP712EncodingSession* session, EIP712Frame* frame, const void* buf, size_t len);
bool checkreturn eip712_extendFrameExtendedHashWithEncodedType(EIP712EncodingSession* session, EIP712Frame* frame, const char* encodedType, size_t encodedTypeLen);
bool checkreturn eip712_nextFrameField(EIP712EncodingSession* session, EIP712Frame* frame, const char* fieldName, size_t fieldNameLen);
bool checkreturn eip712_appendFrameAtomicField(EIP712EncodingSession* session, EIP712Frame* frame, const char* type, size_t typeLen, const char* name, size_t nameLen, const uint8_t* value, size_t valueLen);
bool checkreturn eip712_appendFrameDynamicData(EIP712EncodingSession* session, EIP712Frame* frame, const uint8_t* data, size_t len);

// session/frame/struct.c
bool checkreturn eip712_initStructFrame(EIP712EncodingSession* session, EIP712Frame* frame, const char* encodedType, size_t encodedTypeLen, const char* fieldName, size_t fieldNameLen);
bool checkreturn eip712_finalizeStructFrame(EIP712EncodingSession* session, EIP712Frame* frame);
bool checkreturn eip712_nextStructFrameField(EIP712EncodingSession* session, EIP712Frame* frame, const char* fieldName, size_t fieldNameLen);
bool checkreturn eip712_extendStructFrameExtendedHash(EIP712EncodingSession* session, EIP712Frame* frame, const void* buf, size_t len);
bool checkreturn eip712_extendStructFrameExtendedHashWithEncodedType(EIP712EncodingSession* session, EIP712Frame* frame, const char* encodedType, size_t encodedTypeLen);
bool checkreturn eip712_appendStructFrameDynamicData(EIP712EncodingSession* session, EIP712Frame* frame, const uint8_t* data, size_t len);

// session/frame/dynamicData.c
bool checkreturn eip712_initDynamicDataFrame(EIP712EncodingSession* session, EIP712Frame* frame, const char* encodedType, size_t encodedTypeLen, const char* fieldName, size_t fieldNameLen);
bool checkreturn eip712_finalizeDynamicDataFrame(EIP712EncodingSession* session, EIP712Frame* frame);
bool checkreturn eip712_nextDynamicDataFrameField(EIP712EncodingSession* session, EIP712Frame* frame, const char* fieldName, size_t fieldNameLen);
bool checkreturn eip712_extendDynamicDataFrameExtendedHash(EIP712EncodingSession* session, EIP712Frame* frame, const void* buf, size_t len);
bool checkreturn eip712_extendDynamicDataFrameExtendedHashWithEncodedType(EIP712EncodingSession* session, EIP712Frame* frame, const char* encodedType, size_t encodedTypeLen);
bool checkreturn eip712_appendDynamicDataFrameDynamicData(EIP712EncodingSession* session, EIP712Frame* frame, const uint8_t* data, size_t len);
size_t checkreturn eip712_getDynamicDataLen(const EIP712Frame* frame);

// session/frame/array.c
bool checkreturn eip712_initArrayFrame(EIP712EncodingSession* session, EIP712Frame* frame, const char* encodedType, size_t encodedTypeLen, const char* fieldName, size_t fieldNameLen);
bool checkreturn eip712_finalizeArrayFrame(EIP712EncodingSession* session, EIP712Frame* frame);
bool checkreturn eip712_nextArrayFrameField(EIP712EncodingSession* session, EIP712Frame* frame, const char* fieldName, size_t fieldNameLen);
bool checkreturn eip712_extendArrayFrameExtendedHash(EIP712EncodingSession* session, EIP712Frame* frame, const void* buf, size_t len);
bool checkreturn eip712_extendArrayFrameExtendedHashWithEncodedType(EIP712EncodingSession* session, EIP712Frame* frame, const char* encodedType, size_t encodedTypeLen);
bool checkreturn eip712_appendArrayFrameDynamicData(EIP712EncodingSession* session, EIP712Frame* frame, const uint8_t* data, size_t len);

// display.c
bool checkreturn eip712_displayEmptyStruct(EIP712EncodingSession* session, const char* name, size_t nameLen, const char* type, size_t typeLen);
bool checkreturn eip712_displayEmptyArray(EIP712EncodingSession* session, const char* name, size_t nameLen, const char* type, size_t typeLen);
bool checkreturn eip712_displayAtomicField(EIP712EncodingSession* session, const char* name, size_t nameLen, const char* type, size_t typeLen, const uint8_t* valueBuf, size_t valueBufLen);
bool checkreturn eip712_displayDynamicField(EIP712EncodingSession* session, const char* name, size_t nameLen, const char* type, size_t typeLen, const uint8_t* valueBuf, size_t valueBufLen, size_t valueLen);

// eip712.c
void eip712_sign(const EIP712Sign *msg, const HDNode *node, EthereumMessageSignature *resp, EIP712EncodingSession* session);
int eip712_verify(const EIP712Verify *msg, EIP712EncodingSession* session);

#endif
