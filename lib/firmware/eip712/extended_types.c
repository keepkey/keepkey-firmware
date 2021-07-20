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

#include "keepkey/board/confirm_sm.h"

#include <stdio.h>

static bool eip712_setBitAtIndex(uint8_t array[EIP712_FIELD_LIMIT_BITFIELD_SIZE], size_t index) {
  size_t i = index >> 3;
  eip712_assert(i < EIP712_FIELD_LIMIT_BITFIELD_SIZE);
  array[i] |= 1 << (index & 0x07);

  return true;

abort:
  return false;
}

static size_t eip712_countBits(uint8_t array[EIP712_FIELD_LIMIT_BITFIELD_SIZE]) {
  bool sawFirstZero = false;
  size_t count = 0;
  for (uint8_t i = 0; i < EIP712_FIELD_LIMIT_BITFIELD_SIZE; i++) {
    uint8_t x = array[i];
    if (x == 0xff) {
      count += 8;
      continue;
    }
    for (uint8_t j = 0; j < 8; j++) {
      if ((x >> j) & 0x01) {
        if (sawFirstZero) return -1;
        count += 1;
      } else {
        sawFirstZero = true;
      }
    }
  }
  return count;
}

void eip712_extendExtendedHash(uint8_t hashBuf[SHA3_256_DIGEST_LENGTH], const char* buf, size_t len) {
  if (!hashBuf) return;

  // char foo[128] = { 0 };
  // snprintf(foo, sizeof(foo), "0x%08lx: \"%*.s\"", (uint32_t)hashBuf, (int)len, buf);
  // review_without_button_request("eip712_extendExtendedHash", "%s", foo);

  EIP712KeccakHash hash;
  eip712_keccak_init(&hash);
  eip712_keccak_update(&hash, hashBuf, sizeof(hash.digest));
  eip712_keccak_update(&hash, buf, len);
  eip712_keccak_finalize(&hash);
  memcpy(hashBuf, hash.digest, sizeof(hash.digest));
}

static bool eip712_extendExtendedHashWithEncodedTypeInner(
  uint8_t extendedTypeHash[SHA3_256_DIGEST_LENGTH],
  const char* encodedType,
  size_t encodedTypeLen,
  const char* typeName,
  size_t typeNameLen,
  uint8_t typeBitfield[EIP712_FIELD_LIMIT_BITFIELD_SIZE],
  size_t depth
) {
  const char* elementType = NULL;
  size_t elementTypeLen = 0;
  const char* numElementsAscii = NULL;
  size_t numElementsAsciiLen = 0;
  if (eip712_isDynamicType(typeName, typeNameLen) || eip712_isAtomicType(typeName, typeNameLen, NULL)) {
    eip712_extendExtendedHash(extendedTypeHash, typeName, typeNameLen);
    return true;
  } else if (eip712_isArrayType(typeName, typeNameLen, &elementType, &elementTypeLen, NULL, &numElementsAscii, &numElementsAsciiLen)) {
    eip712_assert(eip712_extendExtendedHashWithEncodedTypeInner(extendedTypeHash, encodedType, encodedTypeLen, elementType, elementTypeLen, typeBitfield, depth + 1));
    eip712_extendExtendedHash(extendedTypeHash, "[", 1);
    eip712_extendExtendedHash(extendedTypeHash, numElementsAscii, numElementsAsciiLen);
    eip712_extendExtendedHash(extendedTypeHash, "]", 1);
    return true;
  }

  // Note this is a check for NULL, not for typeNameLen == 0. This excluded any misdetected zero-length
  // substrings of encodedType, but passes the initial call from eip712_extendExtendedHashWithEncodedType().
  if (typeName) eip712_assert(eip712_isValidIdentifier(typeName, typeNameLen));

  const char* inEnd = encodedType + encodedTypeLen;
  eip712_assert(encodedType <= inEnd);
  // This isn't a security check; we just don't want to hang if something goes wrong
  eip712_assert(depth < EIP712_STACK_DEPTH_LIMIT);

  const char* fields = NULL;
  size_t fieldsLen = 0;
  size_t typeIndex = 0;
  eip712_assert(eip712_findStructTypeInEncodedType(encodedType, encodedTypeLen, typeName, typeNameLen, &typeName, &typeNameLen, &fields, &fieldsLen, &typeIndex));
  eip712_assert(fields);
  eip712_assert(eip712_setBitAtIndex(typeBitfield, typeIndex));
  const char* fieldsEnd = fields + fieldsLen;

  eip712_extendExtendedHash(extendedTypeHash, typeName, typeNameLen);
  eip712_extendExtendedHash(extendedTypeHash, "(", 1);

  const char* field = fields;
  while (field < fieldsEnd) {
    const char* fieldEnd = memchr(field, ',', fieldsEnd - field);
    // If we don't find a comma, it's ok, it's just the last field in the list
    if (fieldEnd == NULL) fieldEnd = fieldsEnd;
    eip712_assert(fieldEnd >= field && fieldEnd <= fieldsEnd);
    size_t fieldLen = fieldEnd - field;
    eip712_assert(fieldLen > 0);

    if (field != fields) eip712_extendExtendedHash(extendedTypeHash, ",", 1);

    const char* fieldType = field;

    const char* fieldTypeEnd = memchr(fieldType, ' ', fieldEnd - fieldType);
    eip712_assert(fieldTypeEnd >= fieldType && fieldTypeEnd <= fieldEnd);
    size_t fieldTypeLen = fieldTypeEnd - fieldType;
    eip712_assert(fieldTypeLen > 0);
  
    const char* fieldName = fieldTypeEnd + 1;
    eip712_assert(fieldName >= field && fieldName <= fieldEnd);
    const char* fieldNameEnd = fieldEnd;
    size_t fieldNameLen = fieldNameEnd - fieldName;
    eip712_assert(eip712_isValidIdentifier(fieldName, fieldNameLen));

    eip712_extendExtendedHash(extendedTypeHash, fieldName, fieldNameLen);
    eip712_extendExtendedHash(extendedTypeHash, " ", 1);
    eip712_assert(eip712_extendExtendedHashWithEncodedTypeInner(extendedTypeHash, encodedType, encodedTypeLen, fieldType, fieldTypeLen, typeBitfield, depth + 1));

    field = fieldEnd + 1;
  }
  eip712_extendExtendedHash(extendedTypeHash, ")", 1);

  return true;

abort:
  return false;
}

bool eip712_extendExtendedHashWithEncodedType(uint8_t extendedTypeHash[SHA3_256_DIGEST_LENGTH], const char* encodedType, size_t encodedTypeLen) {
  uint8_t typeBitfield[EIP712_FIELD_LIMIT_BITFIELD_SIZE] = { 0 };
  size_t typeCount = 0;

  eip712_assert(eip712_countTypesInEncodedType(encodedType, encodedTypeLen, &typeCount));
  eip712_assert(typeCount > 0);
  eip712_assert(eip712_extendExtendedHashWithEncodedTypeInner(extendedTypeHash, encodedType, encodedTypeLen, NULL, 0, typeBitfield, 0));
  eip712_assert(eip712_countBits(typeBitfield) == typeCount);

  return true;

abort:
  return false;
}
