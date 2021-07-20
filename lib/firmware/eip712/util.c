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

static bool eip712_decodeAsciiInt(const char* in, size_t len, uint32_t* out) {
  if (out) *out = 0;
  uint32_t acc = 0;
  // the length restriction prevents overflow of uint32_t
  if (len == 0 || len > 9 || in[0] == '0') return false;
  for (size_t i = 0; i < len; i++) {
    char x = in[i];
    if (x < '0' || x > '9') return false;
    acc = (acc * 10) + (x - '0');
  }
  if (out) *out = acc;
  return true;
}

bool eip712_isValidIdentifier(const char* name, size_t len) {
  if (len == 0) return false;
  for (size_t i = 0; i < len; i++) {
    char x = name[i];
    if (!(
      (x >= 'a' && x <= 'z') || 
      (x >= 'A' && x <= 'Z') || 
      x == '$' ||
      x == '_' ||
      (i > 0 && x >= '0' && x <= '9') ||
      false
    )) return false;
  }
  return true;
}

bool eip712_isAtomicType(const char* type, size_t typeLen, int8_t* padLen) {
  if (padLen) *padLen = 0;

  if (typeLen == 4 && memcmp(type, "bool", 4) == 0) {
    if (padLen) *padLen = 31;
    return true;
  }
  if (typeLen == 7 && memcmp(type, "address", 7) == 0) {
    if (padLen) *padLen = 12;
    return true;
  }
  uint32_t dataLen = 0;
  if (typeLen > 5 && memcmp(type, "bytes", 5) == 0 && eip712_decodeAsciiInt(type + 5, typeLen - 5, &dataLen)) {
    if (dataLen == 0 || dataLen > 32) return false;
    if (padLen) *padLen = -1 * (32 - dataLen);
    return true;
  }
  if (
    (typeLen > 4 && memcmp(type, "uint", 4) == 0 && eip712_decodeAsciiInt(type + 4, typeLen - 4, &dataLen)) ||
    (typeLen > 3 && memcmp(type, "int", 3) == 0 && eip712_decodeAsciiInt(type + 3, typeLen - 3, &dataLen)) ||
    false
  ) {
    if (dataLen & 0x07) return false;
    dataLen >>= 3;
    if (padLen) *padLen = 32 - dataLen;
    return true;
  }
  return false;
}

bool eip712_isDynamicType(const char* type, size_t typeLen) {
  return (
    (typeLen == 5 && memcmp(type, "bytes", 5) == 0) || 
    (typeLen == 6 && memcmp(type, "string", 6) == 0) || 
    false
  );
}

bool eip712_isArrayType(
  const char* type,
  size_t typeLen,
  const char** elementTypeOut,
  size_t* elementTypeLenOut,
  uint32_t* numElementsOut,
  const char** numElementsAsciiOut,
  size_t* numElementsAsciiLenOut
) {
  if (elementTypeOut) *elementTypeOut = NULL;
  if (elementTypeLenOut) *elementTypeLenOut = 0;
  if (numElementsOut) *numElementsOut = 0;
  if (numElementsAsciiOut) *numElementsAsciiOut = NULL;
  if (numElementsAsciiLenOut) *numElementsAsciiLenOut = 0;

  // Minimal array type: "A[]"
  if (typeLen < 3) return false;
  
  // Must end with ']'
  const char* numElementsAsciiEnd = &type[typeLen - 1];
  if (*numElementsAsciiEnd != ']') return false;

  // Extract numElements
  const char* numElementsAscii = numElementsAsciiEnd;
  while (numElementsAscii > type && *(--numElementsAscii) != '[') {}
  if (numElementsAscii <= type) return false;  // opening bracket not found (or is the first char)
  numElementsAscii += 1; // Advance to character after opening bracket
  eip712_assert(numElementsAscii <= numElementsAsciiEnd);
  size_t numElementsAsciiLen = numElementsAsciiEnd - numElementsAscii;

  if (numElementsAscii == numElementsAsciiEnd) {
    if (numElementsOut) *numElementsOut = UINT32_MAX;
  } else {
    if (!eip712_decodeAsciiInt(numElementsAscii, numElementsAsciiEnd - numElementsAscii, numElementsOut)) return false;
  }

  const char* elementType = type;
  size_t elementTypeLen = numElementsAscii - type - 1; // minus one for the '[' before numElements

  if (elementTypeOut) *elementTypeOut = elementType;
  if (elementTypeLenOut) *elementTypeLenOut = elementTypeLen;
  if (numElementsAsciiOut) *numElementsAsciiOut = numElementsAscii;
  if (numElementsAsciiLenOut) *numElementsAsciiLenOut = numElementsAsciiLen;

  review_without_button_request("eip712_isArrayType", "%.*s\n%.*s\n%*.s", (int)typeLen, type, (int)elementTypeLen, elementType, (int)numElementsAsciiLen, numElementsAscii);

  return true;

abort:
  return false;
}

void eip712_keccak_init(EIP712KeccakHash* x) {
  keccak_256_Init(&x->ctx);
}

void eip712_keccak_update(EIP712KeccakHash* x, const void* buf, size_t len) {
  return keccak_Update(&x->ctx, (const uint8_t*)buf, len);
}

void eip712_keccak_finalize(EIP712KeccakHash* x) {
  uint8_t digest[SHA3_256_DIGEST_LENGTH];
  keccak_Final(&x->ctx, digest);
  memcpy(x->digest, digest, sizeof(digest));
}
