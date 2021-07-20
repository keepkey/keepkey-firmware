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

static bool eip712_findStructTypeInEncodedTypeInner(
  const char* encodedType,
  size_t encodedTypeLen,
  const char* target,
  size_t targetLen,
  bool countTypes,
  const char** typeNameOut,
  size_t* typeNameOutLen,
  const char** typeOut,
  size_t* typeOutLen,
  size_t* indexOut
) {
  if (typeNameOut) *typeNameOut = NULL;
  if (typeNameOutLen) *typeNameOutLen = 0;
  if (typeOut) *typeOut = NULL;
  if (typeOutLen) *typeOutLen = 0;
  if (indexOut) *indexOut = 0;

  if (countTypes) {
    eip712_assert(targetLen == 0);
  }

  const char* inEnd = encodedType + encodedTypeLen;
  eip712_assert(encodedType <= inEnd);

  const char* name = encodedType;
  while (name < inEnd) {
    const char* nameEnd = memchr(name, '(', inEnd - name);
    eip712_assert(name <= nameEnd && nameEnd <= inEnd);
    size_t nameLen = nameEnd - name;
    eip712_assert(eip712_isValidIdentifier(name, nameLen));

    const char* type = nameEnd + 1;
    // [type..typeEnd] must be separated from the type's name and the end
    // of the string by at least 1 character
    eip712_assert(type > nameEnd && type < inEnd);

    const char* typeEnd = memchr(type, ')', inEnd - type);
    eip712_assert(type <= typeEnd && typeEnd < inEnd);
    size_t typeLen = typeEnd - type;

    if (!countTypes && ((targetLen == 0) || (nameLen == targetLen && memcmp(target, name, targetLen) == 0))) {
      if (typeNameOut) *typeNameOut = name;
      if (typeNameOutLen) *typeNameOutLen = nameLen;
      if (typeOut) *typeOut = type;
      if (typeOutLen) *typeOutLen = typeLen;
      return true;
    }

    name = typeEnd + 1;
    if (indexOut) {
      *indexOut += 1;
      eip712_assert(*indexOut != 0);
    }
  }
  return countTypes;

abort:
  return false;
}

bool eip712_findStructTypeInEncodedType(
  const char* encodedType,
  size_t encodedTypeLen,
  const char* target,
  size_t targetLen,
  const char** typeNameOut,
  size_t* typeNameOutLen,
  const char** typeOut,
  size_t* typeOutLen,
  size_t* indexOut
) {
  return eip712_findStructTypeInEncodedTypeInner(encodedType, encodedTypeLen, target, targetLen, false, typeNameOut, typeNameOutLen, typeOut, typeOutLen, indexOut);
}

bool eip712_countTypesInEncodedType(const char* encodedType, size_t encodedTypeLen, size_t* typeCountOut) {
  if (eip712_isDynamicType(encodedType, encodedTypeLen) || eip712_isAtomicType(encodedType, encodedTypeLen, NULL)) {
    if (typeCountOut) *typeCountOut = 1;
    return true;
  }
  const char* elementType = NULL;
  size_t elementTypeLen = 0;
  if (eip712_isArrayType(encodedType, encodedTypeLen, &elementType, &elementTypeLen, NULL, NULL, NULL)) {
    return eip712_countTypesInEncodedType(elementType, elementTypeLen, typeCountOut);
  }
  return eip712_findStructTypeInEncodedTypeInner(encodedType, encodedTypeLen, NULL, 0, true, NULL, 0, NULL, 0, typeCountOut);
}
