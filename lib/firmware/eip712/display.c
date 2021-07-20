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
#include "trezor/crypto/address.h"
#include "trezor/crypto/bignum.h"

#include <stdio.h>

static bool eip712_formatValueForDisplay(
  const char* type,
  size_t typeLen,
  const uint8_t* valueBuf,
  size_t valueBufLen,
  size_t valueLen,
  char* out,
  size_t outSize,
  size_t* outLen
) {
  eip712_assert(valueLen >= valueBufLen);

  *outLen = 0;
  if (typeLen == 4 && memcmp(type, "bool", 4) == 0) {
    // Bools are just the strings "true" or "false"
    eip712_assert(valueBufLen == 1);
    eip712_assert(valueBufLen == valueLen);
    if (valueBuf[0] != 0) {
      *outLen += snprintf(out + *outLen, outSize - *outLen, "true");
    } else {
      *outLen += snprintf(out + *outLen, outSize - *outLen, "false");
    }
  } else if (typeLen == 6 && memcmp(type, "string", 6) == 0) {
    // Display strings in JSON-style double-quoted encoding
    *outLen += snprintf(out + *outLen, outSize - *outLen, "\"");
    for (size_t i = 0; i < valueBufLen; i++) {
      if (valueBuf[i] != '"' && valueBuf[i] != '\\') {
        *outLen += snprintf(out + *outLen, outSize - *outLen, "%c", valueBuf[i]);
      } else {
        *outLen += snprintf(out + *outLen, outSize - *outLen, "\\%c", valueBuf[i]);
      }
    }
    *outLen += snprintf(out + *outLen, outSize - *outLen, "\"");
  } else if (typeLen == 7 && memcmp(type, "address", 7) == 0 && valueBufLen == 20) {
    // Display addresses using EIP-55
    char address[40];
    ethereum_address_checksum(valueBuf, address, false, 0);
    *outLen += snprintf(out + *outLen, outSize - *outLen, "0x");
    *outLen += snprintf(out + *outLen, outSize - *outLen, "%.*s", sizeof(address), address);
  } else if ((
      (typeLen >= 4 && memcmp(type, "uint", 4) == 0) ||
      (typeLen >= 3 && memcmp(type, "int", 3) == 0)
  ) && valueBufLen > 0 && valueBufLen <= 32) {
    // Display integers as decimal numbers
    bool isNegative = type[0] == 'i' && (valueBuf[0] & 0x80);
    uint8_t numBuf[32];
    // Sign-extend negative ints
    memset(numBuf, (isNegative ? 0xff : 0x00), sizeof(numBuf));
    memcpy(numBuf + (32 - valueBufLen), valueBuf, valueBufLen);
    bignum256 num;
    bn_read_be(numBuf, &num);
    char numStr[79];  // UINT256_MAX is 78 characters long in base 10
    bn_format(&num, NULL, NULL, 0, 0, false, numStr, sizeof(numStr));
    *outLen += snprintf(out + *outLen, outSize - *outLen, "%.*s(%s)", (int)typeLen, type, numStr);
  } else if (valueBufLen > 0) {
    // Everything else with actual content gets rendered as 0x-prefixed hex
    *outLen += snprintf(out + *outLen, outSize - *outLen, "0x");
    for (size_t i = 0; i < valueBufLen; i++) {
      *outLen += snprintf(out + *outLen, outSize - *outLen, "%02x", valueBuf[i]);
    }
  } else if (valueLen == 0) {
    // And truly empty values render as "(empty)"
    eip712_assert(valueBufLen == valueLen);
    *outLen += snprintf(out + *outLen, outSize - *outLen, "(empty)");
  }

  // Anything whose display has been truncated (i.e. dynamic data) gets a trailing ellipsis
  if (valueBufLen < valueLen) {
    *outLen += snprintf(out + *outLen, outSize - *outLen, "...");
  }

  return true;

abort:
  return false;
}

static bool eip712_formatStructPath(EIP712EncodingSession* session, const char* name, size_t nameLen, const char* type, size_t typeLen, char* out, size_t outSize, size_t* outLen) {
  eip712_assert(eip712_sessionOk(session));

  if (session->numFrames > 0) *outLen += snprintf(out + *outLen, outSize - *outLen, "%s", session->frames[0].typeName);
  for (size_t i = 1; i < session->numFrames; i++) {
    *outLen += snprintf(out + *outLen, outSize - *outLen, " / %s: %s", session->frames[i].fieldName, session->frames[i].typeName);
  }
  if (nameLen > 0 || typeLen > 0) {
    if (session->numFrames > 0) *outLen += snprintf(out + *outLen, outSize - *outLen, " / ");
    if (nameLen > 0) *outLen += snprintf(out + *outLen, outSize - *outLen, "%.*s", (int)nameLen, name);
    if (nameLen > 0 && typeLen > 0) *outLen += snprintf(out + *outLen, outSize - *outLen, ": ");
    if (typeLen > 0) *outLen += snprintf(out + *outLen, outSize - *outLen, "%.*s", (int)typeLen, type);
  }

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_displayEmptyStruct(EIP712EncodingSession* session, const char* name, size_t nameLen, const char* type, size_t typeLen) {
  eip712_assert(eip712_sessionOk(session));

  char structPath[256];
  size_t structPathLen = 0;
  eip712_assert(eip712_formatStructPath(session, name, nameLen, type, typeLen, structPath, sizeof(structPath), &structPathLen));
  // eip712_assert(confirm(
  //   ButtonRequestType_ButtonRequest_ProtectCall,
  //   "EIP-712 Typed Data",
  //   "%.*s\n(empty)",
  //   (int)structPathLen, structPath
  // ));
  eip712_assert(confirm(ButtonRequestType_ButtonRequest_ProtectCall, structPath, "(empty)"));

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

static bool eip712_displayField(EIP712EncodingSession* session, const char* name, size_t nameLen, const char* type, size_t typeLen, const uint8_t* valueBuf, size_t valueBufLen, size_t valueLen) {
  eip712_assert(eip712_sessionOk(session));

  char serialized[256];
  size_t serializedLen = 0;
  eip712_assert(eip712_formatValueForDisplay(type, typeLen, valueBuf, valueBufLen, valueLen, serialized, sizeof(serialized), &serializedLen));

  char structPath[256];
  size_t structPathLen = 0;
  eip712_assert(eip712_formatStructPath(session, name, nameLen, type, typeLen, structPath, sizeof(structPath), &structPathLen));
  // eip712_assert(confirm(
  //   ButtonRequestType_ButtonRequest_ProtectCall,
  //   "EIP-712 Typed Data",
  //   "%.*s\n%.*s",
  //   (int)structPathLen, structPath,
  //   (int)serializedLen, serialized
  // ));
  eip712_assert(confirm(ButtonRequestType_ButtonRequest_ProtectCall, structPath, "%.*s", (int)serializedLen, serialized));

  return true;

abort:
  eip712_abortSession(session);
  return false;
}

bool eip712_displayAtomicField(EIP712EncodingSession* session, const char* name, size_t nameLen, const char* type, size_t typeLen, const uint8_t* valueBuf, size_t valueBufLen) {
  return eip712_displayField(session, name, nameLen, type, typeLen, valueBuf, valueBufLen, valueBufLen);
}

bool eip712_displayDynamicField(EIP712EncodingSession* session, const char* name, size_t nameLen, const char* type, size_t typeLen, const uint8_t* valueBuf, size_t valueBufLen, size_t valueLen) {
  return eip712_displayField(session, name, nameLen, type, typeLen, valueBuf, valueBufLen, valueLen);
}

bool eip712_displayEmptyArray(EIP712EncodingSession* session, const char* name, size_t nameLen, const char* type, size_t typeLen) {
  return eip712_displayEmptyStruct(session, name, nameLen, type, typeLen);
}
