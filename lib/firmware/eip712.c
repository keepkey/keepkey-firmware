
/*
 * Copyright (c) 2022 markrypto  (cryptoakorn@gmail.com)
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

/*
    Produces hashes based on the metamask v4 rules. This is different from the
   EIP-712 spec in how arrays of structs are hashed but is compatable with
   metamask. See https://github.com/MetaMask/eth-sig-util/pull/107

    eip712 data rules:
    Parser wants to see C strings, not javascript strings:
        requires all complete json message strings to be enclosed by braces,
   i.e., { ... } Cannot have entire json string quoted, i.e., "{ ... }" will not
   work. Remove all quote escape chars, e.g., {"types":  not  {\"types\": ints:
   Strings representing ints must fit into a long size (64-bits). Note: Do not
   prefix ints or uints with 0x All hex and byte strings must be big-endian Byte
   strings and address should be prefixed by 0x
*/

#include <errno.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/memory.h"
#include "keepkey/firmware/eip712.h"
#include "keepkey/firmware/tiny-json.h"
#include "trezor/crypto/sha3.h"
#include "trezor/crypto/memzero.h"

static const char* udefList[MAX_USERDEF_TYPES] = {0};
static dm confirmProp;

static const char* nameForValue;

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static bool decode_address(const char* string, uint8_t decoded[20]) {
  if (!string || strlen(string) != ADDRESS_SIZE || string[0] != '0' ||
      string[1] != 'x') {
    return false;
  }

  for (size_t i = 0; i < 20; i++) {
    const int high = hex_nibble(string[2 + 2 * i]);
    const int low = hex_nibble(string[3 + 2 * i]);
    if (high < 0 || low < 0) return false;
    decoded[i] = (uint8_t)((high << 4) | low);
  }
  return true;
}

/* Append value to dest, a caller-allocated, NUL-terminated buffer of
   STRBUFSIZE+1 bytes. Returns false and leaves dest untouched if the result
   would not fit. Deliberately never truncates: a truncated encodeType string
   hashes to a typehash the host did not ask for, and two distinct type sets
   sharing a prefix would collide, so callers must fail closed instead. */
static bool append_type_string(char* dest, const char* value) {
  if (!dest || !value) return false;
  const size_t used = strnlen(dest, STRBUFSIZE + 1);
  const size_t added = strlen(value);
  if (used > STRBUFSIZE || added > STRBUFSIZE - used) return false;
  memcpy(dest + used, value, added + 1);
  return true;
}

/* Read a run of decimal digits at *cursor into *value, refusing anything that
   would exceed limit. strtol()/strtoul() cannot be used for type-string widths:
   they saturate silently, so "bytes4294967297" and "uint4294967552" become
   small in-range numbers after the caller's cast and a type the host invented
   gets encoded as a type the user was shown. Advances *cursor past the digits
   only on success. */
static bool parse_bounded_decimal(const char** cursor, size_t limit,
                                  size_t* value) {
  const char* p = *cursor;
  if (*p < '0' || *p > '9') return false;

  size_t parsed = 0;
  while (*p >= '0' && *p <= '9') {
    const size_t digit = (size_t)(*p - '0');
    if (parsed > (limit - digit) / 10) return false;
    parsed = parsed * 10 + digit;
    p++;
  }
  *cursor = p;
  *value = parsed;
  return true;
}

/* Parse the array part of a type name: "" (not an array), "[]" (dynamic) or
   "[N]" (fixed, N > 0). Anything else is rejected outright. */
static bool parse_array_suffix(const char* suffix, bool* fixed,
                               size_t* expected) {
  *fixed = false;
  *expected = 0;
  if (*suffix == '\0') return true;
  if (*suffix++ != '[') return false;
  if (*suffix == ']') return suffix[1] == '\0';

  size_t count = 0;
  if (!parse_bounded_decimal(&suffix, (size_t)-1, &count) || count == 0 ||
      suffix[0] != ']' || suffix[1] != '\0') {
    return false;
  }
  *fixed = true;
  *expected = count;
  return true;
}

static bool type_array_suffix_is_valid(const char* suffix) {
  bool fixed = false;
  size_t expected = 0;
  return parse_array_suffix(suffix, &fixed, &expected);
}

/* A declared Type[N] must be supplied with exactly N elements. Without this
   the device hashes whatever cardinality the host sent while displaying it as
   the declared type, so a compliant verifier reconstructing Type[N] computes a
   different hash than the one the user approved. */
static bool fixed_array_cardinality_matches(const char* type,
                                            const json_t* value) {
  const char* suffix = strchr(type, '[');
  if (!suffix) return true;

  bool fixed = false;
  size_t expected = 0;
  if (!parse_array_suffix(suffix, &fixed, &expected)) return false;
  if (!fixed) return true;
  if (json_getType(value) != JSON_ARRAY) return false;

  size_t actual = 0;
  for (const json_t* element = json_getChild(value); element;
       element = json_getSibling(element)) {
    if (++actual > expected) return false;
  }
  return actual == expected;
}

/* Match the WHOLE type name, not a prefix. The dispatch this replaces used
   strncmp() with a truncated length, so a user-defined struct named
   "addressBook" was classified ADDRESS, "interval" was INT and "stringUtils"
   was STRING -- the struct the user is shown as a struct is encoded as a
   primitive and its own definition never enters the encodeType string. */
static bool type_matches(const char* type, const char* base) {
  const size_t len = strlen(base);
  return strncmp(type, base, len) == 0 &&
         type_array_suffix_is_valid(type + len);
}

static bool type_is_integer(const char* type, const char* prefix) {
  const size_t prefix_len = strlen(prefix);
  if (strncmp(type, prefix, prefix_len) != 0) return false;
  const char* p = type + prefix_len;
  size_t bits = 0;
  const bool has_bits = *p >= '0' && *p <= '9';
  if (has_bits && !parse_bounded_decimal(&p, 256, &bits)) return false;
  if (has_bits && (bits < 8 || bits > 256 || (bits % 8) != 0)) return false;
  return type_array_suffix_is_valid(p);
}

static unsigned integer_type_width(const char* type, const char* prefix) {
  const char* p = type + strlen(prefix);
  if (*p < '0' || *p > '9') return 256;
  size_t bits = 0;
  if (!parse_bounded_decimal(&p, 256, &bits)) return 256;
  return (unsigned)bits;
}

/* Classify "bytes" / "bytesN" and recover N without the 8-bit truncation the
   old (uint8_t)strtol() cast performed. */
static bool type_is_bytes(const char* type, unsigned* byte_size,
                          bool* dynamic) {
  if (strncmp(type, "bytes", 5) != 0) return false;
  const char* p = type + 5;
  if (*p == '\0' || *p == '[') {
    if (!type_array_suffix_is_valid(p)) return false;
    *byte_size = 0;
    *dynamic = true;
    return true;
  }
  size_t size = 0;
  if (!parse_bounded_decimal(&p, 32, &size) || size == 0 ||
      !type_array_suffix_is_valid(p))
    return false;
  *byte_size = (unsigned)size;
  *dynamic = false;
  return true;
}

/* A 0x-prefixed, even-length, all-hex string, optionally of an exact byte
   count. The encoders walked the value two characters at a time with no
   validation at all: an odd-length value stepped OVER the terminating NUL and
   fed adjacent RAM into the keccak state while the OLED showed only the short
   value the host sent. */
static bool hex_string_is_valid(const char* string, size_t expected_bytes,
                                bool exact_size) {
  if (!string || string[0] != '0' || string[1] != 'x') return false;
  const size_t chars = strlen(string + 2);
  if ((chars & 1) != 0 || (exact_size && chars != 2 * expected_bytes))
    return false;
  for (size_t i = 0; i < chars; i++) {
    if (hex_nibble(string[i + 2]) < 0) return false;
  }
  return true;
}

int encodableType(const char* typeStr) {
  int ctr;

  if (!typeStr || typeStr[0] == '\0') return NOT_ENCODABLE;

  if (type_matches(typeStr, "address")) {
    return ADDRESS;
  }
  if (type_matches(typeStr, "string")) {
    return STRING;
  }
  if (type_is_integer(typeStr, "int")) {
    // This could be 'int8', 'int16', ..., 'int256'
    return INT;
  }
  if (type_is_integer(typeStr, "uint")) {
    // This could be 'uint8', 'uint16', ..., 'uint256'
    return UINT;
  }
  unsigned byte_size = 0;
  bool dynamic = false;
  if (type_is_bytes(typeStr, &byte_size, &dynamic)) {
    // This could be 'bytes', 'bytes1', ..., 'bytes32'
    return dynamic ? BYTES : BYTES_N;
  }
  if (type_matches(typeStr, "bool")) {
    return BOOL;
  }

  // See if type already defined. If so, skip, otherwise add it to list
  for (ctr = 0; ctr < MAX_USERDEF_TYPES; ctr++) {
    char typeNoArrTok[MAX_TYPESTRING] = {0};

    strncpy(typeNoArrTok, typeStr, sizeof(typeNoArrTok) - 1);
    strtok(typeNoArrTok, "[");  // eliminate the array tokens if there

    if (udefList[ctr] != 0) {
      /* Compare the stored name (minus any array tokens) against the candidate
         by equal length plus a real prefix match. The previous form passed
         strlen(stored) - strlen(candidate) as the length: for two same-length
         names that is 0, so strncmp() returned 0 and ANY same-length struct was
         reported as already-defined -- parseType() then never appended that
         struct's definition and the typehash was computed over an incomplete
         type set. When the candidate was longer the subtraction underflowed to
         a huge size_t. */
      const size_t previous_len = strcspn(udefList[ctr], "[");
      const size_t candidate_len = strlen(typeNoArrTok);
      if (previous_len == candidate_len &&
          strncmp(udefList[ctr], typeNoArrTok, candidate_len) == 0) {
        return PREV_USERDEF;
      } else {
      }

    } else {
      udefList[ctr] = typeStr;
      return UDEF_TYPE;
    }
  }
  if (ctr == MAX_USERDEF_TYPES) {
    return TOO_MANY_UDEFS;
  }

  return NOT_ENCODABLE;  // not encodable
}

/*
    Entry:
            eip712Types points to eip712 json type structure to parse
            typeS points to the type to parse from jType
            typeStr points to caller allocated, zeroized string buffer of size
   STRBUFSIZE+1 Exit: typeStr points to hashable type string returns error list
   status

    NOTE: reentrant!
*/
int parseType(const json_t* eip712Types, const char* typeS, char* typeStr) {
  json_t const *tarray, *pairs;
  const json_t* jType;
  char append[STRBUFSIZE + 1] = {0};
  const char* typeType = NULL;
  const json_t* obTest;
  const char* nameTest;

  if (NULL == (jType = json_getProperty(eip712Types, typeS))) {
    return JSON_TYPE_S_ERR;
  }

  if (NULL == (nameTest = json_getName(jType))) {
    return JSON_TYPE_S_NAMEERR;
  }

  if (!append_type_string(typeStr, nameTest) ||
      !append_type_string(typeStr, "(")) {
    return UDEF_NAME_ERROR;
  }

  tarray = json_getChild(jType);
  while (tarray != 0) {
    if (NULL == (pairs = json_getChild(tarray))) {
      return JSON_NO_PAIRS;
    }
    // should be type JSON_TEXT
    if (pairs->type != JSON_TEXT) {
      return JSON_PAIRS_NOTEXT;
    } else {
      if (NULL == (obTest = json_getSibling(pairs))) {
        return JSON_NO_PAIRS_SIB;
      }
      typeType = json_getValue(obTest);
      int encTest = encodableType(typeType);
      if (encTest == UDEF_TYPE) {
        // This is a user-defined type, parse it and append later
        if (']' == typeType[strlen(typeType) - 1]) {
          // array of structs. To parse name, remove array tokens.
          char typeNoArrTok[MAX_TYPESTRING] = {0};
          strncpy(typeNoArrTok, typeType, sizeof(typeNoArrTok) - 1);
          if (strlen(typeNoArrTok) < strlen(typeType)) {
            return UDEF_NAME_ERROR;
          }

          strtok(typeNoArrTok, "[");
          int errRet;
          if (STACK_GOOD != (errRet = memcheck(STACK_SIZE_GUARD))) {
            return errRet;
          }
          if (SUCCESS !=
              (errRet = parseType(eip712Types, typeNoArrTok, append))) {
            return errRet;
          }
        } else {
          int errRet;
          if (STACK_GOOD != (errRet = memcheck(STACK_SIZE_GUARD))) {
            return errRet;
          }
          if (SUCCESS != (errRet = parseType(eip712Types, typeType, append))) {
            return errRet;
          }
        }
      } else if (encTest == TOO_MANY_UDEFS) {
        return UDEFS_OVERFLOW;
      } else if (encTest == NOT_ENCODABLE) {
        return TYPE_NOT_ENCODABLE;
      }

      const char* pVal = json_getValue(pairs);
      if (NULL == pVal) {
        return JSON_NOPAIRVAL;
      }
      if (!append_type_string(typeStr, typeType) ||
          !append_type_string(typeStr, " ") ||
          !append_type_string(typeStr, pVal) ||
          !append_type_string(typeStr, ",")) {
        return UDEF_NAME_ERROR;
      }
    }
    tarray = json_getSibling(tarray);
  }
  // typeStr ends with a ',' unless there are no parameters to the type.
  if (typeStr[strlen(typeStr) - 1] == ',') {
    // replace last comma with a paren
    typeStr[strlen(typeStr) - 1] = ')';
  } else {
    // append paren, there are no parameters
    if (!append_type_string(typeStr, ")")) {
      return UDEF_NAME_ERROR;
    }
  }
  if (strlen(append) > 0) {
    if (!append_type_string(typeStr, append)) {
      return UDEF_NAME_ERROR;
    }
  }

  return SUCCESS;
}

int encAddress(const char* string, uint8_t* encoded) {
  if (string == NULL) {
    return ADDR_STRING_NULL;
  }
  uint8_t decoded[20];
  if (!decode_address(string, decoded)) {
    return ADDR_STRING_VFLOW;
  }

  memset(encoded, 0, 12);
  memcpy(encoded + 12, decoded, sizeof(decoded));
  return SUCCESS;
}

int encString(const char* string, uint8_t* encoded) {
  struct SHA3_CTX strCtx;

  sha3_256_Init(&strCtx);
  sha3_Update(&strCtx, (const unsigned char*)string, (size_t)strlen(string));
  keccak_Final(&strCtx, encoded);
  return SUCCESS;
}

int encodeBytes(const char* string, uint8_t* encoded) {
  /* Refuse before hashing: the walk below steps two characters at a time, so
     an odd-length or non-hex value would read past the end of the host's JSON
     buffer and hash bytes the user was never shown. */
  if (!hex_string_is_valid(string, 0, false)) return GENERAL_ERROR;
  struct SHA3_CTX byteCtx;
  const char* valStrPtr = string + 2;

  sha3_256_Init(&byteCtx);
  while (*valStrPtr != '\0') {
    const uint8_t valByte =
        (uint8_t)((hex_nibble(valStrPtr[0]) << 4) | hex_nibble(valStrPtr[1]));
    sha3_Update(&byteCtx, &valByte, sizeof(valByte));
    valStrPtr += 2;
  }
  keccak_Final(&byteCtx, encoded);
  return SUCCESS;
}

int encodeBytesN(const char* typeT, const char* string, uint8_t* encoded) {
  /* N comes from type_is_bytes(), which parses it with a bound instead of
     (uint8_t)strtol(): "bytes4294967297" used to wrap to 1 and sail past the
     "32 < byteTypeSize" guard. The value must then be exactly N bytes -- the
     old code right-padded a short value and accepted an over-long one, in both
     cases producing a struct hash for a type the host invented. */
  unsigned byteTypeSize = 0;
  bool dynamic = false;
  if (!type_is_bytes(typeT, &byteTypeSize, &dynamic) || dynamic) {
    return BYTESN_SIZE_ERROR;
  }
  if (!hex_string_is_valid(string, byteTypeSize, true)) {
    return BYTESN_STRING_ERROR;
  }
  memset(encoded, 0, 32);
  // bytesN are zero padded on the right
  for (size_t i = 0; i < byteTypeSize; i++) {
    encoded[i] = (uint8_t)((hex_nibble(string[2 + 2 * i]) << 4) |
                           hex_nibble(string[3 + 2 * i]));
  }
  return SUCCESS;
}

/* These screens were review(), which calls confirm_helper() and then returns
   true unconditionally. confirm_helper() returns false when the host sends a
   Cancel or Initialize tiny message, so a host could refuse every field screen
   and encode() would still hash typed data the user never saw. They are
   confirm() now and refusal is reported to parseVals() as USER_CANCELLED, so
   no hash is produced at all. */
int confirmName(const char* name, bool valAvailable) {
  if (!name) return GENERAL_ERROR;
  /* Record the name unconditionally. confirmValue() labels the value screen
     with it, including every element of an array, and an aggregate field left
     it holding the PREVIOUS field's name -- so the elements of an address[]
     were each shown captioned with an unrelated field. */
  nameForValue = name;
  if (!valAvailable) {
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "MESSAGE DATA",
                 "Press button to continue for\n\"%s\" values", name)) {
      return USER_CANCELLED;
    }
  }
  return SUCCESS;
}

int confirmValue(const char* value) {
  /* A NULL value is a parse failure, not a refusal: reporting it as
     USER_CANCELLED would send FailureType_Failure_ActionCancelled for a
     malformed message. It must never reach confirm("%s"). */
  if (!value) return GENERAL_ERROR;
  if (!confirm(ButtonRequestType_ButtonRequest_Other, "MESSAGE DATA", "%s %s",
               nameForValue, value)) {
    return USER_CANCELLED;
  }
  return SUCCESS;
}

static const char *dsname = NULL, *dsversion = NULL, *dschainId = NULL,
                  *dsverifyingContract = NULL;

bool eip712_parse_canonical_u32(const char* text, uint32_t* value) {
  if (!text || !value || text[0] == '\0') return false;
  if (text[0] == '0' && text[1] != '\0') return false;

  uint32_t parsed = 0;
  for (const char* p = text; *p != '\0'; p++) {
    if (*p < '0' || *p > '9') return false;
    const uint32_t digit = (uint32_t)(*p - '0');
    if (parsed > (UINT32_MAX - digit) / 10) return false;
    parsed = parsed * 10 + digit;
  }

  *value = parsed;
  return true;
}

static void clearDsVals(void) {
  dsname = NULL;
  dsversion = NULL;
  dschainId = NULL;
  dsverifyingContract = NULL;
}

void marshallDsVals(const char* value) {
  if (0 == strncmp(nameForValue, "name", sizeof("name"))) {
    dsname = value;
  }
  if (0 == strncmp(nameForValue, "version", sizeof("version"))) {
    dsversion = value;
  }
  if (0 == strncmp(nameForValue, "chainId", sizeof("chainId"))) {
    dschainId = value;
  }
  if (0 ==
      strncmp(nameForValue, "verifyingContract", sizeof("verifyingContract"))) {
    dsverifyingContract = value;
  }
  return;
}

/* Domain-separator values are marshalled and shown together on dsConfirm()'s
   single screen; every other value gets its own screen here. Refusal of either
   is reported to parseVals() so no hash is produced. */
static int confirmTypedValue(bool ds_vals, const char* value) {
  if (!value) return GENERAL_ERROR;
  if (ds_vals) {
    marshallDsVals(value);
    return SUCCESS;
  }
  return confirmValue(value);
}

int dsConfirm(void) {
  char name[41] = {0};
  char version[11] = {0};
  IconType iconNum = NO_ICON;
  char title[64] = {0};
  char* fillerStr = "";
  char chainStr[33] = {0};
  char verifyingContract[65] = {0};

  if (dsname != NULL) {
    strncpy(name, dsname, 40);
  }
  if (dsversion != NULL) {
    strncpy(version, dsversion, 10);
  }

  if (dsverifyingContract != NULL) {
    /* EIP-712 types are host-controlled, so verifyingContract may reach this
     * function without having passed through the address encoder. Validate it
     * before any fixed-offset read or display.
     *
     * Merge note (#439 vs #440/GH #436): both branches fixed the same OOB read.
     * This one is kept because it is strictly stronger — it validates the hex
     * digits as well as the length and prefix, and it fails closed. The other
     * checked only length and "0x", then set dsverifyingContract = NULL and
     * fell through to a raw display, so a value like "0xZZZZ..." still reached
     * sscanf and a malformed contract was shown rather than refused. */
    /* Scoped to this block: cppcheck's variableScope rightly flagged it at
       function scope, and CI treats that as fatal. Twenty bytes exactly, the
       destination decode_address() validates into. */
    uint8_t addrHexStr[20] = {0};
    if (!decode_address(dsverifyingContract, addrHexStr)) {
      clearDsVals();
      return ADDR_STRING_VFLOW;
    }
    (void)addrHexStr;
    snprintf(verifyingContract, sizeof(verifyingContract),
             "Verifying Contract: %s", dsverifyingContract);
  }

  if (NULL != dschainId) {
    /* Merge note: the release branch parsed this with sscanf("%" SCNu32),
     * which accepts a trailing space, a leading '+', and non-canonical forms
     * like "007", and cannot report overflow. eip712_parse_canonical_u32()
     * rejects all of those and fails closed, so it is used instead. See the
     * cases in unittests/firmware/ethereum.cpp. */
    uint32_t chainInt = 0;
    if (!eip712_parse_canonical_u32(dschainId, &chainInt)) {
      clearDsVals();
      return GENERAL_ERROR;
    }
    (void)chainInt;
    // As more chains are supported, add icon choice below
    // TBD: not implemented for first release
    // if (chainInt == 1) {
    //     iconNum = ETHEREUM_ICON;
    // }
  }
  strncpy(title, name, 40);
  if (NULL != dsversion) {
    strncat(title, " Ver: ", 63 - strlen(title));
    strncat(title, version, 63 - strlen(title));
  }
  if (NULL != dschainId) {
    snprintf(chainStr, 32, "chain %s,  ", dschainId);
  }
  // snprintf(contractStr, 64, "verifyingContract: %s", verifyingContract);
  bool confirmed =
      confirm_with_icon(ButtonRequestType_ButtonRequest_Other, iconNum, title,
                        "%s %s%s", chainStr, verifyingContract, fillerStr);
  /* Clear the marshalled domain values on the refusal path too: they are file
     statics and a later attempt must not inherit them. */
  clearDsVals();
  return confirmed ? SUCCESS : USER_CANCELLED;
}

/*
    Entry:
            eip712Types points to the eip712 types structure
            jType points to eip712 json type structure to parse
            nextVal points to the next value to encode
            msgCtx points to caller allocated hash context to hash encoded
   values into. Exit: msgCtx points to current final hash context returns error
   status

    NOTE: reentrant!
*/
int parseVals(const json_t* eip712Types, const json_t* jType,
              const json_t* nextVal, struct SHA3_CTX* msgCtx) {
  json_t const *tarray, *pairs, *walkVals, *obTest;
  int ctr;
  const char* typeType = NULL;
  uint8_t encBytes[32] = {0};  // holds the encrypted bytes for the message
  const char* valStr = NULL;
  struct SHA3_CTX valCtx = {0};  // local hash context
  bool ds_vals = 0;  // domain sep values are confirmed on a single screen
  int errRet;

  if (0 ==
      strncmp(json_getName(jType), "EIP712Domain", sizeof("EIP712Domain"))) {
    ds_vals = true;
  }

  tarray = json_getChild(jType);

  while (tarray != 0) {
    if (NULL == (pairs = json_getChild(tarray))) {
      return JSON_NO_PAIRS;
    }
    // should be type JSON_TEXT
    if (pairs->type != JSON_TEXT) {
      return JSON_PAIRS_NOTEXT;
    } else {
      const char* typeName = json_getValue(pairs);
      if (NULL == typeName) {
        return JSON_NOPAIRNAME;
      }
      if (NULL == (obTest = json_getSibling(pairs))) {
        return JSON_NO_PAIRS_SIB;
      }
      if (NULL == (typeType = json_getValue(obTest))) {
        return JSON_TYPE_T_NOVAL;
      }
      walkVals = nextVal;
      while (0 != walkVals) {
        if (0 == strcmp(json_getName(walkVals), typeName)) {
          break;
        } else {
          // keep looking for val
          walkVals = json_getSibling(walkVals);
        }
      }

      if (walkVals == 0) {
        return JSON_TYPE_WNOVAL;
      }
      const jsonType_t value_type = json_getType(walkVals);
      if (!fixed_array_cardinality_matches(typeType, walkVals)) {
        return GENERAL_ERROR;
      }
      const bool hasValue = value_type == JSON_TEXT ||
                            value_type == JSON_INTEGER ||
                            value_type == JSON_BOOLEAN;
      valStr = hasValue ? json_getValue(walkVals) : NULL;
      if (SUCCESS != (errRet = confirmName(typeName, hasValue))) {
        return errRet;
      }

      {
        if (type_matches(typeType, "address")) {
          if (']' == typeType[strlen(typeType) - 1]) {
            // array of addresses
            if (value_type != JSON_ARRAY) return GENERAL_ERROR;
            json_t const* addrVals = json_getChild(walkVals);
            sha3_256_Init(&valCtx);  // hash of concatenated encoded strings
            while (0 != addrVals) {
              if (json_getType(addrVals) != JSON_TEXT) return GENERAL_ERROR;
              const char* address = json_getValue(addrVals);
              // just walk the string values assuming, for fixed sizes, all
              // values are there.
              if (SUCCESS != (errRet = confirmTypedValue(ds_vals, address))) {
                return errRet;
              }

              errRet = encAddress(address, encBytes);
              if (SUCCESS != errRet) {
                return errRet;
              }
              sha3_Update(&valCtx, (const unsigned char*)encBytes, 32);
              addrVals = json_getSibling(addrVals);
            }
            keccak_Final(&valCtx, encBytes);
          } else {
            if (value_type != JSON_TEXT) return GENERAL_ERROR;
            if (SUCCESS != (errRet = confirmTypedValue(ds_vals, valStr))) {
              return errRet;
            }
            errRet = encAddress(valStr, encBytes);
            if (SUCCESS != errRet) {
              return errRet;
            }
          }

        } else if (type_matches(typeType, "string")) {
          if (']' == typeType[strlen(typeType) - 1]) {
            // array of strings
            if (value_type != JSON_ARRAY) return GENERAL_ERROR;
            json_t const* stringVals = json_getChild(walkVals);
            uint8_t strEncBytes[32];
            sha3_256_Init(&valCtx);  // hash of concatenated encoded strings
            while (0 != stringVals) {
              if (json_getType(stringVals) != JSON_TEXT) return GENERAL_ERROR;
              const char* string_value = json_getValue(stringVals);
              // just walk the string values assuming, for fixed sizes, all
              // values are there.
              if (SUCCESS !=
                  (errRet = confirmTypedValue(ds_vals, string_value))) {
                return errRet;
              }
              errRet = encString(string_value, strEncBytes);
              if (SUCCESS != errRet) {
                return errRet;
              }
              sha3_Update(&valCtx, (const unsigned char*)strEncBytes, 32);
              stringVals = json_getSibling(stringVals);
            }
            keccak_Final(&valCtx, encBytes);
          } else {
            if (value_type != JSON_TEXT) return GENERAL_ERROR;
            if (SUCCESS != (errRet = confirmTypedValue(ds_vals, valStr))) {
              return errRet;
            }
            errRet = encString(valStr, encBytes);
            if (SUCCESS != errRet) {
              return errRet;
            }
          }

        } else if (type_is_integer(typeType, "uint") ||
                   type_is_integer(typeType, "int")) {
          if (']' == typeType[strlen(typeType) - 1]) {
            return INT_ARRAY_ERROR;
          } else {
            if (value_type != JSON_TEXT && value_type != JSON_INTEGER)
              return GENERAL_ERROR;
            if (SUCCESS != (errRet = confirmTypedValue(ds_vals, valStr))) {
              return errRet;
            }
            const bool is_uint = type_is_integer(typeType, "uint");
            uint8_t negInt = 0;  // 0 is positive, 1 is negative
            if (!is_uint) {
              if (*valStr == '-') {
                negInt = 1;
              }
            }
            // parse out the length val
            for (ctr = 0; ctr < 32; ctr++) {
              if (negInt) {
                // sign extend negative values
                encBytes[ctr] = 0xFF;
              } else {
                // zero padding for positive
                encBytes[ctr] = 0;
              }
            }
            // all int strings are assumed to be base 10 and fit into 64 bits
            const char* digits = valStr + (negInt ? 1 : 0);
            if (*digits == '\0') return GENERAL_ERROR;
            for (const char* p = digits; *p; p++) {
              if (*p < '0' || *p > '9') return GENERAL_ERROR;
            }
            errno = 0;
            char* endptr = NULL;
            long long intVal = strtoll(valStr, &endptr, 10);
            if (errno == ERANGE || endptr == valStr || *endptr != '\0') {
              return GENERAL_ERROR;
            }
            if (is_uint && intVal < 0) {
              return GENERAL_ERROR;
            }
            const unsigned declared_bits =
                integer_type_width(typeType, is_uint ? "uint" : "int");
            if (declared_bits < 64) {
              if (is_uint) {
                const uint64_t max_value = (UINT64_C(1) << declared_bits) - 1;
                if ((uint64_t)intVal > max_value) return GENERAL_ERROR;
              } else {
                const int64_t min_value = -(INT64_C(1) << (declared_bits - 1));
                const int64_t max_value =
                    (INT64_C(1) << (declared_bits - 1)) - 1;
                if (intVal < min_value || intVal > max_value)
                  return GENERAL_ERROR;
              }
            }
            // Needs to be big endian, so add to encBytes appropriately
            const uint64_t intBits = (uint64_t)intVal;
            encBytes[24] = (intBits >> 56) & 0xff;
            encBytes[25] = (intBits >> 48) & 0xff;
            encBytes[26] = (intBits >> 40) & 0xff;
            encBytes[27] = (intBits >> 32) & 0xff;
            encBytes[28] = (intBits >> 24) & 0xff;
            encBytes[29] = (intBits >> 16) & 0xff;
            encBytes[30] = (intBits >> 8) & 0xff;
            encBytes[31] = intBits & 0xff;
          }

        } else {
          unsigned byte_size = 0;
          bool dynamic_bytes = false;
          if (type_is_bytes(typeType, &byte_size, &dynamic_bytes)) {
            if (']' == typeType[strlen(typeType) - 1]) {
              return BYTESN_ARRAY_ERROR;
            } else {
              if (value_type != JSON_TEXT) return GENERAL_ERROR;
              // This could be 'bytes', 'bytes1', ..., 'bytes32'
              if (SUCCESS != (errRet = confirmTypedValue(ds_vals, valStr))) {
                return errRet;
              }
              if (dynamic_bytes) {
                errRet = encodeBytes(valStr, encBytes);
                if (SUCCESS != errRet) {
                  return errRet;
                }

              } else {
                errRet = encodeBytesN(typeType, valStr, encBytes);
                if (SUCCESS != errRet) {
                  return errRet;
                }
              }
            }

          } else if (type_matches(typeType, "bool")) {
            if (']' == typeType[strlen(typeType) - 1]) {
              return BOOL_ARRAY_ERROR;
            } else {
              if (value_type != JSON_BOOLEAN && value_type != JSON_TEXT)
                return GENERAL_ERROR;
              if (SUCCESS != (errRet = confirmTypedValue(ds_vals, valStr))) {
                return errRet;
              }
              if (strcmp(valStr, "true") != 0 && strcmp(valStr, "false") != 0)
                return GENERAL_ERROR;
              for (ctr = 0; ctr < 32; ctr++) {
                // leading zeros in bool
                encBytes[ctr] = 0;
              }
              if (strcmp(valStr, "true") == 0) {
                encBytes[31] = 0x01;
              }
            }

          } else {
            // encode user defined type
            char encSubTypeStr[STRBUFSIZE + 1] = {0};
            // clear out the user-defined types list
            for (ctr = 0; ctr < MAX_USERDEF_TYPES; ctr++) {
              udefList[ctr] = NULL;
            }

            char typeNoArrTok[MAX_TYPESTRING] = {0};
            // need to get typehash of type first
            if (']' == typeType[strlen(typeType) - 1]) {
              // array of structs. To parse name, remove array tokens.
              if (value_type != JSON_ARRAY) return GENERAL_ERROR;
              strncpy(typeNoArrTok, typeType, sizeof(typeNoArrTok) - 1);
              if (strlen(typeNoArrTok) < strlen(typeType)) {
                return UDEF_ARRAY_NAME_ERR;
              }
              strtok(typeNoArrTok, "[");
              if (STACK_GOOD != (errRet = memcheck(STACK_SIZE_GUARD))) {
                return errRet;
              }
              if (SUCCESS != (errRet = parseType(eip712Types, typeNoArrTok,
                                                 encSubTypeStr))) {
                return errRet;
              }
            } else {
              if (STACK_GOOD != (errRet = memcheck(STACK_SIZE_GUARD))) {
                return errRet;
              }
              if (SUCCESS !=
                  (errRet = parseType(eip712Types, typeType, encSubTypeStr))) {
                return errRet;
              }
            }
            sha3_256_Init(&valCtx);
            sha3_Update(&valCtx, (const unsigned char*)encSubTypeStr,
                        (size_t)strlen(encSubTypeStr));
            keccak_Final(&valCtx, encBytes);

            if (']' == typeType[strlen(typeType) - 1]) {
              // array of udefs
              struct SHA3_CTX eleCtx = {0};  // local hash context
              struct SHA3_CTX arrCtx = {0};  // array elements hash context
              uint8_t eleHashBytes[32];

              sha3_256_Init(&arrCtx);

              json_t const* udefVals = json_getChild(walkVals);
              while (0 != udefVals) {
                if (json_getType(udefVals) != JSON_OBJ) return GENERAL_ERROR;
                sha3_256_Init(&eleCtx);
                sha3_Update(&eleCtx, (const unsigned char*)encBytes, 32);
                if (STACK_GOOD != (errRet = memcheck(STACK_SIZE_GUARD))) {
                  return errRet;
                }
                if (SUCCESS !=
                    (errRet = parseVals(
                         eip712Types,
                         json_getProperty(eip712Types,
                                          strtok(typeNoArrTok, "]")),
                         json_getChild(udefVals),  // where to get the values
                         &eleCtx  // encode hash happens in parse, this is the
                                  // return
                         ))) {
                  return errRet;
                }
                keccak_Final(&eleCtx, eleHashBytes);
                sha3_Update(&arrCtx, (const unsigned char*)eleHashBytes, 32);
                // just walk the udef values assuming, for fixed sizes, all
                // values are there.
                udefVals = json_getSibling(udefVals);
              }
              keccak_Final(&arrCtx, encBytes);

            } else {
              if (value_type != JSON_OBJ) return GENERAL_ERROR;
              sha3_256_Init(&valCtx);
              sha3_Update(&valCtx, (const unsigned char*)encBytes,
                          (size_t)sizeof(encBytes));
              if (STACK_GOOD != (errRet = memcheck(STACK_SIZE_GUARD))) {
                return errRet;
              }
              if (SUCCESS !=
                  (errRet = parseVals(
                       eip712Types, json_getProperty(eip712Types, typeType),
                       json_getChild(walkVals),  // where to get the values
                       &valCtx  // val hash happens in parse, this is the return
                       ))) {
                return errRet;
              }
              keccak_Final(&valCtx, encBytes);
            }
          }
        }
      }

      // hash encoded bytes to final context
      sha3_Update(msgCtx, (const unsigned char*)encBytes, 32);
    }
    tarray = json_getSibling(tarray);
  }
  if (ds_vals) {
    if (SUCCESS != (errRet = dsConfirm())) {
      return errRet;
    }
  }

  return SUCCESS;
}

int encode(const json_t* jsonTypes, const json_t* jsonVals, const char* typeS,
           uint8_t* hashRet) {
  int ctr;
  char encTypeStr[STRBUFSIZE + 1] = {0};
  uint8_t typeHash[32];
  struct SHA3_CTX finalCtx = {0};
  int errRet;
  json_t const* typesProp;
  json_t const* typeSprop;
  json_t const* domainOrMessageProp;
  json_t const* valsProp;
  const char* domOrMsgStr = NULL;

  // clear out the user-defined types list
  for (ctr = 0; ctr < MAX_USERDEF_TYPES; ctr++) {
    udefList[ctr] = NULL;
  }
  if (NULL == (typesProp = json_getProperty(jsonTypes, "types"))) {
    errRet = JSON_TYPESPROPERR;
    return errRet;
  }
  if (SUCCESS != (errRet = parseType(typesProp, typeS, encTypeStr))) {
    return errRet;
  }

  sha3_256_Init(&finalCtx);
  sha3_Update(&finalCtx, (const unsigned char*)encTypeStr,
              (size_t)strlen(encTypeStr));
  keccak_Final(&finalCtx, typeHash);

  // They typehash must be the first message of the final hash, this is the
  // start
  sha3_256_Init(&finalCtx);
  sha3_Update(&finalCtx, (const unsigned char*)typeHash,
              (size_t)sizeof(typeHash));

  if (NULL == (typeSprop = json_getProperty(
                   typesProp, typeS))) {  // e.g., typeS = "EIP712Domain"
    errRet = JSON_TYPESPROPERR;
    return errRet;
  }

  if (0 == strncmp(typeS, "EIP712Domain", sizeof("EIP712Domain"))) {
    confirmProp = DOMAIN;
    domOrMsgStr = "domain";
  } else {
    // This is the message value encoding
    confirmProp = MESSAGE;
    domOrMsgStr = "message";
  }
  if (NULL == (domainOrMessageProp = json_getProperty(
                   jsonVals, domOrMsgStr))) {  // "message" or "domain" property
    if (confirmProp == DOMAIN) {
      errRet = JSON_DPROPERR;
    } else {
      errRet = JSON_MPROPERR;
    }
    return errRet;
  }
  if (NULL ==
      (valsProp = json_getChild(
           domainOrMessageProp))) {  // "message" or "domain" property values
    if (confirmProp == MESSAGE) {
      errRet = NULL_MSG_HASH;  // this is legal, not an error.
      return errRet;
    }
  }

  if (SUCCESS !=
      (errRet = parseVals(typesProp, typeSprop, valsProp, &finalCtx))) {
    return errRet;
  }

  keccak_Final(&finalCtx, hashRet);
  // clear typeStr
  memzero(encTypeStr, sizeof(encTypeStr));

  return SUCCESS;
}
