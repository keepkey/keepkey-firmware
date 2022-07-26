
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
    Produces hashes based on the metamask v4 rules. This is different from the EIP-712 spec
    in how arrays of structs are hashed but is compatable with metamask.
    See https://github.com/MetaMask/eth-sig-util/pull/107

    eip712 data rules:
    Parser wants to see C strings, not javascript strings:
        requires all complete json message strings to be enclosed by braces, i.e., { ... }
        Cannot have entire json string quoted, i.e., "{ ... }" will not work.
        Remove all quote escape chars, e.g., {"types":  not  {\"types\":
    int values must be hex. Negative sign indicates negative value, e.g., -5, -8a67 
        Note: Do not prefix ints or uints with 0x
    All hex and byte strings must be big-endian
    Byte strings and address should be prefixed by 0x
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "keepkey/board/confirm_sm.h"
#include "keepkey/firmware/tiny-json.h"
#include "trezor/crypto/sha3.h"
#include "trezor/crypto/memzero.h"

// Example
// DEBUG_DISPLAY_VAL("sig", "sig %s", 65, resp->signature.bytes[ctr]);

#define USE_KECCAK 1
#define ADDRESS_SIZE        42
#define JSON_OBJ_POOL_SIZE  100
#define STRBUFSIZE          511
#define MAX_USERDEF_TYPES   10      // This is max number of user defined type allowed
#define MAX_TYPESTRING      33      // maximum size for a type string

typedef enum {
    NOT_ENCODABLE = 0,
    ADDRESS,
    STRING,
    UINT,
    INT,
    BYTES,
    BYTES_N,
    BOOL,
    UDEF_TYPE,
    PREV_USERDEF,
    TOO_MANY_UDEFS
} basicType;

static const char *udefList[MAX_USERDEF_TYPES] = {0};

int encodableType(const char *typeStr) {
    int ctr;

    if (0 == strncmp(typeStr, "address", sizeof("address")-1)) {
        return ADDRESS;
    }
    if (0 == strncmp(typeStr, "string", sizeof("string")-1)) {
        return STRING;
    }
    if (0 == strncmp(typeStr, "int", sizeof("int")-1)) {
        // This could be 'int8', 'int16', ..., 'int256'
        return INT;
    }
    if (0 == strncmp(typeStr, "uint", sizeof("uint")-1)) {
        // This could be 'uint8', 'uint16', ..., 'uint256'
        return UINT;
    }
    if (0 == strncmp(typeStr, "bytes", sizeof("bytes")-1)) {
        // This could be 'bytes', 'bytes1', ..., 'bytes32'
        if (0 == strcmp(typeStr, "bytes")) {
            return BYTES;
        } else {
            // parse out the length val
            uint8_t byteTypeSize = (uint8_t)(strtol((typeStr+5), NULL, 10));
            if (byteTypeSize > 32) {
                return NOT_ENCODABLE;
            } else {
                return BYTES_N;
            }
        }
    }
    if (0 == strcmp(typeStr, "bool")) {
        return BOOL;
    }

    // See if type already defined. If so, skip, otherwise add it to list
    for(ctr=0; ctr<MAX_USERDEF_TYPES; ctr++) {
        char typeNoArrTok[MAX_TYPESTRING] = {0};

        strncpy(typeNoArrTok, typeStr, sizeof(typeNoArrTok)-1);
        strtok(typeNoArrTok, "[");  // eliminate the array tokens if there

        if (udefList[ctr] != 0) {
            if (0 == strncmp(udefList[ctr], typeNoArrTok, strlen(udefList[ctr])-strlen(typeNoArrTok))) {
                return PREV_USERDEF;
            }
            else {}

        } else {
            udefList[ctr] = typeStr;
            return UDEF_TYPE;
        }
    }
    if (ctr == MAX_USERDEF_TYPES) {
        //TODO fix this  printf("could not add %d %s\n", ctr, typeStr);
        return TOO_MANY_UDEFS;
    }

    return NOT_ENCODABLE; // not encodable
}

/*
    Entry: 
            eip712Types points to eip712 json type structure to parse
            typeS points to the type to parse from jType
            typeStr points to caller allocated, zeroized string buffer of size STRBUFSIZE+1
    Exit:  
            typeStr points to hashable type string

    NOTE: reentrant!
*/
int parseType(const json_t *eip712Types, const char *typeS, char *typeStr) {
    json_t const *tarray, *pairs;
    const json_t *jType;
    char append[STRBUFSIZE+1] = {0};
    int encTest;
    const char *typeType = NULL;

    jType = json_getProperty(eip712Types, typeS);

    strncat(typeStr, json_getName(jType), STRBUFSIZE - strlen((const char *)typeStr));
    strncat(typeStr, "(", STRBUFSIZE - strlen((const char *)typeStr));

    tarray = json_getChild(jType);
    while (tarray != 0) {
        pairs = json_getChild(tarray);
        // should be type JSON_TEXT
        if (pairs->type != JSON_TEXT) {
            //TODO fix this  printf("type %d not printable\n", pairs->type);
        } else {
            typeType = json_getValue(json_getSibling(pairs));
            encTest = encodableType(typeType);
            if (encTest == UDEF_TYPE) {
                //This is a user-defined type, parse it and append later
                if (']' == typeType[strlen(typeType)-1]) {
                    // array of structs. To parse name, remove array tokens.
                    char typeNoArrTok[MAX_TYPESTRING] = {0};
                    strncpy(typeNoArrTok, typeType, sizeof(typeNoArrTok)-1);
                    if (strlen(typeNoArrTok) < strlen(typeType)) {
                        //TODO fix this  printf("ERROR: UDEF array type name is >32: %s, %lu\n", typeType, strlen(typeType));
                        return 0;
                    }

                    strtok(typeNoArrTok, "[");
                    parseType(eip712Types, typeNoArrTok, append);
                } else {
                parseType(eip712Types, typeType, append);
                }
            } else if (encTest == TOO_MANY_UDEFS) {
                //TODO fix this  printf ("too many user defined types!");
                return 0;
            }             
            strncat(typeStr, json_getValue(json_getSibling(pairs)), STRBUFSIZE - strlen((const char *)typeStr));
            strncat(typeStr, " ", STRBUFSIZE - strlen((const char *)typeStr));
            strncat(typeStr, json_getValue(pairs), STRBUFSIZE - strlen((const char *)typeStr));
            strncat(typeStr, ",", STRBUFSIZE - strlen((const char *)typeStr));
            
        }
        tarray = json_getSibling(tarray);
    }
    // typeStr ends with a ',' unless there are no parameters to the type.
    if (typeStr[strlen(typeStr)-1] == ',') {
        // replace last comma with a paren
        typeStr[strlen(typeStr)-1] = ')';
    } else {
        // append paren, there are no parameters
        strncat(typeStr, ")", STRBUFSIZE - 1);
    }
    if (strlen(append) > 0) {
        strncat(typeStr, append, STRBUFSIZE - strlen((const char *)append));
    }

    return 1;
}

int encAddress(const char *string, uint8_t *encoded) {
    unsigned ctr;
    char byteStrBuf[3] = {0};

    if (ADDRESS_SIZE < strlen(string)) {
        //TODO fix this  printf("ERROR: Address string too big %lu\n", strlen(string));
        return 0;
    }

    for (ctr=0; ctr<12; ctr++) {
        encoded[ctr] = '\0';
    }
    for (ctr=12; ctr<32; ctr++) {
        strncpy(byteStrBuf, &string[2*((ctr-12))+2], 2);
        encoded[ctr] = (uint8_t)(strtol(byteStrBuf, NULL, 16));
    }
    return 1;
}

int encString(const char *string, uint8_t *encoded) {
    struct SHA3_CTX strCtx;

    sha3_256_Init(&strCtx);
    sha3_Update(&strCtx, (const unsigned char *)string, (size_t)strlen(string));
    keccak_Final(&strCtx, encoded);
    return 1;
}

int encodeBytes(const char *string, uint8_t *encoded) {
    struct SHA3_CTX byteCtx;
    const char *valStrPtr = string+2;
    uint8_t valByte[1];
    char byteStrBuf[3] = {0};

    sha3_256_Init(&byteCtx);
    while (*valStrPtr != '\0') {
        strncpy(byteStrBuf, valStrPtr, 2);
        valByte[0] = (uint8_t)(strtol(byteStrBuf, NULL, 16));
        sha3_Update(&byteCtx, 
                    (const unsigned char *)valByte, 
                    (size_t)sizeof(uint8_t));
        valStrPtr+=2;
    }
    keccak_Final(&byteCtx, encoded);
    return 1;
}

#define MAX_ENCBYTEN_SIZE   66
int encodeBytesN(const char *typeT, const char *string, uint8_t *encoded) {
    char byteStrBuf[3] = {0};
    unsigned ctr;

    if (MAX_ENCBYTEN_SIZE < strlen(string)) {
        //TODO fix this  printf("ERROR: bytesN string too big %lu\n", strlen(string));
        return 0;
    }

    // parse out the length val
    uint8_t byteTypeSize = (uint8_t)(strtol((typeT+5), NULL, 10));
    if (32 < byteTypeSize) {
        //TODO fix this  printf("byteN size error, N>32:%u/n", byteTypeSize);
        return(0);
    }
    for (ctr=0; ctr<32; ctr++) {
        // zero padding
        encoded[ctr] = 0;
    }
    unsigned zeroFillLen = 32 - ((strlen(string)-2/* skip '0x' */)/2);
    // bytesN are zero padded on the right
    for (ctr=zeroFillLen; ctr<32; ctr++) {
        strncpy(byteStrBuf, &string[2+2*(ctr-zeroFillLen)], 2);
        encoded[ctr-zeroFillLen] = (uint8_t)(strtol(byteStrBuf, NULL, 16));
    }
    return 1;
}

int confirmName(const char *name, bool valAvailable) {
    if (valAvailable) {
        printf("\nConfirm\n%s ", name);
    } else {
        printf("\"%s\" values, press button to continue\n", name);
    }
    return 1;
}

int confirmValue(const char *value) {
    printf("%s\n", value);
    return 1;
}

/*
    Entry: 
            eip712Types points to the eip712 types structure
            jType points to eip712 json type structure to parse
            nextVal points to the next value to encode
            msgCtx points to caller allocated hash context to hash encoded values into.
    Exit:  
            msgCtx points to current final hash context

    NOTE: reentrant!
*/
int parseVals(const json_t *eip712Types, const json_t *jType, const json_t *nextVal, struct SHA3_CTX *msgCtx) {
    json_t const *tarray, *pairs, *walkVals;
    int ctr;
    const char *typeName = NULL, *typeType = NULL;
    uint8_t encBytes[32] = {0};     // holds the encrypted bytes for the message
    const char *valStr = NULL;
    char byteStrBuf[3] = {0};
    struct SHA3_CTX valCtx = {0};   // local hash context
    bool hasValue = 0;

    tarray = json_getChild(jType);
    while (tarray != 0) {
        pairs = json_getChild(tarray);
        // should be type JSON_TEXT
        if (pairs->type != JSON_TEXT) {
            //TODO fix this  printf("type %d not printable\n", pairs->type);
        } else {
            typeName = json_getValue(pairs);
            typeType = json_getValue(json_getSibling(pairs));
            walkVals = nextVal;
            while (0 != walkVals) {
                if (0 == strcmp(json_getName(walkVals), typeName)) {
                    valStr = json_getValue(walkVals);
                    break;
                } else {
                    // keep looking for val
                    walkVals = json_getSibling(walkVals);
                }
            }

            if (JSON_TEXT == json_getType(walkVals) || JSON_INTEGER == json_getType(walkVals)) {
                hasValue = 1;
            } else {
                hasValue = 0;
            }
            confirmName(typeName, hasValue);

            if (walkVals == 0) {
                //TODO fix this  printf("error: value for \"%s\" not found!\n", typeName);

            } else {

                if (0 == strncmp("address", typeType, strlen("address")-1)) {
                    if (']' == typeType[strlen(typeType)-1]) {
                        // array of addresses
                        json_t const *addrVals = json_getChild(walkVals);
                        sha3_256_Init(&valCtx);     // hash of concatenated encoded strings
                        while (0 != addrVals) {
                            // just walk the string values assuming, for fixed sizes, all values are there.
                            confirmValue(json_getValue(addrVals));
                            encAddress(json_getValue(addrVals), encBytes);
                            sha3_Update(&valCtx, (const unsigned char *)encBytes, 32);
                            addrVals = json_getSibling(addrVals);
                        }
                        keccak_Final(&valCtx, encBytes);
                    } else {
                        confirmValue(valStr);
                        encAddress(valStr, encBytes);
                    }

                } else if (0 == strncmp("string", typeType, strlen("string")-1)) {
                    if (']' == typeType[strlen(typeType)-1]) {
                        // array of strings
                        json_t const *stringVals = json_getChild(walkVals);
                        uint8_t strEncBytes[32];
                        sha3_256_Init(&valCtx);     // hash of concatenated encoded strings
                        while (0 != stringVals) {
                            // just walk the string values assuming, for fixed sizes, all values are there.
                            confirmValue(json_getValue(stringVals));
                            encString(json_getValue(stringVals), strEncBytes);
                            sha3_Update(&valCtx, (const unsigned char *)strEncBytes, 32);
                            stringVals = json_getSibling(stringVals);
                        }
                        keccak_Final(&valCtx, encBytes);
                    } else {
                        confirmValue(valStr);
                        encString(valStr, encBytes);
                    }

                } else if ((0 == strncmp("uint", typeType, strlen("uint")-1)) ||
                           (0 == strncmp("int", typeType, strlen("int")-1))) {

                    if (']' == typeType[strlen(typeType)-1]) {
                        //TODO fix this  printf("ERROR: INT and UINT arrays not yet implemented\n");
                        return 0;
                    } else {
                        confirmValue(valStr);
                        uint8_t negInt = 0;     // 0 is positive, 1 is negative
                        if (0 == strncmp("int", typeType, strlen("int")-1)) {
                            if (*valStr == '-') {
                                negInt = 1;
                            }
                        }
                        // parse out the length val
                        for (ctr=0; ctr<32; ctr++) {
                            if (negInt) {
                                // sign extend negative values
                                encBytes[ctr] = 0xFF;
                            } else {
                                // zero padding for positive
                                encBytes[ctr] = 0;
                            }
                        }
                        unsigned zeroFillLen = 32 - ((strlen(valStr)-negInt)/2+1);
                        for (ctr=zeroFillLen; ctr<32; ctr++) {
                            strncpy(byteStrBuf, &valStr[2*(ctr-(zeroFillLen))], 2);
                            encBytes[ctr] = (uint8_t)(strtol(byteStrBuf, NULL, 16));
                        }
                   }

                } else if (0 == strncmp("bytes", typeType, strlen("bytes"))) {
                    if (']' == typeType[strlen(typeType)-1]) {
                        //TODO fix this  printf("ERROR: bytesN arrays not yet implemented\n");
                        return 0;
                    } else {
                        // This could be 'bytes', 'bytes1', ..., 'bytes32'
                        confirmValue(valStr);
                        if (0 == strcmp(typeType, "bytes")) {
                           encodeBytes(valStr, encBytes);

                        } else {
                            encodeBytesN(typeType, valStr, encBytes);
                        }
                    }

                } else if (0 == strncmp("bool", typeType, strlen(typeType))) {
                    if (']' == typeType[strlen(typeType)-1]) {
                        //TODO fix this  printf("ERROR: bool arrays not yet implemented\n");
                        return 0;
                    } else {
                        confirmValue(valStr);
                        for (ctr=0; ctr<32; ctr++) {
                            // leading zeros in bool
                            encBytes[ctr] = 0;
                        }
                        if (0 == strncmp(valStr, "true", sizeof("true"))) {
                            encBytes[31] = 0x01;
                        }
                    }
 
                } else {
                    // encode user defined type
                    char encSubTypeStr[STRBUFSIZE+1] = {0};
                    // clear out the user-defined types list
                    for(ctr=0; ctr<MAX_USERDEF_TYPES; ctr++) {
                        udefList[ctr] = NULL;
                    }  
                                            
                    char typeNoArrTok[MAX_TYPESTRING] = {0};
                    // need to get typehash of type first
                    if (']' == typeType[strlen(typeType)-1]) {
                        // array of structs. To parse name, remove array tokens.
                        strncpy(typeNoArrTok, typeType, sizeof(typeNoArrTok)-1);
                        if (strlen(typeNoArrTok) < strlen(typeType)) {
                            //TODO fix this  printf("ERROR: UDEF array type name is >32: %s, %lu\n", typeType, strlen(typeType));
                            return 0;
                        }
                        strtok(typeNoArrTok, "[");
                        parseType(eip712Types, typeNoArrTok, encSubTypeStr);
                    } else {
                        parseType(eip712Types, typeType, encSubTypeStr);
                    }
                    sha3_256_Init(&valCtx);
                    sha3_Update(&valCtx, (const unsigned char *)encSubTypeStr, (size_t)strlen(encSubTypeStr));
                    keccak_Final(&valCtx, encBytes);
 
                    if (']' == typeType[strlen(typeType)-1]) {
                        // array of udefs
                        struct SHA3_CTX eleCtx = {0};   // local hash context
                        struct SHA3_CTX arrCtx = {0};   // array elements hash context
                        uint8_t eleHashBytes[32];

                        sha3_256_Init(&arrCtx);

                        json_t const *udefVals = json_getChild(walkVals);
                        while (0 != udefVals) {
                            sha3_256_Init(&eleCtx);
                            sha3_Update(&eleCtx, (const unsigned char *)encBytes, 32);
                            parseVals(
                                  eip712Types,
                                  json_getProperty(eip712Types, strtok(typeNoArrTok, "]")),
                                  json_getChild(udefVals),                // where to get the values
                                  &eleCtx                                 // encode hash happens in parse, this is the return
                                  );  
                            keccak_Final(&eleCtx, eleHashBytes);
                            sha3_Update(&arrCtx, (const unsigned char *)eleHashBytes, 32);
                            // just walk the udef values assuming, for fixed sizes, all values are there.
                            udefVals = json_getSibling(udefVals);
                        } 
                        keccak_Final(&arrCtx, encBytes);

                    } else {
                        sha3_256_Init(&valCtx);
                        sha3_Update(&valCtx, (const unsigned char *)encBytes, (size_t)sizeof(encBytes));
                        parseVals(
                                  eip712Types,
                                  json_getProperty(eip712Types, typeType),
                                  json_getChild(walkVals),                // where to get the values
                                  &valCtx           // val hash happens in parse, this is the return
                                  );    
                        keccak_Final(&valCtx, encBytes);
                    }                         
                }
            }

            // hash encoded bytes to final context
            sha3_Update(msgCtx, (const unsigned char *)encBytes, 32);
        }
        tarray = json_getSibling(tarray); 
    }
    return 1;
}

int encode(const json_t *jsonTypes, const json_t *jsonVals, const char *typeS, uint8_t *hashRet) {
    int ctr;
    char encTypeStr[STRBUFSIZE+1] = {0};
    uint8_t typeHash[32];
    struct SHA3_CTX finalCtx = {0};

    // clear out the user-defined types list
    for(ctr=0; ctr<MAX_USERDEF_TYPES; ctr++) {
        udefList[ctr] = NULL;
    }  

    parseType(json_getProperty(jsonTypes, "types"), typeS,   // e.g., "EIP712Domain"
              encTypeStr                                      // will return with typestr
              );                                                            
    sha3_256_Init(&finalCtx);
    sha3_Update(&finalCtx, (const unsigned char *)encTypeStr, (size_t)strlen(encTypeStr));
    keccak_Final(&finalCtx, typeHash);

    // They typehash must be the first message of the final hash, this is the start 
    sha3_256_Init(&finalCtx);
    sha3_Update(&finalCtx, (const unsigned char *)typeHash, (size_t)sizeof(typeHash));

    if (0 == strncmp(typeS, "EIP712Domain", sizeof("EIP712Domain"))) {
        parseVals(json_getProperty(jsonTypes, "types"),
              json_getProperty(json_getProperty(jsonTypes, "types"), typeS),   // e.g., "EIP712Domain" 
              json_getChild(json_getProperty(jsonVals, "domain" )),                // where to get the values
              &finalCtx                                                         // val hash happens in parse, this is the return
              );
    } else {
        // This is the message value encoding
        if (NULL == json_getChild(json_getProperty(jsonVals, "message" ))) {
            // return 2 for null message hash (this is a legal value)
            return 2;
        }
        parseVals(json_getProperty(jsonTypes, "types"),
              json_getProperty(json_getProperty(jsonTypes, "types"), typeS),   // e.g., "EIP712Domain" 
              json_getChild(json_getProperty(jsonVals, "message" )),                // where to get the values
              &finalCtx                                                         // val hash happens in parse, this is the return
              );
    }

    keccak_Final(&finalCtx, hashRet);
    // clear typeStr
    memzero(encTypeStr, sizeof(encTypeStr));

    return 1;
}

