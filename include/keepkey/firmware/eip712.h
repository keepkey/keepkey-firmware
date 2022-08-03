
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
#ifndef EIP712_H
#define EIP712_H

#define USE_KECCAK 1
#define ADDRESS_SIZE        42
#define JSON_OBJ_POOL_SIZE  100
#define STRBUFSIZE          511
#define MAX_USERDEF_TYPES   10      // This is max number of user defined type allowed
#define MAX_TYPESTRING      33      // maximum size for a type string
#define MAX_ENCBYTEN_SIZE   66
#define STACK_REENTRANCY_REQ    1280    // calculate this from a re-entrant call (unsigned)&p - (unsigned)&end)
#define STACK_SIZE_GUARD        (STACK_REENTRANCY_REQ + 64) // Can't recurse without this much stack available

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

typedef enum {
    DOMAIN = 1,
    MESSAGE
} dm;

// error list status
#define SUCCESS              1
#define NULL_MSG_HASH        2      // this is legal, not an error
#define GENERAL_ERROR        3
#define UDEF_NAME_ERROR      4
#define UDEFS_OVERFLOW       5
#define UDEF_ARRAY_NAME_ERR  6
#define ADDR_STRING_VFLOW    7
#define BYTESN_STRING_ERROR  8
#define BYTESN_SIZE_ERROR    9
#define INT_ARRAY_ERROR     10
#define BYTESN_ARRAY_ERROR  11
#define BOOL_ARRAY_ERROR    12
#define RECURSION_ERROR     13

#define JSON_PTYPENAMEERR   14
#define JSON_PTYPEVALERR    15
#define JSON_TYPESPROPERR   16
#define JSON_TYPE_SPROPERR  17
#define JSON_DPROPERR       18
#define MSG_NO_DS           19
#define JSON_MPROPERR       20
#define JSON_PTYPESOBJERR   21
#define JSON_TYPE_S_ERR     22
#define JSON_TYPE_S_NAMEERR 23
#define UNUSED_ERR_2        24          // available for re-use
#define JSON_NO_PAIRS       25
#define JSON_PAIRS_NOTEXT   26
#define JSON_NO_PAIRS_SIB   27
#define TYPE_NOT_ENCODABLE  28
#define JSON_NOPAIRVAL      29
#define JSON_NOPAIRNAME     30
#define JSON_TYPE_T_NOVAL   31
#define ADDR_STRING_NULL    32
#define JSON_TYPE_WNOVAL    33

#define LAST_ERROR         JSON_TYPE_WNOVAL


int memcheck(void);

#endif

