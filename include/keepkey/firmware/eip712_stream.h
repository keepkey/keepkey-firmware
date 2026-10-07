/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
 *
 * Portions derived from OneKey firmware-classic1s
 * (legacy/firmware/ethereum_typed_data.h, commit 885e51d3), which is
 * LGPL-3.0-or-later and itself carries the Trezor copyright chain
 * (Alex Beregszaszi, Pavol Rusnak, Jochen Hoenicke). The encodeData rules,
 * the value validation and the encodeType dependency closure follow that
 * implementation; the memory design does not -- see eip712_stream.c.
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

#ifndef KEEPKEY_FIRMWARE_EIP712_STREAM_H
#define KEEPKEY_FIRMWARE_EIP712_STREAM_H

#include <stdbool.h>
#include <stdint.h>

#include "messages-ethereum.pb.h"

/* Longest type string we render: a struct name (< EIP712_MAX_STRUCT_NAME) or
 * an elementary type, plus array suffixes such as "[10][10][10][10]". */
#define EIP712_MAX_TYPE_NAME 112

/* Nesting bound and C-stack recursion bound; checked BEFORE descending. */
#define EIP712_MAX_DEPTH 3

/* Shared pool of 32-byte member encodings; a completed container collapses to
 * one digest in its parent's slot. Only ONE SHA3_CTX (~400 B) is ever live,
 * which is what fits SRAM. Slots along a path add up: Seaport needs
 * 11 + n + 6, so 24 slots take seven items. */
#define EIP712_MAX_SLOTS 24

/* Widest single leaf the device will absorb. Each EthereumTypedDataValueAck
 * carries one complete value, so this bounds a whole dynamic `bytes` or
 * `string` value (it is hashed, not kept). */
#define EIP712_MAX_LEAF 1024

/* Distinct struct types one primary type may reference, including itself.
 * Permit2's PermitSingle needs 2, Seaport's OrderComponents 3. */
#define EIP712_MAX_STRUCTS 3

/* The wire allows 80; each byte costs EIP712_MAX_STRUCTS of SRAM. */
#define EIP712_MAX_STRUCT_NAME 32

typedef struct {
  uint64_t chain_id;
  uint8_t verifying_contract[20];
  uint8_t primary_type_hash[32];
  bool has_chain_id;
  bool has_verifying_contract;
  bool has_primary_type_hash;
  uint8_t domain_hashes[3][32]; /* name, version, salt */
  uint8_t domain_present;
} Eip712DomainFacts;

/* Canonical ASCII identifier: the bytes hashed are the bytes rendered. */
bool eip712_identifier_ok(const char* name);

/* Member list by struct name, NULL if not supplied. Unit tests back it with
 * a fixture table. */
typedef const EthereumTypedDataStructAck* (*Eip712StructLookup)(
    const char* name, void* ctx);

/* typeHash of encodeType = primary || referenced structs SORTED BY NAME.
 * False if a struct is missing, the closure exceeds EIP712_MAX_STRUCTS, or a
 * member type cannot be spelled. */
bool eip712_type_hash(const char* name, Eip712StructLookup lookup, void* ctx,
                      uint8_t out[32]);

/* Solidity type spelled exactly as encodeType needs (part of typeHash).
 * False if inexpressible or `out` would overflow. */
bool eip712_type_name(const EthereumTypedDataStructAck_EthereumFieldType* field,
                      char* out, size_t out_len);

/* Encode one validated leaf into exactly 32 bytes, per EIP-712 encodeData.
 * `value`/`value_len` are the raw big-endian bytes from the host. */
bool eip712_encode_leaf(
    const EthereumTypedDataStructAck_EthereumFieldType* field,
    const uint8_t* value, uint16_t value_len, uint8_t out[32]);

/* Validated uintN/intN leaf (N big-endian bytes) as review-screen decimal. */
bool eip712_render_integer(
    const EthereumTypedDataStructAck_EthereumFieldType* field,
    const uint8_t* value, uint16_t len, char* out, size_t out_size);

/* Reject a leaf whose bytes cannot mean what its declared type says.
 * Runs BEFORE encoding and before display, so nothing unvalidated is shown. */
bool eip712_validate_leaf(
    const EthereumTypedDataStructAck_EthereumFieldType* field,
    const uint8_t* value, uint16_t value_len);

/* Keep only facts the domain stream proves; duplicates fail closed. */
bool eip712_domain_facts_observe(
    Eip712DomainFacts* facts, const char* member_name,
    const EthereumTypedDataStructAck_EthereumFieldType* field,
    const uint8_t* value, uint16_t value_len);

bool eip712_stream_domain_facts(Eip712DomainFacts* facts);
/* The signing account's path while a certified definition is in use, so the
 * ERC-7730 runtime can recognise the signer's own address. */
bool eip712_stream_signer_path(uint32_t address_n[6], size_t* count);
bool eip712_stream_domain_matches(uint8_t field, uint8_t literal_kind,
                                  const uint8_t* value, size_t length,
                                  bool require_absent);

/* ── The walk: a RESUMABLE state machine (no blocking request/response
 * primitive exists). Each handler emits at most one request and returns; the
 * next Ack resumes at member_path. Phase A streams each struct's encodeType
 * closure; phase B absorbs each leaf as it is displayed. */

typedef enum {
  EIP712_IDLE = 0,
  EIP712_WANT_STRUCT, /* a StructAck will arrive next */
  EIP712_WANT_VALUE,  /* a ValueAck will arrive next */
} Eip712Wait;

/* The walk never writes a message itself, keeping it unit-testable. */
typedef enum {
  EIP712_REQ_NONE = 0,
  EIP712_REQ_STRUCT,     /* send EthereumTypedDataStructRequest */
  EIP712_REQ_VALUE,      /* send EthereumTypedDataValueRequest */
  EIP712_REQ_DEFINITION, /* authenticate the preloaded ERC-7730 program */
  EIP712_REQ_DONE,       /* both hashes ready: derive, sign, respond */
  EIP712_REQ_FAIL,       /* send Failure(error) */
  EIP712_REQ_CANCELLED,  /* the user declined a screen */
} Eip712ReqKind;

typedef struct {
  Eip712ReqKind kind;
  char struct_name[EIP712_MAX_STRUCT_NAME];
  uint32_t member_path[EIP712_MAX_DEPTH + 2];
  uint8_t member_path_len;
  const char* error;
  uint8_t domain_separator[32];
  uint8_t message_hash[32];
  uint32_t address_n[6];
  size_t address_n_count;
  /* For the final signing screen. */
  char primary_type[EIP712_MAX_STRUCT_NAME];
  bool message_empty;
  bool domain_only; /* primaryType EIP712Domain: sign keccak(0x1901 || ds) */
} Eip712Next;

const Eip712Next* eip712_stream_next(void);

/* Begin a signing session. Fills in the first request. */
bool eip712_stream_begin(const EthereumSignTypedData* msg,
                         bool require_definition);
bool eip712_stream_definition_accepted(void);
/* Next certified pass; the reviewed domain and path stay fixed. */
bool eip712_stream_resume_for_field(void);

/* False = session torn down and EIP712_REQ_FAIL or EIP712_REQ_CANCELLED
 * staged; the caller must still pump it to send the terminal response. */
bool eip712_stream_on_struct(const EthereumTypedDataStructAck* ack);
bool eip712_stream_on_value(const EthereumTypedDataValueAck* ack);

/* True while a session is live, so the FSM can reject an out-of-order Ack. */
Eip712Wait eip712_stream_waiting(void);

/* A half-walked document must never survive into the next session. */
void eip712_stream_abort(void);

#endif /* KEEPKEY_FIRMWARE_EIP712_STREAM_H */
