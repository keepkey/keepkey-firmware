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

/* Longest Solidity type string we will render: "uint256[10][10][10][10]" and
 * friends, plus a struct name at EthereumTypedDataStructRequest.name's 80. */
#define EIP712_MAX_TYPE_NAME 112

/* How deep the value walk may nest: message -> struct -> array -> struct ...
 * Every level costs one frame on the C stack, so this is the recursion bound
 * as well as the semantic one. EIP712_MAX_DEPTH is checked BEFORE descending,
 * never after. */
#define EIP712_MAX_DEPTH 3

/* Slots in the shared encoding pool. Each open container holds one 32-byte
 * slot per member encoded so far; when it completes, those collapse to a
 * single 32-byte digest written into the parent's next slot.
 *
 * This is the whole memory argument. A SHA3_CTX is ~400 bytes, so keeping one
 * open per container costs 2,000 bytes at depth 5 -- more than the entire SRAM
 * reserve above the linker floor. Buffering 32-byte encodings instead costs
 * EIP712_MAX_SLOTS * 32, and only ONE SHA3_CTX is ever live: the one folding a
 * finished container. */
#define EIP712_MAX_SLOTS 12

/* Widest single leaf the device will absorb. A dynamic `bytes` or `string` is
 * hashed, not stored, so this bounds one chunk rather than the whole value. */
#define EIP712_MAX_LEAF 1024

/* Distinct struct types one document may reference, including EIP712Domain
 * and the primary type. Permit2's PermitSingle needs 2, Seaport's
 * OrderComponents 3. */
#define EIP712_MAX_STRUCTS 3

/* Longest struct name we will hold. The wire allows 80; names this long do
 * not occur in practice and every one costs EIP712_MAX_STRUCTS bytes. */
#define EIP712_MAX_STRUCT_NAME 32

typedef struct {
  uint64_t chain_id;
  uint8_t verifying_contract[20];
  uint8_t primary_type_hash[32];
  bool has_chain_id;
  bool has_verifying_contract;
  bool has_primary_type_hash;
} Eip712DomainFacts;

/* Canonical ASCII Solidity identifier. Besides being part of encodeType, a
 * member name is also the review-screen title, so this guarantees the exact
 * bytes hashed are the exact bytes rendered (no truncation/control glyphs). */
bool eip712_identifier_ok(const char* name);

/* Fetch one struct's member list by name. Returns NULL if the host has not
 * supplied it. Firmware backs this with the streaming state machine; the unit
 * tests back it with a fixture table, which is what makes encodeType testable
 * without a device. */
typedef const EthereumTypedDataStructAck* (*Eip712StructLookup)(
    const char* name, void* ctx);

/* Assemble encodeType(name) and hash it, per EIP-712:
 *
 *   encodeType = <primary segment> || <each referenced struct, SORTED BY NAME>
 *
 * The sort is the part the old parser got wrong: eip712.c appended referenced
 * definitions in DISCOVERY order and there is no sort call anywhere in it, so
 * two structs named out of alphabetical order produced a typeHash no compliant
 * verifier reproduces -- an internally consistent device signing something
 * nobody else agrees the document says.
 *
 * Returns false if a referenced struct is missing, the closure exceeds
 * EIP712_MAX_STRUCTS, or any member type cannot be spelled. */
bool eip712_type_hash(const char* name, Eip712StructLookup lookup, void* ctx,
                      uint8_t out[32]);

/* Render a field's Solidity type exactly as encodeType must spell it --
 * "uint256", "bytes32", "Person[3]", "int16[2][][4]". This string is part of
 * typeHash, so a divergence here is a divergence in the signature.
 * Returns false if the type is not expressible or would overflow `out`. */
bool eip712_type_name(const EthereumTypedDataStructAck_EthereumFieldType* field,
                      char* out, size_t out_len);

/* Encode one validated leaf into exactly 32 bytes, per EIP-712 encodeData.
 * `value`/`value_len` are the raw big-endian bytes from the host. */
bool eip712_encode_leaf(
    const EthereumTypedDataStructAck_EthereumFieldType* field,
    const uint8_t* value, uint16_t value_len, uint8_t out[32]);

/* Reject a leaf whose bytes cannot mean what its declared type says.
 * Runs BEFORE encoding and before display, so nothing unvalidated is shown. */
bool eip712_validate_leaf(
    const EthereumTypedDataStructAck_EthereumFieldType* field,
    const uint8_t* value, uint16_t value_len);

/* Retain only lookup facts that the canonical domain stream itself proves.
 * Unknown domain fields are ignored; duplicate binding fields fail closed. */
bool eip712_domain_facts_observe(
    Eip712DomainFacts* facts, const char* member_name,
    const EthereumTypedDataStructAck_EthereumFieldType* field,
    const uint8_t* value, uint16_t value_len);

bool eip712_stream_domain_facts(Eip712DomainFacts* facts);

#endif

/* ── The walk ────────────────────────────────────────────────────────
 *
 * KeepKey has no blocking request/response primitive. wait_for_tiny_msg is a
 * 64-byte channel for ButtonAck and PinAck; a StructAck is 6 KB. OneKey drives
 * its walk from a re-entrant call() that pumps usbPoll() from inside a handler,
 * and that cannot be transplanted here.
 *
 * So the walk is a RESUMABLE state machine. Each handler runs to completion,
 * emits at most one request, and returns; the next Ack resumes it. State lives
 * in one static block, and the member_path is the cursor.
 *
 * Two sequential machines:
 *   A. typeHash -- for the struct a frame is about to hash, stream its
 *      encodeType closure and cache the digest.
 *   B. values   -- walk members, absorbing each leaf as it is displayed.
 */

typedef enum {
  EIP712_IDLE = 0,
  EIP712_WANT_STRUCT, /* a StructAck will arrive next */
  EIP712_WANT_VALUE,  /* a ValueAck will arrive next */
  EIP712_FAILED,
} Eip712Wait;

/* What the machine wants next. The walk never writes a message: RESP_INIT uses
 * msg_resp, which is private to fsm.c, and keeping key material and the wire
 * out of the walk is what lets the whole thing be unit-tested. */
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
} Eip712Next;

const Eip712Next* eip712_stream_next(void);

/* Begin a signing session. Fills in the first request. */
bool eip712_stream_begin(const EthereumSignTypedData* msg,
                         bool require_definition);
bool eip712_stream_definition_accepted(void);

/* Feed the machine. Each returns false and tears the session down on any
 * protocol or validation error, having already sent a Failure. */
bool eip712_stream_on_struct(const EthereumTypedDataStructAck* ack);
bool eip712_stream_on_value(const EthereumTypedDataValueAck* ack);

/* True while a session is live, so the FSM can reject an out-of-order Ack. */
Eip712Wait eip712_stream_waiting(void);

/* Drop all session state. Called on completion, failure, Initialize and
 * ClearSession -- a half-walked document must never survive into the next one.
 */
void eip712_stream_abort(void);
