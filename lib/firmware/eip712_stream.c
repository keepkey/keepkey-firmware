/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
 *
 * Portions derived from OneKey firmware-classic1s
 * (legacy/firmware/ethereum_typed_data.h, commit 885e51d3), LGPL-3.0-or-later,
 * which itself carries the Trezor copyright chain (Alex Beregszaszi,
 * Pavol Rusnak, Jochen Hoenicke).
 *
 * Taken from that implementation: the encodeData rules, the leaf validation,
 * and the shape of the encodeType dependency closure.
 *
 * NOT taken from it: the memory design. OneKey declares a ~31 KB
 * TypedDataEnvelope on the stack and holds the whole schema; that is roughly
 * 1.8x this device's entire runtime SRAM. See eip712_stream.h for what
 * replaces it.
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

#include "keepkey/firmware/eip712_stream.h"

#include <stdio.h>
#include <string.h>

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/erc7730_format.h"
#include "keepkey/firmware/ethereum.h"
#include "trezor/crypto/address.h"
#include "trezor/crypto/bignum.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/sha3.h"

typedef EthereumTypedDataStructAck_EthereumFieldType Eip712FieldType;
typedef EthereumTypedDataStructAck_EthereumDataType Eip712DataType;

static bool identifier_ok(const char* name, size_t max, bool colon) {
  if (!name) return false;
  size_t len = strlen(name);
  if (len == 0 || len + 1 > max) return false;
  char first = name[0];
  if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') ||
        first == '_' || first == '$')) {
    return false;
  }
  for (size_t i = 1; i < len; i++) {
    char c = name[i];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || c == '_' || c == '$' ||
          (colon && c == ':'))) {
      return false;
    }
  }
  return true;
}

bool eip712_identifier_ok(const char* name) {
  return identifier_ok(name, EIP712_MAX_MEMBER_NAME, false);
}

bool eip712_type_identifier_ok(const char* name) {
  return identifier_ok(name, EIP712_MAX_STRUCT_NAME, true);
}

/* encodeType spelling. Hashed into typeHash: a wrong character signs a
 * different document. Canonical only ("uint256", "bytes", "bytes32"). */
bool eip712_type_name(const Eip712FieldType* field, char* out, size_t out_len) {
  if (!field || !out || out_len == 0) return false;
  if (field->array_levels_count >
      sizeof(field->array_levels) / sizeof(field->array_levels[0]))
    return false;

  const char* base;
  char scratch[EIP712_MAX_TYPE_NAME];

  switch (field->data_type) {
    case EthereumTypedDataStructAck_EthereumDataType_UINT:
    case EthereumTypedDataStructAck_EthereumDataType_INT: {
      /* size is BYTES on the wire, spelled in BITS; only 1..32 is canonical. */
      if (!field->has_size || field->size < 1 || field->size > 32) return false;
      const char* stem =
          field->data_type == EthereumTypedDataStructAck_EthereumDataType_UINT
              ? "uint"
              : "int";
      snprintf(scratch, sizeof(scratch), "%s%u", stem,
               (unsigned)(field->size * 8));
      base = scratch;
      break;
    }
    case EthereumTypedDataStructAck_EthereumDataType_BYTES:
      if (field->has_size) {
        if (field->size < 1 || field->size > 32) return false;
        snprintf(scratch, sizeof(scratch), "bytes%u", (unsigned)field->size);
        base = scratch;
      } else {
        base = "bytes";
      }
      break;
    case EthereumTypedDataStructAck_EthereumDataType_STRING:
      base = "string";
      break;
    case EthereumTypedDataStructAck_EthereumDataType_BOOL:
      base = "bool";
      break;
    case EthereumTypedDataStructAck_EthereumDataType_ADDRESS:
      base = "address";
      break;
    case EthereumTypedDataStructAck_EthereumDataType_STRUCT:
      if (!field->has_struct_name ||
          !eip712_type_identifier_ok(field->struct_name))
        return false;
      base = field->struct_name;
      break;
    default:
      /* ARRAY is reserved: dimensions live in array_levels. */
      return false;
  }

  size_t len = strlen(base);
  if (len + 1 > out_len) return false;
  memcpy(out, base, len);
  out[len] = '\0';

  /* Dimensions in written order: int16[2][][4] is array_levels {2, 0, 4}. */
  for (size_t i = 0; i < field->array_levels_count; i++) {
    char dim[16];
    if (field->array_levels[i] == 0) {
      memcpy(dim, "[]", 3);
    } else {
      snprintf(dim, sizeof(dim), "[%u]", (unsigned)field->array_levels[i]);
    }
    size_t dim_len = strlen(dim);
    if (len + dim_len + 1 > out_len) return false;
    memcpy(out + len, dim, dim_len);
    len += dim_len;
    out[len] = '\0';
  }
  return true;
}

/* encodeData: every member is 32 bytes; atomics pad, dynamics hash. Structs
 * and arrays are folded by the walker before reaching here. */
static void write_rightpad32(const uint8_t* value, uint16_t value_len,
                             uint8_t out[32]) {
  memset(out, 0, 32);
  memcpy(out, value, value_len);
}

static void write_leftpad32(const uint8_t* value, uint16_t value_len,
                            bool is_signed, uint8_t out[32]) {
  /* Sign-extend a negative intN; everything else zero-extends. */
  if (is_signed && value_len > 0 && (value[0] & 0x80)) {
    memset(out, 0xFF, 32);
  } else {
    memset(out, 0x00, 32);
  }
  memcpy(out + (32 - value_len), value, value_len);
}

bool eip712_encode_leaf(const Eip712FieldType* field, const uint8_t* value,
                        uint16_t value_len, uint8_t out[32]) {
  if (!field || !out) return false;
  if (value_len > 32 &&
      field->data_type != EthereumTypedDataStructAck_EthereumDataType_STRING &&
      !(field->data_type == EthereumTypedDataStructAck_EthereumDataType_BYTES &&
        !field->has_size)) {
    /* Only dynamic forms may exceed a word; padders would truncate. */
    return false;
  }
  if (value_len > 0 && !value) return false;

  switch (field->data_type) {
    case EthereumTypedDataStructAck_EthereumDataType_BYTES:
      if (field->has_size) {
        write_rightpad32(value, value_len, out);
      } else {
        keccak_256(value, value_len, out);
      }
      return true;
    case EthereumTypedDataStructAck_EthereumDataType_STRING:
      keccak_256(value, value_len, out);
      return true;
    case EthereumTypedDataStructAck_EthereumDataType_INT:
      write_leftpad32(value, value_len, true, out);
      return true;
    case EthereumTypedDataStructAck_EthereumDataType_UINT:
    case EthereumTypedDataStructAck_EthereumDataType_BOOL:
    case EthereumTypedDataStructAck_EthereumDataType_ADDRESS:
      write_leftpad32(value, value_len, false, out);
      return true;
    default:
      return false;
  }
}

/* Leaf validation: runs before display AND encoding. Control bytes such as
 * a newline in a Snapshot vote's reason are valid: the review escapes every
 * byte outside 0x21-0x7e as \xNN and a backslash as \\, so no two strings
 * draw the same screen. Incremental, so a string sent in chunks is checked
 * by the same rules across chunk boundaries. */
typedef struct {
  uint32_t cp;   /* the code point decoded so far */
  uint8_t need;  /* continuation bytes still owed */
  uint8_t extra; /* continuation bytes of the sequence being decoded */
} Eip712Utf8;

static bool utf8_feed(Eip712Utf8* st, const uint8_t* s, size_t len) {
  static const uint32_t min_cp[4] = {0, 0x80, 0x800, 0x10000};
  for (size_t i = 0; i < len; i++) {
    const uint8_t c = s[i];
    if (st->need == 0) {
      if (c < 0x80) continue;
      if ((c & 0xE0) == 0xC0) {
        st->extra = 1;
        st->cp = c & 0x1F;
      } else if ((c & 0xF0) == 0xE0) {
        st->extra = 2;
        st->cp = c & 0x0F;
      } else if ((c & 0xF8) == 0xF0) {
        st->extra = 3;
        st->cp = c & 0x07;
      } else {
        return false;
      }
      st->need = st->extra;
      continue;
    }
    if ((c & 0xC0) != 0x80) return false;
    st->cp = (st->cp << 6) | (c & 0x3F);
    if (--st->need) continue;
    /* Overlongs and surrogates also break injectivity. */
    if (st->cp < min_cp[st->extra] || st->cp > 0x10FFFF ||
        (st->cp >= 0xD800 && st->cp <= 0xDFFF))
      return false;
  }
  return true;
}

static bool is_valid_utf8(const uint8_t* s, uint16_t len) {
  Eip712Utf8 st = {0};
  return utf8_feed(&st, s, len) && st.need == 0;
}

bool eip712_validate_leaf(const Eip712FieldType* field, const uint8_t* value,
                          uint16_t value_len) {
  if (!field) return false;
  if (value_len > 0 && !value) return false;

  switch (field->data_type) {
    case EthereumTypedDataStructAck_EthereumDataType_BOOL:
      return value_len == 1 && (value[0] == 0 || value[0] == 1);
    case EthereumTypedDataStructAck_EthereumDataType_ADDRESS:
      return value_len == 20;
    case EthereumTypedDataStructAck_EthereumDataType_STRING:
      return is_valid_utf8(value, value_len);
    case EthereumTypedDataStructAck_EthereumDataType_BYTES:
      /* bytesN is exactly N, N in [1,32], rejected here as a validation error
       * rather than later as a Cancel. Dynamic bytes: any length we hold. */
      if (field->has_size)
        return field->size >= 1 && field->size <= 32 &&
               value_len == field->size;
      return value_len <= EIP712_MAX_LEAF;
    case EthereumTypedDataStructAck_EthereumDataType_UINT:
    case EthereumTypedDataStructAck_EthereumDataType_INT:
      /* Exactly the declared width, big endian: a short value would pad into
       * a different number. */
      if (!field->has_size || field->size < 1 || field->size > 32) return false;
      return value_len == field->size;
    default:
      return false;
  }
}

bool eip712_domain_facts_observe(Eip712DomainFacts* facts,
                                 const char* member_name,
                                 const Eip712FieldType* field,
                                 const uint8_t* value, uint16_t value_len) {
  if (!facts || !member_name || !field || (!value && value_len != 0) ||
      !eip712_validate_leaf(field, value, value_len))
    return false;
  static const char* const members[] = {"name", "version", "salt", "chainId",
                                        "verifyingContract"};
  int index = 0;
  while (index < 5 && strcmp(member_name, members[index]) != 0) index++;
  if (index == 5) return true;
  const uint8_t bit = 1u << index;
  if ((facts->domain_present & bit) != 0) return false;
  facts->domain_present |= bit;

  const uint8_t type = field->data_type;
  if (index < 3) {
    if ((index < 2 &&
         type != EthereumTypedDataStructAck_EthereumDataType_STRING) ||
        (index == 2 &&
         (type != EthereumTypedDataStructAck_EthereumDataType_BYTES ||
          !field->has_size || field->size != 32))) {
      facts->domain_present |= EIP712_DOMAIN_UNBINDABLE;
      return true;
    }
    keccak_256(value, value_len, facts->domain_hashes[index]);
    return true;
  }
  if (index == 3) {
    size_t offset = 0;
    while (offset < value_len && value[offset] == 0) offset++;
    uint64_t chain_id = 0;
    if (type == EthereumTypedDataStructAck_EthereumDataType_UINT &&
        value_len - offset <= sizeof(facts->chain_id))
      for (size_t i = offset; i < value_len; i++)
        chain_id = (chain_id << 8) | value[i];
    /* 0 is also every value too wide for the facts, and every non-uint. */
    if (chain_id == 0) {
      facts->domain_present |= EIP712_DOMAIN_UNBINDABLE;
      return true;
    }
    facts->chain_id = chain_id;
    facts->has_chain_id = true;
    return true;
  }
  if (type != EthereumTypedDataStructAck_EthereumDataType_ADDRESS) {
    facts->domain_present |= EIP712_DOMAIN_UNBINDABLE;
    return true;
  }
  memcpy(facts->verifying_contract, value, sizeof(facts->verifying_contract));
  facts->has_verifying_contract = true;
  return true;
}

/* encodeType(S) = seg(S) || seg(D1) || ... with D1..Dn every struct S
 * transitively references, SORTED BY NAME (unsorted hashes a type string no
 * verifier reproduces). Segments stream into keccak; only names are held, each
 * once, and everything else refers to a struct by its index in the table. */

typedef struct {
  char names[EIP712_MAX_STRUCTS + 1][EIP712_MAX_STRUCT_NAME];
  uint8_t count;
} Eip712Names;

/* index[0] is the struct itself; the rest is its closure. */
typedef struct {
  uint8_t index[EIP712_MAX_STRUCTS];
  uint8_t count;
} Eip712Closure;

#define EIP712_NO_TYPE 0xFF

/* The index of `name`, added if new; EIP712_NO_TYPE if malformed or full. */
static uint8_t names_intern(Eip712Names* t, const char* name) {
  if (!eip712_type_identifier_ok(name)) return EIP712_NO_TYPE;
  for (uint8_t i = 0; i < t->count; i++) {
    if (strcmp(t->names[i], name) == 0) return i;
  }
  if (t->count >= EIP712_MAX_STRUCTS + 1) return EIP712_NO_TYPE;
  strlcpy(t->names[t->count], name, EIP712_MAX_STRUCT_NAME);
  return t->count++;
}

static bool closure_add(Eip712Closure* c, Eip712Names* t, const char* name) {
  const uint8_t index = names_intern(t, name);
  if (index == EIP712_NO_TYPE) return false;
  for (uint8_t i = 0; i < c->count; i++) {
    if (c->index[i] == index) return true;
  }
  if (c->count >= EIP712_MAX_STRUCTS) return false;
  c->index[c->count++] = index;
  return true;
}

/* Insertion sort index[start..count) by name; the one ordering rule for both
 * paths. */
static void sort_closure_tail(Eip712Closure* c, const Eip712Names* t,
                              uint8_t start) {
  for (uint8_t i = start + 1; i < c->count; i++) {
    const uint8_t key = c->index[i];
    int16_t j = (int16_t)i - 1;
    while (j >= (int16_t)start &&
           strcmp(t->names[c->index[j]], t->names[key]) > 0) {
      c->index[j + 1] = c->index[j];
      j--;
    }
    c->index[j + 1] = key;
  }
}

/* `name` followed by every struct it transitively references, sorted. Iterative
 * over the growing closure, so a cyclical schema terminates. */
static bool closure_collect(const char* name, Eip712StructLookup lookup,
                            void* ctx, Eip712Names* names, Eip712Closure* out) {
  memset(names, 0, sizeof(*names));
  memset(out, 0, sizeof(*out));
  if (!closure_add(out, names, name)) return false;

  for (uint8_t i = 0; i < out->count; i++) {
    const EthereumTypedDataStructAck* def =
        lookup(names->names[out->index[i]], ctx);
    if (!def) return false;
    for (size_t m = 0; m < def->members_count; m++) {
      const Eip712FieldType* ft = &def->members[m].type;
      if (ft->data_type != EthereumTypedDataStructAck_EthereumDataType_STRUCT)
        continue;
      if (!ft->has_struct_name) return false;
      if (!closure_add(out, names, ft->struct_name)) return false;
    }
  }

  /* The primary type leads and is not sorted with the rest. */
  sort_closure_tail(out, names, 1);
  return true;
}

/* Stream "Name(type1 name1,type2 name2,...)" into the hash. */
static bool hash_segment_from_ack(const char* name,
                                  const EthereumTypedDataStructAck* def,
                                  SHA3_CTX* hash) {
  if (!def || !eip712_type_identifier_ok(name)) return false;

  keccak_Update(hash, (const uint8_t*)name, strlen(name));
  keccak_Update(hash, (const uint8_t*)"(", 1);

  for (size_t m = 0; m < def->members_count; m++) {
    char type_name[EIP712_MAX_TYPE_NAME];
    if (!eip712_type_name(&def->members[m].type, type_name, sizeof(type_name)))
      return false;
    const char* member_name = def->members[m].name;
    if (!eip712_identifier_ok(member_name)) return false;
    for (size_t prior = 0; prior < m; prior++) {
      if (strcmp(member_name, def->members[prior].name) == 0) return false;
    }

    if (m > 0) keccak_Update(hash, (const uint8_t*)",", 1);
    keccak_Update(hash, (const uint8_t*)type_name, strlen(type_name));
    keccak_Update(hash, (const uint8_t*)" ", 1);
    keccak_Update(hash, (const uint8_t*)member_name, strlen(member_name));
  }

  keccak_Update(hash, (const uint8_t*)")", 1);
  return true;
}

static bool hash_type_segment(const char* name, Eip712StructLookup lookup,
                              void* ctx, SHA3_CTX* hash) {
  const EthereumTypedDataStructAck* def = lookup(name, ctx);
  return hash_segment_from_ack(name, def, hash);
}

bool eip712_type_hash(const char* name, Eip712StructLookup lookup, void* ctx,
                      uint8_t out[32]) {
  if (!name || !lookup || !out || !eip712_type_identifier_ok(name))
    return false;

  Eip712Names names;
  Eip712Closure closure;
  if (!closure_collect(name, lookup, ctx, &names, &closure)) return false;

  SHA3_CTX hash;
  keccak_256_Init(&hash);
  for (uint8_t i = 0; i < closure.count; i++) {
    if (!hash_type_segment(names.names[closure.index[i]], lookup, ctx, &hash))
      return false;
  }
  keccak_Final(&hash, out);
  return true;
}

/* Session state, all .bss: counts against the stack gap (_stack - _ebss must
 * stay >= 16,384 B). One SHA3_CTX: encodeType streams and frame folds never
 * overlap. */
typedef struct {
  /* Parent member name for review paths, at e712.labels + label_off; empty
   * for array elements. */
  uint8_t label_off;
  uint8_t slot_base;    /* first slot in the pool belonging to this frame */
  uint8_t member_count; /* members declared by the struct */
  bool is_array;
  /* Next member (or element) to absorb: a streamed array's length is uint16
   * on the wire. */
  uint16_t member_index;
  /* A struct frame never reads the array half and vice versa. */
  union {
    struct {
      uint8_t type_hash[32]; /* lives exactly as long as the frame */
      uint8_t type;          /* index into e712.types */
      bool have_type_hash;
      uint8_t safe_facts; /* a SafeTx's SAFE_*, read so far */
    } s;
    struct {
      uint32_t elem_size;
      uint32_t array_levels[4];
      uint16_t array_len;
      uint8_t elem_data_type;
      bool elem_has_size;
      uint8_t elem_type; /* index into e712.types, or EIP712_NO_TYPE */
      uint8_t levels_total;
      uint8_t level_index;
    } a;
  } u;
} Eip712Frame;

/* A `bytes` leaf calling multiSend(bytes), read a byte at a time so it spans
 * chunks: only the inner call in progress is kept. */
typedef struct {
  uint32_t left; /* packed bytes not yet read; the length word while read */
  uint32_t need; /* inner data bytes left; dataLength while read */
  uint16_t call; /* the inner call being read, from 1 */
  uint8_t phase; /* MS_* */
  uint8_t at;    /* position in the word or header, or in data (stops at 68) */
  uint8_t seen;  /* MS_SEEN_* */
  uint8_t facts; /* MS_FACT_*, kept once the scan stops */
  uint8_t to[20];
  uint8_t spender[20];
} Eip712MultiSend;

static struct {
  bool active;
  Eip712Wait waiting;

  uint32_t address_n[6];
  uint8_t address_n_count;
  char primary_type[EIP712_MAX_STRUCT_NAME];
  bool metamask_v4_compat;
  bool require_definition;
  bool definition_accepted;
  Eip712DomainFacts domain_facts;

  /* 0 = domain, 1 = message. */
  uint8_t root;
  uint8_t domain_separator[32];
  bool have_domain_separator;
  bool message_value_confirmed;

  Eip712Frame stack[EIP712_MAX_DEPTH];
  uint8_t depth;
  /* The labels of stack[1..depth), packed in stack order, each NUL-ended. */
  char labels[EIP712_MAX_PATH];

  uint8_t pool[EIP712_MAX_SLOTS][32];
  uint8_t slots_used;

  /* The outermost open array absorbs each element as it completes, so its
   * length costs no pool slots. A bare Keccak state: the bytes waiting for a
   * permutation are XORed in place, so no 136-byte block buffer is kept. */
  uint64_t array_sponge[25];
  uint8_t array_sponge_bytes; /* absorbed since the last permutation */
  uint8_t array_owner;        /* 1 + stack index of that array, 0 = none */
  /* 1 + stack index of an array of fixed-size leaves nested inside it, whose
   * words go straight into the idle e712.hash: no slots either. */
  uint8_t hash_owner;

  /* 1 + the pool slot holding SafeTx.to, 0 = none: the token an embedded
   * approve() in SafeTx.data calls. Every pop clears it, so it never
   * outlives the frame that read it. */
  uint8_t safe_to_slot;

  Eip712MultiSend multisend;

  SHA3_CTX hash;

  /* The one outstanding value request, stored compactly (not the wire
   * FieldType) to save .bss. */
  uint8_t pending_data_type;
  bool pending_has_size;
  uint32_t pending_size;
  char pending_name[EIP712_MAX_MEMBER_NAME];

  /* An array's LENGTH is in flight; its frame is not pushed yet. */
  bool want_array_len;
  uint32_t pending_declared_dim;

  /* A `bytes` or `string` value longer than EIP712_MAX_LEAF, arriving in
   * chunks hashed into e712.hash, idle while a value is read. A string is
   * read twice: counted and checked whole, then shown. */
  struct {
    uint32_t total;  /* 0 = none in flight */
    uint32_t offset; /* the next byte wanted */
    uint32_t parts;  /* screens of the whole value */
    uint32_t shown;  /* screens shown so far */
    bool showing;    /* false during a string's counting pass */
    Eip712Utf8 utf8;
    uint8_t counted[32]; /* the counting pass's keccak */
  } chunk;

  uint8_t phase;
  /* Every struct named this session (the domain's and the message's), with
   * the schema first supplied for it: a repeated StructAck must match. */
  Eip712Names types;
  uint8_t schema_digest[EIP712_MAX_STRUCTS + 1][32];
  uint8_t schema_known; /* bit i: schema_digest[i] is set */
  uint8_t requested;    /* types index of the outstanding StructRequest */
  Eip712Closure closure;
  uint8_t closure_index;
} e712;

_Static_assert(EIP712_MAX_STRUCTS + 1 <= 8, "schema_known is one byte");
_Static_assert(EIP712_MAX_STRUCTS + 1 < EIP712_NO_TYPE, "type index range");
_Static_assert(EIP712_MAX_PATH <= 256, "label_off is one byte");

static bool unbindable(void) {
  return (e712.domain_facts.domain_present & EIP712_DOMAIN_UNBINDABLE) != 0;
}

bool eip712_stream_domain_matches(uint8_t field, uint8_t literal_kind,
                                  const uint8_t* value, size_t length,
                                  bool require_absent) {
  if (!e712.have_domain_separator || unbindable() || field < 1 || field > 5 ||
      (!value && length != 0))
    return false;
  const Eip712DomainFacts* facts = &e712.domain_facts;
  if (field == 3) {
    if (require_absent) return !facts->has_chain_id;
    if (!facts->has_chain_id || literal_kind != 7 || length == 0 || length > 8)
      return false;
    uint64_t chain = 0;
    for (size_t i = 0; i < length; i++) chain = (chain << 8) | value[i];
    return chain == facts->chain_id;
  }
  if (field == 4) {
    if (require_absent) return !facts->has_verifying_contract;
    return facts->has_verifying_contract && literal_kind == 5 && length == 20 &&
           memcmp(value, facts->verifying_contract, 20) == 0;
  }
  const uint8_t index = field == 5 ? 2 : field - 1;
  const bool present = (facts->domain_present & (1u << index)) != 0;
  if (require_absent) return !present;
  if (!present || literal_kind != (field == 5 ? 3 : 4) ||
      (field == 5 && length != 32))
    return false;
  uint8_t digest[32];
  keccak_256(value, length, digest);
  const bool matches = memcmp(digest, facts->domain_hashes[index], 32) == 0;
  memzero(digest, sizeof(digest));
  return matches;
}

/* What the next StructAck is for. */
enum {
  PH_DISCOVER = 0, /* collecting the closure of the top frame's struct */
  PH_STREAM,       /* hashing encodeType segments in sorted order */
  PH_MEMBER,       /* fetching the top frame's current member type */
};

Eip712Wait eip712_stream_waiting(void) {
  return e712.active ? e712.waiting : EIP712_IDLE;
}

void eip712_stream_abort(void) { memzero(&e712, sizeof(e712)); }

/* Display: one review per leaf, from the SAME bytes about to be absorbed. The
 * body opens with the member's full path (the hashed names), so distinct
 * leaves never draw the same screen. Strings go through
 * erc7730_format_text(). An over-long value is shown in numbered parts, each
 * a required confirmation; confirm() never truncates. */
#define EIP712_BODY_MAX (BODY_CHAR_MAX - 1)

typedef enum {
  EIP712_LEAF_OK = 0,
  EIP712_LEAF_CANCELLED,
  EIP712_LEAF_INVALID,
} Eip712LeafResult;

typedef enum {
  EIP712_RENDER_TEXT,    /* already-rendered ASCII, split by character */
  EIP712_RENDER_HEX,     /* raw bytes as 0x hex */
  EIP712_RENDER_ESCAPED, /* raw string bytes through erc7730_format_text() */
} Eip712Render;

/* Render as much of value[offset..len) as fits `budget` characters. `first`:
 * value[0] is the value's first byte, which hex leads with "0x". */
static bool render_part(Eip712Render how, const uint8_t* value, size_t len,
                        size_t offset, bool first, char* out, size_t budget,
                        size_t* consumed) {
  const size_t left = len - offset;
  *consumed = 0;
  out[0] = '\0';
  if (how == EIP712_RENDER_HEX) {
    static const char digits[] = "0123456789abcdef";
    const size_t lead = first && offset == 0 ? 2 : 0;
    if (budget < lead + 2) return false;
    size_t n = (budget - lead) / 2;
    if (n > left) n = left;
    char* p = out;
    if (lead) {
      *p++ = '0';
      *p++ = 'x';
    }
    for (size_t i = 0; i < n; i++) {
      *p++ = digits[value[offset + i] >> 4];
      *p++ = digits[value[offset + i] & 0x0F];
    }
    *p = '\0';
    *consumed = n;
    return true;
  }
  if (left == 0) return true;
  if (how == EIP712_RENDER_TEXT) {
    const size_t n = left < budget ? left : budget;
    memcpy(out, value + offset, n);
    out[n] = '\0';
    *consumed = n;
    return true;
  }
  /* One byte escapes to <= 4 chars, so budget 4 always progresses. Bytes
   * escape independently, so this finds the longest fitting prefix. */
  if (budget < 4) return false;
  size_t lo = 1, hi = left < budget ? left : budget;
  while (lo < hi) {
    const size_t mid = lo + (hi - lo + 1) / 2;
    if (erc7730_format_text(value + offset, mid, out, budget + 1)) {
      lo = mid;
    } else {
      hi = mid - 1;
    }
  }
  if (!erc7730_format_text(value + offset, lo, out, budget + 1)) return false;
  *consumed = lo;
  return true;
}

static Eip712LeafResult confirm_parts(const char* title, const char* path,
                                      const char* type_name, Eip712Render how,
                                      const uint8_t* value, size_t len) {
  char part[BODY_CHAR_MAX];
  size_t consumed = 0;
  const size_t fixed = strlen(path) + 1 + strlen(type_name) + 2;
  /* " (999/999)" is the widest part counter. */
  if (fixed + 10 + 8 > EIP712_BODY_MAX) return EIP712_LEAF_INVALID;

  if (!render_part(how, value, len, 0, true, part, EIP712_BODY_MAX - fixed,
                   &consumed))
    return EIP712_LEAF_INVALID;
  if (consumed == len)
    return confirm(ButtonRequestType_ButtonRequest_Other, title, "%s\n%s: %s",
                   path, type_name, part)
               ? EIP712_LEAF_OK
               : EIP712_LEAF_CANCELLED;

  const size_t budget = EIP712_BODY_MAX - fixed - 10;
  size_t parts = 0;
  for (size_t offset = 0; offset < len; offset += consumed) {
    if (!render_part(how, value, len, offset, true, part, budget, &consumed) ||
        consumed == 0 || ++parts > 999)
      return EIP712_LEAF_INVALID;
  }
  size_t offset = 0;
  for (size_t i = 1; i <= parts; i++, offset += consumed) {
    if (!render_part(how, value, len, offset, true, part, budget, &consumed))
      return EIP712_LEAF_INVALID;
    if (!confirm(ButtonRequestType_ButtonRequest_Other, title,
                 "%s (%u/%u)\n%s: %s", path, (unsigned)i, (unsigned)parts,
                 type_name, part))
      return EIP712_LEAF_CANCELLED;
  }
  return EIP712_LEAF_OK;
}

/* The member's path from the root being walked: "amount", "from.wallet",
 * "to[1].wallet", "values[0][2]". */
static bool leaf_path(char* out, size_t out_size) {
  size_t used = 0;
  out[0] = '\0';
  for (uint8_t i = 1; i <= e712.depth; i++) {
    const bool leaf = i == e712.depth;
    const Eip712Frame* parent = &e712.stack[i - 1];
    const char* label =
        leaf ? e712.pending_name : e712.labels + e712.stack[i].label_off;
    int n;
    if (parent->is_array) {
      n = snprintf(out + used, out_size - used, "[%u]",
                   (unsigned)parent->member_index);
    } else {
      n = snprintf(out + used, out_size - used, "%s%s", used ? "." : "", label);
    }
    if (n < 0 || (size_t)n >= out_size - used) return false;
    used += (size_t)n;
  }
  return true;
}

bool eip712_render_integer(const Eip712FieldType* field, const uint8_t* value,
                           uint16_t len, char* out, size_t out_size) {
  uint8_t word[32];
  if (len == 0 || len > sizeof(word)) return false;
  memzero(word, sizeof(word));
  memcpy(word + sizeof(word) - len, value, len);
  const bool negative =
      field->data_type == EthereumTypedDataStructAck_EthereumDataType_INT &&
      (value[0] & 0x80);
  if (negative) {
    /* Two's-complement magnitude within the declared width. */
    for (size_t i = sizeof(word) - len; i < sizeof(word); i++)
      word[i] = (uint8_t)~word[i];
    for (size_t i = sizeof(word); i-- > sizeof(word) - len;)
      if (++word[i] != 0) break;
  }
  bignum256 amount;
  bn_read_be(word, &amount);
  const size_t written = bn_format(&amount, negative ? "-" : NULL, NULL, 0, 0,
                                   false, out, out_size);
  memzero(&amount, sizeof(amount));
  return written > 0;
}

/* An unlimited permit (EIP-2612 or DAI on the domain's verifyingContract,
 * Permit2 on its token member) names that value on its own screen: the
 * type's maximum reads UNLIMITED, under a warning title. NULL otherwise. */
static const char* unlimited_permit_text(const Eip712FieldType* field,
                                         const uint8_t* value, uint16_t len) {
  if (e712.root != 1) return NULL;
  const Eip712Frame* f = &e712.stack[e712.depth - 1];
  if (f->is_array) return NULL;
  const char* name = e712.types.names[f->u.s.type];
  const char* member = e712.pending_name;
  if (field->data_type == EthereumTypedDataStructAck_EthereumDataType_BOOL)
    return strcmp(name, "Permit") == 0 && strcmp(member, "allowed") == 0 &&
                   value[0] == 1
               ? "UNLIMITED (allowed)"
               : NULL;
  if (field->data_type != EthereumTypedDataStructAck_EthereumDataType_UINT ||
      !((strcmp(name, "Permit") == 0 && strcmp(member, "value") == 0) ||
        ((strcmp(name, "PermitDetails") == 0 ||
          strcmp(name, "TokenPermissions") == 0) &&
         strcmp(member, "amount") == 0)))
    return NULL;
  /* The leaf is exactly the declared width, so all ones is its maximum. */
  for (uint16_t i = 0; i < len; i++)
    if (value[i] != 0xff) return NULL;
  return len > 0 ? "UNLIMITED" : NULL;
}

/* Fixed and short: a wrapped title draws over the body, and a primary type
 * may fill a whole row. The final signing screen names the primary type. */
static const char* leaf_title(void) {
  return e712.root == 0 ? "EIP-712 Domain" : "EIP-712 Message";
}

/* approve(spender, amount) carried in a dynamic `bytes` leaf, such as a
 * Safe transaction's data: the policy of a top-level approve. */
static bool embedded_approve(const Eip712FieldType* field, const uint8_t* value,
                             uint16_t len) {
  return field->data_type ==
             EthereumTypedDataStructAck_EthereumDataType_BYTES &&
         !field->has_size && len >= 68 &&
         memcmp(value, "\x09\x5e\xa7\xb3", 4) == 0;
}

/* Pre-0.8 Solidity masks the spender word's high bytes, so a dirty one
 * still grants the allowance on chain: refused, as ethereum.c does. */
static bool embedded_approve_is_dirty(const uint8_t* value) {
  for (size_t i = 4; i < 16; i++)
    if (value[i] != 0) return true;
  return false;
}

/* The domain's chainId names addresses and tokens; 0 when it has none. */
static uint32_t domain_chain_id(void) {
  const uint64_t chain = e712.domain_facts.chain_id;
  return e712.domain_facts.has_chain_id && chain <= UINT32_MAX ? (uint32_t)chain
                                                               : 0;
}

/* True when the open frame is a SafeTx struct. */
static bool in_safe_tx(void) {
  const Eip712Frame* f = &e712.stack[e712.depth - 1];
  return !f->is_array && strcmp(e712.types.names[f->u.s.type], "SafeTx") == 0;
}

/* The open SafeTx's `to`, once read; NULL before then. */
static const uint8_t* safe_tx_to(void) {
  const Eip712Frame* f = &e712.stack[e712.depth - 1];
  const uint8_t to = e712.safe_to_slot;
  if (in_safe_tx() && to > f->slot_base && to <= f->slot_base + f->member_index)
    return e712.pool[to - 1] + 12;
  return NULL;
}

/* An unlimited embedded approve signs only after the UNLIMITED warning,
 * which names the full spender, and the token from SafeTx.to once seen. */
static Eip712LeafResult confirm_embedded_unlimited(const uint8_t* value) {
  for (size_t i = 36; i < 68; i++)
    if (value[i] != 0xff) return EIP712_LEAF_OK;
  const uint32_t cid = domain_chain_id();
  const bool safe_tx = in_safe_tx();
  const uint8_t* to = safe_tx_to();
  if (to)
    return ethereum_confirmUnlimitedApproval(cid, value + 16, to)
               ? EIP712_LEAF_OK
               : EIP712_LEAF_CANCELLED;
  char spender[43] = "0x";
  ethereum_address_checksum(value + 16, spender + 2, false, cid);
  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "UNLIMITED approval",
                 "Allow %s to spend ALL your tokens of %s", spender,
                 safe_tx ? "the contract in 'to'" : "the contract called")
             ? EIP712_LEAF_OK
             : EIP712_LEAF_CANCELLED;
}

/* A delegatecall runs `target`'s code as the Safe: say so, naming it. */
static bool confirm_delegatecall(const char* title, const char* who,
                                 const uint8_t* target) {
  char code[43] = "the contract in 'to'";
  if (target) {
    code[0] = '0';
    code[1] = 'x';
    ethereum_address_checksum(target, code + 2, false, domain_chain_id());
  }
  return confirm(ButtonRequestType_ButtonRequest_Other, title,
                 "%s gives %s your Safe's full authority. Not checked.", who,
                 code);
}

/* ── Approves inside a MultiSend ──────────────────────────────────────
 * Safe's MultiSend and MultiSendCallOnly take multiSend(bytes transactions),
 * each call packed as operation(1) | to(20) | value(32) | dataLength(32) |
 * data. An approve(spender, 2^256-1) or increaseAllowance(spender, 2^256-1)
 * among them gets the top-level policy: a dirty spender word is refused, and
 * the UNLIMITED warning, naming the spender and the inner `to` as the token,
 * comes as soon as its 68 bytes are read. Matched by selector, not address:
 * the device cannot tell which contract SafeTx.to is, and another contract
 * with this selector costs at most an extra warning.
 *
 * An inner delegatecall (operation 1) runs code the device does not read,
 * with the Safe's authority: it is warned about before its data. A
 * multiSend inside it is not scanned, since its target need not be
 * MultiSend.
 *
 * Only the canonical packing (MultiSend 1.1.1 on) is read: each operation
 * 0 or 1, each call inside `length`, `length` inside the value. Anything
 * else (v1.0.0's ABI words, a cut header, a call running past `length`)
 * stops the scan with the "Batch not checked" warning, before the bytes
 * that follow; the bytes themselves are always shown in full. */
enum { MS_OFF, MS_SELECTOR, MS_OFFSET, MS_LENGTH, MS_HEADER, MS_DATA };
#define MS_HEADER_LEN 85
#define MS_SEEN_APPROVE 1   /* data so far starts 0x095ea7b3 */
#define MS_SEEN_INCREASE 2  /* data so far starts 0x39509351 */
#define MS_SEEN_DIRTY 4     /* the spender word has high bytes set */
#define MS_SEEN_FINITE 8    /* the amount word is not all ones */
#define MS_SEEN_HUGE 16     /* dataLength exceeds 32 bits */
#define MS_SEEN_DELEGATE 32 /* this call's operation is 1 */
#define MS_FACT_CLEAN 1     /* read to its end, every call canonical */
#define MS_FACT_DELEGATE 2  /* some inner call is a delegatecall */

typedef enum {
  MS_SCAN_OK,
  MS_SCAN_CANCELLED,
  MS_SCAN_DIRTY, /* an inner approve's spender word is dirty */
} MultisendScan;

/* Every leaf starts here, whole or chunked, before any of its bytes is fed. */
static void multisend_begin(const Eip712FieldType* field, const uint8_t* value,
                            size_t len) {
  memzero(&e712.multisend, sizeof(e712.multisend));
  if (field->data_type == EthereumTypedDataStructAck_EthereumDataType_BYTES &&
      !field->has_size && len >= 4 && memcmp(value, "\x8d\x80\xff\x0a", 4) == 0)
    e712.multisend.phase = MS_SELECTOR;
}

static void multisend_phase(uint8_t phase) {
  e712.multisend.phase = phase;
  e712.multisend.at = 0;
}

/* The batch was read to its end. */
static MultisendScan multisend_done(void) {
  e712.multisend.facts |= MS_FACT_CLEAN;
  e712.multisend.phase = MS_OFF;
  return MS_SCAN_OK;
}

/* The scan stops here: said before any more of the bytes is shown. */
static MultisendScan multisend_unchecked(void) {
  e712.multisend.phase = MS_OFF;
  return confirm(ButtonRequestType_ButtonRequest_Other, "Batch not checked",
                 "KeepKey could not read this batch's calls; approvals "
                 "inside it are not shown.")
             ? MS_SCAN_OK
             : MS_SCAN_CANCELLED;
}

static MultisendScan multisend_byte(uint8_t b) {
  static const uint8_t approve[4] = {0x09, 0x5e, 0xa7, 0xb3};
  static const uint8_t increase[4] = {0x39, 0x50, 0x93, 0x51};
  Eip712MultiSend* ms = &e712.multisend;
  const uint8_t at = ms->at++;
  switch (ms->phase) {
    case MS_SELECTOR:
      if (at == 3) multisend_phase(MS_OFFSET);
      return MS_SCAN_OK;
    case MS_OFFSET:
      if (b != (at == 31 ? 0x20 : 0)) return multisend_unchecked();
      if (at == 31) multisend_phase(MS_LENGTH);
      return MS_SCAN_OK;
    case MS_LENGTH:
      if (at < 28 && b != 0) return multisend_unchecked();
      ms->left = (ms->left << 8) | b;
      if (at == 31) {
        if (!ms->left) return multisend_done();
        multisend_phase(MS_HEADER);
      }
      return MS_SCAN_OK;
    case MS_HEADER:
      if (at == 0) {
        if (b > 1) return multisend_unchecked();
        ms->call++;
        ms->seen = b ? MS_SEEN_DELEGATE : 0;
      } else if (at <= 20) {
        ms->to[at - 1] = b;
      } else if (at >= 53 && at < 81) {
        if (b != 0) ms->seen |= MS_SEEN_HUGE;
      } else if (at >= 81) {
        ms->need = (ms->need << 8) | b;
      }
      ms->left--;
      if (at < MS_HEADER_LEN - 1)
        return ms->left ? MS_SCAN_OK : multisend_unchecked();
      /* The call's data must end inside the batch. */
      if ((ms->seen & MS_SEEN_HUGE) || ms->need > ms->left)
        return multisend_unchecked();
      if (ms->seen & MS_SEEN_DELEGATE) {
        char who[16];
        snprintf(who, sizeof(who), "Call #%u", (unsigned)ms->call);
        ms->facts |= MS_FACT_DELEGATE;
        if (!confirm_delegatecall("Delegatecall in batch", who, ms->to))
          return MS_SCAN_CANCELLED;
      }
      ms->seen = MS_SEEN_APPROVE | MS_SEEN_INCREASE;
      multisend_phase(ms->need ? MS_DATA : MS_HEADER);
      return ms->left ? MS_SCAN_OK : multisend_done();
    default: { /* MS_DATA */
      MultisendScan result = MS_SCAN_OK;
      if (at < 4) {
        if (b != approve[at]) ms->seen &= ~MS_SEEN_APPROVE;
        if (b != increase[at]) ms->seen &= ~MS_SEEN_INCREASE;
      } else if (at < 16) {
        if (b != 0) ms->seen |= MS_SEEN_DIRTY;
      } else if (at < 36) {
        ms->spender[at - 16] = b;
      } else if (at < 68) {
        if (b != 0xff) ms->seen |= MS_SEEN_FINITE;
      } else {
        ms->at = 68;
      }
      if (at == 67 && (ms->seen & (MS_SEEN_APPROVE | MS_SEEN_INCREASE))) {
        if (ms->seen & MS_SEEN_DIRTY) return MS_SCAN_DIRTY;
        if (!(ms->seen & MS_SEEN_FINITE) &&
            !ethereum_confirmUnlimitedApproval(domain_chain_id(), ms->spender,
                                               ms->to))
          result = MS_SCAN_CANCELLED;
      }
      if (--ms->need == 0) multisend_phase(MS_HEADER);
      /* need <= left: the batch ends at a call's end. */
      if (--ms->left == 0) multisend_done();
      return result;
    }
  }
}

static MultisendScan multisend_feed(const uint8_t* bytes, size_t len) {
  for (size_t i = 0; i < len && e712.multisend.phase != MS_OFF; i++) {
    const MultisendScan step = multisend_byte(bytes[i]);
    if (step != MS_SCAN_OK) return step;
  }
  return MS_SCAN_OK;
}

/* ── A SafeTx delegatecall ────────────────────────────────────────────
 * operation 1 runs SafeTx.to's code as the Safe. A Safe app's batch is the
 * one case read in full: `to` a Safe MultiSend deployment and `data` a
 * multiSend the scan read to its end, with no delegatecall inside. Anything
 * else is warned about when the last of `to`, `operation` and `data` is
 * read, in any order, or when the SafeTx ends without one of them. */
#define SAFE_DELEGATE 1   /* operation is 1 */
#define SAFE_DATA 2       /* data has been read */
#define SAFE_UNCHECKED 4  /* data is not such a batch */
#define SAFE_TO 8         /* to has been read */
#define SAFE_MULTISEND 16 /* to is a MultiSend deployment */
#define SAFE_DECIDED 32

/* MultiSend and MultiSendCallOnly, every address variant of each release
 * that packs its calls (1.1.1 on; 1.0.0 takes ABI words), from
 * safe-global/safe-deployments 7b1fb6d6, src/assets/v1.x.x/multi_send*.json.
 * Each address holds the same code on every chain that has it, so the
 * list is not per chain. */
static const uint8_t safe_multisend[][20] = {
    /* 1.1.1 MultiSend */
    {0x8d, 0x29, 0xbe, 0x29, 0x92, 0x3b, 0x68, 0xab, 0xfd, 0xd2,
     0x1e, 0x54, 0x1b, 0x93, 0x74, 0x73, 0x7b, 0x49, 0xcd, 0xad},
    /* 1.3.0 MultiSend: canonical, eip155, zksync */
    {0xa2, 0x38, 0xcb, 0xeb, 0x14, 0x2c, 0x10, 0xef, 0x7a, 0xd8,
     0x44, 0x2c, 0x6d, 0x1f, 0x9e, 0x89, 0xe0, 0x7e, 0x77, 0x61},
    {0x99, 0x87, 0x39, 0xbf, 0xda, 0xad, 0xde, 0x7c, 0x93, 0x3b,
     0x94, 0x2a, 0x68, 0x05, 0x39, 0x33, 0x09, 0x8f, 0x9e, 0xda},
    {0x0d, 0xfc, 0xcc, 0xb9, 0x52, 0x25, 0xff, 0xb0, 0x3c, 0x6f,
     0xbb, 0x25, 0x59, 0xb5, 0x30, 0xc2, 0xb7, 0xc8, 0xa9, 0x12},
    /* 1.3.0 MultiSendCallOnly: canonical, eip155, zksync */
    {0x40, 0xa2, 0xac, 0xcb, 0xd9, 0x2b, 0xca, 0x93, 0x8b, 0x02,
     0x01, 0x0e, 0x17, 0xa5, 0xb8, 0x92, 0x9b, 0x49, 0x13, 0x0d},
    {0xa1, 0xda, 0xbe, 0xf3, 0x3b, 0x3b, 0x82, 0xc7, 0x81, 0x4b,
     0x6d, 0x82, 0xa7, 0x9e, 0x50, 0xf4, 0xac, 0x44, 0x10, 0x2b},
    {0xf2, 0x20, 0xd3, 0xb4, 0xdf, 0xb2, 0x3c, 0x4a, 0xde, 0x8c,
     0x88, 0xe5, 0x26, 0xc1, 0x35, 0x3a, 0xba, 0xcb, 0xc3, 0x8f},
    /* 1.4.1 MultiSend: canonical, zksync */
    {0x38, 0x86, 0x9b, 0xf6, 0x6a, 0x61, 0xcf, 0x6b, 0xdb, 0x99,
     0x6a, 0x6a, 0xe4, 0x0d, 0x58, 0x53, 0xfd, 0x43, 0xb5, 0x26},
    {0x30, 0x9d, 0x0b, 0x19, 0x0f, 0xec, 0xca, 0x8e, 0x1d, 0x5d,
     0x83, 0x09, 0xa1, 0x6f, 0x7e, 0x3c, 0xb1, 0x33, 0xe8, 0x85},
    /* 1.4.1 MultiSendCallOnly: canonical, zksync */
    {0x96, 0x41, 0xd7, 0x64, 0xfc, 0x13, 0xc8, 0xb6, 0x24, 0xc0,
     0x44, 0x30, 0xc7, 0x35, 0x6c, 0x1c, 0x7c, 0x81, 0x02, 0xe2},
    {0x04, 0x08, 0xef, 0x01, 0x19, 0x60, 0xd0, 0x23, 0x49, 0xd5,
     0x02, 0x86, 0xd2, 0x05, 0x31, 0x22, 0x9b, 0xce, 0xf7, 0x73},
    /* 1.5.0 MultiSend, MultiSendCallOnly */
    {0x21, 0x85, 0x43, 0x28, 0x80, 0x04, 0xcd, 0x07, 0x83, 0x24,
     0x72, 0xd4, 0x64, 0x64, 0x81, 0x73, 0xc7, 0x7d, 0x7e, 0xb7},
    {0xa8, 0x3c, 0x33, 0x6b, 0x20, 0x40, 0x1a, 0xf7, 0x73, 0xb6,
     0x21, 0x9b, 0xa5, 0x02, 0x71, 0x74, 0x33, 0x8d, 0x18, 0x36},
};

static bool is_safe_multisend(const uint8_t* to) {
  for (size_t i = 0; i < sizeof(safe_multisend) / 20; i++)
    if (memcmp(to, safe_multisend[i], 20) == 0) return true;
  return false;
}

/* Decide once all three are read, or, `closing`, once the SafeTx ends.
 * False to stop. */
static bool safe_delegate_decide(uint8_t* facts, bool closing,
                                 const uint8_t* to) {
  const uint8_t read = SAFE_DELEGATE | SAFE_DATA | SAFE_TO;
  if (!(*facts & SAFE_DELEGATE) || (*facts & SAFE_DECIDED)) return true;
  if ((*facts & read) != read && !closing) return true;
  *facts |= SAFE_DECIDED;
  if ((*facts & (read | SAFE_MULTISEND | SAFE_UNCHECKED)) ==
      (read | SAFE_MULTISEND))
    return true;
  return confirm_delegatecall("Delegatecall", "SafeTx", to);
}

/* After this SafeTx leaf's own checks, before its screen. False to stop. */
static bool safe_delegate_approved(const Eip712FieldType* field,
                                   const uint8_t* value, size_t len) {
  if (e712.root != 1 || !in_safe_tx()) return true;
  uint8_t* facts = &e712.stack[e712.depth - 1].u.s.safe_facts;
  const uint8_t* to = safe_tx_to();
  if (field->data_type == EthereumTypedDataStructAck_EthereumDataType_BYTES &&
      strcmp(e712.pending_name, "data") == 0) {
    *facts |= SAFE_DATA;
    if ((e712.multisend.facts & (MS_FACT_CLEAN | MS_FACT_DELEGATE)) !=
        MS_FACT_CLEAN)
      *facts |= SAFE_UNCHECKED;
  } else if (field->data_type ==
                 EthereumTypedDataStructAck_EthereumDataType_ADDRESS &&
             strcmp(e712.pending_name, "to") == 0) {
    *facts |= SAFE_TO;
    if (is_safe_multisend(value)) *facts |= SAFE_MULTISEND;
    to = value;
  } else if (field->data_type ==
                 EthereumTypedDataStructAck_EthereumDataType_UINT &&
             strcmp(e712.pending_name, "operation") == 0 && len > 0 &&
             value[len - 1] == 1) {
    for (size_t i = 0; i + 1 < len; i++)
      if (value[i] != 0) return true;
    *facts |= SAFE_DELEGATE;
  }
  return safe_delegate_decide(facts, false, to);
}

static Eip712LeafResult eip712_confirm_leaf(const Eip712FieldType* field,
                                            const uint8_t* value,
                                            uint16_t len) {
  char type_name[EIP712_MAX_TYPE_NAME];
  char path[EIP712_MAX_PATH];
  char text[82]; /* "-" + 78 digits, or a checksummed address */
  if (!eip712_type_name(field, type_name, sizeof(type_name)) ||
      !leaf_path(path, sizeof(path)))
    return EIP712_LEAF_INVALID;
  const char* title = leaf_title();
  const char* unlimited = unlimited_permit_text(field, value, len);
  if (unlimited) {
    return confirm_parts("UNLIMITED approval", path, type_name,
                         EIP712_RENDER_TEXT, (const uint8_t*)unlimited,
                         strlen(unlimited));
  }

  switch (field->data_type) {
    case EthereumTypedDataStructAck_EthereumDataType_STRING:
      return confirm_parts(title, path, type_name, EIP712_RENDER_ESCAPED, value,
                           len);
    case EthereumTypedDataStructAck_EthereumDataType_BOOL:
      strlcpy(text, value[0] ? "true" : "false", sizeof(text));
      break;
    case EthereumTypedDataStructAck_EthereumDataType_ADDRESS:
      text[0] = '0';
      text[1] = 'x';
      ethereum_address_checksum(value, text + 2, false, 0);
      break;
    case EthereumTypedDataStructAck_EthereumDataType_UINT:
    case EthereumTypedDataStructAck_EthereumDataType_INT:
      if (!eip712_render_integer(field, value, len, text, sizeof(text)))
        return EIP712_LEAF_INVALID;
      break;
    case EthereumTypedDataStructAck_EthereumDataType_BYTES:
      if (embedded_approve(field, value, len)) {
        const Eip712LeafResult warned = confirm_embedded_unlimited(value);
        if (warned != EIP712_LEAF_OK) return warned;
      }
      return confirm_parts(title, path, type_name, EIP712_RENDER_HEX, value,
                           len);
    default:
      return EIP712_LEAF_INVALID;
  }
  return confirm_parts(title, path, type_name, EIP712_RENDER_TEXT,
                       (const uint8_t*)text, strlen(text));
}

/* An empty array has no element screen, so it would otherwise sign unseen.
 * `arr` is staged but not pushed, so leaf_path() still ends at the array. */
static Eip712LeafResult eip712_confirm_empty_array(const Eip712Frame* arr) {
  Eip712FieldType type;
  char type_name[EIP712_MAX_TYPE_NAME];
  char path[EIP712_MAX_PATH];
  memzero(&type, sizeof(type));
  type.data_type = (Eip712DataType)arr->u.a.elem_data_type;
  type.has_size = arr->u.a.elem_has_size;
  type.size = arr->u.a.elem_size;
  if (arr->u.a.elem_type != EIP712_NO_TYPE) {
    type.has_struct_name = true;
    strlcpy(type.struct_name, e712.types.names[arr->u.a.elem_type],
            sizeof(type.struct_name));
  }
  /* This level's type keeps its inner dimensions; the outermost is last. */
  type.array_levels_count = arr->u.a.levels_total - arr->u.a.level_index;
  memcpy(type.array_levels, arr->u.a.array_levels,
         type.array_levels_count * sizeof(type.array_levels[0]));
  if (!eip712_type_name(&type, type_name, sizeof(type_name)) ||
      !leaf_path(path, sizeof(path)))
    return EIP712_LEAF_INVALID;
  static const char empty[] = "0 items";
  return confirm_parts(leaf_title(), path, type_name, EIP712_RENDER_TEXT,
                       (const uint8_t*)empty, sizeof(empty) - 1);
}

/* The walk: each function emits one request and returns, or finishes; the
 * next Ack resumes the machine. */

static Eip712Next next_step;

const Eip712Next* eip712_stream_next(void) { return &next_step; }

static void fail(const char* why) {
  bool was_active = e712.active;
  eip712_stream_abort();
  (void)was_active;
  memzero(&next_step, sizeof(next_step));
  next_step.kind = EIP712_REQ_FAIL;
  next_step.error = why;
}

/* True when the user approved the screen; otherwise the walk has ended. */
static bool review_approved(Eip712LeafResult shown) {
  if (shown == EIP712_LEAF_INVALID) {
    fail("EIP-712 value cannot be displayed");
    return false;
  }
  if (shown != EIP712_LEAF_OK) {
    eip712_stream_abort();
    memzero(&next_step, sizeof(next_step));
    next_step.kind = EIP712_REQ_CANCELLED;
    return false;
  }
  if (e712.root == 1) e712.message_value_confirmed = true;
  return true;
}

/* Scan the next bytes of a multiSend leaf, before any screen of them; `last`
 * when they end the value. True to go on; otherwise the walk has ended. */
static bool multisend_reviewed(const uint8_t* bytes, size_t len, bool last) {
  MultisendScan scan = multisend_feed(bytes, len);
  /* The value ended before the batch did. */
  if (scan == MS_SCAN_OK && last && e712.multisend.phase != MS_OFF)
    scan = multisend_unchecked();
  switch (scan) {
    case MS_SCAN_OK:
      return true;
    case MS_SCAN_CANCELLED:
      return review_approved(EIP712_LEAF_CANCELLED);
    default: /* MS_SCAN_DIRTY */
      fail("Malformed ERC20 approval");
      return false;
  }
}

static void request_struct(uint8_t type) {
  memzero(&next_step, sizeof(next_step));
  next_step.kind = EIP712_REQ_STRUCT;
  strlcpy(next_step.struct_name, e712.types.names[type],
          sizeof(next_step.struct_name));
  e712.requested = type;
  e712.waiting = EIP712_WANT_STRUCT;
}

/* The path is rebuilt from the frame stack, so they cannot drift. */
static void request_value(void) {
  memzero(&next_step, sizeof(next_step));
  next_step.kind = EIP712_REQ_VALUE;
  next_step.member_path_len = 1 + e712.depth;
  next_step.member_path[0] = e712.root;
  for (uint8_t i = 0; i < e712.depth; i++) {
    next_step.member_path[1 + i] = e712.stack[i].member_index;
  }
  e712.waiting = EIP712_WANT_VALUE;
}

/* Give `staged` (stack[depth], not pushed yet) its label, after the labels of
 * the open frames. Each label costs its length + 1 here and at least that in
 * the review path, which also holds the leaf, so a document this refuses has
 * a path leaf_path() could not render either. */
static bool stage_label(Eip712Frame* staged, const char* name) {
  size_t off = 0;
  if (e712.depth > 1) {
    const Eip712Frame* top = &e712.stack[e712.depth - 1];
    off = top->label_off + strlen(e712.labels + top->label_off) + 1;
  }
  const size_t len = strlen(name);
  if (off + len + 1 > sizeof(e712.labels)) return false;
  memcpy(e712.labels + off, name, len + 1);
  staged->label_off = (uint8_t)off;
  return true;
}

/* typeHash for the top frame's struct; recomputed per use to save .bss. */
static void begin_type_hash(void) {
  const Eip712Frame* f = &e712.stack[e712.depth - 1];
  memzero(&e712.closure, sizeof(e712.closure));
  e712.closure.index[0] = f->u.s.type;
  e712.closure.count = 1;
  e712.closure_index = 0;
  e712.phase = PH_DISCOVER;
  request_struct(f->u.s.type);
}

/* Make stack[0] the struct `name` and start its walk. */
static bool begin_root(const char* name) {
  memzero(&e712.stack[0], sizeof(e712.stack[0]));
  e712.stack[0].u.s.type = names_intern(&e712.types, name);
  if (e712.stack[0].u.s.type == EIP712_NO_TYPE) {
    fail("EIP-712 type graph too large or malformed");
    return false;
  }
  e712.depth = 1;
  e712.slots_used = 0;
  e712.array_owner = 0;
  e712.hash_owner = 0;
  e712.safe_to_slot = 0;
  begin_type_hash();
  return true;
}

static bool array_streams(const Eip712Frame* f) {
  return e712.array_owner != 0 && f == &e712.stack[e712.array_owner - 1];
}

static bool array_hashes(const Eip712Frame* f) {
  return e712.hash_owner != 0 && f == &e712.stack[e712.hash_owner - 1];
}

/* Its elements are leaves of a fixed width, never chunked: nothing else uses
 * e712.hash until the array closes. */
static bool array_of_fixed_leaves(const Eip712Frame* arr) {
  const uint8_t type = arr->u.a.elem_data_type;
  return arr->u.a.level_index + 1 == arr->u.a.levels_total &&
         type != EthereumTypedDataStructAck_EthereumDataType_STRUCT &&
         type != EthereumTypedDataStructAck_EthereumDataType_STRING &&
         (type != EthereumTypedDataStructAck_EthereumDataType_BYTES ||
          arr->u.a.elem_has_size);
}

/* Width of a frame's own region in the pool: a streamed array has none. */
static uint8_t array_slots(const Eip712Frame* arr) {
  return array_streams(arr) || array_hashes(arr) ? 0
                                                 : (uint8_t)arr->u.a.array_len;
}

/* Keccak-f on the bare state. Absorbing a zero block XORs nothing in, so
 * the library's block step is exactly the permutation. Runs only between
 * folds, while e712.hash is idle. */
static void array_sponge_permute(void) {
  static const uint8_t zero_block[SHA3_256_BLOCK_LENGTH];
  keccak_256_Init(&e712.hash);
  memcpy(e712.hash.hash, e712.array_sponge, sizeof(e712.array_sponge));
  keccak_Update(&e712.hash, zero_block, sizeof(zero_block));
  memcpy(e712.array_sponge, e712.hash.hash, sizeof(e712.array_sponge));
  memzero(&e712.hash, sizeof(e712.hash));
  e712.array_sponge_bytes = 0;
}

/* Lanes are little-endian, as in sha3_process_block(). */
static void array_sponge_xor(uint8_t at, uint8_t byte) {
  e712.array_sponge[at / 8] ^= (uint64_t)byte << (8 * (at % 8));
}

static void array_sponge_absorb(const uint8_t word[32]) {
  for (uint8_t i = 0; i < 32; i++) {
    array_sponge_xor(e712.array_sponge_bytes++, word[i]);
    if (e712.array_sponge_bytes == SHA3_256_BLOCK_LENGTH)
      array_sponge_permute();
  }
}

/* keccak_Final()'s padding: 0x01 after the data, 0x80 in the last byte. */
static void array_sponge_final(uint8_t out[32]) {
  array_sponge_xor(e712.array_sponge_bytes, 0x01);
  array_sponge_xor(SHA3_256_BLOCK_LENGTH - 1, 0x80);
  array_sponge_permute();
  for (uint8_t i = 0; i < 32; i++)
    out[i] = (uint8_t)(e712.array_sponge[i / 8] >> (8 * (i % 8)));
  memzero(e712.array_sponge, sizeof(e712.array_sponge));
  e712.array_owner = 0;
}

/* struct: keccak(typeHash || enc(m1..mn)); array: keccak(enc(e1..en)). */
static bool fold_frame(uint8_t out[32]) {
  const Eip712Frame* f = &e712.stack[e712.depth - 1];
  /* A later frame may reuse this one's slots: its `to` is gone with it. */
  e712.safe_to_slot = 0;
  if (array_streams(f) || array_hashes(f)) {
    if (array_hashes(f)) {
      keccak_Final(&e712.hash, out);
      e712.hash_owner = 0;
    } else {
      array_sponge_final(out);
    }
    e712.slots_used = f->slot_base;
    e712.depth--;
    return true;
  }
  keccak_256_Init(&e712.hash);
  if (!f->is_array) {
    if (!f->u.s.have_type_hash) return false;
    keccak_Update(&e712.hash, f->u.s.type_hash, 32);
  }
  for (uint16_t i = 0; i < f->member_index; i++) {
    keccak_Update(&e712.hash, e712.pool[f->slot_base + i], 32);
  }
  keccak_Final(&e712.hash, out);
  e712.slots_used = f->slot_base;
  e712.depth--;
  return true;
}

static void advance_after_slot(void);

/* A container finished. Give its digest to the parent, or finish the root. */
static void complete_frame(void) {
  uint8_t digest[32];
  /* A SafeTx with operation 1 but no `to` or `data` is warned about now. */
  if (e712.root == 1 && in_safe_tx() &&
      !safe_delegate_decide(&e712.stack[e712.depth - 1].u.s.safe_facts, true,
                            safe_tx_to())) {
    review_approved(EIP712_LEAF_CANCELLED);
    return;
  }
  if (!fold_frame(digest)) {
    fail("EIP-712 internal hash state lost");
    return;
  }

  if (e712.depth > 0) {
    Eip712Frame* parent = &e712.stack[e712.depth - 1];
    if (array_streams(parent)) {
      array_sponge_absorb(digest);
    } else {
      memcpy(e712.pool[parent->slot_base + parent->member_index], digest, 32);
    }
    parent->member_index++;
    advance_after_slot();
    return;
  }

  const bool domain_only = strcmp(e712.primary_type, "EIP712Domain") == 0;
  if (e712.root == 0) {
    memcpy(e712.domain_separator, digest, 32);
    e712.have_domain_separator = true;
  }
  if (e712.root == 0 && !domain_only) {
    /* The domain is hashed. Now the message, under the same session. */
    e712.root = 1;
    begin_root(e712.primary_type);
    return;
  }

  /* The FSM derives the key and signs; no key material in this unit. */
  memzero(&next_step, sizeof(next_step));
  next_step.kind = EIP712_REQ_DONE;
  memcpy(next_step.domain_separator, e712.domain_separator, 32);
  /* MetaMask v4 / eth-sig-util sign keccak(0x1901 || domainSeparator) when the
   * primary type is the domain itself: there is no message hash. */
  next_step.domain_only = domain_only;
  next_step.message_empty = domain_only || !e712.message_value_confirmed;
  if (!domain_only) memcpy(next_step.message_hash, digest, 32);
  strlcpy(next_step.primary_type, e712.primary_type,
          sizeof(next_step.primary_type));
  memcpy(next_step.address_n, e712.address_n,
         e712.address_n_count * sizeof(uint32_t));
  next_step.address_n_count = e712.address_n_count;
  if (e712.require_definition) {
    e712.active = false;
    e712.waiting = EIP712_IDLE;
    memzero(e712.stack, sizeof(e712.stack));
    memzero(e712.pool, sizeof(e712.pool));
  } else {
    eip712_stream_abort();
  }
}

/* An element's kind (array, struct, leaf) is fixed by the TYPE, never by the
 * host. */
static void drive_array_element(void) {
  Eip712Frame* arr = &e712.stack[e712.depth - 1];

  if (arr->u.a.level_index + 1 < arr->u.a.levels_total) {
    if (e712.depth >= EIP712_MAX_DEPTH) {
      fail("EIP-712 array nests too deeply for this device");
      return;
    }
    Eip712Frame* inner = &e712.stack[e712.depth];
    memzero(inner, sizeof(*inner));
    if (!stage_label(inner, "")) {
      fail("EIP-712 member path too long for this device");
      return;
    }
    inner->is_array = true;
    inner->slot_base = arr->slot_base + array_slots(arr);
    inner->u.a = arr->u.a;
    inner->u.a.array_len = 0;
    inner->u.a.level_index = arr->u.a.level_index + 1;
    e712.pending_declared_dim =
        inner->u.a.array_levels[inner->u.a.levels_total - 1u -
                                inner->u.a.level_index];
    e712.want_array_len = true;
    request_value();
    return;
  }

  if (arr->u.a.elem_data_type ==
      EthereumTypedDataStructAck_EthereumDataType_STRUCT) {
    if (e712.depth >= EIP712_MAX_DEPTH) {
      fail("EIP-712 document nests too deeply for this device");
      return;
    }
    if (arr->u.a.elem_type == EIP712_NO_TYPE) {
      fail("EIP-712 array of structs has no type name");
      return;
    }
    Eip712Frame* child = &e712.stack[e712.depth];
    memzero(child, sizeof(*child));
    if (!stage_label(child, "")) {
      fail("EIP-712 member path too long for this device");
      return;
    }
    child->u.s.type = arr->u.a.elem_type;
    child->slot_base = arr->slot_base + array_slots(arr);
    e712.depth++;
    begin_type_hash();
    return;
  }

  e712.pending_data_type = arr->u.a.elem_data_type;
  e712.pending_has_size = arr->u.a.elem_has_size;
  e712.pending_size = arr->u.a.elem_size;
  strlcpy(e712.pending_name, "item", sizeof(e712.pending_name));
  request_value();
}

/* A slot was just filled. Either the frame is done, or fetch the next member.
 */
static void advance_after_slot(void) {
  const Eip712Frame* f = &e712.stack[e712.depth - 1];
  if (f->is_array) {
    if (f->member_index >= f->u.a.array_len) {
      complete_frame();
      return;
    }
    drive_array_element();
    return;
  }
  if (f->member_index >= f->member_count) {
    complete_frame();
    return;
  }
  e712.phase = PH_MEMBER;
  request_struct(f->u.s.type);
}

bool eip712_stream_begin(const EthereumSignTypedData* msg,
                         bool require_definition) {
  eip712_stream_abort();

  if (msg->address_n_count > 6) {
    fail("EIP-712 path too deep");
    return false;
  }
  /* primary_type is `required` on the wire, so nanopb emits no has_ flag --
   * an absent one cannot decode at all. Empty and over-long still can. */
  if (!eip712_type_identifier_ok(msg->primary_type)) {
    fail("EIP-712 primary type missing or too long");
    return false;
  }
  /* v4 only: never sign a v3 document under v4 rules. */
  if (msg->has_metamask_v4_compat && !msg->metamask_v4_compat) {
    fail("Only MetaMask v4 array hashing is supported");
    return false;
  }
  if (require_definition && strcmp(msg->primary_type, "EIP712Domain") == 0) {
    fail("ERC-7730 cannot describe a domain-only signature");
    return false;
  }

  e712.active = true;
  e712.metamask_v4_compat = true;
  e712.require_definition = require_definition;
  e712.address_n_count = (uint8_t)msg->address_n_count;
  memcpy(e712.address_n, msg->address_n,
         msg->address_n_count * sizeof(uint32_t));
  strlcpy(e712.primary_type, msg->primary_type, EIP712_MAX_STRUCT_NAME);

  /* The domain is hashed first, under the same session, so the message can
   * never be signed against a domain the user did not see. */
  e712.root = 0;
  return begin_root("EIP712Domain");
}

bool eip712_stream_resume_for_field(void) {
  if (next_step.kind == EIP712_REQ_DEFINITION)
    return eip712_stream_definition_accepted();
  if (e712.active || next_step.kind != EIP712_REQ_DONE ||
      !e712.require_definition || !e712.definition_accepted ||
      !e712.have_domain_separator)
    return false;
  e712.active = true;
  e712.root = 1;
  memzero(e712.stack, sizeof(e712.stack));
  memzero(e712.pool, sizeof(e712.pool));
  return begin_root(e712.primary_type);
}

/* Seaport's BulkOrder and LooksRare's BatchOrder sign a Merkle tree of 2^h
 * orders with one signature. The device cannot review 2^h orders, so the
 * shape is refused before any of it is shown. Narrow on purpose: the primary
 * type's name, its `tree` member, the order struct and every dimension 2. */
static bool is_bulk_order_tree(const EthereumTypedDataStructAck* ack) {
  const char* order;
  if (strcmp(e712.primary_type, "BulkOrder") == 0) {
    order = "OrderComponents"; /* Seaport */
  } else if (strcmp(e712.primary_type, "BatchOrder") == 0) {
    order = "Maker"; /* LooksRare v2 */
  } else {
    return false;
  }
  for (size_t m = 0; m < ack->members_count; m++) {
    const Eip712FieldType* ft = &ack->members[m].type;
    if (strcmp(ack->members[m].name, "tree") != 0) continue;
    if (ft->data_type != EthereumTypedDataStructAck_EthereumDataType_STRUCT ||
        !ft->has_struct_name || strcmp(ft->struct_name, order) != 0 ||
        ft->array_levels_count == 0)
      return false;
    for (size_t i = 0; i < ft->array_levels_count; i++) {
      if (ft->array_levels[i] != 2) return false;
    }
    return true;
  }
  return false;
}

bool eip712_stream_on_struct(const EthereumTypedDataStructAck* ack) {
  if (!e712.active || e712.waiting != EIP712_WANT_STRUCT) {
    fail("Unexpected EIP-712 struct");
    return false;
  }
  e712.waiting = EIP712_IDLE;

  if (ack->members_count > EIP712_MAX_SLOTS) {
    fail("EIP-712 struct has too many members for this device");
    return false;
  }

  /* Names are hashed and displayed: ASCII identifiers only (no controls,
   * lookalikes or truncation); no duplicate members. */
  for (size_t i = 0; i < ack->members_count; i++) {
    const char* member_name = ack->members[i].name;
    char type_name[EIP712_MAX_TYPE_NAME];
    if (!eip712_identifier_ok(member_name) ||
        !eip712_type_name(&ack->members[i].type, type_name,
                          sizeof(type_name))) {
      fail("EIP-712 struct member is malformed");
      return false;
    }
    for (size_t j = 0; j < i; j++) {
      if (strcmp(member_name, ack->members[j].name) == 0) {
        fail("EIP-712 struct has duplicate members");
        return false;
      }
    }
  }

  /* A repeated schema supplies display names and value types as well as
   * encodeType bytes. Bind all three uses to the first canonical segment. */
  SHA3_CTX schema_hash;
  uint8_t schema_digest[32];
  keccak_256_Init(&schema_hash);
  const uint8_t requested = e712.requested;
  if (!hash_segment_from_ack(e712.types.names[requested], ack, &schema_hash)) {
    fail("Invalid EIP-712 schema");
    return false;
  }
  /* The spelling alone does not fix a member's kind: a struct may be named
   * "uint256". Bind each data_type too; encodeType bytes are unchanged. */
  for (size_t i = 0; i < ack->members_count; i++) {
    const uint8_t kind = (uint8_t)ack->members[i].type.data_type;
    keccak_Update(&schema_hash, &kind, 1);
  }
  keccak_Final(&schema_hash, schema_digest);
  const uint8_t known = (uint8_t)(1u << requested);
  if (!(e712.schema_known & known)) {
    memcpy(e712.schema_digest[requested], schema_digest, 32);
    e712.schema_known |= known;
  } else if (memcmp(e712.schema_digest[requested], schema_digest, 32) != 0) {
    fail("EIP-712 schema changed during signing");
    return false;
  }

  switch (e712.phase) {
    case PH_DISCOVER: {
      if (e712.root == 1 && e712.depth == 1 && e712.closure_index == 0 &&
          is_bulk_order_tree(ack)) {
        fail("Bulk order: sign listings individually");
        return false;
      }
      /* Grow the closure; the already-present check terminates cycles. */
      for (size_t m = 0; m < ack->members_count; m++) {
        const Eip712FieldType* ft = &ack->members[m].type;
        if (ft->data_type != EthereumTypedDataStructAck_EthereumDataType_STRUCT)
          continue;
        if (!ft->has_struct_name ||
            !closure_add(&e712.closure, &e712.types, ft->struct_name)) {
          fail("EIP-712 type graph too large or malformed");
          return false;
        }
      }
      e712.closure_index++;
      if (e712.closure_index < e712.closure.count) {
        request_struct(e712.closure.index[e712.closure_index]);
        return true;
      }
      /* Sort everything after the primary segment, which leads. */
      sort_closure_tail(&e712.closure, &e712.types, 1);
      e712.closure_index = 0;
      e712.phase = PH_STREAM;
      keccak_256_Init(&e712.hash);
      request_struct(e712.closure.index[0]);
      return true;
    }

    case PH_STREAM: {
      if (!hash_segment_from_ack(e712.types.names[requested], ack,
                                 &e712.hash)) {
        fail("EIP-712 type could not be spelled");
        return false;
      }
      e712.closure_index++;
      if (e712.closure_index < e712.closure.count) {
        request_struct(e712.closure.index[e712.closure_index]);
        return true;
      }
      Eip712Frame* tf = &e712.stack[e712.depth - 1];
      keccak_Final(&e712.hash, tf->u.s.type_hash);
      tf->u.s.have_type_hash = true;
      if (e712.root == 1 && e712.depth == 1) {
        memcpy(e712.domain_facts.primary_type_hash, tf->u.s.type_hash, 32);
        e712.domain_facts.has_primary_type_hash = true;
        if (e712.require_definition && !e712.definition_accepted) {
          memzero(&next_step, sizeof(next_step));
          next_step.kind = EIP712_REQ_DEFINITION;
          e712.waiting = EIP712_IDLE;
          return true;
        }
      }
      e712.phase = PH_MEMBER;
      request_struct(e712.stack[e712.depth - 1].u.s.type);
      return true;
    }

    case PH_MEMBER: {
      Eip712Frame* f = &e712.stack[e712.depth - 1];
      f->member_count = (uint8_t)ack->members_count;
      /* A nested member-less struct has no leaf to show, so its presence, or
       * an array's element count of it, would be signed unseen. An empty
       * root is named on the final screen and flagged there as empty. */
      if (f->member_count == 0 && e712.depth > 1) {
        fail("EIP-712 struct has no members");
        return false;
      }
      if (f->member_index >= f->member_count) {
        complete_frame();
        return true;
      }
      if (f->slot_base + f->member_count > EIP712_MAX_SLOTS) {
        fail("EIP-712 document too wide for this device");
        return false;
      }

      const EthereumTypedDataStructAck_EthereumStructMember* m =
          &ack->members[f->member_index];
      e712.pending_data_type = (uint8_t)m->type.data_type;
      e712.pending_has_size = m->type.has_size;
      e712.pending_size = m->type.size;
      strlcpy(e712.pending_name, m->name, sizeof(e712.pending_name));

      if (m->type.array_levels_count > 0) {
        if (e712.depth >= EIP712_MAX_DEPTH || m->type.array_levels_count > 4) {
          fail("EIP-712 array nests too deeply for this device");
          return false;
        }
        /* Stage the frame without pushing it, so member_path points AT the
         * array while its length is requested. */
        Eip712Frame* arr = &e712.stack[e712.depth];
        memzero(arr, sizeof(*arr));
        arr->is_array = true;
        arr->slot_base = f->slot_base + f->member_count;
        if (!stage_label(arr, m->name)) {
          fail("EIP-712 member path too long for this device");
          return false;
        }
        arr->u.a.elem_data_type = (uint8_t)m->type.data_type;
        arr->u.a.elem_has_size = m->type.has_size;
        arr->u.a.elem_size = m->type.size;
        arr->u.a.elem_type = EIP712_NO_TYPE;
        if (m->type.data_type ==
                EthereumTypedDataStructAck_EthereumDataType_STRUCT &&
            m->type.has_struct_name) {
          arr->u.a.elem_type = names_intern(&e712.types, m->type.struct_name);
          if (arr->u.a.elem_type == EIP712_NO_TYPE) {
            fail("EIP-712 type graph too large or malformed");
            return false;
          }
        }
        arr->u.a.levels_total = (uint8_t)m->type.array_levels_count;
        arr->u.a.level_index = 0;
        memcpy(arr->u.a.array_levels, m->type.array_levels,
               sizeof(arr->u.a.array_levels));
        /* Solidity writes the outermost dimension last: T[2][3] is three
         * arrays of two T values. */
        e712.pending_declared_dim =
            arr->u.a.array_levels[arr->u.a.levels_total - 1u];
        e712.want_array_len = true;
        request_value();
        return true;
      }

      if (m->type.data_type ==
          EthereumTypedDataStructAck_EthereumDataType_STRUCT) {
        if (e712.depth >= EIP712_MAX_DEPTH) {
          fail("EIP-712 document nests too deeply for this device");
          return false;
        }
        if (!m->type.has_struct_name) {
          fail("EIP-712 struct member has no type name");
          return false;
        }
        Eip712Frame* child = &e712.stack[e712.depth];
        memzero(child, sizeof(*child));
        child->u.s.type = names_intern(&e712.types, m->type.struct_name);
        if (child->u.s.type == EIP712_NO_TYPE) {
          fail("EIP-712 type graph too large or malformed");
          return false;
        }
        if (!stage_label(child, m->name)) {
          fail("EIP-712 member path too long for this device");
          return false;
        }
        child->slot_base = f->slot_base + f->member_count;
        e712.depth++;
        begin_type_hash();
        return true;
      }

      request_value();
      return true;
    }
    default:
      fail("EIP-712 internal state");
      return false;
  }
}

/* The pending leaf's type, as the walk recorded it. */
static void pending_field(Eip712FieldType* field) {
  memzero(field, sizeof(*field));
  field->data_type = (Eip712DataType)e712.pending_data_type;
  field->has_size = e712.pending_has_size;
  field->size = e712.pending_size;
}

/* The leaf's encodeData word: into its slot, or the streamed array. */
static void finish_leaf(const uint8_t word[32]) {
  Eip712Frame* f = &e712.stack[e712.depth - 1];
  if (array_streams(f)) {
    array_sponge_absorb(word);
  } else if (array_hashes(f)) {
    keccak_Update(&e712.hash, word, 32);
  } else {
    memcpy(e712.pool[f->slot_base + f->member_index], word, 32);
  }
  f->member_index++;
  advance_after_slot();
}

/* ── Chunked values ──────────────────────────────────────────────────
 * A dynamic `bytes` or `string` leaf over EIP712_MAX_LEAF arrives in chunks
 * of that size. Each is hashed as it arrives (the leaf is keccak(value), so
 * streaming is exact) and shown in numbered parts counted over the WHOLE
 * value. Hex parts follow from the length alone. A string's do not (one byte
 * draws as one to four characters), so a string is read twice: the first
 * pass checks its UTF-8 and counts its parts before anything is shown, the
 * second shows them, and the two passes must hash alike. */

/* " (99999/99999)": the widest counter of a chunked value. */
#define EIP712_CHUNK_COUNTER 14
#define EIP712_MAX_PARTS 99999u

/* The pending leaf's labels, and the characters left for each part. */
static bool chunk_labels(const Eip712FieldType* field, char* type_name,
                         char* path, size_t* budget) {
  if (!eip712_type_name(field, type_name, EIP712_MAX_TYPE_NAME) ||
      !leaf_path(path, EIP712_MAX_PATH))
    return false;
  const size_t fixed =
      strlen(path) + 1 + strlen(type_name) + 2 + EIP712_CHUNK_COUNTER;
  if (fixed + 8 > EIP712_BODY_MAX) return false;
  *budget = EIP712_BODY_MAX - fixed;
  return true;
}

/* How many parts render_part() splits `len` bytes of hex into. */
static uint32_t hex_parts(uint32_t len, bool first, size_t budget) {
  uint32_t parts = 0;
  if (first) {
    const size_t lead = (budget - 2) / 2;
    parts = 1;
    len = len > lead ? len - (uint32_t)lead : 0;
  }
  const size_t per = budget / 2;
  return parts + (uint32_t)((len + per - 1) / per);
}

/* One chunk's parts: counted (string pass one) or shown. */
static Eip712LeafResult chunk_parts(const char* path, const char* type_name,
                                    Eip712Render how, const uint8_t* value,
                                    size_t len, bool first, size_t budget) {
  char part[BODY_CHAR_MAX];
  size_t consumed = 0;
  for (size_t offset = 0; offset < len; offset += consumed) {
    if (!render_part(how, value, len, offset, first, part, budget, &consumed) ||
        consumed == 0)
      return EIP712_LEAF_INVALID;
    if (!e712.chunk.showing) {
      if (++e712.chunk.parts > EIP712_MAX_PARTS) return EIP712_LEAF_INVALID;
      continue;
    }
    if (e712.chunk.shown >= e712.chunk.parts) return EIP712_LEAF_INVALID;
    e712.chunk.shown++;
    if (!confirm(ButtonRequestType_ButtonRequest_Other, leaf_title(),
                 "%s (%u/%u)\n%s: %s", path, (unsigned)e712.chunk.shown,
                 (unsigned)e712.chunk.parts, type_name, part))
      return EIP712_LEAF_CANCELLED;
  }
  return EIP712_LEAF_OK;
}

static void request_chunk(void) {
  request_value();
  next_step.has_value_offset = true;
  next_step.value_offset = e712.chunk.offset;
}

/* Count or show one chunk, absorb it, and ask for the next. */
static bool chunk_absorb(const Eip712FieldType* field, const uint8_t* bytes,
                         uint16_t len) {
  const bool text =
      field->data_type == EthereumTypedDataStructAck_EthereumDataType_STRING;
  char type_name[EIP712_MAX_TYPE_NAME];
  char path[EIP712_MAX_PATH];
  size_t budget;
  if (!chunk_labels(field, type_name, path, &budget)) {
    fail("EIP-712 value cannot be displayed");
    return false;
  }
  if (!e712.chunk.showing && !utf8_feed(&e712.chunk.utf8, bytes, len)) {
    fail("EIP-712 value does not match its declared type");
    return false;
  }
  if (e712.chunk.showing) {
    const bool last = e712.chunk.offset + len == e712.chunk.total;
    if (!multisend_reviewed(bytes, len, last)) return false;
    if (last && !review_approved(safe_delegate_approved(field, bytes, len)
                                     ? EIP712_LEAF_OK
                                     : EIP712_LEAF_CANCELLED))
      return false;
  }
  const Eip712LeafResult parts = chunk_parts(
      path, type_name, text ? EIP712_RENDER_ESCAPED : EIP712_RENDER_HEX, bytes,
      len, e712.chunk.offset == 0, budget);
  if (!e712.chunk.showing && parts != EIP712_LEAF_OK) {
    fail("EIP-712 value cannot be displayed");
    return false;
  }
  if (e712.chunk.showing && !review_approved(parts)) return false;

  keccak_Update(&e712.hash, bytes, len);
  e712.chunk.offset += len;
  if (e712.chunk.offset < e712.chunk.total) {
    request_chunk();
    return true;
  }

  uint8_t word[32];
  keccak_Final(&e712.hash, word);
  if (!e712.chunk.showing) {
    if (e712.chunk.utf8.need != 0) {
      fail("EIP-712 value does not match its declared type");
      return false;
    }
    /* Counted and checked whole: now show it, from the start. */
    memcpy(e712.chunk.counted, word, 32);
    e712.chunk.showing = true;
    e712.chunk.offset = 0;
    keccak_256_Init(&e712.hash);
    request_chunk();
    return true;
  }
  if (text && memcmp(word, e712.chunk.counted, 32) != 0) {
    fail("EIP-712 value changed while it was shown");
    return false;
  }
  if (e712.chunk.shown != e712.chunk.parts) {
    fail("EIP-712 value cannot be displayed");
    return false;
  }
  memzero(&e712.chunk, sizeof(e712.chunk));
  finish_leaf(word);
  return true;
}

/* The first chunk: value_total_length names the whole value's length. */
static bool chunk_begin(const Eip712FieldType* field,
                        const EthereumTypedDataValueAck* ack) {
  const bool text =
      field->data_type == EthereumTypedDataStructAck_EthereumDataType_STRING;
  if (!text &&
      !(field->data_type == EthereumTypedDataStructAck_EthereumDataType_BYTES &&
        !field->has_size)) {
    fail("EIP-712 value cannot be chunked");
    return false;
  }
  /* The domain's facts are read from whole values; none is ever this long. */
  if (e712.root == 0) {
    fail("EIP-712 domain value too long");
    return false;
  }
  if (ack->value_total_length <= EIP712_MAX_LEAF) {
    fail("EIP-712 value chunk has the wrong length");
    return false;
  }
  if (ack->value_total_length > EIP712_MAX_VALUE) {
    fail("EIP-712 value too long for this device");
    return false;
  }
  if (ack->value.size != EIP712_MAX_LEAF) {
    fail("EIP-712 value chunk has the wrong length");
    return false;
  }
  memzero(&e712.chunk, sizeof(e712.chunk));
  e712.chunk.total = ack->value_total_length;
  e712.chunk.showing = !text;
  if (!text) {
    char type_name[EIP712_MAX_TYPE_NAME];
    char path[EIP712_MAX_PATH];
    size_t budget;
    if (!chunk_labels(field, type_name, path, &budget)) {
      fail("EIP-712 value cannot be displayed");
      return false;
    }
    for (uint32_t at = 0; at < e712.chunk.total; at += EIP712_MAX_LEAF) {
      const uint32_t left = e712.chunk.total - at;
      e712.chunk.parts += hex_parts(
          left < EIP712_MAX_LEAF ? left : EIP712_MAX_LEAF, at == 0, budget);
    }
    if (e712.chunk.parts > EIP712_MAX_PARTS) {
      fail("EIP-712 value cannot be displayed");
      return false;
    }
    /* An embedded approve needs only its first 68 bytes: refused or warned
     * about before any screen of the bytes. */
    if (embedded_approve(field, ack->value.bytes, ack->value.size)) {
      if (embedded_approve_is_dirty(ack->value.bytes)) {
        fail("Malformed ERC20 approval");
        return false;
      }
      if (!review_approved(confirm_embedded_unlimited(ack->value.bytes)))
        return false;
    }
  }
  multisend_begin(field, ack->value.bytes, ack->value.size);
  keccak_256_Init(&e712.hash);
  return chunk_absorb(field, ack->value.bytes, ack->value.size);
}

/* A later chunk: exactly the bytes at the offset asked for. */
static bool chunk_next(const EthereumTypedDataValueAck* ack) {
  if (!ack->has_value_offset || ack->value_offset != e712.chunk.offset ||
      ack->has_value_total_length) {
    fail("EIP-712 value chunk out of order");
    return false;
  }
  const uint32_t left = e712.chunk.total - e712.chunk.offset;
  if (ack->value.size != (left < EIP712_MAX_LEAF ? left : EIP712_MAX_LEAF)) {
    fail("EIP-712 value chunk has the wrong length");
    return false;
  }
  Eip712FieldType field;
  pending_field(&field);
  return chunk_absorb(&field, ack->value.bytes, ack->value.size);
}

bool eip712_stream_on_value(const EthereumTypedDataValueAck* ack) {
  if (!e712.active || e712.waiting != EIP712_WANT_VALUE) {
    fail("Unexpected EIP-712 value");
    return false;
  }
  e712.waiting = EIP712_IDLE;

  if (e712.chunk.total != 0) return chunk_next(ack);
  /* Only a request that names an offset may be answered with one. */
  if (ack->has_value_offset) {
    fail("EIP-712 value chunk out of order");
    return false;
  }

  if (e712.want_array_len) {
    /* Big-endian uint16. Anything else is a host not speaking this protocol. */
    if (ack->value.size != 2 || ack->has_value_total_length) {
      fail("EIP-712 array length must be two bytes");
      return false;
    }
    uint16_t len = (uint16_t)((ack->value.bytes[0] << 8) | ack->value.bytes[1]);
    Eip712Frame* arr = &e712.stack[e712.depth];

    /* A fixed dimension is in typeHash; any other count signs another type. */
    if (e712.pending_declared_dim != 0 && len != e712.pending_declared_dim) {
      fail("EIP-712 array length does not match its declared size");
      return false;
    }
    if (e712.array_owner == 0) {
      /* Only arrays nested inside this one keep their elements in slots. */
      memzero(e712.array_sponge, sizeof(e712.array_sponge));
      e712.array_sponge_bytes = 0;
      e712.array_owner = (uint8_t)(e712.depth + 1);
    } else if (e712.hash_owner == 0 && array_of_fixed_leaves(arr)) {
      /* UniswapX V3 curve points: relativeAmounts inside baseOutputs[]. */
      keccak_256_Init(&e712.hash);
      e712.hash_owner = (uint8_t)(e712.depth + 1);
    } else if ((uint32_t)arr->slot_base + len > EIP712_MAX_SLOTS) {
      fail("EIP-712 array is too long for this device");
      return false;
    }
    if (len == 0 && !review_approved(eip712_confirm_empty_array(arr)))
      return false;

    arr->u.a.array_len = len;
    arr->member_index = 0;
    e712.depth++;
    e712.want_array_len = false;

    if (len == 0) {
      /* An empty array still hashes -- keccak of no bytes at all. */
      complete_frame();
      return true;
    }
    drive_array_element();
    return true;
  }

  Eip712FieldType rebuilt;
  pending_field(&rebuilt);
  const Eip712FieldType* field = &rebuilt;
  const uint8_t* bytes = ack->value.bytes;
  uint16_t len = ack->value.size;
  if (ack->has_value_total_length) return chunk_begin(field, ack);

  /* Validate before drawing and before absorbing. */
  if (!eip712_validate_leaf(field, bytes, len)) {
    fail("EIP-712 value does not match its declared type");
    return false;
  }
  if (embedded_approve(field, bytes, len) && embedded_approve_is_dirty(bytes)) {
    fail("Malformed ERC20 approval");
    return false;
  }
  if (e712.root == 0 && e712.depth == 1 &&
      !eip712_domain_facts_observe(&e712.domain_facts, e712.pending_name, field,
                                   bytes, len)) {
    fail("EIP-712 domain binding is invalid");
    return false;
  }

  multisend_begin(field, bytes, len);
  if (!multisend_reviewed(bytes, len, true)) return false;
  if (!review_approved(safe_delegate_approved(field, bytes, len)
                           ? EIP712_LEAF_OK
                           : EIP712_LEAF_CANCELLED))
    return false;

  /* Display and absorb from the SAME buffer: no second read can differ. */
  if (!review_approved(eip712_confirm_leaf(field, bytes, len))) return false;

  const Eip712Frame* f = &e712.stack[e712.depth - 1];
  uint8_t word[32];
  if (!eip712_encode_leaf(field, bytes, len, word)) {
    fail("EIP-712 value could not be encoded");
    return false;
  }
  if (e712.root == 1 && !f->is_array &&
      field->data_type == EthereumTypedDataStructAck_EthereumDataType_ADDRESS &&
      strcmp(e712.pending_name, "to") == 0 &&
      strcmp(e712.types.names[f->u.s.type], "SafeTx") == 0)
    e712.safe_to_slot = (uint8_t)(f->slot_base + f->member_index + 1);
  finish_leaf(word);
  return true;
}

bool eip712_stream_domain_facts(Eip712DomainFacts* facts) {
  /* Unbindable facts bind nothing: every ERC-7730 consumer fails closed. */
  if (!facts || !e712.active || unbindable()) return false;
  memcpy(facts, &e712.domain_facts, sizeof(*facts));
  return true;
}

bool eip712_stream_signer_path(uint32_t address_n[6], size_t* count) {
  /* An empty path is the root key, exactly as signing derives it. */
  if (!address_n || !count || !e712.require_definition ||
      e712.address_n_count > 6)
    return false;
  memcpy(address_n, e712.address_n, e712.address_n_count * sizeof(uint32_t));
  *count = e712.address_n_count;
  return true;
}

bool eip712_stream_definition_accepted(void) {
  if (!e712.active || !e712.require_definition ||
      !e712.domain_facts.has_primary_type_hash || unbindable() ||
      e712.definition_accepted || next_step.kind != EIP712_REQ_DEFINITION)
    return false;
  e712.definition_accepted = true;
  e712.phase = PH_MEMBER;
  request_struct(e712.stack[e712.depth - 1].u.s.type);
  return true;
}
