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
#include "trezor/crypto/address.h"
#include "trezor/crypto/bignum.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/sha3.h"

typedef EthereumTypedDataStructAck_EthereumFieldType Eip712FieldType;
typedef EthereumTypedDataStructAck_EthereumDataType Eip712DataType;

bool eip712_identifier_ok(const char* name) {
  if (!name) return false;
  size_t len = strlen(name);
  if (len == 0 || len + 1 > EIP712_MAX_STRUCT_NAME) return false;
  char first = name[0];
  if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') ||
        first == '_' || first == '$')) {
    return false;
  }
  for (size_t i = 1; i < len; i++) {
    char c = name[i];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || c == '_' || c == '$')) {
      return false;
    }
  }
  return true;
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
      if (!field->has_struct_name || !eip712_identifier_ok(field->struct_name))
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

/* Leaf validation: runs before display AND encoding. */
static bool is_valid_utf8_printable(const uint8_t* s, uint16_t len) {
  uint16_t i = 0;
  while (i < len) {
    uint8_t c = s[i];
    /* Control bytes break display injectivity (two strings, one screen). */
    if (c < 0x20 || c == 0x7F) return false;
    uint8_t extra;
    uint32_t cp;
    if (c < 0x80) {
      i++;
      continue;
    } else if ((c & 0xE0) == 0xC0) {
      extra = 1;
      cp = c & 0x1F;
    } else if ((c & 0xF0) == 0xE0) {
      extra = 2;
      cp = c & 0x0F;
    } else if ((c & 0xF8) == 0xF0) {
      extra = 3;
      cp = c & 0x07;
    } else {
      return false;
    }
    if (i + extra >= len) return false;
    for (uint8_t k = 1; k <= extra; k++) {
      uint8_t cc = s[i + k];
      if ((cc & 0xC0) != 0x80) return false;
      cp = (cp << 6) | (cc & 0x3F);
    }
    /* Overlongs and surrogates also break injectivity. */
    if (extra == 1 && cp < 0x80) return false;
    if (extra == 2 && cp < 0x800) return false;
    if (extra == 3 && cp < 0x10000) return false;
    if (cp > 0x10FFFF) return false;
    if (cp >= 0xD800 && cp <= 0xDFFF) return false;
    i += extra + 1;
  }
  return true;
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
      return is_valid_utf8_printable(value, value_len);
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
  const int hash_index = strcmp(member_name, "name") == 0      ? 0
                         : strcmp(member_name, "version") == 0 ? 1
                         : strcmp(member_name, "salt") == 0    ? 2
                                                               : -1;
  if (hash_index >= 0) {
    const uint8_t bit = 1u << hash_index;
    if ((facts->domain_present & bit) != 0 ||
        (hash_index < 2 &&
         field->data_type !=
             EthereumTypedDataStructAck_EthereumDataType_STRING) ||
        (hash_index == 2 &&
         (field->data_type !=
              EthereumTypedDataStructAck_EthereumDataType_BYTES ||
          !field->has_size || field->size != 32 || value_len != 32)))
      return false;
    keccak_256(value, value_len, facts->domain_hashes[hash_index]);
    facts->domain_present |= bit;
    return true;
  }
  if (strcmp(member_name, "chainId") == 0) {
    if (facts->has_chain_id ||
        field->data_type != EthereumTypedDataStructAck_EthereumDataType_UINT ||
        value_len == 0 || value_len > 32)
      return false;
    size_t offset = 0;
    while (offset < value_len && value[offset] == 0) offset++;
    if (value_len - offset > sizeof(facts->chain_id)) return false;
    uint64_t chain_id = 0;
    for (; offset < value_len; offset++)
      chain_id = (chain_id << 8) | value[offset];
    if (chain_id == 0) return false;
    facts->chain_id = chain_id;
    facts->has_chain_id = true;
    return true;
  }
  if (strcmp(member_name, "verifyingContract") == 0) {
    if (facts->has_verifying_contract ||
        field->data_type !=
            EthereumTypedDataStructAck_EthereumDataType_ADDRESS ||
        value_len != sizeof(facts->verifying_contract))
      return false;
    memcpy(facts->verifying_contract, value, sizeof(facts->verifying_contract));
    facts->has_verifying_contract = true;
  }
  return true;
}

/* encodeType(S) = seg(S) || seg(D1) || ... with D1..Dn every struct S
 * transitively references, SORTED BY NAME (unsorted hashes a type string no
 * verifier reproduces). Segments stream into keccak; only names are held. */

typedef struct {
  char names[EIP712_MAX_STRUCTS][EIP712_MAX_STRUCT_NAME];
  uint8_t count;
} Eip712Closure;

static bool closure_contains(const Eip712Closure* c, const char* name) {
  for (uint8_t i = 0; i < c->count; i++) {
    if (strcmp(c->names[i], name) == 0) return true;
  }
  return false;
}

static bool closure_add(Eip712Closure* c, const char* name) {
  size_t len = strlen(name);
  if (!eip712_identifier_ok(name)) return false;
  if (closure_contains(c, name)) return true;
  if (c->count >= EIP712_MAX_STRUCTS) return false;
  memcpy(c->names[c->count], name, len + 1);
  c->count++;
  return true;
}

/* Insertion sort names[start..count); the one ordering rule for both paths. */
static void sort_closure_tail(Eip712Closure* c, uint8_t start) {
  for (uint8_t i = start + 1; i < c->count; i++) {
    char key[EIP712_MAX_STRUCT_NAME];
    memcpy(key, c->names[i], EIP712_MAX_STRUCT_NAME);
    int16_t j = (int16_t)i - 1;
    while (j >= (int16_t)start && strcmp(c->names[j], key) > 0) {
      memcpy(c->names[j + 1], c->names[j], EIP712_MAX_STRUCT_NAME);
      j--;
    }
    memcpy(c->names[j + 1], key, EIP712_MAX_STRUCT_NAME);
  }
}

/* Every struct `name` transitively references, excluding itself. Iterative
 * over the growing closure, so a cyclical schema terminates. */
static bool closure_collect(const char* name, Eip712StructLookup lookup,
                            void* ctx, Eip712Closure* out) {
  Eip712Closure seen;
  memset(&seen, 0, sizeof(seen));
  if (!closure_add(&seen, name)) return false;

  for (uint8_t i = 0; i < seen.count; i++) {
    const EthereumTypedDataStructAck* def = lookup(seen.names[i], ctx);
    if (!def) return false;
    for (size_t m = 0; m < def->members_count; m++) {
      const Eip712FieldType* ft = &def->members[m].type;
      if (ft->data_type != EthereumTypedDataStructAck_EthereumDataType_STRUCT)
        continue;
      if (!ft->has_struct_name) return false;
      if (!closure_add(&seen, ft->struct_name)) return false;
    }
  }

  /* The primary type leads and is not sorted with the rest. */
  memset(out, 0, sizeof(*out));
  for (uint8_t i = 1; i < seen.count; i++) {
    if (!closure_add(out, seen.names[i])) return false;
  }

  sort_closure_tail(out, 0);
  return true;
}

/* Stream "Name(type1 name1,type2 name2,...)" into the hash. */
static bool hash_segment_from_ack(const char* name,
                                  const EthereumTypedDataStructAck* def,
                                  SHA3_CTX* hash) {
  if (!def || !eip712_identifier_ok(name)) return false;

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
  if (!name || !lookup || !out) return false;
  if (strlen(name) == 0 || strlen(name) + 1 > EIP712_MAX_STRUCT_NAME)
    return false;

  Eip712Closure deps;
  if (!closure_collect(name, lookup, ctx, &deps)) return false;

  SHA3_CTX hash;
  keccak_256_Init(&hash);
  if (!hash_type_segment(name, lookup, ctx, &hash)) return false;
  for (uint8_t i = 0; i < deps.count; i++) {
    if (!hash_type_segment(deps.names[i], lookup, ctx, &hash)) return false;
  }
  keccak_Final(&hash, out);
  return true;
}

/* Session state, all .bss: counts against the stack gap (_stack - _ebss must
 * stay >= 16,384 B). One SHA3_CTX: encodeType streams and frame folds never
 * overlap. */
typedef struct {
  char name[EIP712_MAX_STRUCT_NAME];
  /* Parent member name for review paths; empty for array elements. */
  char label[EIP712_MAX_STRUCT_NAME];
  uint8_t slot_base;    /* first slot in the pool belonging to this frame */
  uint8_t member_count; /* members declared by the struct */
  uint8_t member_index; /* next member to absorb */
  bool is_array;
  uint8_t elem_data_type;
  bool elem_has_size;
  uint32_t elem_size;
  char elem_struct[EIP712_MAX_STRUCT_NAME];
  uint8_t levels_total;
  uint8_t level_index;
  uint32_t array_levels[4];
  bool have_type_hash;
  uint8_t type_hash[32]; /* lives exactly as long as the frame that needs it */
  uint16_t array_len;
} Eip712Frame;

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

  uint8_t pool[EIP712_MAX_SLOTS][32];
  uint8_t slots_used;

  SHA3_CTX hash;

  /* The one outstanding value request, stored compactly (not the wire
   * FieldType) to save .bss. */
  uint8_t pending_data_type;
  bool pending_has_size;
  uint32_t pending_size;
  char pending_name[EIP712_MAX_STRUCT_NAME];

  /* An array's LENGTH is in flight; its frame is not pushed yet. */
  bool want_array_len;
  uint32_t pending_declared_dim;

  uint8_t phase;
  Eip712Closure closure;
  uint8_t closure_index;
  struct {
    char name[EIP712_MAX_STRUCT_NAME];
    uint8_t digest[32];
  } schemas[EIP712_MAX_STRUCTS + 1];
  uint8_t schema_count;
} e712;

bool eip712_stream_domain_matches(uint8_t field, uint8_t literal_kind,
                                  const uint8_t* value, size_t length,
                                  bool require_absent) {
  if (!e712.have_domain_separator || field < 1 || field > 5 ||
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

/* Render as much of value[offset..len) as fits `budget` characters. */
static bool render_part(Eip712Render how, const uint8_t* value, size_t len,
                        size_t offset, char* out, size_t budget,
                        size_t* consumed) {
  const size_t left = len - offset;
  *consumed = 0;
  out[0] = '\0';
  if (how == EIP712_RENDER_HEX) {
    static const char digits[] = "0123456789abcdef";
    const size_t lead = offset == 0 ? 2 : 0;
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
  /* One byte escapes to <= 4 chars, so budget 4 always progresses. Finds a
   * fitting prefix, not necessarily the longest (not monotonic). */
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

  if (!render_part(how, value, len, 0, part, EIP712_BODY_MAX - fixed,
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
    if (!render_part(how, value, len, offset, part, budget, &consumed) ||
        consumed == 0 || ++parts > 999)
      return EIP712_LEAF_INVALID;
  }
  size_t offset = 0;
  for (size_t i = 1; i <= parts; i++, offset += consumed) {
    if (!render_part(how, value, len, offset, part, budget, &consumed))
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
    const char* label = leaf ? e712.pending_name : e712.stack[i].label;
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

static Eip712LeafResult eip712_confirm_leaf(const Eip712FieldType* field,
                                            const uint8_t* value,
                                            uint16_t len) {
  char type_name[EIP712_MAX_TYPE_NAME];
  char path[160];
  char text[82]; /* "-" + 78 digits, or a checksummed address */
  if (!eip712_type_name(field, type_name, sizeof(type_name)) ||
      !leaf_path(path, sizeof(path)))
    return EIP712_LEAF_INVALID;
  const char* title = e712.root == 0 ? "EIP-712 Domain" : e712.primary_type;

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
      return confirm_parts(title, path, type_name, EIP712_RENDER_HEX, value,
                           len);
    default:
      return EIP712_LEAF_INVALID;
  }
  return confirm_parts(title, path, type_name, EIP712_RENDER_TEXT,
                       (const uint8_t*)text, strlen(text));
}

/* Unlimited permits (EIP-2612, DAI, Permit2) are refused, as in approve(). */
static bool is_unlimited_permit(const Eip712FieldType* field,
                                const uint8_t* value, uint16_t len) {
  if (e712.root != 1) return false;
  const Eip712Frame* f = &e712.stack[e712.depth - 1];
  if (f->is_array) return false;
  const char* member = e712.pending_name;
  if (field->data_type == EthereumTypedDataStructAck_EthereumDataType_BOOL)
    return strcmp(f->name, "Permit") == 0 && strcmp(member, "allowed") == 0 &&
           value[0] == 1;
  if (field->data_type != EthereumTypedDataStructAck_EthereumDataType_UINT ||
      !((strcmp(f->name, "Permit") == 0 && strcmp(member, "value") == 0) ||
        ((strcmp(f->name, "PermitDetails") == 0 ||
          strcmp(f->name, "TokenPermissions") == 0) &&
         strcmp(member, "amount") == 0)))
    return false;
  for (uint16_t i = 0; i < len; i++)
    if (value[i] != 0xff) return false;
  return len > 0;
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

static void request_struct(const char* name) {
  memzero(&next_step, sizeof(next_step));
  next_step.kind = EIP712_REQ_STRUCT;
  strlcpy(next_step.struct_name, name, sizeof(next_step.struct_name));
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

/* typeHash for the top frame's struct; recomputed per use to save .bss. */
static void begin_type_hash(void) {
  const Eip712Frame* f = &e712.stack[e712.depth - 1];
  memzero(&e712.closure, sizeof(e712.closure));
  if (!closure_add(&e712.closure, f->name)) {
    fail("EIP-712 struct name too long");
    return;
  }
  e712.closure_index = 0;
  e712.phase = PH_DISCOVER;
  request_struct(f->name);
}

/* struct: keccak(typeHash || enc(m1..mn)); array: keccak(enc(e1..en)). */
static bool fold_frame(uint8_t out[32]) {
  const Eip712Frame* f = &e712.stack[e712.depth - 1];
  keccak_256_Init(&e712.hash);
  if (!f->is_array) {
    if (!f->have_type_hash) return false;
    keccak_Update(&e712.hash, f->type_hash, 32);
  }
  for (uint8_t i = 0; i < f->member_index; i++) {
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
  if (!fold_frame(digest)) {
    fail("EIP-712 internal hash state lost");
    return;
  }

  if (e712.depth > 0) {
    Eip712Frame* parent = &e712.stack[e712.depth - 1];
    memcpy(e712.pool[parent->slot_base + parent->member_index], digest, 32);
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
    e712.depth = 1;
    e712.slots_used = 0;
    memzero(&e712.stack[0], sizeof(e712.stack[0]));
    strlcpy(e712.stack[0].name, e712.primary_type, EIP712_MAX_STRUCT_NAME);
    begin_type_hash();
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

  if (arr->level_index + 1 < arr->levels_total) {
    if (e712.depth >= EIP712_MAX_DEPTH) {
      fail("EIP-712 array nests too deeply for this device");
      return;
    }
    Eip712Frame* inner = &e712.stack[e712.depth];
    memzero(inner, sizeof(*inner));
    inner->is_array = true;
    inner->slot_base = arr->slot_base + arr->array_len;
    inner->elem_data_type = arr->elem_data_type;
    inner->elem_has_size = arr->elem_has_size;
    inner->elem_size = arr->elem_size;
    strlcpy(inner->elem_struct, arr->elem_struct, EIP712_MAX_STRUCT_NAME);
    inner->levels_total = arr->levels_total;
    inner->level_index = arr->level_index + 1;
    memcpy(inner->array_levels, arr->array_levels, sizeof(inner->array_levels));
    e712.pending_declared_dim =
        inner->array_levels[inner->levels_total - 1u - inner->level_index];
    e712.want_array_len = true;
    request_value();
    return;
  }

  if (arr->elem_data_type ==
      EthereumTypedDataStructAck_EthereumDataType_STRUCT) {
    if (e712.depth >= EIP712_MAX_DEPTH) {
      fail("EIP-712 document nests too deeply for this device");
      return;
    }
    if (arr->elem_struct[0] == 0) {
      fail("EIP-712 array of structs has no type name");
      return;
    }
    Eip712Frame* child = &e712.stack[e712.depth];
    memzero(child, sizeof(*child));
    strlcpy(child->name, arr->elem_struct, EIP712_MAX_STRUCT_NAME);
    child->slot_base = arr->slot_base + arr->array_len;
    e712.depth++;
    begin_type_hash();
    return;
  }

  e712.pending_data_type = arr->elem_data_type;
  e712.pending_has_size = arr->elem_has_size;
  e712.pending_size = arr->elem_size;
  strlcpy(e712.pending_name, "item", sizeof(e712.pending_name));
  request_value();
}

/* A slot was just filled. Either the frame is done, or fetch the next member.
 */
static void advance_after_slot(void) {
  const Eip712Frame* f = &e712.stack[e712.depth - 1];
  if (f->is_array) {
    if (f->member_index >= f->array_len) {
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
  request_struct(f->name);
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
  if (!eip712_identifier_ok(msg->primary_type)) {
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
  e712.depth = 1;
  strlcpy(e712.stack[0].name, "EIP712Domain", EIP712_MAX_STRUCT_NAME);
  begin_type_hash();
  return true;
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
  e712.depth = 1;
  e712.slots_used = 0;
  memzero(e712.stack, sizeof(e712.stack));
  memzero(e712.pool, sizeof(e712.pool));
  strlcpy(e712.stack[0].name, e712.primary_type, EIP712_MAX_STRUCT_NAME);
  begin_type_hash();
  return true;
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
  if (!hash_segment_from_ack(next_step.struct_name, ack, &schema_hash)) {
    fail("Invalid EIP-712 schema");
    return false;
  }
  keccak_Final(&schema_hash, schema_digest);
  uint8_t schema_index = 0;
  while (schema_index < e712.schema_count &&
         strcmp(e712.schemas[schema_index].name, next_step.struct_name) != 0)
    schema_index++;
  if (schema_index == e712.schema_count) {
    if (schema_index >= EIP712_MAX_STRUCTS + 1) {
      fail("Too many EIP-712 schemas");
      return false;
    }
    strlcpy(e712.schemas[schema_index].name, next_step.struct_name,
            sizeof(e712.schemas[schema_index].name));
    memcpy(e712.schemas[schema_index].digest, schema_digest, 32);
    e712.schema_count++;
  } else if (memcmp(e712.schemas[schema_index].digest, schema_digest, 32) !=
             0) {
    fail("EIP-712 schema changed during signing");
    return false;
  }

  switch (e712.phase) {
    case PH_DISCOVER: {
      /* Grow the closure; the already-present check terminates cycles. */
      for (size_t m = 0; m < ack->members_count; m++) {
        const Eip712FieldType* ft = &ack->members[m].type;
        if (ft->data_type != EthereumTypedDataStructAck_EthereumDataType_STRUCT)
          continue;
        if (!ft->has_struct_name ||
            !closure_add(&e712.closure, ft->struct_name)) {
          fail("EIP-712 type graph too large or malformed");
          return false;
        }
      }
      e712.closure_index++;
      if (e712.closure_index < e712.closure.count) {
        request_struct(e712.closure.names[e712.closure_index]);
        return true;
      }
      /* Sort everything after the primary segment, which leads. */
      sort_closure_tail(&e712.closure, 1);
      e712.closure_index = 0;
      e712.phase = PH_STREAM;
      keccak_256_Init(&e712.hash);
      request_struct(e712.closure.names[0]);
      return true;
    }

    case PH_STREAM: {
      if (!hash_segment_from_ack(e712.closure.names[e712.closure_index], ack,
                                 &e712.hash)) {
        fail("EIP-712 type could not be spelled");
        return false;
      }
      e712.closure_index++;
      if (e712.closure_index < e712.closure.count) {
        request_struct(e712.closure.names[e712.closure_index]);
        return true;
      }
      Eip712Frame* tf = &e712.stack[e712.depth - 1];
      keccak_Final(&e712.hash, tf->type_hash);
      tf->have_type_hash = true;
      if (e712.root == 1 && e712.depth == 1) {
        memcpy(e712.domain_facts.primary_type_hash, tf->type_hash, 32);
        e712.domain_facts.has_primary_type_hash = true;
        if (e712.require_definition && !e712.definition_accepted) {
          memzero(&next_step, sizeof(next_step));
          next_step.kind = EIP712_REQ_DEFINITION;
          e712.waiting = EIP712_IDLE;
          return true;
        }
      }
      e712.phase = PH_MEMBER;
      request_struct(e712.stack[e712.depth - 1].name);
      return true;
    }

    case PH_MEMBER: {
      Eip712Frame* f = &e712.stack[e712.depth - 1];
      f->member_count = (uint8_t)ack->members_count;
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
        strlcpy(arr->label, m->name, sizeof(arr->label));
        arr->elem_data_type = (uint8_t)m->type.data_type;
        arr->elem_has_size = m->type.has_size;
        arr->elem_size = m->type.size;
        if (m->type.has_struct_name) {
          strlcpy(arr->elem_struct, m->type.struct_name,
                  EIP712_MAX_STRUCT_NAME);
        }
        arr->levels_total = (uint8_t)m->type.array_levels_count;
        arr->level_index = 0;
        memcpy(arr->array_levels, m->type.array_levels,
               sizeof(arr->array_levels));
        /* Solidity writes the outermost dimension last: T[2][3] is three
         * arrays of two T values. */
        e712.pending_declared_dim = arr->array_levels[arr->levels_total - 1u];
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
        strlcpy(child->name, m->type.struct_name, EIP712_MAX_STRUCT_NAME);
        strlcpy(child->label, m->name, sizeof(child->label));
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

bool eip712_stream_on_value(const EthereumTypedDataValueAck* ack) {
  if (!e712.active || e712.waiting != EIP712_WANT_VALUE) {
    fail("Unexpected EIP-712 value");
    return false;
  }
  e712.waiting = EIP712_IDLE;

  if (e712.want_array_len) {
    /* Big-endian uint16. Anything else is a host not speaking this protocol. */
    if (ack->value.size != 2) {
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
    if ((uint32_t)arr->slot_base + len > EIP712_MAX_SLOTS) {
      fail("EIP-712 array is too long for this device");
      return false;
    }

    arr->array_len = len;
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
  memzero(&rebuilt, sizeof(rebuilt));
  rebuilt.data_type = (Eip712DataType)e712.pending_data_type;
  rebuilt.has_size = e712.pending_has_size;
  rebuilt.size = e712.pending_size;
  const Eip712FieldType* field = &rebuilt;
  const uint8_t* bytes = ack->value.bytes;
  uint16_t len = ack->value.size;

  /* Validate before drawing and before absorbing. */
  if (!eip712_validate_leaf(field, bytes, len)) {
    fail("EIP-712 value does not match its declared type");
    return false;
  }
  if (e712.root == 0 && e712.depth == 1 &&
      !eip712_domain_facts_observe(&e712.domain_facts, e712.pending_name, field,
                                   bytes, len)) {
    fail("EIP-712 domain binding is invalid");
    return false;
  }

  if (is_unlimited_permit(field, bytes, len)) {
    fail("Unlimited ERC20 approval is disabled");
    return false;
  }

  /* Display and absorb from the SAME buffer: no second read can differ. */
  const Eip712LeafResult shown = eip712_confirm_leaf(field, bytes, len);
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

  Eip712Frame* f = &e712.stack[e712.depth - 1];
  if (!eip712_encode_leaf(field, bytes, len,
                          e712.pool[f->slot_base + f->member_index])) {
    fail("EIP-712 value could not be encoded");
    return false;
  }
  f->member_index++;
  advance_after_slot();
  return true;
}

bool eip712_stream_domain_facts(Eip712DomainFacts* facts) {
  if (!facts || !e712.active) return false;
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
      !e712.domain_facts.has_primary_type_hash || e712.definition_accepted ||
      next_step.kind != EIP712_REQ_DEFINITION)
    return false;
  e712.definition_accepted = true;
  e712.phase = PH_MEMBER;
  request_struct(e712.stack[e712.depth - 1].name);
  return true;
}
