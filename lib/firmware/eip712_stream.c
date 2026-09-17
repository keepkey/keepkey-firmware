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
#include "memzero.h"
#include "sha3.h"

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

/* ── encodeType spelling ─────────────────────────────────────────────
 *
 * The type string is hashed into typeHash, so getting a character wrong here
 * is not a display bug -- it silently produces a signature over a different
 * document. Spellings are canonical: "uint256", never "uint0256"; "bytes"
 * for the dynamic form, "bytes32" for the fixed one.
 */
bool eip712_type_name(const Eip712FieldType* field, char* out, size_t out_len) {
  if (!field || !out || out_len == 0) return false;

  const char* base;
  char scratch[EIP712_MAX_TYPE_NAME];

  switch (field->data_type) {
    case EthereumTypedDataStructAck_EthereumDataType_UINT:
    case EthereumTypedDataStructAck_EthereumDataType_INT: {
      /* size is carried in BYTES on the wire and spelled in BITS. Anything
       * outside 1..32 bytes has no canonical spelling, so refuse rather than
       * invent one. */
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
      /* ARRAY is reserved on this wire: dimensions live in array_levels, and a
       * field whose data_type IS an array means the host is speaking a
       * protocol we did not agree to. */
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

/* ── encodeData ──────────────────────────────────────────────────────
 *
 * Every member encodes to exactly 32 bytes. Atomics pad, dynamics hash.
 * Structs and arrays never reach here: the walker folds them first and hands
 * the parent their 32-byte digest.
 */
static void write_rightpad32(const uint8_t* value, uint16_t value_len,
                             uint8_t out[32]) {
  memset(out, 0, 32);
  memcpy(out, value, value_len);
}

static void write_leftpad32(const uint8_t* value, uint16_t value_len,
                            bool is_signed, uint8_t out[32]) {
  /* Sign-extend a negative intN to 256 bits. An unsigned value, and a
   * zero-length one, extend with zeroes. */
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
    /* Only the dynamic forms may exceed a word; everything else would be
     * silently truncated by the padders. */
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

/* ── leaf validation ─────────────────────────────────────────────────
 *
 * Runs before encoding AND before display, so nothing unvalidated ever
 * reaches the screen or the hash.
 */
static bool is_valid_utf8_printable(const uint8_t* s, uint16_t len) {
  uint16_t i = 0;
  while (i < len) {
    uint8_t c = s[i];
    /* Control bytes are rejected outright. The renderer's injectivity -- that
     * two different strings cannot draw the same screen -- is what the user's
     * consent rests on, and a bare newline or NUL breaks it. */
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
    /* Overlong encodings and surrogates are two spellings of one character,
     * which would break injectivity the same way a control byte does. */
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
      /* bytesN is exactly N, N in [1,32] (bytes0 doesn't exist; >32 doesn't
       * fit a word) -- same bound UINT/INT already enforce below. Without
       * it, an out-of-spec size only failed later inside eip712_type_name(),
       * whose failure gets reported to the host as a user Cancel instead of
       * a validation error. Dynamic bytes (no declared size) is any length
       * we can hold. */
      if (field->has_size)
        return field->size >= 1 && field->size <= 32 &&
               value_len == field->size;
      return value_len <= EIP712_MAX_LEAF;
    case EthereumTypedDataStructAck_EthereumDataType_UINT:
    case EthereumTypedDataStructAck_EthereumDataType_INT:
      /* The host sends the declared width, big endian, no padding games. A
       * short value would left-pad into a different number than the host
       * meant, and a long one would not fit the word. */
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

/* ── encodeType ──────────────────────────────────────────────────────
 *
 *   encodeType(S) = seg(S) || seg(D1) || seg(D2) || ...
 *
 * where D1..Dn are every struct S transitively references, SORTED BY NAME,
 * and seg(T) = "T(type1 name1,type2 name2,...)".
 *
 * The sort is what eip712.c never did. It appended referenced definitions in
 * discovery order -- there is no sort call anywhere in that file -- so a
 * document naming two structs out of alphabetical order hashed a type string
 * no compliant verifier reproduces. The device would have been internally
 * consistent and still signing something nobody else agrees the document says.
 *
 * Nothing is stored: each segment is streamed into a keccak context as it is
 * fetched, so only the closure's NAMES are held.
 */

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

/* Insertion sort names[start..count) by name. n <= EIP712_MAX_STRUCTS, so this
 * is cheaper and far easier to audit than pulling in qsort -- and one copy of
 * the ordering rule means the walk and the offline closure cannot disagree
 * about it. */
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

/* Collect every struct `name` transitively references, excluding itself.
 * Iterative: the worklist is the closure itself, walked as it grows, so a
 * cyclical schema terminates on the already-present check rather than
 * recursing. EIP-712 leaves cyclical data undefined; we simply do not loop. */
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
      /* `seen` grows while we iterate it, which is the traversal. */
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

/* ── Session state ───────────────────────────────────────────────────
 *
 * Every byte here is .bss, and .bss is the only thing that counts against the
 * linker gap -- that gap IS the stack, so transients on it are free.
 *
 * Measured budget: _stack - _ebss is 17,716 B against a 16,384 B floor, so
 * there are 1,332 B to spend. The sizes in eip712_stream.h are chosen to fit
 * with margin, not chosen first and hoped for.
 *
 * The single SHA3_CTX is shared. Only one hash is ever in progress: either an
 * encodeType stream (which spans round trips, so it must live here) or a frame
 * fold (which completes inside one handler and could have been a local). One
 * context serves both because they never overlap.
 */
typedef struct {
  char name[EIP712_MAX_STRUCT_NAME];
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
  bool have_expected_hashes;
  uint8_t expected_domain_separator[32];
  uint8_t expected_message_hash[32];

  /* Root 0 is the domain, root 1 the message; the domain separator is kept
   * while the message is walked. */
  uint8_t root;
  uint8_t domain_separator[32];
  bool have_domain_separator;

  Eip712Frame stack[EIP712_MAX_DEPTH];
  uint8_t depth;

  uint8_t pool[EIP712_MAX_SLOTS][32];
  uint8_t slots_used;

  SHA3_CTX hash;

  /* Only one value request is ever outstanding, so one pending field serves
   * the whole walk rather than one per frame.
   *
   * Stored COMPACTLY rather than as the wire type: a wire FieldType carries
   * struct_name[80] and array_levels[4], and by the time a value is in flight
   * the struct name has already been copied into the child frame and arrays
   * are refused. Keeping the wire type here cost ~100 bytes of .bss that the
   * linker gate does not have to spare. */
  uint8_t pending_data_type;
  bool pending_has_size;
  uint32_t pending_size;
  char pending_name[EIP712_MAX_STRUCT_NAME];

  /* typeHash sub-machine */
  /* True while an array's LENGTH is the value in flight. The frame is not
   * pushed until the length arrives, so the member_path the device sees still
   * points AT the array rather than into it. */
  bool want_array_len;
  uint32_t pending_declared_dim;

  uint8_t phase;
  Eip712Closure closure;
  uint8_t closure_index;
} e712;

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

/* ── Display ─────────────────────────────────────────────────────────
 *
 * One screen per leaf, drawn from the SAME bytes that are about to be
 * absorbed. The field NAME comes from the struct definition, which is the same
 * text hashed into encodeType -- so the label and the commitment cannot
 * disagree either.
 *
 * Values render as hex with an 0x prefix, except strings, which render as
 * themselves, and bool. Hex is unambiguous and needs no bignum; it is also
 * plainly worse to read than a decimal amount, and that is a known v1
 * limitation rather than a considered end state.
 */
static bool eip712_confirm_leaf(const char* name, const Eip712FieldType* field,
                                const uint8_t* value, uint16_t len) {
  char type_name[EIP712_MAX_TYPE_NAME];
  if (!eip712_type_name(field, type_name, sizeof(type_name))) return false;

  if (field->data_type == EthereumTypedDataStructAck_EthereumDataType_STRING) {
    /* Already validated as printable UTF-8, so it can be shown as text. */
    char text[EIP712_MAX_LEAF + 1];
    if (len > EIP712_MAX_LEAF) return false;
    memcpy(text, value, len);
    text[len] = '\0';
    return confirm(ButtonRequestType_ButtonRequest_Other, name, "%s", text);
  }

  if (field->data_type == EthereumTypedDataStructAck_EthereumDataType_BOOL) {
    return confirm(ButtonRequestType_ButtonRequest_Other, name, "%s",
                   value[0] ? "true" : "false");
  }

  /* Everything else as 0x hex. confirm_helper paginates, so a long dynamic
   * bytes value is disclosed across screens rather than truncated -- the
   * exact-byte disclosure rule 7.14.2 established. */
  /* Sized for a WHOLE leaf, so nothing signed is ever cut off the screen.
   * confirm_helper paginates a long body across screens, which is the
   * exact-byte disclosure rule 7.14.2 established -- a cap here would either
   * truncate a signed value or refuse a valid one. This is ~2 KB of stack
   * inside a 16 KB stack, and stack is not what the linker gate measures. */
  char hex[2 + 2 * EIP712_MAX_LEAF + 1];
  if (len > EIP712_MAX_LEAF) return false;
  hex[0] = '0';
  hex[1] = 'x';
  for (uint16_t i = 0; i < len; i++) {
    static const char d[] = "0123456789abcdef";
    hex[2 + 2 * i] = d[value[i] >> 4];
    hex[3 + 2 * i] = d[value[i] & 0x0F];
  }
  hex[2 + 2 * len] = '\0';
  return confirm(ButtonRequestType_ButtonRequest_Other, name, "%s: %s",
                 type_name, hex);
}

/* ── The walk ────────────────────────────────────────────────────────
 *
 * Every function below either emits exactly one request and returns, or
 * finishes the signature. Nothing blocks: KeepKey has no full-message
 * request/response primitive, so the machine is resumed by the next Ack.
 */

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

/* The path is the cursor, and it is rebuilt from the frame stack rather than
 * maintained alongside it -- one source of truth, so they cannot drift. */
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

/* Start computing typeHash for the top frame's struct. A struct that appears
 * twice is hashed twice -- round trips are cheap here and .bss is not. */
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

/* Fold a completed container into 32 bytes and hand it to its parent.
 *
 *   struct: keccak(typeHash || enc(m1) || ... || enc(mn))
 *   array:  keccak(enc(e1) || ... || enc(en))   -- no typeHash, per EIP-712
 */
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

  if (e712.root == 0) {
    /* The domain is hashed. Now the message, under the same session. */
    memcpy(e712.domain_separator, digest, 32);
    e712.have_domain_separator = true;
    e712.root = 1;
    e712.depth = 1;
    e712.slots_used = 0;
    memzero(&e712.stack[0], sizeof(e712.stack[0]));
    strlcpy(e712.stack[0].name, e712.primary_type, EIP712_MAX_STRUCT_NAME);
    begin_type_hash();
    return;
  }

  /* Both halves are in hand. The FSM derives the key and signs: the response
   * buffer and the node live there, and keeping key material out of this
   * translation unit keeps it unit-testable. */
  if (e712.have_expected_hashes) {
    if (memcmp(e712.expected_domain_separator, e712.domain_separator, 32) !=
            0 ||
        memcmp(e712.expected_message_hash, digest, 32) != 0) {
      memzero(digest, sizeof(digest));
      fail("EIP-712 replay changed the signed document");
      return;
    }
  } else {
    memcpy(e712.expected_domain_separator, e712.domain_separator, 32);
    memcpy(e712.expected_message_hash, digest, 32);
    e712.have_expected_hashes = true;
  }
  memzero(&next_step, sizeof(next_step));
  next_step.kind = EIP712_REQ_DONE;
  memcpy(next_step.domain_separator, e712.domain_separator, 32);
  memcpy(next_step.message_hash, digest, 32);
  memcpy(next_step.address_n, e712.address_n,
         e712.address_n_count * sizeof(uint32_t));
  next_step.address_n_count = e712.address_n_count;
  e712.waiting = EIP712_IDLE;
}

/* Point the machine at element member_index of the array frame on top.
 *
 * An element is one of three things, and which one is fixed by the TYPE rather
 * than by anything the host sends alongside the value: another array while
 * dimensions remain, a struct if the leaf type is one, otherwise a leaf. */
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
    e712.pending_declared_dim = 0;
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
  /* MetaMask v3 hashes arrays of structs differently from v4. We implement v4
   * only, and refusing v3 is better than signing it under v4 rules. */
  if (msg->has_metamask_v4_compat && !msg->metamask_v4_compat) {
    fail("Only MetaMask v4 array hashing is supported");
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

bool eip712_stream_replay(void) {
  if (!e712.active || !e712.definition_accepted ||
      !e712.have_expected_hashes || next_step.kind != EIP712_REQ_DONE)
    return false;
  e712.root = 0;
  e712.have_domain_separator = false;
  e712.depth = 1;
  e712.slots_used = 0;
  e712.want_array_len = false;
  e712.pending_declared_dim = 0;
  memzero(&e712.domain_facts, sizeof(e712.domain_facts));
  memzero(e712.stack, sizeof(e712.stack));
  memzero(e712.pool, sizeof(e712.pool));
  strlcpy(e712.stack[0].name, "EIP712Domain", EIP712_MAX_STRUCT_NAME);
  begin_type_hash();
  return next_step.kind == EIP712_REQ_STRUCT;
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

  /* Names are both encodeType bytes and screen titles. Restrict them to the
   * canonical ASCII identifier subset that fits pending_name exactly; a host
   * cannot smuggle controls, Unicode lookalikes or a truncated label onto the
   * review screen. Duplicate members are not a canonical struct definition. */
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

  switch (e712.phase) {
    case PH_DISCOVER: {
      /* Note every struct this one references, then move to the next unvisited
       * name. The closure grows while we walk it, which IS the traversal, and
       * the already-present check is what terminates a cyclical schema. */
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
      /* Discovery done. Sort everything after the primary segment, which
       * always leads. This is the ordering eip712.c never applied. */
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
        /* Stage the element descriptor in the frame we are ABOUT to push, then
         * ask for the array's length. The frame is not pushed yet, so the
         * member_path the device sends still points AT the array rather than
         * into it -- which is exactly the path whose value is the length. */
        Eip712Frame* arr = &e712.stack[e712.depth];
        memzero(arr, sizeof(*arr));
        arr->is_array = true;
        arr->slot_base = f->slot_base + f->member_count;
        arr->elem_data_type = (uint8_t)m->type.data_type;
        arr->elem_has_size = m->type.has_size;
        arr->elem_size = m->type.size;
        if (m->type.has_struct_name) {
          strlcpy(arr->elem_struct, m->type.struct_name,
                  EIP712_MAX_STRUCT_NAME);
        }
        arr->levels_total = (uint8_t)m->type.array_levels_count;
        arr->level_index = 0;
        e712.pending_declared_dim = m->type.array_levels[0];
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

    /* A FIXED dimension is part of the type string and therefore of typeHash.
     * Accepting a different count would sign a document whose type declares
     * another, and nothing downstream could notice. */
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

  /* Validate BEFORE anything is drawn, so no unvalidated byte reaches the
   * screen, and before anything is absorbed, so nothing unshown reaches the
   * hash. */
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

  /* Display and absorb from the SAME buffer in the same call. This is the
   * property the old JSON parser could not offer and the reason it was
   * withdrawn: there is no second read that could return something else. */
  if (!e712.definition_accepted &&
      !eip712_confirm_leaf(e712.pending_name, field, bytes, len)) {
    eip712_stream_abort();
    memzero(&next_step, sizeof(next_step));
    next_step.kind = EIP712_REQ_CANCELLED;
    return false;
  }

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

bool eip712_stream_container_hash(uint16_t source_index, uint8_t value[32]) {
  if (!value || !e712.active) return false;
  if (source_index == 5 && e712.have_domain_separator) {
    memcpy(value, e712.domain_separator, 32);
    return true;
  }
  if (source_index == 6 && e712.domain_facts.has_primary_type_hash) {
    memcpy(value, e712.domain_facts.primary_type_hash, 32);
    return true;
  }
  return false;
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
