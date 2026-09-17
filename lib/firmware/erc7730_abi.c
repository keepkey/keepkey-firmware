#include "keepkey/firmware/erc7730_abi.h"

#include <limits.h>

typedef struct {
  const Erc7730AbiProgram* program;
  const uint8_t* data;
  size_t len;
  uint32_t elements;
} AbiContext;

static bool add_size(size_t a, size_t b, size_t* out) {
  if (a > SIZE_MAX - b) return false;
  *out = a + b;
  return true;
}

static bool mul_size(size_t a, size_t b, size_t* out) {
  if (a != 0 && b > SIZE_MAX / a) return false;
  *out = a * b;
  return true;
}

static bool range_ok(const AbiContext* ctx, size_t off, size_t size) {
  return off <= ctx->len && size <= ctx->len - off;
}

static bool read_word_size(const AbiContext* ctx, size_t off, size_t* out) {
  if (!range_ok(ctx, off, 32)) return false;
  /* size_t is at most 64 bits on supported test/build hosts. Reject rather
   * than truncate any non-zero high byte from the 256-bit ABI word. */
  const size_t keep = sizeof(size_t);
  for (size_t i = 0; i < 32 - keep; i++) {
    if (ctx->data[off + i] != 0) return false;
  }
  size_t value = 0;
  for (size_t i = 32 - keep; i < 32; i++) {
    value = (value << 8) | ctx->data[off + i];
  }
  *out = value;
  return true;
}

static bool node_dynamic(const Erc7730AbiProgram* p, uint16_t index,
                         uint8_t depth, bool* dynamic) {
  if (!p || !p->nodes || index >= p->node_count ||
      depth > ERC7730_ABI_MAX_DEPTH)
    return false;
  const Erc7730AbiNode* n = &p->nodes[index];
  switch (n->kind) {
    case ERC7730_ABI_BYTES:
    case ERC7730_ABI_STRING:
      *dynamic = true;
      return true;
    case ERC7730_ABI_ARRAY: {
      if (n->array_length == ERC7730_ABI_DYNAMIC_ARRAY) {
        *dynamic = true;
        return true;
      }
      return node_dynamic(p, n->first_child, depth + 1, dynamic);
    }
    case ERC7730_ABI_TUPLE:
      for (uint16_t i = 0; i < n->child_count; i++) {
        bool child_dynamic = false;
        if (!node_dynamic(p, (uint16_t)(n->first_child + i), depth + 1,
                          &child_dynamic))
          return false;
        if (child_dynamic) {
          *dynamic = true;
          return true;
        }
      }
      *dynamic = false;
      return true;
    default:
      *dynamic = false;
      return true;
  }
}

static bool static_size(const Erc7730AbiProgram* p, uint16_t index,
                        uint8_t depth, size_t* out) {
  bool dynamic = false;
  if (!node_dynamic(p, index, depth, &dynamic) || dynamic) return false;
  const Erc7730AbiNode* n = &p->nodes[index];
  if (n->kind != ERC7730_ABI_TUPLE && n->kind != ERC7730_ABI_ARRAY) {
    *out = 32;
    return true;
  }
  size_t total = 0;
  if (n->kind == ERC7730_ABI_ARRAY) {
    size_t element_size = 0;
    if (!static_size(p, n->first_child, depth + 1, &element_size) ||
        !mul_size(element_size, n->array_length, &total))
      return false;
  } else {
    for (uint16_t i = 0; i < n->child_count; i++) {
      size_t child_size = 0;
      if (!static_size(p, (uint16_t)(n->first_child + i), depth + 1,
                       &child_size) ||
          !add_size(total, child_size, &total))
        return false;
    }
  }
  *out = total;
  return true;
}

Erc7730AbiResult erc7730_abi_validate_program(const Erc7730AbiProgram* p) {
  if (!p || !p->nodes || p->node_count == 0 ||
      p->node_count > ERC7730_ABI_MAX_NODES || p->root >= p->node_count)
    return ERC7730_ABI_BAD_PROGRAM;
  if (p->root != 0 || p->nodes[0].kind != ERC7730_ABI_TUPLE)
    return ERC7730_ABI_BAD_PROGRAM;
  uint64_t child_mask = 0;
  uint8_t depths[ERC7730_ABI_MAX_NODES] = {0};
  depths[0] = 1;
  for (uint16_t i = 0; i < p->node_count; i++) {
    const Erc7730AbiNode* n = &p->nodes[i];
    if (depths[i] == 0) return ERC7730_ABI_BAD_PROGRAM;
    switch (n->kind) {
      case ERC7730_ABI_UINT:
      case ERC7730_ABI_INT:
        if (n->size < 8 || n->size > 256 || (n->size & 7) != 0)
          return ERC7730_ABI_BAD_PROGRAM;
        break;
      case ERC7730_ABI_FIXED_BYTES:
        if (n->size == 0 || n->size > 32) return ERC7730_ABI_BAD_PROGRAM;
        break;
      case ERC7730_ABI_ADDRESS:
      case ERC7730_ABI_BOOL:
      case ERC7730_ABI_BYTES:
      case ERC7730_ABI_STRING:
        break;
      case ERC7730_ABI_TUPLE:
        if (n->child_count == 0 || n->first_child <= i ||
            n->first_child >= p->node_count ||
            n->child_count > p->node_count - n->first_child)
          return ERC7730_ABI_BAD_PROGRAM;
        break;
      case ERC7730_ABI_ARRAY:
        if (n->child_count != 1 || n->first_child <= i ||
            n->first_child >= p->node_count ||
            (n->array_length != ERC7730_ABI_DYNAMIC_ARRAY &&
             (n->array_length == 0 ||
              n->array_length > ERC7730_ABI_MAX_ARRAY_ELEMENTS)))
          return ERC7730_ABI_BAD_PROGRAM;
        break;
      default:
        return ERC7730_ABI_BAD_PROGRAM;
    }
    if (n->kind == ERC7730_ABI_TUPLE || n->kind == ERC7730_ABI_ARRAY) {
      for (uint16_t child_index = 0; child_index < n->child_count;
           child_index++) {
        const uint16_t child = (uint16_t)(n->first_child + child_index);
        const uint64_t child_bit = UINT64_C(1) << child;
        if ((child_mask & child_bit) != 0) return ERC7730_ABI_BAD_PROGRAM;
        child_mask |= child_bit;
        depths[child] = (uint8_t)(depths[i] + 1u);
        if (depths[child] > ERC7730_ABI_MAX_DEPTH)
          return ERC7730_ABI_RESOURCE_LIMIT;
      }
    }
  }
  const uint64_t expected_children = p->node_count == 64
                                         ? UINT64_MAX & ~UINT64_C(1)
                                         : (UINT64_C(1) << p->node_count) - 2u;
  if (child_mask != expected_children) return ERC7730_ABI_BAD_PROGRAM;
  bool ignored = false;
  if (!node_dynamic(p, p->root, 0, &ignored)) return ERC7730_ABI_RESOURCE_LIMIT;
  return ERC7730_ABI_OK;
}

static Erc7730AbiResult validate_value(AbiContext* ctx, uint16_t node,
                                       size_t off, uint8_t depth,
                                       size_t* encoded_len);

static Erc7730AbiResult validate_sequence(AbiContext* ctx, uint16_t first_node,
                                          uint16_t node_count,
                                          uint16_t repeated_node, size_t count,
                                          size_t base, uint8_t depth,
                                          size_t* encoded_len) {
  if (depth > ERC7730_ABI_MAX_DEPTH) return ERC7730_ABI_RESOURCE_LIMIT;
  size_t head_size = 0;
  for (size_t i = 0; i < count; i++) {
    uint16_t child = node_count ? (uint16_t)(first_node + i) : repeated_node;
    bool dynamic = false;
    size_t slot = 0;
    if (!node_dynamic(ctx->program, child, depth + 1, &dynamic))
      return ERC7730_ABI_BAD_PROGRAM;
    if (dynamic) {
      slot = 32;
    } else if (!static_size(ctx->program, child, depth + 1, &slot)) {
      return ERC7730_ABI_BAD_PROGRAM;
    }
    if (!add_size(head_size, slot, &head_size)) return ERC7730_ABI_BOUNDS;
  }
  if (!range_ok(ctx, base, head_size)) return ERC7730_ABI_BOUNDS;

  size_t head = 0;
  size_t tail = head_size;
  for (size_t i = 0; i < count; i++) {
    uint16_t child = node_count ? (uint16_t)(first_node + i) : repeated_node;
    bool dynamic = false;
    if (!node_dynamic(ctx->program, child, depth + 1, &dynamic))
      return ERC7730_ABI_BAD_PROGRAM;
    size_t child_len = 0;
    if (dynamic) {
      size_t relative = 0;
      if (!read_word_size(ctx, base + head, &relative))
        return ERC7730_ABI_BOUNDS;
      /* A unique canonical encoding has monotonically packed tails. This one
       * equality rejects head pointers, gaps, aliases, overlaps and reordering.
       */
      if (relative != tail || (relative & 31) != 0)
        return ERC7730_ABI_NON_CANONICAL;
      size_t child_off = 0;
      if (!add_size(base, relative, &child_off)) return ERC7730_ABI_BOUNDS;
      Erc7730AbiResult r =
          validate_value(ctx, child, child_off, depth + 1, &child_len);
      if (r != ERC7730_ABI_OK) return r;
      if (!add_size(tail, child_len, &tail)) return ERC7730_ABI_BOUNDS;
      head += 32;
    } else {
      Erc7730AbiResult r =
          validate_value(ctx, child, base + head, depth + 1, &child_len);
      if (r != ERC7730_ABI_OK) return r;
      if (!add_size(head, child_len, &head)) return ERC7730_ABI_BOUNDS;
    }
  }
  *encoded_len = tail;
  return ERC7730_ABI_OK;
}

static Erc7730AbiResult validate_atomic(const AbiContext* ctx,
                                        const Erc7730AbiNode* n, size_t off) {
  if (!range_ok(ctx, off, 32)) return ERC7730_ABI_BOUNDS;
  const uint8_t* word = ctx->data + off;
  size_t used = 32;
  uint8_t pad = 0;
  switch (n->kind) {
    case ERC7730_ABI_UINT:
      used = n->size / 8;
      break;
    case ERC7730_ABI_INT:
      used = n->size / 8;
      pad = (word[32 - used] & 0x80) ? 0xff : 0;
      break;
    case ERC7730_ABI_ADDRESS:
      used = 20;
      break;
    case ERC7730_ABI_BOOL:
      used = 1;
      if (word[31] > 1) return ERC7730_ABI_NON_CANONICAL;
      break;
    case ERC7730_ABI_FIXED_BYTES:
      for (size_t i = n->size; i < 32; i++) {
        if (word[i] != 0) return ERC7730_ABI_NON_CANONICAL;
      }
      return ERC7730_ABI_OK;
    default:
      return ERC7730_ABI_BAD_PROGRAM;
  }
  for (size_t i = 0; i < 32 - used; i++) {
    if (word[i] != pad) return ERC7730_ABI_NON_CANONICAL;
  }
  return ERC7730_ABI_OK;
}

static bool valid_utf8(const uint8_t* s, size_t len) {
  size_t i = 0;
  while (i < len) {
    uint8_t c = s[i++];
    if (c < 0x80) continue;
    uint32_t cp = 0;
    size_t continuation = 0;
    if (c >= 0xc2 && c <= 0xdf) {
      cp = c & 0x1f;
      continuation = 1;
    } else if (c >= 0xe0 && c <= 0xef) {
      cp = c & 0x0f;
      continuation = 2;
    } else if (c >= 0xf0 && c <= 0xf4) {
      cp = c & 0x07;
      continuation = 3;
    } else {
      return false;
    }
    if (continuation > len - i) return false;
    for (size_t j = 0; j < continuation; j++) {
      uint8_t next = s[i++];
      if ((next & 0xc0) != 0x80) return false;
      cp = (cp << 6) | (next & 0x3f);
    }
    if ((continuation == 2 && cp < 0x800) ||
        (continuation == 3 && cp < 0x10000) || (cp >= 0xd800 && cp <= 0xdfff) ||
        cp > 0x10ffff)
      return false;
  }
  return true;
}

static Erc7730AbiResult validate_value(AbiContext* ctx, uint16_t node,
                                       size_t off, uint8_t depth,
                                       size_t* encoded_len) {
  if (depth > ERC7730_ABI_MAX_DEPTH) return ERC7730_ABI_RESOURCE_LIMIT;
  if (node >= ctx->program->node_count) return ERC7730_ABI_BAD_PROGRAM;
  const Erc7730AbiNode* n = &ctx->program->nodes[node];
  switch (n->kind) {
    case ERC7730_ABI_UINT:
    case ERC7730_ABI_INT:
    case ERC7730_ABI_ADDRESS:
    case ERC7730_ABI_BOOL:
    case ERC7730_ABI_FIXED_BYTES: {
      Erc7730AbiResult r = validate_atomic(ctx, n, off);
      if (r == ERC7730_ABI_OK) *encoded_len = 32;
      return r;
    }
    case ERC7730_ABI_BYTES:
    case ERC7730_ABI_STRING: {
      size_t payload_len = 0;
      if (!read_word_size(ctx, off, &payload_len)) return ERC7730_ABI_BOUNDS;
      size_t rounded = 0;
      if (!add_size(payload_len, 31, &rounded)) return ERC7730_ABI_BOUNDS;
      rounded &= ~(size_t)31;
      size_t total = 0;
      if (!add_size(32, rounded, &total) || !range_ok(ctx, off, total))
        return ERC7730_ABI_BOUNDS;
      for (size_t i = payload_len; i < rounded; i++) {
        if (ctx->data[off + 32 + i] != 0) return ERC7730_ABI_NON_CANONICAL;
      }
      if (n->kind == ERC7730_ABI_STRING &&
          !valid_utf8(ctx->data + off + 32, payload_len))
        return ERC7730_ABI_NON_CANONICAL;
      *encoded_len = total;
      return ERC7730_ABI_OK;
    }
    case ERC7730_ABI_TUPLE:
      return validate_sequence(ctx, n->first_child, n->child_count, 0,
                               n->child_count, off, depth, encoded_len);
    case ERC7730_ABI_ARRAY: {
      size_t count = n->array_length;
      size_t base = off;
      size_t prefix = 0;
      if (count == ERC7730_ABI_DYNAMIC_ARRAY) {
        if (!read_word_size(ctx, off, &count)) return ERC7730_ABI_BOUNDS;
        if (count > ERC7730_ABI_MAX_ARRAY_ELEMENTS)
          return ERC7730_ABI_RESOURCE_LIMIT;
        if (!add_size(off, 32, &base)) return ERC7730_ABI_BOUNDS;
        prefix = 32;
      }
      if (ctx->elements > ERC7730_ABI_MAX_ARRAY_ELEMENTS - count)
        return ERC7730_ABI_RESOURCE_LIMIT;
      ctx->elements += (uint32_t)count;
      size_t body = 0;
      Erc7730AbiResult r = validate_sequence(ctx, 0, 0, n->first_child, count,
                                             base, depth, &body);
      if (r != ERC7730_ABI_OK) return r;
      if (!add_size(prefix, body, encoded_len)) return ERC7730_ABI_BOUNDS;
      return ERC7730_ABI_OK;
    }
    default:
      return ERC7730_ABI_BAD_PROGRAM;
  }
}

Erc7730AbiResult erc7730_abi_validate(const Erc7730AbiProgram* program,
                                      const uint8_t* data, size_t data_len) {
  Erc7730AbiResult r = erc7730_abi_validate_program(program);
  if (r != ERC7730_ABI_OK) return r;
  if (!data && data_len != 0) return ERC7730_ABI_BOUNDS;
  AbiContext ctx = {program, data, data_len, 0};
  size_t used = 0;
  r = validate_value(&ctx, program->root, 0, 0, &used);
  if (r != ERC7730_ABI_OK) return r;
  return used == data_len ? ERC7730_ABI_OK : ERC7730_ABI_NON_CANONICAL;
}

/* Locate one immediate child after validation has established canonicality. */
static Erc7730AbiResult locate_child(AbiContext* ctx, uint16_t parent,
                                     size_t parent_off, int32_t requested,
                                     uint16_t* child_node, size_t* child_off) {
  const Erc7730AbiNode* n = &ctx->program->nodes[parent];
  size_t count = 0;
  size_t base = parent_off;
  uint16_t first = 0;
  bool repeated = false;
  if (n->kind == ERC7730_ABI_TUPLE) {
    if (requested < 0) return ERC7730_ABI_BAD_PATH;
    count = n->child_count;
    first = n->first_child;
  } else if (n->kind == ERC7730_ABI_ARRAY) {
    count = n->array_length;
    if (count == ERC7730_ABI_DYNAMIC_ARRAY) {
      if (!read_word_size(ctx, parent_off, &count)) return ERC7730_ABI_BOUNDS;
      base += 32;
    }
    repeated = true;
    first = n->first_child;
  } else {
    return ERC7730_ABI_BAD_PATH;
  }
  int64_t selected = requested;
  if (selected < 0) selected += (int64_t)count;
  if (selected < 0 || (uint64_t)selected >= count) return ERC7730_ABI_BAD_PATH;

  size_t head = 0;
  size_t tail = 0;
  /* Derive the full head size; canonical validation means dynamic offsets can
   * then be read directly without retaining a decoded tree. */
  for (size_t i = 0; i < count; i++) {
    uint16_t child = repeated ? first : (uint16_t)(first + i);
    bool dynamic = false;
    size_t slot = 0;
    if (!node_dynamic(ctx->program, child, 0, &dynamic))
      return ERC7730_ABI_BAD_PROGRAM;
    if (dynamic)
      slot = 32;
    else if (!static_size(ctx->program, child, 0, &slot))
      return ERC7730_ABI_BAD_PROGRAM;
    if (i == (size_t)selected) {
      *child_node = child;
      if (dynamic) {
        if (!read_word_size(ctx, base + head, &tail) ||
            !add_size(base, tail, child_off))
          return ERC7730_ABI_BOUNDS;
      } else {
        if (!add_size(base, head, child_off)) return ERC7730_ABI_BOUNDS;
      }
      return ERC7730_ABI_OK;
    }
    if (!add_size(head, slot, &head)) return ERC7730_ABI_BOUNDS;
  }
  return ERC7730_ABI_BAD_PATH;
}

Erc7730AbiResult erc7730_abi_resolve(const Erc7730AbiProgram* program,
                                     const uint8_t* data, size_t data_len,
                                     const int32_t* path, size_t path_len,
                                     Erc7730AbiValue* out) {
  if (!out || (!path && path_len != 0) || path_len > ERC7730_ABI_MAX_PATH)
    return ERC7730_ABI_BAD_PATH;
  Erc7730AbiResult r = erc7730_abi_validate(program, data, data_len);
  if (r != ERC7730_ABI_OK) return r;
  AbiContext ctx = {program, data, data_len, 0};
  uint16_t node = program->root;
  size_t off = 0;
  for (size_t i = 0; i < path_len; i++) {
    r = locate_child(&ctx, node, off, path[i], &node, &off);
    if (r != ERC7730_ABI_OK) return r;
  }
  size_t encoded_len = 0;
  r = validate_value(&ctx, node, off, 0, &encoded_len);
  if (r != ERC7730_ABI_OK) return r;
  const Erc7730AbiNode* n = &program->nodes[node];
  size_t view_off = off;
  size_t view_len = encoded_len;
  if (n->kind == ERC7730_ABI_BYTES || n->kind == ERC7730_ABI_STRING) {
    if (!read_word_size(&ctx, off, &view_len) || !add_size(off, 32, &view_off))
      return ERC7730_ABI_BOUNDS;
  }
  out->data = data + view_off;
  out->data_len = view_len;
  out->node = node;
  out->encoded_offset = off;
  out->encoded_length = encoded_len;
  return ERC7730_ABI_OK;
}
