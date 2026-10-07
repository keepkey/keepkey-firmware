#include "keepkey/firmware/erc7730_abi_stream.h"

#include <string.h>

#include "trezor/crypto/memzero.h"

enum {
  STREAM_VALUE = 1,
  STREAM_SEQUENCE_HEAD,
  STREAM_SEQUENCE_TAIL,
  STREAM_BYTES_LENGTH,
  STREAM_BYTES_PAYLOAD,
  STREAM_ARRAY_LENGTH,
};

static bool add_size(size_t a, size_t b, size_t* out) {
  if (a > SIZE_MAX - b) return false;
  *out = a + b;
  return true;
}

static bool word_size(const uint8_t word[32], size_t* value) {
  const size_t prefix = 32 - sizeof(size_t);
  for (size_t i = 0; i < prefix; i++) {
    if (word[i] != 0) return false;
  }
  size_t result = 0;
  for (size_t i = prefix; i < 32; i++) result = (result << 8) | word[i];
  *value = result;
  return true;
}

static Erc7730AbiResult push_value(Erc7730AbiStream* s, uint16_t node,
                                   uint8_t path_depth, bool target_prefix) {
  if (s->depth >= ERC7730_ABI_MAX_DEPTH) return ERC7730_ABI_RESOURCE_LIMIT;
  Erc7730AbiStreamFrame* f = &s->frames[s->depth++];
  memzero(f, sizeof(*f));
  f->node = node;
  f->path_depth = path_depth;
  f->target_prefix = target_prefix;
  f->mode = STREAM_VALUE;
  f->utf8_lower = 0x80;
  f->utf8_upper = 0xbf;
  return ERC7730_ABI_OK;
}

static void child_target(const Erc7730AbiStream* s,
                         const Erc7730AbiStreamFrame* parent,
                         const Erc7730AbiNode* parent_node, uint16_t index,
                         uint8_t* path_depth, bool* target_prefix) {
  *path_depth = parent->path_depth + 1u;
  *target_prefix = parent->target_prefix;
  if (!*target_prefix || *path_depth > s->capture_path_count) {
    *target_prefix = false;
    return;
  }
  int32_t wanted = s->capture_path[*path_depth - 1u];
  if (parent_node->kind == ERC7730_ABI_ARRAY && wanted < 0)
    wanted += parent->child_count;
  *target_prefix = wanted >= 0 && (uint32_t)wanted == index;
}

static void pop_frame(Erc7730AbiStream* s) {
  Erc7730AbiStreamFrame* f = &s->frames[s->depth - 1u];
  if (f->mode == STREAM_SEQUENCE_TAIL) s->pending_used = f->pending_start;
  memzero(f, sizeof(*f));
  s->depth--;
}

/* A capture that names an array returns its element count as a word. */
static void capture_array_length(Erc7730AbiStream* s,
                                 const Erc7730AbiStreamFrame* f, size_t count) {
  if (!f->target_prefix || f->path_depth != s->capture_path_count) return;
  memzero(s->capture.data, sizeof(s->capture.data));
  s->capture.data[30] = (uint8_t)(count >> 8);
  s->capture.data[31] = (uint8_t)count;
  s->capture.length = 32;
  s->capture.node = f->node;
  s->capture_found = true;
}

/* Reserve one pending slot per dynamic child. Head offsets are stored top
 * down so the tail consumes, and releases, them from the top of the stack:
 * a nested sequence only needs the slots its parent has not yet consumed. */
static Erc7730AbiResult make_sequence(Erc7730AbiStream* s,
                                      Erc7730AbiStreamFrame* f,
                                      uint16_t first_child,
                                      uint16_t child_count, bool repeated,
                                      size_t base) {
  if (child_count > ERC7730_ABI_MAX_ARRAY_ELEMENTS)
    return ERC7730_ABI_RESOURCE_LIMIT;
  uint16_t dynamic_count = 0;
  for (uint16_t i = 0; i < child_count; i++) {
    bool dynamic = false;
    if (!erc7730_abi_node_dynamic(&s->program,
                                  (uint16_t)(first_child + (repeated ? 0 : i)),
                                  0, &dynamic))
      return ERC7730_ABI_BAD_PROGRAM;
    if (dynamic) dynamic_count++;
  }
  if (dynamic_count > ERC7730_ABI_MAX_PENDING - s->pending_used)
    return ERC7730_ABI_RESOURCE_LIMIT;
  f->first_child = first_child;
  f->child_count = child_count;
  f->item_index = 0;
  f->pending_start = s->pending_used;
  f->pending_count = dynamic_count;
  f->pending_index = 0;
  s->pending_used += dynamic_count;
  f->base = base;
  f->repeated = repeated;
  f->mode = STREAM_SEQUENCE_HEAD;
  return ERC7730_ABI_OK;
}

static Erc7730AbiResult prepare(Erc7730AbiStream* s) {
  const size_t word_start =
      s->received >= sizeof(s->word) ? s->received - sizeof(s->word) : 0;
  while (s->depth != 0) {
    Erc7730AbiStreamFrame* f = &s->frames[s->depth - 1u];
    const Erc7730AbiNode* n = &s->program.nodes[f->node];
    if (f->mode == STREAM_VALUE) {
      if (n->kind <= ERC7730_ABI_FIXED_BYTES) return ERC7730_ABI_OK;
      if (n->kind == ERC7730_ABI_BYTES || n->kind == ERC7730_ABI_STRING) {
        f->mode = STREAM_BYTES_LENGTH;
        return ERC7730_ABI_OK;
      }
      if (n->kind == ERC7730_ABI_TUPLE) {
        Erc7730AbiResult r = make_sequence(s, f, n->first_child, n->child_count,
                                           false, word_start);
        if (r != ERC7730_ABI_OK) return r;
        continue;
      }
      if (n->kind == ERC7730_ABI_ARRAY) {
        if (n->array_length == ERC7730_ABI_DYNAMIC_ARRAY) {
          f->mode = STREAM_ARRAY_LENGTH;
          return ERC7730_ABI_OK;
        }
        if (s->elements >
            (uint32_t)ERC7730_ABI_MAX_ARRAY_ELEMENTS - n->array_length)
          return ERC7730_ABI_RESOURCE_LIMIT;
        s->elements += n->array_length;
        capture_array_length(s, f, n->array_length);
        Erc7730AbiResult r = make_sequence(s, f, n->first_child,
                                           n->array_length, true, word_start);
        if (r != ERC7730_ABI_OK) return r;
        continue;
      }
      return ERC7730_ABI_BAD_PROGRAM;
    }
    if (f->mode == STREAM_SEQUENCE_HEAD) {
      if (f->item_index == f->child_count) {
        f->mode = STREAM_SEQUENCE_TAIL;
        continue;
      }
      const uint16_t child = f->repeated
                                 ? f->first_child
                                 : (uint16_t)(f->first_child + f->item_index);
      const uint16_t item_index = f->item_index++;
      uint8_t path_depth = 0;
      bool target_prefix = false;
      child_target(s, f, n, item_index, &path_depth, &target_prefix);
      bool dynamic = false;
      if (!erc7730_abi_node_dynamic(&s->program, child, 0, &dynamic))
        return ERC7730_ABI_BAD_PROGRAM;
      if (dynamic) return ERC7730_ABI_OK;
      Erc7730AbiResult r = push_value(s, child, path_depth, target_prefix);
      if (r != ERC7730_ABI_OK) return r;
      continue;
    }
    if (f->mode == STREAM_SEQUENCE_TAIL) {
      if (s->pending_used == f->pending_start) {
        pop_frame(s);
        continue;
      }
      const Erc7730AbiPending* pending = &s->pending[--s->pending_used];
      if (word_start < f->base ||
          word_start - f->base != pending->declared_offset)
        return ERC7730_ABI_NON_CANONICAL;
      Erc7730AbiResult r = push_value(s, pending->node, pending->path_depth,
                                      pending->target_prefix);
      if (r != ERC7730_ABI_OK) return r;
      continue;
    }
    return ERC7730_ABI_OK;
  }
  return ERC7730_ABI_OK;
}

static Erc7730AbiResult consume_atomic(const Erc7730AbiNode* n,
                                       const uint8_t word[32]) {
  size_t used = 32;
  uint8_t pad = 0;
  if (n->kind == ERC7730_ABI_UINT) {
    used = n->size / 8;
  } else if (n->kind == ERC7730_ABI_INT) {
    used = n->size / 8;
    pad = (word[32 - used] & 0x80) ? 0xff : 0;
  } else if (n->kind == ERC7730_ABI_ADDRESS) {
    used = 20;
  } else if (n->kind == ERC7730_ABI_BOOL) {
    used = 1;
    if (word[31] > 1) return ERC7730_ABI_NON_CANONICAL;
  } else if (n->kind == ERC7730_ABI_FIXED_BYTES) {
    for (size_t i = n->size; i < 32; i++) {
      if (word[i] != 0) return ERC7730_ABI_NON_CANONICAL;
    }
    return ERC7730_ABI_OK;
  } else {
    return ERC7730_ABI_BAD_PROGRAM;
  }
  for (size_t i = 0; i < 32 - used; i++) {
    if (word[i] != pad) return ERC7730_ABI_NON_CANONICAL;
  }
  return ERC7730_ABI_OK;
}

static Erc7730AbiResult consume_word(Erc7730AbiStream* s) {
  Erc7730AbiResult r = prepare(s);
  if (r != ERC7730_ABI_OK || s->depth == 0)
    return r == ERC7730_ABI_OK ? ERC7730_ABI_NON_CANONICAL : r;
  Erc7730AbiStreamFrame* f = &s->frames[s->depth - 1u];
  const Erc7730AbiNode* n = &s->program.nodes[f->node];
  if (f->mode == STREAM_VALUE) {
    r = consume_atomic(n, s->word);
    if (r == ERC7730_ABI_OK) {
      if (f->target_prefix && f->path_depth == s->capture_path_count) {
        memcpy(s->capture.data, s->word, sizeof(s->word));
        s->capture.length = sizeof(s->word);
        s->capture.node = f->node;
        s->capture_found = true;
      }
      pop_frame(s);
    }
  } else if (f->mode == STREAM_SEQUENCE_HEAD) {
    const uint16_t child =
        f->repeated ? f->first_child
                    : (uint16_t)(f->first_child + f->item_index - 1u);
    size_t declared = 0;
    if (!word_size(s->word, &declared) || (declared & 31u) != 0)
      return ERC7730_ABI_NON_CANONICAL;
    if (f->pending_index >= f->pending_count) return ERC7730_ABI_BAD_PROGRAM;
    const uint16_t item_index = f->item_index - 1u;
    uint8_t path_depth = 0;
    bool target_prefix = false;
    child_target(s, f, n, item_index, &path_depth, &target_prefix);
    s->pending[f->pending_start + f->pending_count - 1u - f->pending_index++] =
        (Erc7730AbiPending){declared, child, path_depth, target_prefix};
  } else if (f->mode == STREAM_BYTES_LENGTH) {
    size_t length = 0;
    if (!word_size(s->word, &length)) return ERC7730_ABI_BOUNDS;
    size_t rounded = 0;
    if (!add_size(length, 31, &rounded)) return ERC7730_ABI_BOUNDS;
    rounded &= ~(size_t)31;
    f->payload_remaining = length;
    f->base = rounded;
    f->mode = STREAM_BYTES_PAYLOAD;
    f->capture = f->target_prefix && f->path_depth == s->capture_path_count;
    if (f->capture && s->capture_locate) {
      s->located_length = length;
      s->located_offset = s->received; /* the payload starts next */
      s->capture.length = length < 4 ? length : 4;
      s->capture.node = f->node;
    } else if (f->capture) {
      if (length > sizeof(s->capture.data)) {
        s->capture_overflow = true;
        s->located_length = length;
        s->capture.length = 0;
      } else {
        s->capture.length = length;
      }
      s->capture.node = f->node;
    }
    if (rounded == 0) {
      if (f->capture) s->capture_found = true;
      pop_frame(s);
    }
  } else if (f->mode == STREAM_BYTES_PAYLOAD) {
    const size_t used = f->payload_remaining < 32 ? f->payload_remaining : 32;
    if (n->kind == ERC7730_ABI_STRING) {
      for (size_t i = 0; i < used; i++) {
        if (!erc7730_utf8_consume(&f->utf8_remaining, &f->utf8_lower,
                                  &f->utf8_upper, s->word[i], false))
          return ERC7730_ABI_NON_CANONICAL;
      }
    }
    if (f->capture && s->capture_locate) {
      /* Keep only the leading bytes: the selector of an embedded call. */
      const size_t done = s->located_length - f->payload_remaining;
      for (size_t i = 0; i < used && done + i < s->capture.length; i++)
        s->capture.data[done + i] = s->word[i];
    } else if (f->capture && !s->capture_overflow && used != 0) {
      memcpy(s->capture.data + (s->capture.length - f->payload_remaining),
             s->word, used);
    }
    for (size_t i = used; i < 32; i++) {
      if (s->word[i] != 0) return ERC7730_ABI_NON_CANONICAL;
    }
    f->payload_remaining -= used;
    f->base -= 32;
    if (f->base == 0) {
      if (f->utf8_remaining != 0) return ERC7730_ABI_NON_CANONICAL;
      if (f->capture) s->capture_found = true;
      pop_frame(s);
    }
  } else if (f->mode == STREAM_ARRAY_LENGTH) {
    size_t count = 0;
    if (!word_size(s->word, &count)) return ERC7730_ABI_BOUNDS;
    if (count > ERC7730_ABI_MAX_ARRAY_ELEMENTS ||
        s->elements > ERC7730_ABI_MAX_ARRAY_ELEMENTS - count)
      return ERC7730_ABI_RESOURCE_LIMIT;
    s->elements += (uint32_t)count;
    capture_array_length(s, f, count);
    r = make_sequence(s, f, n->first_child, (uint16_t)count, true, s->received);
  } else {
    return ERC7730_ABI_BAD_PROGRAM;
  }
  return r;
}

Erc7730AbiResult erc7730_abi_stream_begin(Erc7730AbiStream* stream,
                                          const Erc7730AbiProgram* program,
                                          size_t total_length) {
  Erc7730AbiStream* s = stream;
  if (!s) return ERC7730_ABI_BAD_PROGRAM;
  memzero(s, sizeof(*s));
  Erc7730AbiResult r = erc7730_abi_validate_program(program);
  if (r != ERC7730_ABI_OK || (total_length & 31u) != 0) {
    s->failed = true;
    return r != ERC7730_ABI_OK ? r : ERC7730_ABI_NON_CANONICAL;
  }
  s->program = *program;
  s->total_length = total_length;
  r = push_value(s, program->root, 0, true);
  if (r != ERC7730_ABI_OK) s->failed = true;
  return r;
}

Erc7730AbiResult erc7730_abi_stream_capture_path(Erc7730AbiStream* stream,
                                                 const int32_t* path,
                                                 size_t path_count) {
  Erc7730AbiStream* s = stream;
  if (!s || !path || path_count == 0 || path_count >= ERC7730_ABI_MAX_DEPTH ||
      s->failed || s->complete || s->received != 0 || s->capture_enabled) {
    if (s) s->failed = true;
    return ERC7730_ABI_BAD_PATH;
  }
  memcpy(s->capture_path, path, path_count * sizeof(*path));
  s->capture_path_count = path_count;
  s->capture_enabled = true;
  return ERC7730_ABI_OK;
}

Erc7730AbiResult erc7730_abi_stream_feed(Erc7730AbiStream* stream,
                                         size_t offset, const uint8_t* data,
                                         size_t data_len) {
  Erc7730AbiStream* s = stream;
  if (!s || !data || data_len == 0 || s->failed || s->complete ||
      offset != s->received || data_len > s->total_length - s->received) {
    if (s) s->failed = true;
    return ERC7730_ABI_BOUNDS;
  }
  for (size_t i = 0; i < data_len; i++) {
    s->word[s->word_received++] = data[i];
    s->received++;
    if (s->word_received == sizeof(s->word)) {
      Erc7730AbiResult r = consume_word(s);
      memzero(s->word, sizeof(s->word));
      s->word_received = 0;
      if (r != ERC7730_ABI_OK) {
        s->failed = true;
        return r;
      }
    }
  }
  return ERC7730_ABI_OK;
}

Erc7730AbiResult erc7730_abi_stream_finish(Erc7730AbiStream* stream) {
  Erc7730AbiStream* s = stream;
  if (!s || s->failed || s->received != s->total_length ||
      s->word_received != 0) {
    if (s) s->failed = true;
    return ERC7730_ABI_BOUNDS;
  }
  Erc7730AbiResult r = prepare(s);
  if (r != ERC7730_ABI_OK || s->depth != 0 || s->pending_used != 0) {
    s->failed = true;
    return r != ERC7730_ABI_OK ? r : ERC7730_ABI_NON_CANONICAL;
  }
  if (s->capture_enabled && !s->capture_found) {
    s->failed = true;
    return ERC7730_ABI_BAD_PATH;
  }
  s->complete = true;
  return ERC7730_ABI_OK;
}

bool erc7730_abi_stream_captured(const Erc7730AbiStream* stream,
                                 Erc7730AbiCapture* capture) {
  const Erc7730AbiStream* s = stream;
  if (!s || !capture || !s->complete || s->failed || !s->capture_enabled ||
      !s->capture_found)
    return false;
  memcpy(capture, &s->capture, sizeof(*capture));
  return true;
}

void erc7730_abi_stream_clear(Erc7730AbiStream* stream) {
  Erc7730AbiStream* s = stream;
  if (s) memzero(s, sizeof(*s));
}
