#include "keepkey/firmware/erc7730_abi_stream.h"

#include "memzero.h"

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

static bool node_dynamic(const Erc7730AbiProgram* p, uint16_t node,
                         uint8_t depth, bool* dynamic) {
  if (depth > ERC7730_ABI_MAX_DEPTH || node >= p->node_count) return false;
  const Erc7730AbiNode* n = &p->nodes[node];
  if (n->kind == ERC7730_ABI_BYTES || n->kind == ERC7730_ABI_STRING ||
      (n->kind == ERC7730_ABI_ARRAY &&
       n->array_length == ERC7730_ABI_DYNAMIC_ARRAY)) {
    *dynamic = true;
    return true;
  }
  if (n->kind == ERC7730_ABI_ARRAY)
    return node_dynamic(p, n->first_child, depth + 1, dynamic);
  if (n->kind == ERC7730_ABI_TUPLE) {
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
  }
  *dynamic = false;
  return true;
}

static Erc7730AbiResult push_value(Erc7730AbiStream* s, uint16_t node) {
  if (s->depth >= ERC7730_ABI_MAX_DEPTH) return ERC7730_ABI_RESOURCE_LIMIT;
  Erc7730AbiStreamFrame* f = &s->frames[s->depth++];
  memzero(f, sizeof(*f));
  f->node = node;
  f->mode = STREAM_VALUE;
  f->utf8_lower = 0x80;
  f->utf8_upper = 0xbf;
  return ERC7730_ABI_OK;
}

static void pop_frame(Erc7730AbiStream* s) {
  Erc7730AbiStreamFrame* f = &s->frames[s->depth - 1u];
  if (f->mode == STREAM_SEQUENCE_TAIL) s->pending_used = f->pending_start;
  memzero(f, sizeof(*f));
  s->depth--;
}

static Erc7730AbiResult make_sequence(Erc7730AbiStream* s,
                                      Erc7730AbiStreamFrame* f,
                                      uint16_t first_child,
                                      uint16_t child_count, bool repeated,
                                      size_t base) {
  if (child_count > ERC7730_ABI_MAX_ARRAY_ELEMENTS)
    return ERC7730_ABI_RESOURCE_LIMIT;
  f->first_child = first_child;
  f->child_count = child_count;
  f->item_index = 0;
  f->pending_start = s->pending_used;
  f->pending_count = 0;
  f->pending_index = 0;
  f->base = base;
  f->repeated = repeated;
  f->mode = STREAM_SEQUENCE_HEAD;
  return ERC7730_ABI_OK;
}

static Erc7730AbiResult prepare(Erc7730AbiStream* s) {
  while (s->depth != 0) {
    Erc7730AbiStreamFrame* f = &s->frames[s->depth - 1u];
    const Erc7730AbiNode* n = &s->program->nodes[f->node];
    if (f->mode == STREAM_VALUE) {
      if (n->kind <= ERC7730_ABI_FIXED_BYTES) return ERC7730_ABI_OK;
      if (n->kind == ERC7730_ABI_BYTES || n->kind == ERC7730_ABI_STRING) {
        f->mode = STREAM_BYTES_LENGTH;
        return ERC7730_ABI_OK;
      }
      if (n->kind == ERC7730_ABI_TUPLE) {
        Erc7730AbiResult r = make_sequence(s, f, n->first_child, n->child_count,
                                           false, s->received);
        if (r != ERC7730_ABI_OK) return r;
        continue;
      }
      if (n->kind == ERC7730_ABI_ARRAY) {
        if (n->array_length == ERC7730_ABI_DYNAMIC_ARRAY) {
          f->mode = STREAM_ARRAY_LENGTH;
          return ERC7730_ABI_OK;
        }
        if (s->elements > ERC7730_ABI_MAX_ARRAY_ELEMENTS - n->array_length)
          return ERC7730_ABI_RESOURCE_LIMIT;
        s->elements += n->array_length;
        Erc7730AbiResult r = make_sequence(s, f, n->first_child,
                                           n->array_length, true, s->received);
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
      f->item_index++;
      bool dynamic = false;
      if (!node_dynamic(s->program, child, 0, &dynamic))
        return ERC7730_ABI_BAD_PROGRAM;
      if (dynamic) return ERC7730_ABI_OK;
      Erc7730AbiResult r = push_value(s, child);
      if (r != ERC7730_ABI_OK) return r;
      continue;
    }
    if (f->mode == STREAM_SEQUENCE_TAIL) {
      if (f->pending_index == f->pending_count) {
        pop_frame(s);
        continue;
      }
      const Erc7730AbiPending* pending =
          &s->pending[f->pending_start + f->pending_index++];
      if (s->received - f->base != pending->declared_offset)
        return ERC7730_ABI_NON_CANONICAL;
      Erc7730AbiResult r = push_value(s, pending->node);
      if (r != ERC7730_ABI_OK) return r;
      continue;
    }
    return ERC7730_ABI_OK;
  }
  return ERC7730_ABI_OK;
}

static Erc7730AbiResult consume_utf8(Erc7730AbiStreamFrame* f, uint8_t byte) {
  if (f->utf8_remaining != 0) {
    if (byte < f->utf8_lower || byte > f->utf8_upper)
      return ERC7730_ABI_NON_CANONICAL;
    f->utf8_lower = 0x80;
    f->utf8_upper = 0xbf;
    f->utf8_remaining--;
    return ERC7730_ABI_OK;
  }
  if (byte < 0x80) return ERC7730_ABI_OK;
  if (byte >= 0xc2 && byte <= 0xdf) {
    f->utf8_remaining = 1;
  } else if (byte == 0xe0) {
    f->utf8_remaining = 2;
    f->utf8_lower = 0xa0;
  } else if (byte >= 0xe1 && byte <= 0xec) {
    f->utf8_remaining = 2;
  } else if (byte == 0xed) {
    f->utf8_remaining = 2;
    f->utf8_upper = 0x9f;
  } else if (byte >= 0xee && byte <= 0xef) {
    f->utf8_remaining = 2;
  } else if (byte == 0xf0) {
    f->utf8_remaining = 3;
    f->utf8_lower = 0x90;
  } else if (byte >= 0xf1 && byte <= 0xf3) {
    f->utf8_remaining = 3;
  } else if (byte == 0xf4) {
    f->utf8_remaining = 3;
    f->utf8_upper = 0x8f;
  } else {
    return ERC7730_ABI_NON_CANONICAL;
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
  const Erc7730AbiNode* n = &s->program->nodes[f->node];
  if (f->mode == STREAM_VALUE) {
    r = consume_atomic(n, s->word);
    if (r == ERC7730_ABI_OK) pop_frame(s);
  } else if (f->mode == STREAM_SEQUENCE_HEAD) {
    const uint16_t child =
        f->repeated ? f->first_child
                    : (uint16_t)(f->first_child + f->item_index - 1u);
    size_t declared = 0;
    if (!word_size(s->word, &declared) || (declared & 31u) != 0)
      return ERC7730_ABI_NON_CANONICAL;
    if (s->pending_used >= ERC7730_ABI_STREAM_MAX_PENDING)
      return ERC7730_ABI_RESOURCE_LIMIT;
    s->pending[s->pending_used++] = (Erc7730AbiPending){child, declared};
    f->pending_count++;
  } else if (f->mode == STREAM_BYTES_LENGTH) {
    size_t length = 0;
    if (!word_size(s->word, &length)) return ERC7730_ABI_BOUNDS;
    size_t rounded = 0;
    if (!add_size(length, 31, &rounded)) return ERC7730_ABI_BOUNDS;
    rounded &= ~(size_t)31;
    f->payload_remaining = length;
    f->base = rounded;
    f->mode = STREAM_BYTES_PAYLOAD;
    if (rounded == 0) pop_frame(s);
  } else if (f->mode == STREAM_BYTES_PAYLOAD) {
    const size_t used = f->payload_remaining < 32 ? f->payload_remaining : 32;
    if (n->kind == ERC7730_ABI_STRING) {
      for (size_t i = 0; i < used; i++) {
        r = consume_utf8(f, s->word[i]);
        if (r != ERC7730_ABI_OK) return r;
      }
    }
    for (size_t i = used; i < 32; i++) {
      if (s->word[i] != 0) return ERC7730_ABI_NON_CANONICAL;
    }
    f->payload_remaining -= used;
    f->base -= 32;
    if (f->base == 0) {
      if (f->utf8_remaining != 0) return ERC7730_ABI_NON_CANONICAL;
      pop_frame(s);
    }
  } else if (f->mode == STREAM_ARRAY_LENGTH) {
    size_t count = 0;
    if (!word_size(s->word, &count)) return ERC7730_ABI_BOUNDS;
    if (count > ERC7730_ABI_MAX_ARRAY_ELEMENTS ||
        s->elements > ERC7730_ABI_MAX_ARRAY_ELEMENTS - count)
      return ERC7730_ABI_RESOURCE_LIMIT;
    s->elements += (uint32_t)count;
    r = make_sequence(s, f, n->first_child, (uint16_t)count, true, s->received);
  } else {
    return ERC7730_ABI_BAD_PROGRAM;
  }
  return r;
}

Erc7730AbiResult erc7730_abi_stream_begin(Erc7730AbiStream* s,
                                          const Erc7730AbiProgram* program,
                                          size_t total_length) {
  if (!s) return ERC7730_ABI_BAD_PROGRAM;
  memzero(s, sizeof(*s));
  Erc7730AbiResult r = erc7730_abi_validate_program(program);
  if (r != ERC7730_ABI_OK || (total_length & 31u) != 0) {
    s->failed = true;
    return r != ERC7730_ABI_OK ? r : ERC7730_ABI_NON_CANONICAL;
  }
  s->program = program;
  s->total_length = total_length;
  r = push_value(s, program->root);
  if (r != ERC7730_ABI_OK) s->failed = true;
  return r;
}

Erc7730AbiResult erc7730_abi_stream_feed(Erc7730AbiStream* s, size_t offset,
                                         const uint8_t* data, size_t data_len) {
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

Erc7730AbiResult erc7730_abi_stream_finish(Erc7730AbiStream* s) {
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
  s->complete = true;
  return ERC7730_ABI_OK;
}

void erc7730_abi_stream_clear(Erc7730AbiStream* s) {
  if (s) memzero(s, sizeof(*s));
}
