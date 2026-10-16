/* Allocation-free CBOR codec for the definite-length CTAP2 data model. */
#include "keepkey/firmware/ctap2/cbor.h"

#include <limits.h>
#include <string.h>

#define CBOR_MAX_NESTING 16

static bool valid_utf8(const uint8_t* text, size_t length) {
  for (size_t i = 0; i < length;) {
    uint8_t first = text[i++];
    if (first < 0x80) continue;
    size_t continuation;
    uint32_t codepoint;
    if (first >= 0xc2 && first <= 0xdf) {
      continuation = 1;
      codepoint = first & 0x1f;
    } else if (first >= 0xe0 && first <= 0xef) {
      continuation = 2;
      codepoint = first & 0x0f;
    } else if (first >= 0xf0 && first <= 0xf4) {
      continuation = 3;
      codepoint = first & 0x07;
    } else {
      return false;
    }
    if (continuation > length - i) return false;
    for (size_t j = 0; j < continuation; ++j) {
      uint8_t next = text[i++];
      if ((next & 0xc0) != 0x80) return false;
      codepoint = (codepoint << 6) | (next & 0x3f);
    }
    if ((continuation == 2 && codepoint < 0x800) ||
        (continuation == 3 && codepoint < 0x10000) ||
        (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff)
      return false;
  }
  return true;
}

static bool encode_raw(CborEncoder* encoder, const uint8_t* data,
                       size_t length) {
  if (encoder->failed || length > encoder->capacity - encoder->offset) {
    encoder->failed = true;
    return false;
  }
  if (length != 0) memcpy(encoder->buffer + encoder->offset, data, length);
  encoder->offset += length;
  return true;
}

static bool encode_head(CborEncoder* encoder, CborType type, uint64_t value) {
  uint8_t head[9];
  size_t length = 1;

  if (value < 24) {
    head[0] = ((uint8_t)type << 5) | (uint8_t)value;
  } else if (value <= UINT8_MAX) {
    head[0] = ((uint8_t)type << 5) | 24;
    head[1] = (uint8_t)value;
    length = 2;
  } else if (value <= UINT16_MAX) {
    head[0] = ((uint8_t)type << 5) | 25;
    head[1] = (uint8_t)(value >> 8);
    head[2] = (uint8_t)value;
    length = 3;
  } else if (value <= UINT32_MAX) {
    head[0] = ((uint8_t)type << 5) | 26;
    head[1] = (uint8_t)(value >> 24);
    head[2] = (uint8_t)(value >> 16);
    head[3] = (uint8_t)(value >> 8);
    head[4] = (uint8_t)value;
    length = 5;
  } else {
    head[0] = ((uint8_t)type << 5) | 27;
    for (size_t i = 0; i < 8; ++i) {
      head[1 + i] = (uint8_t)(value >> (56 - 8 * i));
    }
    length = 9;
  }
  return encode_raw(encoder, head, length);
}

void cbor_encoder_init(CborEncoder* encoder, uint8_t* buffer, size_t capacity) {
  encoder->buffer = buffer;
  encoder->capacity = capacity;
  encoder->offset = 0;
  encoder->failed = false;
}

bool cbor_encode_uint(CborEncoder* encoder, uint64_t value) {
  return encode_head(encoder, CBOR_TYPE_UINT, value);
}

bool cbor_encode_int(CborEncoder* encoder, int64_t value) {
  if (value >= 0) return cbor_encode_uint(encoder, (uint64_t)value);
  return encode_head(encoder, CBOR_TYPE_NEGINT, (uint64_t)(-(value + 1)));
}

bool cbor_encode_bytes(CborEncoder* encoder, const uint8_t* value,
                       size_t length) {
  return encode_head(encoder, CBOR_TYPE_BYTES, length) &&
         encode_raw(encoder, value, length);
}

bool cbor_encode_text(CborEncoder* encoder, const char* value, size_t length) {
  return encode_head(encoder, CBOR_TYPE_TEXT, length) &&
         encode_raw(encoder, (const uint8_t*)value, length);
}

bool cbor_encode_bool(CborEncoder* encoder, bool value) {
  const uint8_t byte = value ? 0xf5 : 0xf4;
  return encode_raw(encoder, &byte, 1);
}

bool cbor_encode_array(CborEncoder* encoder, size_t count) {
  return encode_head(encoder, CBOR_TYPE_ARRAY, count);
}

bool cbor_encode_map(CborEncoder* encoder, size_t pairs) {
  return encode_head(encoder, CBOR_TYPE_MAP, pairs);
}

size_t cbor_encoder_size(const CborEncoder* encoder) {
  return encoder->failed ? 0 : encoder->offset;
}

void cbor_decoder_init(CborDecoder* decoder, const uint8_t* buffer,
                       size_t length) {
  decoder->buffer = buffer;
  decoder->length = length;
  decoder->offset = 0;
}

static bool decode_argument(CborDecoder* decoder, uint8_t additional,
                            uint64_t* argument) {
  size_t bytes;
  if (additional < 24) {
    *argument = additional;
    return true;
  }
  if (additional == 24)
    bytes = 1;
  else if (additional == 25)
    bytes = 2;
  else if (additional == 26)
    bytes = 4;
  else if (additional == 27)
    bytes = 8;
  else
    return false; /* Indefinite lengths and reserved values are forbidden. */

  if (bytes > decoder->length - decoder->offset) return false;
  uint64_t value = 0;
  for (size_t i = 0; i < bytes; ++i) {
    value = (value << 8) | decoder->buffer[decoder->offset++];
  }
  /* Reject non-minimal encodings, as required by CTAP canonical CBOR. */
  if ((bytes == 1 && value < 24) || (bytes == 2 && value <= UINT8_MAX) ||
      (bytes == 4 && value <= UINT16_MAX) ||
      (bytes == 8 && value <= UINT32_MAX))
    return false;
  *argument = value;
  return true;
}

bool cbor_decode_value(CborDecoder* decoder, CborValue* value) {
  if (decoder->offset >= decoder->length) return false;
  uint8_t head = decoder->buffer[decoder->offset++];
  value->type = (CborType)(head >> 5);
  value->data = NULL;
  value->length = 0;
  if (!decode_argument(decoder, head & 0x1f, &value->value)) return false;

  if (value->type == CBOR_TYPE_BYTES || value->type == CBOR_TYPE_TEXT) {
    if (value->value > SIZE_MAX ||
        (size_t)value->value > decoder->length - decoder->offset)
      return false;
    value->data = decoder->buffer + decoder->offset;
    value->length = (size_t)value->value;
    decoder->offset += value->length;
    if (value->type == CBOR_TYPE_TEXT &&
        !valid_utf8(value->data, value->length))
      return false;
  } else if (value->type == CBOR_TYPE_TAG) {
    return false; /* Tags are not part of the CTAP2 canonical data model. */
  } else if (value->type == CBOR_TYPE_SIMPLE && value->value > 23) {
    return false; /* No floats or extended simple values. */
  }
  return true;
}

size_t cbor_utf8_codepoints(const uint8_t* text, size_t length) {
  if (!valid_utf8(text, length)) return SIZE_MAX;
  size_t count = 0;
  for (size_t i = 0; i < length; ++i) count += (text[i] & 0xc0) != 0x80;
  return count;
}

static bool skip_value(CborDecoder* decoder, unsigned depth);

static bool skip_children(CborDecoder* decoder, uint64_t count,
                          unsigned depth) {
  if (count > (uint64_t)(decoder->length - decoder->offset)) return false;
  for (uint64_t i = 0; i < count; ++i) {
    if (!skip_value(decoder, depth)) return false;
  }
  return true;
}

static bool skip_value(CborDecoder* decoder, unsigned depth) {
  CborValue value;
  if (!cbor_decode_value(decoder, &value)) return false;
  if (value.type != CBOR_TYPE_ARRAY && value.type != CBOR_TYPE_MAP) return true;
  if (depth >= CBOR_MAX_NESTING) return false;
  if (value.type == CBOR_TYPE_ARRAY)
    return skip_children(decoder, value.value, depth + 1);
  if (value.type == CBOR_TYPE_MAP) {
    /* Canonical CTAP2 CBOR: keys strictly increase by major type, then
     * encoded length, then bytes, so no map at any depth can carry a
     * duplicate or ambiguous key. */
    if (value.value > (uint64_t)(decoder->length - decoder->offset))
      return false;
    const uint8_t* previous = NULL;
    size_t previous_length = 0;
    for (uint64_t i = 0; i < value.value; ++i) {
      const size_t start = decoder->offset;
      if (!skip_value(decoder, depth + 1)) return false;
      const uint8_t* key = decoder->buffer + start;
      const size_t key_length = decoder->offset - start;
      if (previous) {
        const int type = key[0] >> 5, previous_type = previous[0] >> 5;
        if (type < previous_type ||
            (type == previous_type &&
             (key_length < previous_length ||
              (key_length == previous_length &&
               memcmp(previous, key, key_length) >= 0))))
          return false;
      }
      previous = key;
      previous_length = key_length;
      if (!skip_value(decoder, depth + 1)) return false;
    }
    return true;
  }
  return true;
}

bool cbor_skip_value(CborDecoder* decoder) { return skip_value(decoder, 0); }

bool cbor_map_find(const uint8_t* buffer, size_t length, const char* text,
                   int64_t wanted, CborValue* value, const uint8_t** slice,
                   size_t* slice_length) {
  CborDecoder decoder;
  CborValue map;
  cbor_decoder_init(&decoder, buffer, length);
  if (!cbor_decode_value(&decoder, &map) || map.type != CBOR_TYPE_MAP)
    return false;
  for (uint64_t i = 0; i < map.value; ++i) {
    CborValue key;
    if (!cbor_decode_value(&decoder, &key)) return false;
    bool match;
    if (text != NULL && key.type == CBOR_TYPE_TEXT)
      match =
          key.length == strlen(text) && memcmp(key.data, text, key.length) == 0;
    else if (text == NULL && key.type == CBOR_TYPE_UINT &&
             key.value <= INT64_MAX)
      match = (int64_t)key.value == wanted;
    else if (text == NULL && key.type == CBOR_TYPE_NEGINT &&
             key.value <= INT64_MAX)
      match = -1 - (int64_t)key.value == wanted;
    else
      return false;

    const size_t start = decoder.offset;
    if (!cbor_skip_value(&decoder)) return false;
    if (match) {
      CborDecoder item;
      cbor_decoder_init(&item, buffer + start, decoder.offset - start);
      if (!cbor_decode_value(&item, value)) return false;
      if (slice != NULL) *slice = buffer + start;
      if (slice_length != NULL) *slice_length = decoder.offset - start;
      return true;
    }
  }
  return false;
}
