/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
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

#ifndef EMULATOR
#include <libopencm3/cm3/scb.h>
#endif

#include "keepkey/board/util.h"

#include <inttypes.h>

static const char* hexdigits = "0123456789ABCDEF";

void uint32hex(uint32_t num, char* str) {
  uint32_t i;
  for (i = 0; i < 8; i++) {
    str[i] = hexdigits[(num >> (28 - i * 4)) & 0xF];
  }
}

// converts data to hexa
void data2hex(const void* data, uint32_t len, char* str) {
  uint32_t i;
  const uint8_t* cdata = (uint8_t*)data;
  for (i = 0; i < len; i++) {
    str[i * 2] = hexdigits[(cdata[i] >> 4) & 0xF];
    str[i * 2 + 1] = hexdigits[cdata[i] & 0xF];
  }
  str[len * 2] = 0;
}

uint32_t readprotobufint(uint8_t** ptr) {
  uint32_t result = (**ptr & 0x7F);
  if (**ptr & 0x80) {
    (*ptr)++;
    result += (**ptr & 0x7F) * 128;
    if (**ptr & 0x80) {
      (*ptr)++;
      result += (**ptr & 0x7F) * 128 * 128;
      if (**ptr & 0x80) {
        (*ptr)++;
        result += (**ptr & 0x7F) * 128 * 128 * 128;
        if (**ptr & 0x80) {
          (*ptr)++;
          result += (**ptr & 0x7F) * 128 * 128 * 128 * 128;
        }
      }
    }
  }
  (*ptr)++;
  return result;
}

void rev_byte_order(uint8_t* bfr, size_t len) {
  size_t i;

  for (i = 0; i < len / 2; i++) {
    uint8_t tempdata = bfr[i];
    bfr[i] = bfr[len - i - 1];
    bfr[len - i - 1] = tempdata;
  }
}

/*convert 64bit decimal to string (itoa)*/
void dec64_to_str(uint64_t dec64_val, char* str) {
  unsigned int b = 0;
  static char* sbfr;

  sbfr = str;
  b = dec64_val % 10;
  dec64_val = dec64_val / 10;

  if (dec64_val) {
    dec64_to_str(dec64_val, sbfr);
  }
  *sbfr = '0' + b;
  sbfr++;
}

bool is_valid_ascii(const uint8_t* data, uint32_t size) {
  for (uint32_t i = 0; i < size; i++) {
    if (data[i] < ' ' || data[i] > '~') {
      return false;
    }
  }
  return true;
}

/* convert number in base units to specified decimal precision */
int base_to_precision(uint8_t* dest, const uint8_t* value,
                      const uint8_t dest_len, const uint8_t value_len,
                      const uint8_t precision) {
  if (!(dest && value)) {
    // invalid pointer
    return -1;
  }
  if (dest_len == 0) {
    return -1;
  }

  /* Rewritten with explicit index arithmetic. The previous implementation had
     two defects, both reachable from the Osmosis formatters:

       - it used strlcpy(dst, src, n), whose third argument is the TOTAL size of
         the destination including the NUL, to copy n DIGITS. It therefore
         copied at most n-1 digits and silently dropped the last one, so a
         signed "1234567" rendered as 1.23456 and a signed "1" rendered as
         0.00000.
       - it terminated with dest[dest_len] = '\0', one byte past a buffer whose
         supplied capacity is dest_len. Callers passing sizeof(buf) got a
         one-byte stack overwrite.

     dest_len is the full capacity of dest, NUL included. */

  /* Exact output length, computed before anything is written. */
  size_t out_len;
  if (value_len > precision) {
    /* <leading digits> '.' <precision digits>, or just the digits when there
       is no fractional part to separate. */
    out_len = (size_t)value_len + (precision ? 1u : 0u);
  } else {
    /* "0." then precision digits, left-padded with zeros. */
    out_len = 2u + (size_t)precision;
  }
  if (out_len + 1u > (size_t)dest_len) {
    // value too large for output buffer
    return -1;
  }

  size_t w = 0;
  if (value_len > precision) {
    const size_t leading = (size_t)value_len - precision;
    memcpy(dest + w, value, leading);
    w += leading;
    if (precision) {
      dest[w++] = '.';
      memcpy(dest + w, value + leading, precision);
      w += precision;
    }
  } else {
    dest[w++] = '0';
    dest[w++] = '.';
    const size_t pad = (size_t)precision - value_len;
    memset(dest + w, '0', pad);
    w += pad;
    memcpy(dest + w, value, value_len);
    w += value_len;
  }
  dest[w] = '\0';
  return 0;
}
