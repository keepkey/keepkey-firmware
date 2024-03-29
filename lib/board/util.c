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

static const char *hexdigits = "0123456789ABCDEF";

void uint32hex(uint32_t num, char *str) {
  uint32_t i;
  for (i = 0; i < 8; i++) {
    str[i] = hexdigits[(num >> (28 - i * 4)) & 0xF];
  }
}

// converts data to hexa
void data2hex(const void *data, uint32_t len, char *str) {
  uint32_t i;
  const uint8_t *cdata = (uint8_t *)data;
  for (i = 0; i < len; i++) {
    str[i * 2] = hexdigits[(cdata[i] >> 4) & 0xF];
    str[i * 2 + 1] = hexdigits[cdata[i] & 0xF];
  }
  str[len * 2] = 0;
}

uint32_t readprotobufint(uint8_t **ptr) {
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

void rev_byte_order(uint8_t *bfr, size_t len) {
  size_t i;
  uint8_t tempdata;

  for (i = 0; i < len / 2; i++) {
    tempdata = bfr[i];
    bfr[i] = bfr[len - i - 1];
    bfr[len - i - 1] = tempdata;
  }
}

/*convert 64bit decimal to string (itoa)*/
void dec64_to_str(uint64_t dec64_val, char *str) {
  unsigned int b = 0;
  static char *sbfr;

  sbfr = str;
  b = dec64_val % 10;
  dec64_val = dec64_val / 10;

  if (dec64_val) {
    dec64_to_str(dec64_val, sbfr);
  }
  *sbfr = '0' + b;
  sbfr++;
}

bool is_valid_ascii(const uint8_t *data, uint32_t size) {
  for (uint32_t i = 0; i < size; i++) {
    if (data[i] < ' ' || data[i] > '~') {
      return false;
    }
  }
  return true;
}

/* convert number in base units to specified decimal precision */
int base_to_precision(uint8_t *dest, const uint8_t *value,
                      const uint8_t dest_len, const uint8_t value_len,
                      const uint8_t precision) {
  if (!(dest && value)) {
    // invalid pointer
    return -1;
  }
  if (value_len + 1 > dest_len) {
    // value too large for output buffer
    return -1;
  }
  memset(dest, '0', dest_len);
  uint8_t leading_digits =
      ((value_len - precision) > 0) ? (value_len - precision) : 0;

  if (!leading_digits) {
    memcpy(dest, "0.", 2);
    uint8_t offset =
        2 + (((precision - value_len) > 0) ? (precision - value_len) : 0);
    strlcpy((char *)&dest[offset], (char *)value, value_len);
  } else {
    uint8_t copy_len = MIN((value_len - leading_digits), precision);
    memcpy(dest, value, leading_digits);
    dest[leading_digits] = '.';
    strlcpy((char *)&dest[leading_digits + 1], (char *)&value[leading_digits],
            copy_len);
  }
  dest[dest_len] = '\0';
  return 0;
}
