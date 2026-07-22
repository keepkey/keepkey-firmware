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
int base_to_precision(uint8_t* dest, const uint8_t* value, size_t dest_len,
                      size_t value_len, uint8_t precision) {
  if (!dest || !value || dest_len == 0 || value_len == 0) return -1;

  // Decimal inputs are signed as strings. Accept only their unique canonical
  // representation so the value shown on the OLED is byte-for-byte bound to
  // the value placed in the transaction.
  if ((value_len > 1 && value[0] == '0')) return -1;
  for (size_t i = 0; i < value_len; i++) {
    if (value[i] < '0' || value[i] > '9') return -1;
  }

  size_t rendered_len;
  if (precision == 0) {
    rendered_len = value_len;
  } else if (value_len <= precision) {
    rendered_len = (size_t)precision + 2;  // "0." + precision digits
  } else {
    rendered_len = value_len + 1;  // digits plus decimal point
  }
  if (rendered_len + 1 > dest_len) return -1;

  size_t offset = 0;
  if (precision == 0) {
    memcpy(dest, value, value_len);
    offset = value_len;
  } else if (value_len <= precision) {
    dest[offset++] = '0';
    dest[offset++] = '.';
    const size_t zeroes = (size_t)precision - value_len;
    memset(dest + offset, '0', zeroes);
    offset += zeroes;
    memcpy(dest + offset, value, value_len);
    offset += value_len;
  } else {
    const size_t leading_digits = value_len - precision;
    memcpy(dest, value, leading_digits);
    offset = leading_digits;
    dest[offset++] = '.';
    memcpy(dest + offset, value + leading_digits, precision);
    offset += precision;
  }
  dest[offset] = '\0';
  return 0;
}
