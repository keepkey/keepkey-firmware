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

#ifndef KEEPKEY_BOARD_UTIL_H
#define KEEPKEY_BOARD_UTIL_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define MIN(a, b)       \
  ({                    \
    typeof(a) _a = (a); \
    typeof(b) _b = (b); \
    _a < _b ? _a : _b;  \
  })
#define MAX(a, b)       \
  ({                    \
    typeof(a) _a = (a); \
    typeof(b) _b = (b); \
    _a > _b ? _a : _b;  \
  })

#define CONCAT_IMPL(A, B) A##B
#define CONCAT(A, B) CONCAT_IMPL(A, B)

// converts uint32 to hexa (8 digits)
void uint32hex(uint32_t num, char* str);

// converts data to hexa
void data2hex(const void* data, uint32_t len, char* str);

// read protobuf integer and advance pointer
uint32_t readprotobufint(uint8_t** ptr);
void rev_byte_order(uint8_t* bfr, size_t len);
void dec64_to_str(uint64_t dec64_val, char* str);

bool is_valid_ascii(const uint8_t* data, uint32_t size);

/* Render size bytes of data as a NUL-terminated confirm body of at most
 * out_len - 1 characters.
 *
 * A protobuf `bytes` field is not a C string: it carries its own length, it is
 * not NUL-terminated, and it is free to contain a NUL anywhere. Handing one to
 * "%s" both reads past the field and ends the display at the first embedded
 * NUL, so bytes that go on to be signed never reach the screen.
 * confirm_body_fits() cannot catch that either, because calc_str_line() stops
 * at the same NUL. Rendering from (data, size) is the only shape that cannot
 * hide a signed byte.
 *
 * A message that is not entirely printable ASCII is rendered as hex, so every
 * byte is visible even when one of them is a NUL. When the rendering does not
 * fit, the number of bytes actually shown is stated in front of the preview,
 * where the display's silent clip cannot remove it.
 *
 * \param data     Bytes to show; only the first size of them are read.
 * \param size     Number of bytes, i.e. exactly the number that will be signed.
 * \param out      Destination, always NUL-terminated when out_len > 0.
 * \param out_len  sizeof(out).
 * \returns true iff the body is the message text, false iff it is hex.
 */
bool format_message_body(const uint8_t* data, uint32_t size, char* out,
                         size_t out_len);

int base_to_precision(uint8_t* dest, const uint8_t* value,
                      const uint8_t dest_len, const uint8_t value_len,
                      const uint8_t precision);

#endif
