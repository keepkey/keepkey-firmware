#ifndef KEEPKEY_FIRMWARE_ERC7730_FORMAT_H
#define KEEPKEY_FIRMWARE_ERC7730_FORMAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keepkey/firmware/erc7730_abi_stream.h"

/* Widest rendering: every byte of a capture escaped to four characters. */
#define ERC7730_FORMATTED_VALUE_MAX (4u * ERC7730_ABI_CAPTURE_MAX)

/* Render untrusted text one-to-one on the OLED (the font merges bytes >= 0x80
 * and hides controls; the pager drops leading spaces): '\' is doubled; bytes
 * < 0x20, 0x7f, >= 0x80, and a space at either end or beside a space become
 * \xNN (lowercase hex). Returns false, leaving "", if it does not fit. */
bool erc7730_format_text(const uint8_t* bytes, size_t length, char* output,
                         size_t output_size);

/* Exact decimal of a 256-bit big-endian value; two's complement when
 * `negative` (the caller has seen the sign bit of a signed integer). */
bool erc7730_format_integer(const uint8_t value[32], bool negative,
                            char* output, size_t output_size);

bool erc7730_format_raw(const Erc7730AbiProgram* program,
                        const Erc7730AbiCapture* capture, char* output,
                        size_t output_size);
#endif
