#ifndef KEEPKEY_FIRMWARE_ERC7730_FORMAT_H
#define KEEPKEY_FIRMWARE_ERC7730_FORMAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Render untrusted text so every byte is shown one-to-one on the OLED. The
 * font draws every byte >= 0x80 as the same glyph, control bytes as nothing
 * and the pager drops leading spaces, so the raw bytes are not unambiguous on
 * screen:
 *   - printable ASCII 0x21-0x7e is copied, except a backslash, which is
 *     doubled;
 *   - a space is copied only when it is neither the first nor the last byte
 *     and neither neighbour is a space; otherwise it is written as the four
 *     characters backslash, 'x', '2', '0';
 *   - any byte 0x00-0x1f, 0x7f or >= 0x80 is written as backslash, 'x' and
 *     two lowercase hex digits (so a NUL cannot end the body early).
 * The output is NUL-terminated. Returns false, leaving "" when output_size is
 * nonzero, if the rendering does not fit. */
bool erc7730_format_text(const uint8_t* bytes, size_t length, char* output,
                         size_t output_size);

#endif
