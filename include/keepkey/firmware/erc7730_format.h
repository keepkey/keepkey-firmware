#ifndef KEEPKEY_FIRMWARE_ERC7730_FORMAT_H
#define KEEPKEY_FIRMWARE_ERC7730_FORMAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Render untrusted text so that, inside the same surrounding text, distinct
 * byte strings never draw the same screens. Raw bytes would: the font draws
 * every byte >= 0x80 as the same glyph and control bytes as nothing, the body
 * renderer drops a space where it wraps a line, and the pager drops spaces at
 * a page start, so whether a space is seen depends on where the layout puts
 * it. Each byte is rendered on its own:
 *   - printable ASCII 0x21-0x7e is copied, except a backslash, which is
 *     doubled;
 *   - any other byte, every space included, is written as backslash, 'x'
 *     and two lowercase hex digits (a space is \x20, and a NUL cannot end
 *     the body early).
 * The output is only printable ASCII 0x21-0x7e: no space, newline or control
 * byte, nothing the renderer or pager drops or turns into layout. The mapping
 * is prefix-free and per byte, so the rendering of a concatenation is the
 * concatenation of the renderings, and distinct inputs give distinct glyph
 * sequences however the output is wrapped, paged or the input is split into
 * parts. The output is NUL-terminated. Returns false, leaving "" when
 * output_size is nonzero, if the rendering does not fit. */
bool erc7730_format_text(const uint8_t* bytes, size_t length, char* output,
                         size_t output_size);

#endif
