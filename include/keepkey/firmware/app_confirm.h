/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2015 KeepKey LLC
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

#ifndef APP_CONFIRM_H
#define APP_CONFIRM_H

#include "keepkey/transport/interface.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#define CONFIRM_SIGN_IDENTITY_TITLE 32
#define CONFIRM_SIGN_IDENTITY_BODY 416
#define CONFIRM_SIGN_IDENTITY_KEY 96

bool confirm_cipher(bool encrypt, const char* key);
bool confirm_encrypt_msg(const char* msg, bool signing);
bool confirm_decrypt_msg(const char* msg, const char* address);
bool confirm_transfer_output(ButtonRequestType button_request,
                             const char* amount, const char* to);
bool confirm_transaction_output(ButtonRequestType button_request,
                                const char* amount, const char* to);
bool confirm_transaction_output_no_bold(ButtonRequestType button_request,
                                        const char* amount, const char* to);

bool confirm_erc_token_transfer(ButtonRequestType button_request,
                                const char* msg_body);

bool confirm_transaction(const char* total_amount, const char* fee);
bool confirm_load_device(bool is_node);
bool confirm_address(const char* desc, const char* address);
bool confirm_xpub(const char* node_str, const char* xpub);
bool format_sign_identity_key_selection(const IdentityType* identity,
                                        const char* curve, char* out,
                                        size_t out_len);
bool confirm_sign_identity(const IdentityType* identity, const char* challenge,
                           const char* curve);

/**
 * Render the largest screen-sized prefix of a byte string.
 *
 * Whitespace, backslashes, controls, and non-ASCII bytes use an unambiguous
 * \xNN spelling. This prevents the OLED renderer from discarding leading
 * spaces or interpreting newlines while preserving readable printable text.
 *
 * \returns the number of input bytes represented in out, or zero on error.
 */
/// Escape every byte of `data` into `out`, exactly as confirm_bytes() renders
/// it, but without paging: bytes outside 0x21..0x7E, and '\\' itself, become a
/// four-glyph \\xNN escape.
///
/// For callers that must place the escaped text inside a larger body -- a
/// warning line above it, say -- and so cannot hand the whole screen to
/// confirm_bytes(). Fails rather than truncating, because a partial escape of
/// a secret is exactly the ambiguity the escaping exists to remove.
///
/// \param data     Bytes to escape (NULL only if size is 0).
/// \param size     Number of bytes at `data`.
/// \param out      Destination, always NUL terminated on success.
/// \param out_len  Capacity of `out`, including the terminator.
/// \returns true iff every byte fit.
bool confirm_bytes_escape(const uint8_t* data, size_t size, char* out,
                          size_t out_len);

size_t confirm_bytes_format_page(const uint8_t* data, size_t size, char* out,
                                 size_t out_len);

/** Review every byte of a length-delimited payload over one or more screens. */
bool confirm_bytes(ButtonRequestType button_request, const char* title,
                   const uint8_t* data, size_t size);
bool confirm_cosmos_address(const char* desc, const char* address);
bool confirm_osmosis_address(const char* desc, const char* address);
bool confirm_ethereum_address(const char* desc, const char* address);
bool confirm_nano_address(const char* desc, const char* address);
bool confirm_omni(ButtonRequestType button_request, const char* title,
                  const uint8_t* data, uint32_t size);
bool confirm_data(ButtonRequestType button_request, const char* title,
                  const uint8_t* data, uint32_t size);
#endif
