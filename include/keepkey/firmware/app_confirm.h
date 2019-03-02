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

#define CONFIRM_SIGN_IDENTITY_TITLE 32
#define CONFIRM_SIGN_IDENTITY_BODY 416

bool confirm_cipher(bool encrypt, const char *key);
bool confirm_encrypt_msg(const char *msg, bool signing);
bool confirm_decrypt_msg(const char *msg, const char *address);
bool confirm_exchange_output(const char *from_amount, const char *to_amount, const char *destination);
bool confirm_transfer_output(ButtonRequestType button_request, const char *amount, const char *to);
bool confirm_transaction_output(ButtonRequestType button_request, const char *amount, const char *to);
bool confirm_transaction_output_no_bold(ButtonRequestType button_request,
                                        const char *amount, const char *to);

bool confirm_erc_token_transfer(ButtonRequestType button_request, const char *msg_body);

bool confirm_transaction(const char *total_amount, const char *fee);
bool confirm_load_device(bool is_node);
bool confirm_address(const char *desc, const char *address);
bool confirm_xpub(const char *node_str, const char *xpub);
bool confirm_sign_identity(const IdentityType *identity, const char *challenge);
bool confirm_ethereum_address(const char *desc, const char *address);
bool confirm_data(ButtonRequestType button_request, const char *title, const uint8_t *data, uint32_t size);
#endif
