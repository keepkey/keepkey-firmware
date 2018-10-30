/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2016 Alex Beregszaszi <alex@rtfs.hu>
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

#ifndef __ETHEREUM_H__
#define __ETHEREUM_H__

#include "trezor/crypto/bip32.h"

#include <stdint.h>
#include <stdbool.h>

typedef struct _EthereumSignTx EthereumSignTx;
typedef struct _EthereumTxAck EthereumTxAck;

void ethereum_signing_init(EthereumSignTx *msg, const HDNode *node, bool needs_confirm);
void ethereum_signing_abort(void);
void ethereum_signing_txack(EthereumTxAck *msg);
void format_ethereum_address(const uint8_t *to, char *destination_str,
                             uint32_t destination_str_len);
bool is_token_transaction(EthereumSignTx *msg);

/**
 * \brief Get the number of decimals associated with an erc20 token
 * \param   token_shorcut String corresponding to a token_shortcut in coins table in coins.c
 * \returns uint32_t      The number of decimals to interpret the token with
 */
uint32_t ethereum_get_decimal(const char *token_shortcut);

#endif
