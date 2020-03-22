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

#ifndef SIGNING_H
#define SIGNING_H

#include "trezor/crypto/bip32.h"
#include "keepkey/transport/interface.h"

#include <stdint.h>
#include <stdbool.h>
void txin_dgst_initialize(void);
bool txin_dgst_compare(const char *amt_str, const char *addr_str);
void txin_dgst_getstrs(char *prev, char *cur);
void txin_dgst_save_and_reset(char *amt_str, char *addr_str);
void signing_init(const SignTx *msg, const CoinType *_coin, const HDNode *_root);
void signing_abort(void);
void signing_txack(TransactionType *tx);
void send_fsm_co_error_message(int co_error);

#endif
