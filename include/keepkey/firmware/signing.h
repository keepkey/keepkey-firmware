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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/// Exposed for unit tests: pure predicate, no signing state involved.
bool isCrossAccountSegwitChangeForbidden(const uint32_t* lhs_address_n,
                                         size_t lhs_address_n_count,
                                         const uint32_t* rhs_address_n,
                                         size_t rhs_address_n_count,
                                         OutputScriptType rhs_script_type);

/// Encode the protobuf enum in the fixed four-byte little-endian form used by
/// the Bitcoin transaction-consistency checksum on every target ABI.
void signing_encode_script_type(InputScriptType script_type, uint8_t out[4]);

void signing_init(const SignTx* msg, const CoinType* _coin,
                  const HDNode* _root);
void signing_abort(void);
bool signing_is_active(void);
void signing_txack(TransactionType* tx);
void send_fsm_co_error_message(int co_error);

#endif
