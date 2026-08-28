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

/// Pure helpers exposed so native tests bind ABI-sensitive/security checks.
bool signing_output_multisig_quorum_is_valid(const TxOutputType* txoutput);
void signing_checksum_script_type_bytes(InputScriptType script_type,
                                        uint8_t out[4]);

#if DEBUG_LINK
void signing_test_seed_state(void);
bool signing_test_state_is_cleared(void);
#endif

void signing_init(const SignTx* msg, const CoinType* _coin,
                  const HDNode* _root);
void signing_abort(void);
bool signing_is_active(void);
void signing_txack(TransactionType* tx);
void send_fsm_co_error_message(int co_error);

#endif
