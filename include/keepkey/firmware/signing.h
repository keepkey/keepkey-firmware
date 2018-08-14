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

/* === Includes ============================================================ */

#include "trezor/crypto/bip32.h"
#include "keepkey/transport/interface.h"

#include <stdint.h>
#include <stdbool.h>

/* === Defines ============================================================= */

/* progress_step/meta_step are fixed point numbers, giving the
 * progress per input in permille with these many additional bits.
 */
#define PROGRESS_PRECISION 16
#define VAR_INT_BUFFER 8

/* === Functions =========================================================== */

void signing_init(uint32_t _inputs_count, uint32_t _outputs_count, const CoinType *_coin, const HDNode *_root, uint32_t _version, uint32_t _lock_time);
void signing_abort(void);
void parse_raw_txack(uint8_t *msg, uint32_t msg_size);
void signing_txack(TransactionType *tx);
void send_fsm_co_error_message(int co_error);
bool compile_input_script_sig(TxInputType *tinput);
void digest_for_bip143(const TxInputType *txinput, uint8_t sighash, uint32_t forkid, uint8_t *xhash);

#endif
