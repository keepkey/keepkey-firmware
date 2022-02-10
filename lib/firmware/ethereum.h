/*
 * This file is part of the TREZOR project, https://trezor.io/
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

#include <stdint.h>
#include <stdbool.h>
#include "bip32.h"
#include "messages.pb.h"

void ethereum_signing_init(EthereumSignTx *msg, const HDNode *node);
void ethereum_signing_abort(void);
void ethereum_signing_txack(EthereumTxAck *msg);

void ethereum_message_sign(EthereumSignMessage *msg, const HDNode *node,
                           EthereumMessageSignature *resp);
int ethereum_message_verify(EthereumVerifyMessage *msg);
bool ethereum_isThorchainTx(const EthereumSignTx *msg);
uint8_t ethereum_extractThorchainData(const EthereumSignTx *msg,
                                          char *buffer);
#endif
