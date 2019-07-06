/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2019 ShapeShift
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

#ifndef KEEPKEY_FIRMWARE_ETHEREUMCONTRACTS_H
#define KEEPKEY_FIRMWARE_ETHEREUMCONTRACTS_H

#include "trezor/crypto/bip32.h"

typedef struct _EthereumSignTx EthereumSignTx;

/// \returns true iff there is custom support for this ETH signing request
bool ethereum_contractHandled(uint32_t data_total, const EthereumSignTx *msg,
                              const HDNode *node);

/// \pre requires that `ethereum_contractHandled(msg)`
/// \return true iff the user has confirmed the custom ETH signing request
bool ethereum_contractConfirmed(uint32_t data_total, const EthereumSignTx *msg,
                                const HDNode *node);


bool ethereum_contractIsMethod(const EthereumSignTx *msg, const char *hash, size_t arg_count);
const uint8_t *ethereum_contractGetMethod(const EthereumSignTx *msg);
bool ethereum_contractHasParams(const EthereumSignTx *msg, size_t count);
const uint8_t *ethereum_contractGetParam(const EthereumSignTx *msg, size_t idx);
bool ethereum_contractHasProxiedParams(const EthereumSignTx *msg, size_t count);
const uint8_t *ethereum_contractGetProxiedMethod(const EthereumSignTx *msg);
bool ethereum_contractIsProxyCall(const EthereumSignTx *msg);
void ethereum_contractGetETHValue(const EthereumSignTx *msg, bignum256 *val);
bool ethereum_contractIsETHValueZero(const EthereumSignTx *msg);

#endif
