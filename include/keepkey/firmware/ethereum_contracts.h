/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2022 markrypto
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

#include "hwcrypto/crypto/bip32.h"

typedef struct _EthereumSignTx EthereumSignTx;

/// \returns true iff there is custom support for this ETH signing request
bool ethereum_contractHandled(uint32_t data_total, const EthereumSignTx *msg,
                              const HDNode *node);

/// \pre requires that `ethereum_contractHandled(msg)`
/// \return true iff the user has confirmed the custom ETH signing request
bool ethereum_contractConfirmed(uint32_t data_total, const EthereumSignTx *msg,
                                const HDNode *node);
#endif
