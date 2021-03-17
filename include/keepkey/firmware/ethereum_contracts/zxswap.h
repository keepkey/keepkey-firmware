/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2021 ShapeShift
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

#ifndef KEEPKEY_FIRMWARE_ETHEREUMCONTRACTS_ZXSWAP_H
#define KEEPKEY_FIRMWARE_ETHEREUMCONTRACTS_ZXSWAP_H

#include <inttypes.h>
#include <stdbool.h>

#define ZXSWAP_ADDRESS "\xde\xf1\xc0\xde\xd9\xbe\xc7\xf1\xa1\x67\x08\x19\x83\x32\x40\xf0\x27\xb2\x5e\xff"

typedef struct _EthereumSignTx EthereumSignTx;

bool zx_isZxSwap(const EthereumSignTx *msg);
bool zx_confirmZxSwap(uint32_t data_total, const EthereumSignTx *msg);

#endif
