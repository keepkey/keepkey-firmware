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

#ifndef KEEPKEY_FIRMWARE_ETHEREUMCONTRACTS_ZXLIQUIDTX_H
#define KEEPKEY_FIRMWARE_ETHEREUMCONTRACTS_ZXLIQUIDTX_H

#include <inttypes.h>
#include <stdbool.h>

#define UNISWAP_ROUTER_ADDRESS "\x7a\x25\x0d\x56\x30\xB4\xcF\x53\x97\x39\xdF\x2C\x5d\xAc\xb4\xc6\x59\xF2\x48\x8D"

typedef struct _EthereumSignTx EthereumSignTx;

bool zx_isZxLiquidTx(const EthereumSignTx *msg);
bool zx_confirmZxLiquidTx(uint32_t data_total, const EthereumSignTx *msg);

#endif
