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

#ifndef KEEPKEY_FIRMWARE_ETHEREUMCONTRACTS_THORTX_H
#define KEEPKEY_FIRMWARE_ETHEREUMCONTRACTS_THORTX_H

#include <inttypes.h>
#include <stdbool.h>

#define ETH_ADDRESS "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define ETH_NATIVE  "\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee"

#define THOR_ROUTER "42a5ed456650a09dc10ebc6361a7480fdd61f27b"

typedef struct _EthereumSignTx EthereumSignTx;

bool thor_isThorchainTx(const EthereumSignTx *msg);
bool thor_confirmThorTx(uint32_t data_total, const EthereumSignTx *msg);


#endif
