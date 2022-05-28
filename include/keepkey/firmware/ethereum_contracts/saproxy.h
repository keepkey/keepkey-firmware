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

#ifndef KEEPKEY_FIRMWARE_ETHEREUMCONTRACTS_SAPROXY_H
#define KEEPKEY_FIRMWARE_ETHEREUMCONTRACTS_SAPROXY_H

#include <inttypes.h>
#include <stdbool.h>

#define SAPROXY_ADDRESS "\xbd\x6a\x40\xbb\x90\x4a\xea\x5a\x49\xc5\x90\x50\xb5\x39\x5f\x74\x84\xa4\x20\x3d"
                        
typedef struct _EthereumSignTx EthereumSignTx;

bool sa_isWithdrawFromSalary(const EthereumSignTx *msg);
bool sa_confirmWithdrawFromSalary(uint32_t data_total, const EthereumSignTx *msg);

#endif
