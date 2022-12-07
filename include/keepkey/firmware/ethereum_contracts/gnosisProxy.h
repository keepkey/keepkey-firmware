/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2022 markrypto
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

#ifndef KEEPKEY_FIRMWARE_ETHEREUMCONTRACTS_GNOSISPROXY_H
#define KEEPKEY_FIRMWARE_ETHEREUMCONTRACTS_GNOSISPROXY_H

#include <inttypes.h>
#include <stdbool.h>

#define GNOSISPROXY_ADDRESS "\xC8\xFF\xf0\xD9\x44\x40\x6A\x40\x47\x5a\x0A\x82\x64\x32\x8A\xAC\x8D\x64\x92\x7B"
                        
typedef struct _EthereumSignTx EthereumSignTx;

bool gn_confirmExecTx(uint32_t data_total, const EthereumSignTx *msg);
bool gn_isGnosisProxy(const EthereumSignTx *msg);

#endif
