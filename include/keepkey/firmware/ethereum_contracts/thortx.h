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

#define ETH_ADDRESS                                                          \
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
  "\x00\x00"
#define ETH_NATIVE                                                           \
  "\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee" \
  "\xee\xee"

/* THORChain ETH router (mainnet), current v4.1.1.
 * NOTE: THORChain migrates this router periodically (v1 42a5ed.. -> v3
 * 3624525.. -> v4 d37bbe..). A hardcoded pin must be updated on each migration;
 * the durable path is the signed-metadata clear-sign protocol (host-signed,
 * key-pinned) which needs no firmware update per router change. */
#define THOR_ROUTER "d37bbe5744d730a1d98d8dc97c42f0ca46ad7146"

/* Maya Protocol ETH router (mainnet) */
#define MAYA_ROUTER "d89dce570de35a6f42d3bca7dba50a6d89bfc2a2"

/* deposit(address,address,uint256,string) — legacy selector */
#define THOR_SELECTOR_DEPOSIT "\x1f\xec\xe7\xb4"
/* depositWithExpiry(address,address,uint256,string,uint256) — current selector
 */
#define THOR_SELECTOR_DEPOSIT_WITH_EXPIRY "\x44\xbc\x93\x7b"

typedef struct _EthereumSignTx EthereumSignTx;

bool thor_has_deposit_selector(const EthereumSignTx* msg);
bool thor_is_expiry_variant(const EthereumSignTx* msg);
bool thor_isThorchainTx(const EthereumSignTx* msg);
bool thor_isMayachainTx(const EthereumSignTx* msg);
bool thor_confirmThorTx(uint32_t data_total, const EthereumSignTx* msg);
bool thor_confirmMayaTx(uint32_t data_total, const EthereumSignTx* msg);

#endif
