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

/* THORChain deploys its Router at a DIFFERENT address on every EVM chain, so
 * the pin must be chain-scoped (see thor_router_for_chain): a deposit on any
 * chain but mainnet can never match THOR_ROUTER and would fall to the
 * blind-sign gate. Avalanche C-Chain router, verified live against THORChain
 * /inbound_addresses via a Pioneer quote (2026-07). Lowercase, no 0x, to match
 * thor_format_to_addr's output. Same migration caveat as THOR_ROUTER.
 * ponytail: BSC (chainId 56) and Base (8453) routers also exist on-chain but
 * are omitted until verified against a live node — the shipped Pioneer catalog
 * lists STALE addresses (its AVAX entry 8f66c4ae.. is already wrong vs the live
 * 00dc6100..), and Pioneer currently routes BSC/Base swaps via Relay, not a
 * THORChain deposit, so no such tx reaches the device today. Add each here once
 * verified live. */
#define THOR_ROUTER_AVAX "00dc6100103bc402d490aee3f9a5560cbd91f1d4"

/* Maya Protocol ETH router v4 (mainnet), verified on Etherscan
 * (0xe3985e6b61b814f7cdb188766562ba71b446b46d). The prior pin
 * d89dce57.. has never held contract code on mainnet. */
#define MAYA_ROUTER "e3985e6b61b814f7cdb188766562ba71b446b46d"

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
