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

#include <stdint.h>

#include "trezor/crypto/bip32.h"

#include "keepkey/firmware/ethereum_tokens.h"

typedef struct _EthereumSignTx EthereumSignTx;

/// \returns true iff the 0x Exchange Proxy is deployed at ZXSWAP_ADDRESS on
///          this chain.
///
/// Most decoders in this directory match a contract that only exists on
/// Ethereum mainnet — the Uniswap V2 router, the Sablier proxy — so pinning
/// them to chain_id == 1 is correct: the same 20 bytes on another chain are an
/// unrelated contract, and clear-signing them would narrate the wrong thing.
///
/// The 0x Exchange Proxy is different. It is deployed at the SAME address
/// (0xdef1c0de...) across many chains by design, so the address alone is a
/// meaningful identity and a blanket mainnet pin would stop legitimate 0x
/// swaps on BSC, Polygon and the rest from being clear-signed at all — they
/// would fall through to the raw-calldata path, which is a strictly worse
/// screen for the user.
///
/// Default-deny: a chain absent from this list is not clear-signed, it falls
/// through to the generic disclosure. That is the safe direction, so an
/// incomplete list costs display quality rather than safety.
bool zx_isExchangeProxyChain(uint32_t chain_id);

/// May `token`'s ticker be shown as the asset for a transaction on this chain?
///
/// Ordinary lookup is chain-scoped, including the Ethereum-mainnet
/// 0xeeee..eeee pseudo-address.  This remains a defense-in-depth check for
/// specialized decoders: directly supplied or stale token metadata may be
/// displayed only when its chain ID matches the signing domain.
///
/// \returns false for NULL, UnknownToken, or metadata from another chain.
bool zx_tokenLabelsThisChain(uint32_t chain_id, const TokenType* token);

/// \returns true iff there is custom support for this ETH signing request
bool ethereum_contractHandled(uint32_t data_total, const EthereumSignTx* msg,
                              const HDNode* node);

/// \pre requires that `ethereum_contractHandled(msg)`
/// \return true iff the user has confirmed the custom ETH signing request
bool ethereum_contractConfirmed(uint32_t data_total, const EthereumSignTx* msg,
                                const HDNode* node);
#endif
