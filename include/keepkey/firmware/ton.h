/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2024 KeepKey
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

#ifndef KEEPKEY_FIRMWARE_TON_H
#define KEEPKEY_FIRMWARE_TON_H

#include "trezor/crypto/bip32.h"
#include "trezor/crypto/ed25519-donna/ed25519.h"

#include "messages-ton.pb.h"

// TON address length (Base64 URL-safe encoded, typically 48 chars)
#define TON_ADDRESS_MAX_LEN 64
#define TON_RAW_ADDRESS_MAX_LEN 128

// TON decimals (1 TON = 1,000,000,000 nanoTON)
#define TON_DECIMALS 9

/**
 * Generate TON address from Ed25519 public key
 * @param public_key Ed25519 public key (32 bytes)
 * @param bounceable Bounceable flag for address encoding
 * @param testnet Testnet flag for address encoding
 * @param workchain Workchain ID (-1 or 0)
 * @param address Output buffer for user-friendly Base64 encoded address
 * @param address_len Length of address output buffer
 * @param raw_address Output buffer for raw address format (workchain:hash)
 * @param raw_address_len Length of raw_address output buffer
 * @return true on success, false on failure
 */
bool ton_get_address(const ed25519_public_key public_key, bool bounceable,
                     bool testnet, int32_t workchain, char *address,
                     size_t address_len, char *raw_address,
                     size_t raw_address_len);

/**
 * Format TON amount (nanoTON) for display
 * @param buf Output buffer
 * @param len Length of output buffer
 * @param amount Amount in nanoTON (1 TON = 1,000,000,000 nanoTON)
 */
void ton_formatAmount(char *buf, size_t len, uint64_t amount);

/**
 * Sign a TON transaction
 * @param node HD node containing private key
 * @param msg TonSignTx request message
 * @param resp TonSignedTx response message (will be filled with signature)
 */
void ton_signTx(const HDNode *node, const TonSignTx *msg, TonSignedTx *resp);

#endif
