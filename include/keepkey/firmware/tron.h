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

#ifndef KEEPKEY_FIRMWARE_TRON_H
#define KEEPKEY_FIRMWARE_TRON_H

#include "trezor/crypto/bip32.h"

#include "messages-tron.pb.h"

// TRON address length (Base58Check, typically 34 chars starting with 'T')
#define TRON_ADDRESS_MAX_LEN 64

// TRON decimals (1 TRX = 1,000,000 SUN)
#define TRON_DECIMALS 6

/**
 * Generate TRON address from secp256k1 public key
 * @param public_key secp256k1 public key (33 bytes compressed)
 * @param address Output buffer for Base58Check encoded address
 * @param address_len Length of output buffer
 * @return true on success, false on failure
 */
bool tron_getAddress(const uint8_t public_key[33], char *address,
                     size_t address_len);

/**
 * Format TRON amount (SUN) for display
 * @param buf Output buffer
 * @param len Length of output buffer
 * @param amount Amount in SUN (1 TRX = 1,000,000 SUN)
 */
void tron_formatAmount(char *buf, size_t len, uint64_t amount);

/**
 * Sign a TRON transaction
 * @param node HD node containing private key
 * @param msg TronSignTx request message
 * @param resp TronSignedTx response message (will be filled with signature)
 */
void tron_signTx(const HDNode *node, const TronSignTx *msg,
                 TronSignedTx *resp);

#endif
