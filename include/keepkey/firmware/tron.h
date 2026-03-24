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

// TRON address raw size (1 prefix + 20 hash)
#define TRON_ADDRESS_SIZE 21

// TRON max encoded address size
#define MAX_TRON_ADDR_SIZE 35

// TRON mainnet address prefix
#define TRON_MAINNET_PREFIX 0x41

// TRON decimals (1 TRX = 1,000,000 SUN)
#define TRON_DECIMALS 6

// TRON signature size (r + s + recovery_id)
#define TRON_SIGNATURE_SIZE 65

// TRC-20 transfer(address,uint256) function selector
#define TRC20_TRANSFER_SELECTOR 0xa9059cbb

/**
 * Generate TRON address from secp256k1 public key
 */
bool tron_getAddress(const uint8_t public_key[33], char *address,
                     size_t address_len);

/**
 * Decode a Base58Check TRON address to raw 21-byte form
 * @param address  Base58Check encoded "T..." address
 * @param raw_address  Output buffer (21 bytes: 0x41 prefix + 20 hash)
 * @return true on success, false if decode fails or prefix is wrong
 */
bool tron_decodeAddress(const char *address,
                        uint8_t raw_address[TRON_ADDRESS_SIZE]);

/**
 * Validate a Base58Check TRON address
 */
bool tron_validateAddress(const char *address);

/**
 * Format TRON amount (SUN) for display
 */
void tron_formatAmount(char *buf, size_t len, uint64_t amount);

/**
 * Format a token amount with given decimals for display
 * @param buf       Output buffer
 * @param buf_len   Buffer size
 * @param amount_be 32-byte big-endian amount
 * @param decimals  Token decimal places
 * @param symbol    Token symbol (e.g., "USDT")
 */
void tron_formatTokenAmount(char *buf, size_t buf_len,
                            const uint8_t amount_be[32],
                            uint8_t decimals, const char *symbol);

/**
 * Decode TRC-20 transfer(address,uint256) ABI call data
 * @param data       ABI-encoded call data (>= 68 bytes)
 * @param data_len   Length of call data
 * @param to_raw     Output: 21-byte TRON address (0x41 + 20-byte EVM addr)
 * @param amount_bytes Output: 32-byte big-endian amount
 * @return true if data matches transfer(address,uint256) selector
 */
bool tron_decodeTRC20Transfer(const uint8_t *data, size_t data_len,
                              uint8_t to_raw[TRON_ADDRESS_SIZE],
                              uint8_t amount_bytes[32]);

/**
 * Reconstruct Transaction.raw protobuf from structured fields
 * @param msg        TronSignTx with structured fields
 * @param owner_raw  21-byte raw address of the signer
 * @param out        Output buffer for serialized protobuf
 * @param out_len    In: max capacity; Out: bytes written
 * @param max_len    Maximum buffer size
 * @return true on success
 */
bool tron_serializeRawTransaction(const TronSignTx *msg,
                                  const uint8_t *owner_raw,
                                  uint8_t *out, size_t *out_len,
                                  size_t max_len);

/**
 * Sign a TRON transaction (supports both structured and legacy modes)
 */
bool tron_signTx(const HDNode *node, const TronSignTx *msg,
                 TronSignedTx *resp);

#endif
