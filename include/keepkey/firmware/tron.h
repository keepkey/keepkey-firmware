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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// TRON address length (Base58Check, typically 34 chars starting with 'T')
#define TRON_ADDRESS_MAX_LEN 64

// TRON decimals (1 TRX = 1,000,000 SUN)
#define TRON_DECIMALS 6

// Raw 21-byte TRON address: 0x41 prefix + 20-byte keccak hash tail
#define TRON_RAW_ADDRESS_SIZE 21

/**
 * On-device classification of a TronSignTx raw_data payload.
 *
 * The device signs sha256(raw_data), so anything shown to the user MUST be
 * decoded from raw_data itself — never from side-channel proto fields.
 * Unless every field of the payload is understood, the transaction is
 * TRON_TX_UNVERIFIED and only the blind-sign path may be offered.
 */
typedef enum {
  TRON_TX_UNVERIFIED = 0,   // not fully understood — blind-sign only
  TRON_TX_TRANSFER,         // single TransferContract (native TRX send)
  TRON_TX_TRC20_TRANSFER,   // single TriggerSmartContract: transfer(address,uint256)
} TronTxType;

typedef struct {
  TronTxType type;
  uint8_t owner[TRON_RAW_ADDRESS_SIZE];     // spending account
  uint8_t to[TRON_RAW_ADDRESS_SIZE];        // TRX or token recipient
  uint8_t contract[TRON_RAW_ADDRESS_SIZE];  // TRC-20 token contract
  uint64_t amount;                          // SUN, TransferContract only
  uint8_t trc20_amount[32];                 // big-endian uint256 token base units
  bool has_fee_limit;
  uint64_t fee_limit;                       // SUN
  const uint8_t* memo;                      // points into caller's raw_data
  uint16_t memo_len;
} TronParsedTx;

/**
 * Parse a TRON raw_data protobuf for on-device display.
 * Fail-closed: any unrecognized top-level field, contract type, extra
 * contract, or unexpected parameter field yields TRON_TX_UNVERIFIED.
 * out->memo points into raw — valid only while raw is alive.
 */
TronTxType tron_parseRawTx(const uint8_t* raw, size_t len, TronParsedTx* out);

/**
 * Base58Check-encode a raw 21-byte TRON address for display.
 */
bool tron_addressFromBytes(const uint8_t addr[TRON_RAW_ADDRESS_SIZE],
                           char* out, size_t out_len);

/**
 * Format a TRC-20 uint256 amount (big-endian) as a decimal string of token
 * base units. Token decimals are unknown on-device, so no scaling is done.
 */
bool tron_formatTrc20Amount(const uint8_t amount_be[32], char* buf, size_t len);

/**
 * Generate TRON address from secp256k1 public key
 * @param public_key secp256k1 public key (33 bytes compressed)
 * @param address Output buffer for Base58Check encoded address
 * @param address_len Length of output buffer
 * @return true on success, false on failure
 */
bool tron_getAddress(const uint8_t public_key[33], char* address,
                     size_t address_len);

/**
 * Format TRON amount (SUN) for display
 * @param buf Output buffer
 * @param len Length of output buffer
 * @param amount Amount in SUN (1 TRX = 1,000,000 SUN)
 */
void tron_formatAmount(char* buf, size_t len, uint64_t amount);

/**
 * Sign a TRON transaction
 * @param node HD node containing private key
 * @param msg TronSignTx request message
 * @param resp TronSignedTx response message (will be filled with signature)
 */
bool tron_signTx(const HDNode* node, const TronSignTx* msg, TronSignedTx* resp);

/**
 * Sign an arbitrary message using TIP-191 personal_sign.
 * Hash = keccak256("\x19TRON Signed Message:\n" + ASCII(len) + message)
 * @param node HD node containing private key
 * @param msg TronSignMessage request
 * @param resp TronMessageSignature response (signature + Base58Check address)
 * @return true on success
 */
bool tron_message_sign(const HDNode* node, const TronSignMessage* msg,
                       TronMessageSignature* resp);

/**
 * Verify a TIP-191 signature against the claimed Base58Check TRON address.
 * @return 0 on success, 1 on malformed input, 2 on signature/address mismatch
 */
int tron_message_verify(const TronVerifyMessage* msg);

/**
 * Sign a TIP-712 typed-data digest in hash mode.
 * Host pre-computes the domain separator hash + message hash per the
 * TIP-712 spec; the device assembles
 *   keccak256("\x19\x01" || domain_separator_hash || message_hash)
 * and signs with secp256k1.
 *
 * @param node HD node with public_key filled
 * @param msg  TronSignTypedHash request
 * @param resp TronTypedDataSignature response (signature + Base58Check address)
 * @return true on success
 */
bool tron_typed_hash_sign(const HDNode* node, const TronSignTypedHash* msg,
                          TronTypedDataSignature* resp);

#endif
