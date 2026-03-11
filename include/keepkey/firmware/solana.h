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

#ifndef KEEPKEY_FIRMWARE_SOLANA_H
#define KEEPKEY_FIRMWARE_SOLANA_H

#include "trezor/crypto/bip32.h"
#include "messages-solana.pb.h"

#define SOLANA_ADDRESS_SIZE 50  // Base58-encoded Ed25519 public key (typically 44 chars + null)
#define SOLANA_SIGNATURE_SIZE 64 // Ed25519 signature size

// Convert Ed25519 public key to Solana Base58 address
bool solana_publicKeyToAddress(const uint8_t public_key[32], char *address,
                                size_t address_size);

// Sign Solana transaction (returns false on failure)
bool solana_signTx(const HDNode *node, const SolanaSignTx *msg,
                   SolanaSignedTx *resp);

// Sign Solana message (off-chain signature)
void solana_signMessage(const HDNode *node, const uint8_t *message,
                        size_t message_len, uint8_t *signature_out);

// Display message to user for confirmation
bool solana_confirmMessage(const uint8_t *message, size_t message_len);

#endif
