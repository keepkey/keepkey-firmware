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

#ifndef KEEPKEY_FIRMWARE_SOLANA_TX_H
#define KEEPKEY_FIRMWARE_SOLANA_TX_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Known Solana program IDs
#define SOLANA_SYSTEM_PROGRAM_ID "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define SOLANA_TOKEN_PROGRAM_ID "\x06\xdd\xf6\xe1\xd7\x65\xa1\x93\xd9\xcb\xe1\x46\xce\xeb\x79\xac\x1c\xb4\x85\xed\x5f\x5b\x37\x91\x3a\x8c\xf5\x85\x7e\xff\x00\xa9"
#define SOLANA_STAKE_PROGRAM_ID "\x06\xa7\xd5\x17\x18\xc7\x74\xc9\x28\x56\x63\x98\x69\x1d\x5e\xb6\x8b\x5e\xb8\xa3\x9b\x4b\x6d\x5c\x73\x55\x5b\x21\x00\x00\x00\x00"

// Solana instruction types
typedef enum {
    SOLANA_INSTRUCTION_UNKNOWN = 0,
    SOLANA_INSTRUCTION_SYSTEM_TRANSFER = 1,
    SOLANA_INSTRUCTION_SYSTEM_CREATE_ACCOUNT = 2,
    SOLANA_INSTRUCTION_TOKEN_TRANSFER = 3,
    SOLANA_INSTRUCTION_TOKEN_TRANSFER_CHECKED = 4,
    SOLANA_INSTRUCTION_TOKEN_APPROVE = 5,
    SOLANA_INSTRUCTION_STAKE_DELEGATE = 6,
    SOLANA_INSTRUCTION_STAKE_WITHDRAW = 7
} SolanaInstructionType;

// Parsed instruction data
typedef struct {
    SolanaInstructionType type;
    uint8_t program_id[32];
    uint8_t num_accounts;
    uint8_t account_indices[16];  // Max accounts per instruction
    const uint8_t *data;
    size_t data_len;
} SolanaInstruction;

// Parsed transaction
typedef struct {
    uint8_t num_signatures;
    uint8_t num_required_signatures;
    uint8_t num_readonly_signed;
    uint8_t num_readonly_unsigned;
    uint16_t num_accounts;
    uint8_t account_keys[16][32];  // 16 accounts (512 bytes)
    uint8_t recent_blockhash[32];
    uint8_t num_instructions;
    SolanaInstruction instructions[8];  // 8 instructions
} SolanaParsedTransaction;

// System Transfer instruction data
typedef struct {
    uint64_t lamports;
} SolanaSystemTransfer;

// Token Transfer instruction data
typedef struct {
    uint64_t amount;
    uint8_t decimals;  // For TransferChecked
} SolanaTokenTransfer;

// Read Solana compact-u16 varint
bool read_compact_u16(const uint8_t **data, size_t *remaining, uint16_t *out);

// Parse a raw Solana transaction
bool solana_parseTransaction(const uint8_t *raw_tx, size_t tx_size,
                              SolanaParsedTransaction *parsed);

// Identify instruction type
SolanaInstructionType solana_identifyInstruction(const uint8_t *program_id,
                                                   const uint8_t *data,
                                                   size_t data_len);

// Parse specific instruction types
bool solana_parseSystemTransfer(const uint8_t *data, size_t len,
                                 SolanaSystemTransfer *transfer);

bool solana_parseTokenTransfer(const uint8_t *data, size_t len,
                                SolanaTokenTransfer *transfer);

// Display transaction to user
bool solana_confirmTransaction(const SolanaParsedTransaction *tx,
                                const uint8_t *signer_pubkey);

// Format lamports to SOL string (1 SOL = 1,000,000,000 lamports)
void solana_formatLamports(uint64_t lamports, char *out, size_t out_len);

#endif  // KEEPKEY_FIRMWARE_SOLANA_TX_H
