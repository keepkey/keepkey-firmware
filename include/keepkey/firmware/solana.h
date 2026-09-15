/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2025 KeepKey
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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SOL_DECIMALS 9
#define SOL_PUBKEY_SIZE 32
#define SOL_SIG_SIZE 64
#define SOL_MAX_ACCOUNTS 32
#define SOL_MAX_INSTRUCTIONS 8
#define SOL_LAMPORTS_DIVISOR 1000000000ULL
#define SOL_MAX_TOKEN_DECIMALS 18
#define SOL_MAX_DISPLAY_DECIMALS 9

/* Versioned transaction marker */
#define SOL_VERSION_FLAG 0x80
#define SOL_VERSION_MASK 0x7F

/* Compact-u16 encoding constants */
#define SOL_COMPACT_U16_CONTINUATION 0x80
#define SOL_COMPACT_U16_DATA_MASK 0x7F
#define SOL_COMPACT_U16_BYTE3_MAX 3

/* System program instruction indices */
#define SOL_SYS_CREATE_ACCOUNT 0
#define SOL_SYS_ASSIGN 1
#define SOL_SYS_TRANSFER 2
#define SOL_SYS_ADVANCE_NONCE 4
#define SOL_SYS_WITHDRAW_NONCE 5
#define SOL_SYS_INITIALIZE_NONCE 6
#define SOL_SYS_AUTHORIZE_NONCE 7
#define SOL_SYS_ALLOCATE 8

/* SPL Token program instruction indices */
#define SOL_TOKEN_TRANSFER_IX 3
#define SOL_TOKEN_APPROVE_IX 4
#define SOL_TOKEN_REVOKE_IX 5
#define SOL_TOKEN_SET_AUTHORITY_IX 6
#define SOL_TOKEN_MINT_TO_IX 7
#define SOL_TOKEN_BURN_IX 8
#define SOL_TOKEN_CLOSE_ACCOUNT_IX 9
#define SOL_TOKEN_FREEZE_ACCOUNT_IX 10
#define SOL_TOKEN_THAW_ACCOUNT_IX 11
#define SOL_TOKEN_TRANSFER_CHECKED_IX 12
#define SOL_TOKEN_MINT_TO_CHECKED_IX 14
#define SOL_TOKEN_BURN_CHECKED_IX 15
#define SOL_TOKEN_SYNC_NATIVE_IX 17

/* Stake program instruction indices */
#define SOL_STAKE_AUTHORIZE_IX 1
#define SOL_STAKE_DELEGATE_IX 2
#define SOL_STAKE_SPLIT_IX 3
#define SOL_STAKE_WITHDRAW_IX 4
#define SOL_STAKE_DEACTIVATE_IX 5
#define SOL_STAKE_MERGE_IX 7

/* Vote program instruction indices */
#define SOL_VOTE_AUTHORIZE_IX 1
#define SOL_VOTE_WITHDRAW_IX 3
#define SOL_VOTE_UPDATE_VALIDATOR_IX 4
#define SOL_VOTE_UPDATE_COMMISSION_IX 5

/* Compute Budget program instruction indices */
#define SOL_CB_REQUEST_HEAP_FRAME 1
#define SOL_CB_SET_COMPUTE_UNIT_LIMIT 2
#define SOL_CB_SET_COMPUTE_UNIT_PRICE 3
#define SOL_CB_SET_LOADED_ACCOUNTS_SIZE 4

/* Well-known program IDs */
extern const uint8_t SOL_SYSTEM_PROGRAM[SOL_PUBKEY_SIZE];
extern const uint8_t SOL_TOKEN_PROGRAM[SOL_PUBKEY_SIZE];
extern const uint8_t SOL_TOKEN_2022_PROGRAM[SOL_PUBKEY_SIZE];
extern const uint8_t SOL_STAKE_PROGRAM[SOL_PUBKEY_SIZE];
extern const uint8_t SOL_VOTE_PROGRAM[SOL_PUBKEY_SIZE];
extern const uint8_t SOL_ATA_PROGRAM[SOL_PUBKEY_SIZE];
extern const uint8_t SOL_COMPUTE_BUDGET_PROGRAM[SOL_PUBKEY_SIZE];
extern const uint8_t SOL_MEMO_PROGRAM[SOL_PUBKEY_SIZE];

/* Instruction types recognized by the parser */
typedef enum {
  SOL_INSTR_SYSTEM_TRANSFER,
  SOL_INSTR_SYSTEM_CREATE_ACCOUNT,
  SOL_INSTR_SYSTEM_ADVANCE_NONCE,
  SOL_INSTR_SYSTEM_WITHDRAW_NONCE,
  SOL_INSTR_SYSTEM_INITIALIZE_NONCE,
  SOL_INSTR_SYSTEM_AUTHORIZE_NONCE,
  SOL_INSTR_SYSTEM_ASSIGN,
  SOL_INSTR_SYSTEM_ALLOCATE,
  SOL_INSTR_TOKEN_TRANSFER,
  SOL_INSTR_TOKEN_TRANSFER_CHECKED,
  SOL_INSTR_TOKEN_APPROVE,
  SOL_INSTR_TOKEN_REVOKE,
  SOL_INSTR_TOKEN_SET_AUTHORITY,
  SOL_INSTR_TOKEN_MINT_TO,
  SOL_INSTR_TOKEN_BURN,
  SOL_INSTR_TOKEN_CLOSE_ACCOUNT,
  SOL_INSTR_TOKEN_FREEZE_ACCOUNT,
  SOL_INSTR_TOKEN_THAW_ACCOUNT,
  SOL_INSTR_TOKEN_SYNC_NATIVE,
  SOL_INSTR_STAKE_DELEGATE,
  SOL_INSTR_STAKE_WITHDRAW,
  SOL_INSTR_STAKE_AUTHORIZE,
  SOL_INSTR_STAKE_SPLIT,
  SOL_INSTR_STAKE_DEACTIVATE,
  SOL_INSTR_STAKE_MERGE,
  SOL_INSTR_VOTE_AUTHORIZE,
  SOL_INSTR_VOTE_WITHDRAW,
  SOL_INSTR_VOTE_UPDATE_VALIDATOR,
  SOL_INSTR_VOTE_UPDATE_COMMISSION,
  SOL_INSTR_ATA_CREATE,
  SOL_INSTR_COMPUTE_BUDGET_HEAP_FRAME,
  SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT,
  SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE,
  SOL_INSTR_COMPUTE_BUDGET_LOADED_ACCOUNTS_SIZE,
  SOL_INSTR_MEMO,
  SOL_INSTR_UNKNOWN,
} SolanaInstrType;

/* Parsed instruction */
typedef struct {
  SolanaInstrType type;
  uint8_t program_id[SOL_PUBKEY_SIZE];
  /* Decoded fields (filled based on type) */
  uint8_t from[SOL_PUBKEY_SIZE];
  uint8_t to[SOL_PUBKEY_SIZE];
  uint8_t authority[SOL_PUBKEY_SIZE];
  uint8_t extra[SOL_PUBKEY_SIZE];
  uint64_t amount;
  uint64_t lamports;
  uint64_t extra_value;
  /* For token transfers */
  uint8_t mint[SOL_PUBKEY_SIZE];
  bool has_mint;
  uint8_t extra_u8;
  /* Exact instruction bytes retained for variable-length verified fields
   * such as Memo. The parser bounds this slice inside the signed message. */
  const uint8_t* data;
  size_t data_len;
} SolanaParsedInstruction;

/* Parsed transaction header */
typedef struct {
  uint8_t num_required_sigs;
  uint8_t num_readonly_signed;
  uint8_t num_readonly_unsigned;
  uint8_t num_accounts;
  uint8_t accounts[SOL_MAX_ACCOUNTS][SOL_PUBKEY_SIZE];
  uint8_t recent_blockhash[SOL_PUBKEY_SIZE];
  uint8_t num_instructions;
  SolanaParsedInstruction instructions[SOL_MAX_INSTRUCTIONS];
} SolanaParsedTx;

/* Firmware review result for a Solana message */
typedef enum {
  SOL_TX_REVIEW_MALFORMED = 0,
  SOL_TX_REVIEW_OPAQUE,
  SOL_TX_REVIEW_VERIFIED,
} SolanaTxReview;

/* Inspect a raw Solana transaction and classify it for signing UX */
SolanaTxReview solana_inspectTx(const uint8_t* raw, size_t raw_len,
                                SolanaParsedTx* tx);

/* Parse a raw Solana transaction */
bool solana_parseTx(const uint8_t* raw, size_t raw_len, SolanaParsedTx* tx);

/* Format SOL amount */
void solana_formatAmount(char* buf, size_t len, uint64_t lamports);

/* Maximum priority fee in lamports. Uses the 1.4M-CU protocol cap when no
 * explicit limit is present. Returns false for duplicates or overflow. */
bool solana_calculatePriorityFee(const SolanaParsedTx* tx, uint64_t* fee_out,
                                 bool* has_fee);

/* Format token amount with decimals */
void solana_formatTokenAmount(char* buf, size_t len, uint64_t amount,
                              const char* symbol, uint8_t decimals);

/* Sign transaction */
bool solana_signTx(const HDNode* node, const SolanaSignTx* msg,
                   SolanaSignedTx* resp);

/* Sign a Solana off-chain message with domain separation.
 *
 * Builds the spec envelope (0xFF || "solana offchain" || version || format
 * || length:u16 || message) and Ed25519-signs it. Format 2 (extended
 * UTF-8) is rejected — only formats 0 (ASCII) and 1 (UTF-8 limited) are
 * supported on this device.
 *
 * Caller must have populated node->public_key (hdnode_fill_public_key).
 */
bool solana_offchain_message_sign(const HDNode* node,
                                  const SolanaSignOffchainMessage* msg,
                                  SolanaOffchainMessageSignature* resp);

#endif /* KEEPKEY_FIRMWARE_SOLANA_H */
