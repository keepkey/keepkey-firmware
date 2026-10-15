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
/* KKSOLSW1: max attested lookup-table accounts per tx; more than this is not
   meaningfully reviewable. */
#define SOL_MAX_LUT_ACCOUNTS 8
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
  uint16_t data_len;
  /* Same lifetime as `data`. */
  const uint8_t* acct_indices;
  uint8_t num_acct_indices;
  /* Uses a lookup table: accounts are unknowable on-device; no schema. */
  bool external;
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
  /* v0 message carries an address-table section (KKSOLSC1 refuses it). */
  bool has_lookup_tables;
  /* Addresses a v0 message's lookup tables load (writable + readonly); 0 for
   * legacy and zero-LUT messages. */
  uint32_t num_loaded_accounts;
} SolanaParsedTx;

/* Firmware review result for a Solana message */
typedef enum {
  SOL_TX_REVIEW_MALFORMED = 0,
  SOL_TX_REVIEW_OPAQUE,
  SOL_TX_REVIEW_VERIFIED,
} SolanaTxReview;

/* Firmware-owned tokens: only stable mint/decimals identities. */
typedef struct {
  uint8_t mint[SOL_PUBKEY_SIZE];
  const char* symbol;
  uint8_t decimals;
} SolanaKnownToken;

/* ── KKSOLSC1: reusable instruction schemas, attested once per (program,
 * discriminator); values are decoded from the signed bytes. Safety is
 * structural completeness: disc + arg widths == data length EXACTLY; every
 * displayed account index exists; no address-table section; every OTHER
 * instruction is a compute-budget or Memo companion.
 *
 * Canonical payload (every numeric field is one byte; text printable ASCII,
 * no '%'). The 8-byte instruction arguments it describes (U64, LAMPORTS,
 * TOKEN_AMOUNT, DURATION) are read little-endian, as Solana programs encode
 * them:
 *   magic          8   "KKSOLSC1"
 *   version        1   1 or 2
 *   program_id    32
 *   disc_len       1   1..8
 *   discriminator  disc_len
 *   program name   1 + 1..SOL_SCHEMA_NAME_MAX
 *   instr name     1 + 1..SOL_SCHEMA_NAME_MAX
 *   n_args         1   0..4 (v1), 0..SOL_SCHEMA_MAX_ARGS (v2)
 *     per arg:     type(1) label_len(1) label
 *     TOKEN_AMOUNT (v2) appends mint_account(1)
 *   n_accounts     1   0..SOL_SCHEMA_MAX_ACCOUNTS
 *     per account: index(1) label_len(1) label
 * No bytes may follow. Args are laid out sequentially from the end of the
 * discriminator, in declaration order.
 */
#define SOL_SCHEMA_NAME_MAX 20
#define SOL_SCHEMA_LABEL_MAX 16
#define SOL_SCHEMA_V1_MAX_ARGS 4
#define SOL_SCHEMA_MAX_ARGS 8
#define SOL_SCHEMA_MAX_ACCOUNTS 4
#define SOL_SCHEMA_DISC_MAX 8

typedef enum {
  SOL_SCHEMA_ARG_U64 = 1,          /* 8 bytes, shown as a decimal integer */
  SOL_SCHEMA_ARG_U8 = 2,           /* 1 byte */
  SOL_SCHEMA_ARG_PUBKEY = 3,       /* 32 bytes, shown base58 */
  SOL_SCHEMA_ARG_OPAQUE32 = 4,     /* 32 bytes, paged; non-printable as \xNN */
  SOL_SCHEMA_ARG_LAMPORTS = 5,     /* 8 bytes, shown as SOL */
  SOL_SCHEMA_ARG_TOKEN_AMOUNT = 6, /* 8 bytes; mint is an ix account */
  SOL_SCHEMA_ARG_DURATION = 7,     /* 8-byte seconds */
} SolanaSchemaArgType;

typedef struct {
  SolanaSchemaArgType type;
  char label[SOL_SCHEMA_LABEL_MAX + 1];
  uint8_t mint_account;
} SolanaSchemaArg;

typedef struct {
  uint8_t index;
  char label[SOL_SCHEMA_LABEL_MAX + 1];
} SolanaSchemaAccount;

typedef struct {
  uint8_t program_id[SOL_PUBKEY_SIZE];
  uint8_t disc[SOL_SCHEMA_DISC_MAX];
  uint8_t disc_len;
  char program_name[SOL_SCHEMA_NAME_MAX + 1];
  char instruction_name[SOL_SCHEMA_NAME_MAX + 1];
  SolanaSchemaArg args[SOL_SCHEMA_MAX_ARGS];
  uint8_t num_args;
  SolanaSchemaAccount accounts[SOL_SCHEMA_MAX_ACCOUNTS];
  uint8_t num_accounts;
} SolanaInstrSchema;

/* Bytes one arg consumes; 0 = unknown type (rejected). */
uint16_t solana_schemaArgWidth(SolanaSchemaArgType t);

bool solana_parseInstrSchema(const uint8_t* payload, size_t payload_len,
                             SolanaInstrSchema* out);

/* Find the described instruction and enforce the KKSOLSC1 safety rules
 * above; returns its index via `out_index`. */
bool solana_schemaApplies(const SolanaInstrSchema* schema,
                          const SolanaParsedTx* tx, uint8_t* out_index);

/* Inspect a raw Solana transaction and classify it for signing UX */
SolanaTxReview solana_inspectTx(const uint8_t* raw, size_t raw_len,
                                SolanaParsedTx* tx);

/* Plain text (printable ASCII or '\n') not containing `pubkey`, so it cannot
 * authorize a transaction. */
bool solana_rawMessageIsPlainText(const uint8_t* msg, size_t len,
                                  const uint8_t pubkey[SOL_PUBKEY_SIZE]);

/* Parse a raw Solana transaction */
bool solana_parseTx(const uint8_t* raw, size_t raw_len, SolanaParsedTx* tx);

/* Format SOL amount */
void solana_formatAmount(char* buf, size_t len, uint64_t lamports);

/* Format token amount with decimals */
void solana_formatTokenAmount(char* buf, size_t len, uint64_t amount,
                              const char* symbol, uint8_t decimals);

/* Look up a firmware-owned token identity by its signed mint account. */
const SolanaKnownToken* solana_findKnownToken(
    const uint8_t mint[SOL_PUBKEY_SIZE]);

/* Canonical SPL ATA for (owner, token_program, mint). */
bool solana_deriveAssociatedTokenAddress(
    const uint8_t owner[SOL_PUBKEY_SIZE],
    const uint8_t token_program[SOL_PUBKEY_SIZE],
    const uint8_t mint[SOL_PUBKEY_SIZE], uint8_t out[SOL_PUBKEY_SIZE]);

/* Accept a host-proposed owner only if its ATA equals the signed
 * destination; `out` is untouched on false. */
bool solana_findTokenRecipientOwner(
    const SolanaSignTx* msg, const uint8_t token_program[SOL_PUBKEY_SIZE],
    const uint8_t mint[SOL_PUBKEY_SIZE],
    const uint8_t destination[SOL_PUBKEY_SIZE], uint8_t out[SOL_PUBKEY_SIZE]);

/* Look up token info from the host-provided list */
const SolanaTokenInfo* solana_findTokenInfo(
    const SolanaSignTx* msg, const uint8_t mint[SOL_PUBKEY_SIZE]);

/* Valid user-loaded-signer attestation over (mint, decimals, symbol). The
 * caller must still match decimals to the signed instruction. */
bool solana_token_info_trusted(const SolanaTokenInfo* ti);

/* Label for a signed TransferChecked amount: the firmware-table symbol, or an
 * attested symbol whose decimals equal the signed ones; NULL otherwise. */
const char* solana_displaySymbol(const SolanaTokenInfo* ti,
                                 const SolanaKnownToken* known,
                                 uint8_t signed_decimals);

/* Solana per-transaction compute-unit cap; also bounds an explicit limit. */
#define SOL_MAX_COMPUTE_UNITS 1400000u

/* Compute-unit limit the runtime requests when SetComputeUnitLimit is absent
 * (an upper bound; the fee helper caps it at SOL_MAX_COMPUTE_UNITS). */
uint64_t solana_defaultComputeUnitLimit(const SolanaParsedTx* tx);

/* KKSOLSW1: is the LUT account list attested FOR THIS EXACT TRANSACTION?
 * LUT keys are not in the signed bytes, so unattested they force the tx
 * opaque. Domain-tagged and message-bound against replay:
 *
 *   "KeepKeySolanaTxAccounts/1" || sha256(message) || count(le32) || key[i](32)
 *
 * message = the bytes the device signs. Runtime signer: annotation only, the
 * caller still runs the unverified review. */
/// True iff an attestation listing `attested` accounts covers every account the
/// message's lookup tables load, so "describes N account(s)" is complete.
bool solana_lut_attestation_complete(const SolanaParsedTx* tx, size_t attested);

bool solana_lut_accounts_trusted(const uint8_t* raw_tx, size_t raw_len,
                                 const uint8_t (*accounts)[32],
                                 size_t num_accounts, uint32_t signer_key_id,
                                 const uint8_t* sig, size_t sig_len);

/* ceil(price * min(limit, SOL_MAX_COMPUTE_UNITS) / 1e6) lamports; false on
 * > UINT64_MAX (refuse). */
bool solana_priority_fee_lamports(uint64_t price, uint64_t limit,
                                  uint64_t* out);

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
