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
/* KKSOLSW1: how many lookup-table-resolved accounts a provider may attest for
   one transaction. Bounded because the preimage and the screens are both
   linear in it, and because a provider that needs to name more than eight
   accounts is describing something the user cannot meaningfully review. */
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
  /* Instruction payload (memo body display). Points into the raw message
   * buffer passed to solana_inspectTx — valid only while that buffer is. */
  const uint8_t* data;
  uint16_t data_len;
  /* Account index list, same lifetime as `data`. Needed to resolve a
   * KKSOLSC1 schema's labelled accounts back to real pubkeys. */
  const uint8_t* acct_indices;
  uint8_t num_acct_indices;
  /* True when this instruction reaches into an address-lookup table, so its
   * accounts are NOT present in the signed message. A schema must never be
   * applied to one: the pubkeys it would display are unknowable on-device. */
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
} SolanaParsedTx;

/* Firmware review result for a Solana message */
typedef enum {
  SOL_TX_REVIEW_MALFORMED = 0,
  SOL_TX_REVIEW_OPAQUE,
  SOL_TX_REVIEW_VERIFIED,
} SolanaTxReview;

/* Firmware-owned token definitions. These are intentionally tiny and only
 * cover identities whose mint and decimals are stable enough to be part of
 * the device's trusted display policy. */
typedef struct {
  uint8_t mint[SOL_PUBKEY_SIZE];
  const char* symbol;
  uint8_t decimals;
} SolanaKnownToken;

/* ── KKSOLSC1: reusable instruction schemas ───────────────────────────
 *
 * A schema says how to READ one program instruction — it carries no amounts
 * and no transaction hash. A trusted clearsign signer attests it ONCE per
 * (program, discriminator); every later transaction reuses the same blob and
 * the device decodes the values straight out of the bytes it is signing.
 *
 * Safety rests on structural completeness, not on binding to a transaction:
 *   - discriminator + the declared arg widths must equal the instruction
 *     data length EXACTLY, so no unaccounted byte can carry a second effect;
 *   - every account index the schema displays must exist in the instruction;
 *   - the instruction must not reach into a lookup table (see `external`);
 *   - and every OTHER instruction in the transaction must be one firmware
 *     already recognises, so a schema can never green-light a message whose
 *     real effect sits in an instruction nobody described.
 *
 * Canonical payload (all integers big-endian, text printable ASCII, no '%'):
 *   magic          8   "KKSOLSC1"
 *   version        1   = 1
 *   program_id    32
 *   disc_len       1   1..8
 *   discriminator  disc_len
 *   program name   1 + 1..SOL_SCHEMA_NAME_MAX
 *   instr name     1 + 1..SOL_SCHEMA_NAME_MAX
 *   n_args         1   0..SOL_SCHEMA_MAX_ARGS
 *     per arg:     type(1) label_len(1) label
 *   n_accounts     1   0..SOL_SCHEMA_MAX_ACCOUNTS
 *     per account: index(1) label_len(1) label
 * No bytes may follow. Args are laid out sequentially from the end of the
 * discriminator, in declaration order.
 */
#define SOL_SCHEMA_NAME_MAX 20
#define SOL_SCHEMA_LABEL_MAX 16
#define SOL_SCHEMA_MAX_ARGS 4
#define SOL_SCHEMA_MAX_ACCOUNTS 4
#define SOL_SCHEMA_DISC_MAX 8

typedef enum {
  SOL_SCHEMA_ARG_U64 = 1,      /* 8 bytes, shown as a decimal integer */
  SOL_SCHEMA_ARG_U8 = 2,       /* 1 byte */
  SOL_SCHEMA_ARG_PUBKEY = 3,   /* 32 bytes, shown base58 */
  SOL_SCHEMA_ARG_OPAQUE32 = 4, /* 32 bytes, shown truncated hex */
} SolanaSchemaArgType;

typedef struct {
  SolanaSchemaArgType type;
  char label[SOL_SCHEMA_LABEL_MAX + 1];
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

/* Parse a KKSOLSC1 payload. Validates every length and text field and
 * requires the payload to be consumed exactly. */
/* Byte width one schema arg consumes in the instruction data. 0 = unknown
 * type, which the parser rejects. */
uint16_t solana_schemaArgWidth(SolanaSchemaArgType t);

bool solana_parseInstrSchema(const uint8_t* payload, size_t payload_len,
                             SolanaInstrSchema* out);

/* Find the instruction this schema describes and prove it may be trusted:
 * program id + discriminator match, the schema accounts for the instruction
 * data exactly, its account indices are in range, the instruction is not
 * lookup-table backed, and every other instruction in `tx` is a program
 * firmware already decodes. Returns the matching index via `out_index`. */
bool solana_schemaApplies(const SolanaInstrSchema* schema,
                          const SolanaParsedTx* tx, uint8_t* out_index);

/* Inspect a raw Solana transaction and classify it for signing UX */
SolanaTxReview solana_inspectTx(const uint8_t* raw, size_t raw_len,
                                SolanaParsedTx* tx);

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

/* Derive the canonical SPL associated token account for
 * (owner, token_program, mint), using Solana's find_program_address rules. */
bool solana_deriveAssociatedTokenAddress(
    const uint8_t owner[SOL_PUBKEY_SIZE],
    const uint8_t token_program[SOL_PUBKEY_SIZE],
    const uint8_t mint[SOL_PUBKEY_SIZE], uint8_t out[SOL_PUBKEY_SIZE]);

/* Match a host-provided candidate owner only after deriving its ATA and
 * comparing it to the destination that is present in the signed instruction.
 * Returns the verified owner through out, or false without modifying out. */
bool solana_findTokenRecipientOwner(
    const SolanaSignTx* msg, const uint8_t token_program[SOL_PUBKEY_SIZE],
    const uint8_t mint[SOL_PUBKEY_SIZE],
    const uint8_t destination[SOL_PUBKEY_SIZE], uint8_t out[SOL_PUBKEY_SIZE]);

/* Look up token info from the host-provided list */
const SolanaTokenInfo* solana_findTokenInfo(
    const SolanaSignTx* msg, const uint8_t mint[SOL_PUBKEY_SIZE]);

/* True iff `ti` carries a valid attestation: an ECDSA signature (by a clearsign
 * signer the user loaded) over a domain-separated (mint, decimals, symbol)
 * digest. Range-checks signer_key_id before narrowing it. Verifies only the
 * attested tuple — the caller must additionally confirm the attested decimals
 * match the signed instruction before trusting the amount. */
bool solana_token_info_trusted(const SolanaTokenInfo* ti);

/* KKSOLSW1: is the host-supplied lookup-table account list attested by a
 * clear-sign signer FOR THIS EXACT TRANSACTION?
 *
 * A v0 message may source instruction accounts from an Address Lookup Table.
 * Those bytes are not in the message being signed, so the device cannot derive
 * them and forces the whole transaction opaque -- refused without AdvancedMode,
 * an explicit blind sign with it. A provider may instead attest the resolved
 * list, turning that blind sign into a clear sign.
 *
 * Preimage, domain-tagged so a signature made for any other purpose cannot be
 * replayed as one, and bound to the message so it cannot be replayed onto a
 * different transaction:
 *
 *   "KeepKeySolanaTxAccounts/1" || sha256(raw_tx) || count(le32) || key[i](32)
 *
 * Returns false unless a signer is loaded for `key_id` and the signature
 * verifies. Annotation only: the caller still runs the unverified review. */
bool solana_lut_accounts_trusted(const uint8_t* raw_tx, size_t raw_len,
                                 const uint8_t (*accounts)[32],
                                 size_t num_accounts, uint32_t signer_key_id,
                                 const uint8_t* sig, size_t sig_len);

/* ceil(price * limit / 1,000,000) priority-fee lamports, overflow-safe. Returns
 * false (and leaves *out untouched) if the true value exceeds UINT64_MAX — the
 * caller must then refuse to sign rather than display a wrapped figure. */
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
