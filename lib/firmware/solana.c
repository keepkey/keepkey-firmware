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

#include "keepkey/firmware/solana.h"

#include "keepkey/board/layout.h"

#include "keepkey/firmware/clearsign_root.h"
#include "keepkey/firmware/signed_metadata.h"
#include "trezor/crypto/base58.h"
#include "trezor/crypto/ed25519-donna/ed25519-donna.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/sha2.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Well-known program IDs                                             */
/* ------------------------------------------------------------------ */

/* 11111111111111111111111111111111 */
const uint8_t SOL_SYSTEM_PROGRAM[SOL_PUBKEY_SIZE] = {0};

/* TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA */
const uint8_t SOL_TOKEN_PROGRAM[SOL_PUBKEY_SIZE] = {
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93, 0xd9, 0xcb, 0xe1,
    0x46, 0xce, 0xeb, 0x79, 0xac, 0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b,
    0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9};

/* TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb */
const uint8_t SOL_TOKEN_2022_PROGRAM[SOL_PUBKEY_SIZE] = {
    0x06, 0xdd, 0xf6, 0xe1, 0xee, 0x75, 0x8f, 0xde, 0x18, 0x42, 0x5d,
    0xbc, 0xe4, 0x6c, 0xcd, 0xda, 0xb6, 0x1a, 0xfc, 0x4d, 0x83, 0xb9,
    0x0d, 0x27, 0xfe, 0xbd, 0xf9, 0x28, 0xd8, 0xa1, 0x8b, 0xfc};

/* Stake11111111111111111111111111111111111111 */
const uint8_t SOL_STAKE_PROGRAM[SOL_PUBKEY_SIZE] = {
    0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x2a, 0x98, 0x34, 0x37,
    0xbd, 0xfe, 0x2a, 0x7a, 0xb2, 0x55, 0x7f, 0x53, 0x5c, 0x8a, 0x78,
    0x72, 0x2b, 0x68, 0xa4, 0x9d, 0xc0, 0x00, 0x00, 0x00, 0x00};

/* Vote111111111111111111111111111111111111111 */
const uint8_t SOL_VOTE_PROGRAM[SOL_PUBKEY_SIZE] = {
    0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb, 0x7c, 0x4d, 0x76,
    0x24, 0xeb, 0xd3, 0xbd, 0xb3, 0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10,
    0x43, 0xfc, 0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00};

/* ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL */
const uint8_t SOL_ATA_PROGRAM[SOL_PUBKEY_SIZE] = {
    0x8c, 0x97, 0x25, 0x8f, 0x4e, 0x24, 0x89, 0xf1, 0xbb, 0x3d, 0x10,
    0x29, 0x14, 0x8e, 0x0d, 0x83, 0x0b, 0x5a, 0x13, 0x99, 0xda, 0xff,
    0x10, 0x84, 0x04, 0x8e, 0x7b, 0xd8, 0xdb, 0xe9, 0xf8, 0x59};

/* ComputeBudget111111111111111111111111111111 */
const uint8_t SOL_COMPUTE_BUDGET_PROGRAM[SOL_PUBKEY_SIZE] = {
    0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32, 0xff, 0xec, 0xad,
    0xba, 0x72, 0xc3, 0x9b, 0xe7, 0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7,
    0x12, 0x6b, 0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, 0x00, 0x00};

/* MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr */
const uint8_t SOL_MEMO_PROGRAM[SOL_PUBKEY_SIZE] = {
    0x05, 0x4a, 0x53, 0x5a, 0x99, 0x29, 0x21, 0x06, 0x4d, 0x24, 0xe8,
    0x71, 0x60, 0xda, 0x38, 0x7c, 0x7c, 0x35, 0xb5, 0xdd, 0xbc, 0x92,
    0xbb, 0x81, 0xe4, 0x1f, 0xa8, 0x40, 0x41, 0x05, 0x44, 0x8d};

/* Circle's mainnet SPL USDC mint:
 * EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v. */
static const SolanaKnownToken SOL_KNOWN_TOKENS[] = {{
    {0xc6, 0xfa, 0x7a, 0xf3, 0xbe, 0xdb, 0xad, 0x3a, 0x3d, 0x65, 0xf3,
     0x6a, 0xab, 0xc9, 0x74, 0x31, 0xb1, 0xbb, 0xe4, 0xc2, 0xd2, 0xf6,
     0xe0, 0xe4, 0x7c, 0xa6, 0x02, 0x03, 0x45, 0x2f, 0x5d, 0x61},
    "USDC",
    6,
}};

static const char SOL_PDA_MARKER[] = "ProgramDerivedAddress";

/* ------------------------------------------------------------------ */
/*  Compact-u16 decoder (Solana transaction format)                    */
/* ------------------------------------------------------------------ */

static int read_compact_u16(const uint8_t* data, size_t len, uint16_t* out) {
  if (len < 1) return -1;

  if (data[0] < SOL_COMPACT_U16_CONTINUATION) {
    *out = data[0];
    return 1;
  }

  if (len < 2) return -1;
  if (data[1] < SOL_COMPACT_U16_CONTINUATION) {
    *out = (uint16_t)((data[0] & SOL_COMPACT_U16_DATA_MASK) |
                      ((uint16_t)data[1] << 7));
    return 2;
  }

  if (len < 3) return -1;
  /* Third byte uses bits 14-15, so only values 0-3 are valid
   * (max compact-u16 value is 0xFFFF = 65535). */
  if (data[2] > SOL_COMPACT_U16_BYTE3_MAX) return -1;
  *out = (uint16_t)((data[0] & SOL_COMPACT_U16_DATA_MASK) |
                    ((data[1] & SOL_COMPACT_U16_DATA_MASK) << 7) |
                    ((uint16_t)data[2] << 14));
  return 3;
}

static uint64_t read_le64(const uint8_t* p) {
  return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
         ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
         ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
         ((uint64_t)p[7] << 56);
}

static uint32_t read_le32(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static void copy_account(uint8_t out[SOL_PUBKEY_SIZE], const SolanaParsedTx* tx,
                         const uint8_t* acct_indices, uint16_t num_acct_indices,
                         uint16_t idx) {
  if (idx < num_acct_indices) {
    memcpy(out, tx->accounts[acct_indices[idx]], SOL_PUBKEY_SIZE);
  }
}

/* allow_external_indices: v0 lookup-table accounts (index >= static list)
 * cannot be verified, so they force the tx opaque. Never valid in legacy.
 * Program ids must always be static. *accounts_needed is one past the highest
 * account operand index, so the caller can bound it once the loaded-account
 * count is known. */
static int parse_instruction_section(const uint8_t* raw, size_t raw_len,
                                     size_t* pos_io, SolanaParsedTx* tx,
                                     uint16_t num_accounts, bool* has_unknown,
                                     bool* force_opaque,
                                     bool allow_external_indices,
                                     uint16_t* accounts_needed) {
  size_t pos = *pos_io;
  uint16_t num_instructions;
  int n = read_compact_u16(raw + pos, raw_len - pos, &num_instructions);
  if (n < 0) return -1;
  pos += n;

  if (num_instructions > SOL_MAX_INSTRUCTIONS) {
    /* Too many to display: opaque, but keep walking for structural checks. */
    *force_opaque = true;
    tx->num_instructions = 0;
  } else {
    tx->num_instructions = (uint8_t)num_instructions;
  }

  bool seen_compute_limit = false;
  bool seen_compute_price = false;
  *accounts_needed = 0;

  for (uint16_t i = 0; i < num_instructions; i++) {
    if (pos >= raw_len) return -1;
    uint8_t program_idx = raw[pos++];
    /* Solana invokes only static program ids, never a lookup-table key, a
     * certified one included. */
    if (program_idx >= num_accounts || program_idx >= tx->num_static_accounts)
      return -1;
    bool external = false;

    uint16_t num_acct_indices;
    n = read_compact_u16(raw + pos, raw_len - pos, &num_acct_indices);
    if (n < 0) return -1;
    pos += n;

    if (pos + num_acct_indices > raw_len) return -1;
    const uint8_t* acct_indices = raw + pos;
    pos += num_acct_indices;

    for (uint16_t j = 0; j < num_acct_indices; j++) {
      if (acct_indices[j] >= *accounts_needed)
        *accounts_needed = (uint16_t)acct_indices[j] + 1;
      if (acct_indices[j] >= num_accounts) {
        if (!allow_external_indices) return -1;
        external = true;
      }
    }

    uint16_t data_len;
    n = read_compact_u16(raw + pos, raw_len - pos, &data_len);
    if (n < 0) return -1;
    pos += n;

    if (pos + data_len > raw_len) return -1;
    const uint8_t* instr_data = raw + pos;
    pos += data_len;

    if (i >= SOL_MAX_INSTRUCTIONS || tx->num_instructions == 0) {
      continue;
    }

    SolanaParsedInstruction* pi = &tx->instructions[i];

    /* For KKSOLSC1 schemas; both point into the caller's raw buffer. */
    pi->data = instr_data;
    pi->data_len = data_len;
    pi->acct_indices = acct_indices;
    pi->num_acct_indices =
        num_acct_indices > 255 ? 255 : (uint8_t)num_acct_indices;

    if (external) {
      /* Accounts resolved via lookup tables: unverifiable on-device. */
      pi->type = SOL_INSTR_UNKNOWN;
      pi->external = true;
      *force_opaque = true;
      continue;
    }

    memcpy(pi->program_id, tx->accounts[program_idx], SOL_PUBKEY_SIZE);

    /* Classify and decode */
    /* Every fixed-layout decoder below matches its data length EXACTLY, never
     * `>=`.
     *
     * A `>=` gate decodes the prefix it understands and lets the rest through:
     * solana_signTx() signs the whole raw_tx, so trailing bytes on a recognised
     * instruction were covered by the signature, shown on no screen, and -- the
     * part that matters -- did NOT set *has_unknown, so the transaction was
     * never classified opaque and never met the blind-sign gate. The runtime
     * ignoring those bytes (SPL's unpack reads its fields and drops the tail)
     * is what makes them attractive rather than harmless: free to append, and
     * the device vouches for them.
     *
     * So the rule is: decode only an encoding this device can account for
     * byte-for-byte. Anything else is UNKNOWN, which is not a refusal -- it
     * routes to the opaque path, where the user is told the contents cannot be
     * verified. An encoder that pads therefore loses clear-signing, not the
     * ability to sign.
     *
     * Each gate is the exact number of bytes that decoder reads and can account
     * for. Three of them are not merely the old bound tightened, so they are
     * worth naming:
     *
     *   System CreateAccount is 52 (u32 tag + u64 lamports + u64 space +
     *   Pubkey owner). This code accepted 12 while reading only lamports, so
     *   the space and owner it never looked at were signed unseen.
     *
     *   SPL SetAuthority is 3 or 35, and which one is fixed by its COption
     *   discriminant: a `Some` with no key, or a `None` carrying 32 bytes, is
     *   not an encoding this device can claim to have read.
     *
     *   Stake Authorize is 40. The old `>= 36` let read_le32(instr_data + 36)
     *   run off the end of a 36..39-byte field and report whatever followed it
     *   in the buffer as the authorization type.
     *
     * The ATA branch below already worked this way. */
    if (memcmp(pi->program_id, SOL_SYSTEM_PROGRAM, SOL_PUBKEY_SIZE) == 0) {
      /* System program */
      if (data_len >= 4) {
        uint32_t instr_type = read_le32(instr_data);
        if (instr_type == SOL_SYS_TRANSFER && data_len == 12 &&
            num_acct_indices >= 2) {
          pi->type = SOL_INSTR_SYSTEM_TRANSFER;
          pi->lamports = read_le64(instr_data + 4);
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
        } else if (instr_type == SOL_SYS_CREATE_ACCOUNT && data_len == 52 &&
                   num_acct_indices >= 2) {
          pi->type = SOL_INSTR_SYSTEM_CREATE_ACCOUNT;
          pi->lamports = read_le64(instr_data + 4);
          pi->extra_value = read_le64(instr_data + 12);
          memcpy(pi->extra, instr_data + 20, SOL_PUBKEY_SIZE);
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
        } else if (instr_type == SOL_SYS_ADVANCE_NONCE && data_len == 4 &&
                   num_acct_indices >= 3) {
          pi->type = SOL_INSTR_SYSTEM_ADVANCE_NONCE;
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
        } else if (instr_type == SOL_SYS_WITHDRAW_NONCE && data_len == 12 &&
                   num_acct_indices >= 5) {
          pi->type = SOL_INSTR_SYSTEM_WITHDRAW_NONCE;
          pi->lamports = read_le64(instr_data + 4);
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 4);
        } else if (instr_type == SOL_SYS_INITIALIZE_NONCE && data_len == 36 &&
                   num_acct_indices >= 3) {
          pi->type = SOL_INSTR_SYSTEM_INITIALIZE_NONCE;
          memcpy(pi->authority, instr_data + 4, SOL_PUBKEY_SIZE);
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
        } else if (instr_type == SOL_SYS_AUTHORIZE_NONCE && data_len == 36 &&
                   num_acct_indices >= 2) {
          pi->type = SOL_INSTR_SYSTEM_AUTHORIZE_NONCE;
          memcpy(pi->extra, instr_data + 4, SOL_PUBKEY_SIZE);
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 1);
        } else if (instr_type == SOL_SYS_ASSIGN && data_len == 36 &&
                   num_acct_indices >= 1) {
          pi->type = SOL_INSTR_SYSTEM_ASSIGN;
          memcpy(pi->extra, instr_data + 4, SOL_PUBKEY_SIZE);
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
        } else if (instr_type == SOL_SYS_ALLOCATE && data_len == 12 &&
                   num_acct_indices >= 1) {
          pi->type = SOL_INSTR_SYSTEM_ALLOCATE;
          pi->extra_value = read_le64(instr_data + 4);
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
        } else {
          pi->type = SOL_INSTR_UNKNOWN;
          *has_unknown = true;
        }
      } else {
        pi->type = SOL_INSTR_UNKNOWN;
        *has_unknown = true;
      }
    } else if (memcmp(pi->program_id, SOL_TOKEN_PROGRAM, SOL_PUBKEY_SIZE) ==
                   0 ||
               memcmp(pi->program_id, SOL_TOKEN_2022_PROGRAM,
                      SOL_PUBKEY_SIZE) == 0) {
      /* Token-2022 hooks and fees cannot be shown: opaque (AdvancedMode). */
      const bool is_token2022 =
          memcmp(pi->program_id, SOL_TOKEN_2022_PROGRAM, SOL_PUBKEY_SIZE) == 0;
      if (is_token2022) *force_opaque = true;
      if (data_len >= 1) {
        uint8_t token_instr = instr_data[0];
        if (token_instr == SOL_TOKEN_TRANSFER_IX && data_len == 9 &&
            num_acct_indices >= 3) {
          pi->type = SOL_INSTR_TOKEN_TRANSFER;
          pi->amount = read_le64(instr_data + 1);
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
          /* Unchecked Transfer carries no signed mint or decimals. The device
           * cannot identify what asset the amount moves. */
          *force_opaque = true;
        } else if (token_instr == SOL_TOKEN_TRANSFER_CHECKED_IX &&
                   data_len == 10 && num_acct_indices >= 4) {
          /* Canonical data only: opcode + amount(8) + decimals(1). Accounts
           * [source, mint, dest, authority], then any multisig signers. */
          pi->type = SOL_INSTR_TOKEN_TRANSFER_CHECKED;
          pi->amount = read_le64(instr_data + 1);
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->mint, tx, acct_indices, num_acct_indices, 1);
          pi->has_mint = true;
          copy_account(pi->to, tx, acct_indices, num_acct_indices, 2);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 3);
          /* Decimals live in the signed instruction bytes and are the only
           * authoritative scale for this transfer, so they must never be
           * fabricated. A real TransferChecked data field is exactly 10 bytes
           * (tag + u64 amount + decimals); anything else -- short OR long --
           * falls through to SOL_INSTR_UNKNOWN and the transaction is treated
           * as opaque. */
          pi->extra_u8 = instr_data[9];
        } else if (token_instr == SOL_TOKEN_APPROVE_IX && data_len == 9 &&
                   num_acct_indices >= 3) {
          pi->type = SOL_INSTR_TOKEN_APPROVE;
          pi->amount = read_le64(instr_data + 1);
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
          /* Unchecked Approve likewise carries no mint. */
          *force_opaque = true;
        } else if (token_instr == SOL_TOKEN_REVOKE_IX && data_len == 1 &&
                   num_acct_indices >= 2) {
          pi->type = SOL_INSTR_TOKEN_REVOKE;
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 1);
        } else if (token_instr == SOL_TOKEN_SET_AUTHORITY_IX &&
                   num_acct_indices >= 2 &&
                   ((data_len == 3 && instr_data[2] == 0) ||
                    (data_len == 35 && instr_data[2] == 1))) {
          /* tag + authority_type + COption<Pubkey>: 3 bytes for None, 35 for
             Some. The discriminant and the length must agree -- a `Some` with
             no key, or a `None` carrying 32 bytes, is not an encoding this
             device can claim to have read. */
          pi->type = SOL_INSTR_TOKEN_SET_AUTHORITY;
          pi->extra_u8 = instr_data[1];
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 1);
          if (instr_data[2] == 1) {
            memcpy(pi->extra, instr_data + 3, SOL_PUBKEY_SIZE);
          }
          /* The authority role, target and permanent None revocation require a
           * dedicated complete UX. Until then this is opaque-only. */
          *force_opaque = true;
        } else if (((token_instr == SOL_TOKEN_MINT_TO_IX && data_len == 9) ||
                    (token_instr == SOL_TOKEN_MINT_TO_CHECKED_IX &&
                     data_len == 10)) &&
                   num_acct_indices >= 3) {
          pi->type = SOL_INSTR_TOKEN_MINT_TO;
          pi->amount = read_le64(instr_data + 1);
          copy_account(pi->mint, tx, acct_indices, num_acct_indices, 0);
          pi->has_mint = true;
          copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
          pi->extra_u8 =
              (token_instr == SOL_TOKEN_MINT_TO_CHECKED_IX) ? instr_data[9] : 0;
          /* The shared confirmation does not distinguish checked from
           * unchecked minting. Until it does, raw review is the only honest
           * representation of the signed opcode and scale. */
          *force_opaque = true;
        } else if (((token_instr == SOL_TOKEN_BURN_IX && data_len == 9) ||
                    (token_instr == SOL_TOKEN_BURN_CHECKED_IX &&
                     data_len == 10)) &&
                   num_acct_indices >= 3) {
          pi->type = SOL_INSTR_TOKEN_BURN;
          pi->amount = read_le64(instr_data + 1);
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->mint, tx, acct_indices, num_acct_indices, 1);
          pi->has_mint = true;
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
          pi->extra_u8 =
              (token_instr == SOL_TOKEN_BURN_CHECKED_IX) ? instr_data[9] : 0;
          /* As with minting, do not clear-sign an opcode whose signed decimals
           * are not represented by the confirmation path. */
          *force_opaque = true;
        } else if (token_instr == SOL_TOKEN_CLOSE_ACCOUNT_IX && data_len == 1 &&
                   num_acct_indices >= 3) {
          pi->type = SOL_INSTR_TOKEN_CLOSE_ACCOUNT;
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
        } else if (token_instr == SOL_TOKEN_FREEZE_ACCOUNT_IX &&
                   data_len == 1 && num_acct_indices >= 3) {
          pi->type = SOL_INSTR_TOKEN_FREEZE_ACCOUNT;
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->mint, tx, acct_indices, num_acct_indices, 1);
          pi->has_mint = true;
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
        } else if (token_instr == SOL_TOKEN_THAW_ACCOUNT_IX && data_len == 1 &&
                   num_acct_indices >= 3) {
          pi->type = SOL_INSTR_TOKEN_THAW_ACCOUNT;
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->mint, tx, acct_indices, num_acct_indices, 1);
          pi->has_mint = true;
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
        } else if (token_instr == SOL_TOKEN_SYNC_NATIVE_IX && data_len == 1 &&
                   num_acct_indices >= 1) {
          pi->type = SOL_INSTR_TOKEN_SYNC_NATIVE;
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
        } else {
          pi->type = SOL_INSTR_UNKNOWN;
          *has_unknown = true;
        }
      } else {
        pi->type = SOL_INSTR_UNKNOWN;
        *has_unknown = true;
      }
    } else if (memcmp(pi->program_id, SOL_STAKE_PROGRAM, SOL_PUBKEY_SIZE) ==
               0) {
      if (data_len >= 4) {
        uint32_t stake_instr = read_le32(instr_data);
        if (stake_instr == SOL_STAKE_DELEGATE_IX && data_len == 4 &&
            num_acct_indices >= 6) {
          pi->type = SOL_INSTR_STAKE_DELEGATE;
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 5);
          copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
        } else if (stake_instr == SOL_STAKE_WITHDRAW_IX && data_len == 12 &&
                   num_acct_indices >= 5) {
          pi->type = SOL_INSTR_STAKE_WITHDRAW;
          pi->lamports = read_le64(instr_data + 4);
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 4);
        } else if (stake_instr == SOL_STAKE_AUTHORIZE_IX && data_len == 40 &&
                   num_acct_indices >= 3) {
          /* new_authority(32) at +4 then authorize_type(le32) at +36. */
          uint32_t role = read_le32(instr_data + 36);
          if (role <= 1) {
            pi->type = SOL_INSTR_STAKE_AUTHORIZE;
            memcpy(pi->extra, instr_data + 4, SOL_PUBKEY_SIZE);
            copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
            /* Canonical accounts: stake, clock sysvar, current authority. */
            copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
            pi->extra_u8 = (uint8_t)role;
          } else {
            pi->type = SOL_INSTR_UNKNOWN;
            *has_unknown = true;
          }
        } else if (stake_instr == SOL_STAKE_SPLIT_IX && data_len == 12 &&
                   num_acct_indices >= 3) {
          pi->type = SOL_INSTR_STAKE_SPLIT;
          pi->lamports = read_le64(instr_data + 4);
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
        } else if (stake_instr == SOL_STAKE_DEACTIVATE_IX && data_len == 4 &&
                   num_acct_indices >= 3) {
          pi->type = SOL_INSTR_STAKE_DEACTIVATE;
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
        } else if (stake_instr == SOL_STAKE_MERGE_IX && data_len == 4 &&
                   num_acct_indices >= 5) {
          pi->type = SOL_INSTR_STAKE_MERGE;
          copy_account(pi->to, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 1);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 4);
        } else {
          pi->type = SOL_INSTR_UNKNOWN;
          *has_unknown = true;
        }
      } else {
        pi->type = SOL_INSTR_UNKNOWN;
        *has_unknown = true;
      }
    } else if (memcmp(pi->program_id, SOL_VOTE_PROGRAM, SOL_PUBKEY_SIZE) == 0) {
      if (data_len >= 4) {
        uint32_t vote_instr = read_le32(instr_data);
        if (vote_instr == SOL_VOTE_AUTHORIZE_IX && data_len == 40 &&
            num_acct_indices >= 3) {
          uint32_t role = read_le32(instr_data + 36);
          if (role <= 1) {
            pi->type = SOL_INSTR_VOTE_AUTHORIZE;
            memcpy(pi->extra, instr_data + 4, SOL_PUBKEY_SIZE);
            copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
            /* Canonical accounts: vote, clock sysvar, current authority. */
            copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
            pi->extra_u8 = (uint8_t)role;
          } else {
            pi->type = SOL_INSTR_UNKNOWN;
            *has_unknown = true;
          }
        } else if (vote_instr == SOL_VOTE_WITHDRAW_IX && data_len == 12 &&
                   num_acct_indices >= 3) {
          pi->type = SOL_INSTR_VOTE_WITHDRAW;
          pi->lamports = read_le64(instr_data + 4);
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
        } else if (vote_instr == SOL_VOTE_UPDATE_VALIDATOR_IX &&
                   data_len == 4 && num_acct_indices >= 3) {
          /* No data payload: the new validator is account 1, never trailing
           * data bytes. */
          pi->type = SOL_INSTR_VOTE_UPDATE_VALIDATOR;
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->extra, tx, acct_indices, num_acct_indices, 1);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
        } else if (vote_instr == SOL_VOTE_UPDATE_COMMISSION_IX &&
                   data_len == 5 && num_acct_indices >= 2) {
          pi->type = SOL_INSTR_VOTE_UPDATE_COMMISSION;
          pi->extra_u8 = instr_data[4];
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 1);
        } else {
          pi->type = SOL_INSTR_UNKNOWN;
          *has_unknown = true;
        }
      } else {
        pi->type = SOL_INSTR_UNKNOWN;
        *has_unknown = true;
      }
    } else if (memcmp(pi->program_id, SOL_ATA_PROGRAM, SOL_PUBKEY_SIZE) == 0) {
      /* Empty or 0 = Create, 1 = CreateIdempotent (same accounts and effect,
       * so it displays identically). */
      if (data_len == 0 ||
          (data_len == 1 && (instr_data[0] == 0 || instr_data[0] == 1))) {
        pi->type = SOL_INSTR_ATA_CREATE;
        copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
        copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
        copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
        copy_account(pi->mint, tx, acct_indices, num_acct_indices, 3);
        pi->has_mint = (num_acct_indices >= 4);
        /* Only the canonical six-account legacy-token form is verified. */
        if (num_acct_indices < 6 ||
            memcmp(tx->accounts[acct_indices[4]], SOL_SYSTEM_PROGRAM,
                   SOL_PUBKEY_SIZE) != 0 ||
            memcmp(tx->accounts[acct_indices[5]], SOL_TOKEN_PROGRAM,
                   SOL_PUBKEY_SIZE) != 0) {
          *force_opaque = true;
        }
      } else {
        pi->type = SOL_INSTR_UNKNOWN;
        *has_unknown = true;
      }
    } else if (memcmp(pi->program_id, SOL_COMPUTE_BUDGET_PROGRAM,
                      SOL_PUBKEY_SIZE) == 0) {
      if (data_len >= 1) {
        uint8_t cb_instr = instr_data[0];
        if (cb_instr == SOL_CB_REQUEST_HEAP_FRAME && data_len == 5) {
          pi->type = SOL_INSTR_COMPUTE_BUDGET_HEAP_FRAME;
          pi->extra_value = read_le32(instr_data + 1);
        } else if (cb_instr == SOL_CB_SET_COMPUTE_UNIT_LIMIT && data_len == 5) {
          if (seen_compute_limit) return -1;
          seen_compute_limit = true;
          pi->type = SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT;
          pi->extra_value = read_le32(instr_data + 1);
        } else if (cb_instr == SOL_CB_SET_COMPUTE_UNIT_PRICE && data_len == 9) {
          if (seen_compute_price) return -1;
          seen_compute_price = true;
          pi->type = SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE;
          pi->extra_value = read_le64(instr_data + 1);
        } else if (cb_instr == SOL_CB_SET_LOADED_ACCOUNTS_SIZE &&
                   data_len == 5) {
          pi->type = SOL_INSTR_COMPUTE_BUDGET_LOADED_ACCOUNTS_SIZE;
          pi->extra_value = read_le32(instr_data + 1);
        } else {
          pi->type = SOL_INSTR_UNKNOWN;
          *has_unknown = true;
        }
      } else {
        pi->type = SOL_INSTR_UNKNOWN;
        *has_unknown = true;
      }
    } else if (memcmp(pi->program_id, SOL_MEMO_PROGRAM, SOL_PUBKEY_SIZE) == 0) {
      pi->type = SOL_INSTR_MEMO;
      pi->data = instr_data;
      pi->data_len = data_len;
    } else {
      pi->type = SOL_INSTR_UNKNOWN;
      *has_unknown = true;
    }
  }

  *pos_io = pos;
  return num_instructions;
}

/* ------------------------------------------------------------------ */
/*  Transaction parser                                                 */
/* ------------------------------------------------------------------ */

/* Solana's message sanitize rules for the header: a writable signer (the fee
 * payer) exists, and the signer and read-only unsigned ranges fit inside the
 * static keys without overlapping. Checked before any review classification,
 * since even an opaque message is signable under AdvancedMode. */
static bool solana_header_ok(const SolanaParsedTx* tx, uint16_t num_accounts) {
  return tx->num_readonly_signed < tx->num_required_sigs &&
         (uint16_t)tx->num_required_sigs + tx->num_readonly_unsigned <=
             num_accounts;
}

/* More static keys than accounts[] holds: too many to review, so opaque
 * (AdvancedMode blind-sign; a real transaction is never refused). Signers come
 * first in the key list, so only they are loaded: num_accounts stays nonzero
 * and the fsm still requires the derived key to be a signer (F-715-1). More
 * than SOL_MAX_ACCOUNTS signers cannot fit a Solana packet: MALFORMED. */
static SolanaTxReview solana_oversizedKeyListIsOpaque(const uint8_t* raw,
                                                      size_t raw_len,
                                                      size_t pos,
                                                      uint16_t num_accounts,
                                                      SolanaParsedTx* tx) {
  if (tx->num_required_sigs > SOL_MAX_ACCOUNTS ||
      raw_len - pos < ((size_t)num_accounts + 1) * SOL_PUBKEY_SIZE) {
    return SOL_TX_REVIEW_MALFORMED; /* keys + blockhash must be present */
  }
  memcpy(tx->accounts, raw + pos,
         (size_t)tx->num_required_sigs * SOL_PUBKEY_SIZE);
  tx->num_accounts = tx->num_required_sigs;
  tx->num_static_accounts = tx->num_required_sigs;
  return SOL_TX_REVIEW_OPAQUE;
}

static SolanaTxReview solana_parseLegacyTx(const uint8_t* raw, size_t raw_len,
                                           SolanaParsedTx* tx) {
  memset(tx, 0, sizeof(*tx));
  size_t pos = 0;
  bool has_unknown = false;
  bool force_opaque = false;

  /* Header: num_required_sigs, num_readonly_signed, num_readonly_unsigned */
  if (raw_len < 3) return SOL_TX_REVIEW_MALFORMED;
  tx->num_required_sigs = raw[pos++];
  tx->num_readonly_signed = raw[pos++];
  tx->num_readonly_unsigned = raw[pos++];

  /* Account keys count (compact-u16) */
  uint16_t num_accounts;
  int n = read_compact_u16(raw + pos, raw_len - pos, &num_accounts);
  if (n < 0) return SOL_TX_REVIEW_MALFORMED;
  pos += n;
  if (!solana_header_ok(tx, num_accounts)) return SOL_TX_REVIEW_MALFORMED;

  /* Never stored as a truncated (uint8_t) count: that would let
     solana_signerInTx() read past accounts[] or wrap to 0 and skip the signer
     check (#550). */
  if (num_accounts > SOL_MAX_ACCOUNTS)
    return solana_oversizedKeyListIsOpaque(raw, raw_len, pos, num_accounts, tx);
  tx->num_accounts = (uint8_t)num_accounts;
  tx->num_static_accounts = (uint8_t)num_accounts;

  /* Read account keys */
  for (uint16_t i = 0; i < num_accounts; i++) {
    if (pos + SOL_PUBKEY_SIZE > raw_len) return SOL_TX_REVIEW_MALFORMED;
    memcpy(tx->accounts[i], raw + pos, SOL_PUBKEY_SIZE);
    pos += SOL_PUBKEY_SIZE;
  }

  /* Recent blockhash */
  if (pos + SOL_PUBKEY_SIZE > raw_len) return SOL_TX_REVIEW_MALFORMED;
  memcpy(tx->recent_blockhash, raw + pos, SOL_PUBKEY_SIZE);
  pos += SOL_PUBKEY_SIZE;

  uint16_t accounts_needed;
  n = parse_instruction_section(
      raw, raw_len, &pos, tx, num_accounts, &has_unknown, &force_opaque,
      /*allow_external_indices=*/false, &accounts_needed);
  if (n < 0) return SOL_TX_REVIEW_MALFORMED;

  /* Reject if there are unconsumed bytes — prevents hidden trailing data */
  if (pos != raw_len) return SOL_TX_REVIEW_MALFORMED;

  if (tx->num_instructions == 0 || has_unknown || force_opaque) {
    return SOL_TX_REVIEW_OPAQUE;
  }
  return SOL_TX_REVIEW_VERIFIED;
}

static SolanaTxReview solana_parseVersionedTx(
    const uint8_t* raw, size_t raw_len,
    const uint8_t (*trusted_lut_accounts)[SOL_PUBKEY_SIZE],
    size_t trusted_lut_count, SolanaParsedTx* tx) {
  memset(tx, 0, sizeof(*tx));
  size_t pos = 0;
  bool has_unknown = false;
  bool force_opaque = false;

  if (raw_len < 1) return SOL_TX_REVIEW_MALFORMED;
  uint8_t version_prefix = raw[pos++];
  if ((version_prefix & SOL_VERSION_FLAG) == 0) return SOL_TX_REVIEW_MALFORMED;
  /* 0xFF starts an off-chain message envelope, never a transaction. */
  if (version_prefix == 0xFF) return SOL_TX_REVIEW_MALFORMED;
  /* A later version is not parsed (num_accounts stays 0): the fsm then
   * requires the derived key to appear in the message. */
  if ((version_prefix & SOL_VERSION_MASK) != 0) return SOL_TX_REVIEW_OPAQUE;

  if (raw_len - pos < 3) return SOL_TX_REVIEW_MALFORMED;
  tx->num_required_sigs = raw[pos++];
  tx->num_readonly_signed = raw[pos++];
  tx->num_readonly_unsigned = raw[pos++];

  uint16_t num_accounts;
  int n = read_compact_u16(raw + pos, raw_len - pos, &num_accounts);
  if (n < 0) return SOL_TX_REVIEW_MALFORMED;
  pos += n;
  if (!solana_header_ok(tx, num_accounts)) return SOL_TX_REVIEW_MALFORMED;

  /* Host-supplied certified lookup material that does not fit: refused. An
   * oversized static list alone is opaque, see solana_parseLegacyTx. */
  if (trusted_lut_count > SOL_MAX_LUT_ACCOUNTS ||
      (trusted_lut_count > 0 &&
       num_accounts + trusted_lut_count > SOL_MAX_ACCOUNTS)) {
    return SOL_TX_REVIEW_MALFORMED;
  }
  if (num_accounts > SOL_MAX_ACCOUNTS)
    return solana_oversizedKeyListIsOpaque(raw, raw_len, pos, num_accounts, tx);
  const bool has_trusted_lut = trusted_lut_accounts && trusted_lut_count > 0;
  tx->num_accounts = (uint8_t)(num_accounts + trusted_lut_count);
  tx->num_static_accounts = (uint8_t)num_accounts;

  for (uint16_t i = 0; i < num_accounts; i++) {
    if (pos + SOL_PUBKEY_SIZE > raw_len) return SOL_TX_REVIEW_MALFORMED;
    memcpy(tx->accounts[i], raw + pos, SOL_PUBKEY_SIZE);
    pos += SOL_PUBKEY_SIZE;
  }
  if (has_trusted_lut) {
    for (size_t i = 0; i < trusted_lut_count; i++) {
      memcpy(tx->accounts[num_accounts + i], trusted_lut_accounts[i],
             SOL_PUBKEY_SIZE);
    }
  }

  if (pos + SOL_PUBKEY_SIZE > raw_len) return SOL_TX_REVIEW_MALFORMED;
  memcpy(tx->recent_blockhash, raw + pos, SOL_PUBKEY_SIZE);
  pos += SOL_PUBKEY_SIZE;

  uint16_t accounts_needed;
  n = parse_instruction_section(
      raw, raw_len, &pos, tx, num_accounts + trusted_lut_count, &has_unknown,
      &force_opaque, /*allow_external_indices=*/!has_trusted_lut,
      &accounts_needed);
  if (n < 0) return SOL_TX_REVIEW_MALFORMED;

  uint16_t lookup_table_count;
  n = read_compact_u16(raw + pos, raw_len - pos, &lookup_table_count);
  if (n < 0) return SOL_TX_REVIEW_MALFORMED;
  pos += n;
  tx->has_address_lookups = lookup_table_count != 0;
  if (!has_trusted_lut && lookup_table_count != 0) {
    /* Any ALT section needs unresolved chain state: opaque. */
    force_opaque = true;
    tx->has_lookup_tables = true;
  }

  uint32_t loaded_accounts = 0;
  size_t serialized_lut_count = 0;
  for (uint16_t i = 0; i < lookup_table_count; i++) {
    uint16_t writable_count, readonly_count;
    if (pos + SOL_PUBKEY_SIZE > raw_len) return SOL_TX_REVIEW_MALFORMED;
    pos += SOL_PUBKEY_SIZE; /* lookup table account key */

    n = read_compact_u16(raw + pos, raw_len - pos, &writable_count);
    if (n < 0) return SOL_TX_REVIEW_MALFORMED;
    pos += n;
    if (pos + writable_count > raw_len) return SOL_TX_REVIEW_MALFORMED;
    pos += writable_count;
    serialized_lut_count += writable_count;

    n = read_compact_u16(raw + pos, raw_len - pos, &readonly_count);
    if (n < 0) return SOL_TX_REVIEW_MALFORMED;
    pos += n;
    if (pos + readonly_count > raw_len) return SOL_TX_REVIEW_MALFORMED;
    pos += readonly_count;
    loaded_accounts += (uint32_t)writable_count + readonly_count;
    tx->num_loaded_accounts += (uint32_t)writable_count + readonly_count;
    serialized_lut_count += readonly_count;
    /* Untrusted: keep parsing so a malformed tail is still refused. */
    if (serialized_lut_count > SOL_MAX_LUT_ACCOUNTS && has_trusted_lut) {
      return SOL_TX_REVIEW_MALFORMED;
    }
  }

  if (pos != raw_len) return SOL_TX_REVIEW_MALFORMED;
  /* An operand past the static plus loaded accounts does not exist. */
  if (accounts_needed > num_accounts + loaded_accounts)
    return SOL_TX_REVIEW_MALFORMED;

  /* Exactly one resolved key per serialized lookup index; any mismatch is
   * MALFORMED, never a blind-sign fallback. */
  if (has_trusted_lut &&
      (lookup_table_count == 0 || serialized_lut_count != trusted_lut_count)) {
    return SOL_TX_REVIEW_MALFORMED;
  }

  /* A zero-LUT v0 message verifies like legacy. */
  if (tx->num_instructions == 0 || has_unknown || force_opaque) {
    return SOL_TX_REVIEW_OPAQUE;
  }
  return SOL_TX_REVIEW_VERIFIED;
}

/* Strip an unsigned tx's 0x00 signature-count prefix so parsing and signing
 * use the IDENTICAL message slice. */
static void solana_message_slice(const uint8_t* raw, size_t raw_len,
                                 const uint8_t** msg_out, size_t* len_out) {
  if (raw_len > 1 && raw[0] == 0) {
    raw++;
    raw_len--;
  }
  *msg_out = raw;
  *len_out = raw_len;
}

SolanaTxReview solana_inspectTx(const uint8_t* raw, size_t raw_len,
                                SolanaParsedTx* tx) {
  if (!raw || raw_len == 0) {
    memset(tx, 0, sizeof(*tx));
    return SOL_TX_REVIEW_MALFORMED;
  }

  const uint8_t* msg;
  size_t msg_len;
  solana_message_slice(raw, raw_len, &msg, &msg_len);

  /* Versioned Solana messages set the top bit in byte 0. Malformed v0/ALT
   * payloads fail closed; a v0 message with no lookup tables verifies like
   * legacy, and a lookup table or any later version keeps it opaque. */
  if (msg[0] & SOL_VERSION_FLAG) {
    return solana_parseVersionedTx(msg, msg_len, NULL, 0, tx);
  }

  return solana_parseLegacyTx(msg, msg_len, tx);
}

SolanaTxReview solana_inspectTxWithTrustedLut(
    const uint8_t* raw, size_t raw_len,
    const uint8_t (*lut_accounts)[SOL_PUBKEY_SIZE], size_t num_lut_accounts,
    SolanaParsedTx* tx) {
  if (!raw || raw_len == 0 || !lut_accounts || num_lut_accounts == 0 || !tx) {
    if (tx) memset(tx, 0, sizeof(*tx));
    return SOL_TX_REVIEW_MALFORMED;
  }
  const uint8_t* msg;
  size_t msg_len;
  solana_message_slice(raw, raw_len, &msg, &msg_len);
  if (msg_len == 0 || (msg[0] & SOL_VERSION_FLAG) == 0) {
    memset(tx, 0, sizeof(*tx));
    return SOL_TX_REVIEW_MALFORMED;
  }
  return solana_parseVersionedTx(msg, msg_len, lut_accounts, num_lut_accounts,
                                 tx);
}

/* ------------------------------------------------------------------ */
/*  KKSOLSC1 reusable instruction schemas                              */
/* ------------------------------------------------------------------ */

/* Display-safe: printable ASCII, and no '%' so a label can never smuggle a
 * conversion specifier into a format string. */
static bool schema_text_ok(const uint8_t* v, size_t len) {
  if (len == 0) return false;
  for (size_t i = 0; i < len; i++) {
    if (v[i] < 0x20 || v[i] > 0x7e || v[i] == '%') return false;
  }
  return true;
}

static bool schema_read_text(const uint8_t** cur, const uint8_t* end, char* out,
                             size_t max_len) {
  if (*cur >= end) return false;
  uint8_t len = *(*cur)++;
  if (len == 0 || len > max_len || (size_t)(end - *cur) < len ||
      !schema_text_ok(*cur, len)) {
    return false;
  }
  memcpy(out, *cur, len);
  out[len] = '\0';
  *cur += len;
  return true;
}

/* LAMPORTS or TOKEN_AMOUNT: must carry a role in v3 and appear in the intent.
 */
static bool solana_schemaArgIsAmount(SolanaSchemaArgType t) {
  return t == SOL_SCHEMA_ARG_LAMPORTS || t == SOL_SCHEMA_ARG_TOKEN_AMOUNT;
}

/* Walk the template: literal runs and "{n}" (arg) / "{aN}" (account)
 * placeholders, single digit. False on any malformed or out-of-range
 * placeholder or a stray brace, so a template is fully understood or
 * rejected. */
typedef bool (*IntentVisit)(void* ctx, bool placeholder, bool account,
                            uint8_t index, const char* lit, size_t lit_len);

static bool intent_walk(const SolanaInstrSchema* s, IntentVisit visit,
                        void* ctx) {
  const char* t = s->intent;
  const char* lit = t;
  while (*t) {
    if (*t == '}') return false;
    if (*t != '{') {
      t++;
      continue;
    }
    if (!visit(ctx, false, false, 0, lit, (size_t)(t - lit))) return false;
    const bool account = t[1] == 'a';
    const char* d = t + (account ? 2 : 1);
    if (*d < '0' || *d > '9' || d[1] != '}') return false;
    const uint8_t index = (uint8_t)(*d - '0');
    if (account ? index >= s->num_accounts : index >= s->num_args) {
      return false;
    }
    if (!account && s->args[index].type == SOL_SCHEMA_ARG_OPAQUE32) {
      return false; /* paged bytes cannot sit inside a sentence */
    }
    if (!visit(ctx, true, account, index, NULL, 0)) return false;
    t = d + 2;
    lit = t;
  }
  return visit(ctx, false, false, 0, lit, (size_t)(t - lit));
}

static bool intent_mark(void* ctx, bool placeholder, bool account,
                        uint8_t index, const char* lit, size_t lit_len) {
  (void)lit;
  (void)lit_len;
  if (placeholder && !account) ((uint8_t*)ctx)[index] = 1;
  return true;
}

typedef struct {
  const SolanaInstrSchema* s;
  size_t width;
} IntentWidth;

/* Widest text each placeholder can expand to (see intent_fill_visit):
 * u64 token amount "18446744073709551615. " + a 12-char symbol = 34,
 * a short address "ABCD...WXYZ" = 11. */
static bool intent_width(void* ctx, bool placeholder, bool account,
                         uint8_t index, const char* lit, size_t lit_len) {
  IntentWidth* w = (IntentWidth*)ctx;
  if (!placeholder) {
    if (!intent_literal_ok(lit, lit_len)) return false;
    w->width += lit_len;
  } else if (account) {
    w->width += 11;
  } else {
    switch (w->s->args[index].type) {
      case SOL_SCHEMA_ARG_LAMPORTS:
      case SOL_SCHEMA_ARG_TOKEN_AMOUNT:
        w->width += 34;
        break;
      case SOL_SCHEMA_ARG_U64:
        w->width += 20;
        break;
      case SOL_SCHEMA_ARG_DURATION:
        w->width += 24;
        break;
      case SOL_SCHEMA_ARG_U8:
        w->width += 3;
        break;
      default:
        w->width += 11; /* PUBKEY, shortened */
        break;
    }
  }
  return true;
}

bool solana_intentTemplateValid(const SolanaInstrSchema* s) {
  if (!s || s->intent[0] == '\0') return false;
  uint8_t used[SOL_SCHEMA_MAX_ARGS] = {0};
  if (!intent_walk(s, intent_mark, used)) return false;
  /* A valid template must always render: refuse one whose widest expansion
   * would not fit the summary (SOL_INTENT_TEXT_MAX). */
  IntentWidth w = {s, 0};
  if (!intent_walk(s, intent_width, &w) || w.width > SOL_INTENT_TEXT_MAX) {
    return false;
  }
  for (uint8_t i = 0; i < s->num_args; i++) {
    if (solana_schemaArgIsAmount(s->args[i].type) && !used[i]) {
      return false; /* coverage: every amount is in the sentence */
    }
  }
  return true;
}

/* Byte width an arg consumes in the instruction data. */
uint16_t solana_schemaArgWidth(SolanaSchemaArgType t) {
  switch (t) {
    case SOL_SCHEMA_ARG_U64:
    case SOL_SCHEMA_ARG_LAMPORTS:
    case SOL_SCHEMA_ARG_TOKEN_AMOUNT:
    case SOL_SCHEMA_ARG_DURATION:
      return 8;
    case SOL_SCHEMA_ARG_U8:
      return 1;
    case SOL_SCHEMA_ARG_PUBKEY:
    case SOL_SCHEMA_ARG_OPAQUE32:
      return 32;
  }
  return 0; /* unknown type — caller rejects */
}

bool solana_parseInstrSchema(const uint8_t* payload, size_t payload_len,
                             SolanaInstrSchema* out) {
  static const uint8_t magic[8] = {'K', 'K', 'S', 'O', 'L', 'S', 'C', '1'};
  if (!payload || !out ||
      payload_len < sizeof(magic) + 1 + SOL_PUBKEY_SIZE + 1) {
    return false;
  }
  memset(out, 0, sizeof(*out));
  const uint8_t* cur = payload;
  const uint8_t* end = payload + payload_len;

  if (memcmp(cur, magic, sizeof(magic)) != 0) return false;
  cur += sizeof(magic);
  const uint8_t version = *cur++;
  if (version < 1 || version > 3) return false;
  out->version = version;

  if ((size_t)(end - cur) < SOL_PUBKEY_SIZE + 1) return false;
  memcpy(out->program_id, cur, SOL_PUBKEY_SIZE);
  cur += SOL_PUBKEY_SIZE;

  out->disc_len = *cur++;
  if (out->disc_len == 0 || out->disc_len > SOL_SCHEMA_DISC_MAX ||
      (size_t)(end - cur) < out->disc_len) {
    return false;
  }
  memcpy(out->disc, cur, out->disc_len);
  cur += out->disc_len;

  if (!schema_read_text(&cur, end, out->program_name, SOL_SCHEMA_NAME_MAX) ||
      !schema_read_text(&cur, end, out->instruction_name,
                        SOL_SCHEMA_NAME_MAX) ||
      cur >= end) {
    return false;
  }

  out->num_args = *cur++;
  if (out->num_args >
      (version == 1 ? SOL_SCHEMA_V1_MAX_ARGS : SOL_SCHEMA_MAX_ARGS)) {
    return false;
  }
  for (uint8_t i = 0; i < out->num_args; i++) {
    if (cur >= end) return false;
    uint8_t type = *cur++;
    if (solana_schemaArgWidth((SolanaSchemaArgType)type) == 0 ||
        (version == 1 && type > SOL_SCHEMA_ARG_LAMPORTS)) {
      return false;
    }
    out->args[i].type = (SolanaSchemaArgType)type;
    if (!schema_read_text(&cur, end, out->args[i].label,
                          SOL_SCHEMA_LABEL_MAX)) {
      return false;
    }
    if (type == SOL_SCHEMA_ARG_TOKEN_AMOUNT) {
      if (cur >= end) return false;
      out->args[i].mint_account = *cur++;
    }
    if (version >= 3) {
      if (cur >= end) return false;
      const uint8_t role = *cur++;
      const bool amount = solana_schemaArgIsAmount(out->args[i].type);
      if (amount ? (role < METADATA_ROLE_SPEND_MAX || role > METADATA_ROLE_CAP)
                 : role != METADATA_ROLE_NONE) {
        return false;
      }
      out->args[i].role = role;
    }
  }

  if (cur >= end) return false;
  out->num_accounts = *cur++;
  if (out->num_accounts > SOL_SCHEMA_MAX_ACCOUNTS) return false;
  for (uint8_t i = 0; i < out->num_accounts; i++) {
    if (cur >= end) return false;
    out->accounts[i].index = *cur++;
    if (!schema_read_text(&cur, end, out->accounts[i].label,
                          SOL_SCHEMA_LABEL_MAX)) {
      return false;
    }
  }
  if (version >= 3) {
    if (cur >= end) return false;
    if (*cur == 0) {
      cur++; /* no template: firmware-generated summary */
    } else if (!schema_read_text(&cur, end, out->intent,
                                 SOL_SCHEMA_TEMPLATE_MAX) ||
               !solana_intentTemplateValid(out)) {
      return false;
    }
  }

  return cur == end; /* no trailing bytes */
}

/* Companions that may ride along UNSCREENED: the runtime schema review draws
 * no screen for other instructions, so only ones moving no value and granting
 * no authority qualify. (The certified review also renders static Transfers;
 * see schema_transferIsStatic.) */
static bool solana_schemaCompanionIsInert(SolanaInstrType type) {
  switch (type) {
    case SOL_INSTR_COMPUTE_BUDGET_HEAP_FRAME:
    case SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT:
    case SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE:
    case SOL_INSTR_COMPUTE_BUDGET_LOADED_ACCOUNTS_SIZE:
    case SOL_INSTR_MEMO:
      return true;
    default:
      return false;
  }
}

/* Certified Transfer companion: exactly two accounts, both static keys. A
 * SOL-send destination must never come from a LUT attestation. Matches the
 * Vault/Worker isCertifiedCompanion rule. */
static bool schema_transferIsStatic(const SolanaParsedTx* tx,
                                    const SolanaParsedInstruction* ix) {
  if (ix->num_acct_indices != 2) return false;
  for (uint8_t j = 0; j < ix->num_acct_indices; j++) {
    if (ix->acct_indices[j] >= tx->num_static_accounts) return false;
  }
  return true;
}

bool solana_signerInTx(const uint8_t* pubkey, const SolanaParsedTx* tx) {
  for (uint8_t i = 0; i < tx->num_required_sigs && i < tx->num_accounts; i++)
    if (memcmp(pubkey, tx->accounts[i], SOL_PUBKEY_SIZE) == 0) return true;
  return false;
}

/* Certified companions beyond inert ones and static Transfers: the SOL
 * wrap/unwrap a DEX trade brackets itself with. Each is natively decoded and
 * screened by the certified review, and only the device key's own accounts
 * qualify: a token account it owns (any signer may fund it), a sync of wrapped
 * SOL, and closing its account back to it. Another signer is not the user: a
 * wSOL close moves the whole balance, not just rent. */
static bool schema_signerAccountCompanion(const SolanaParsedTx* tx,
                                          const SolanaParsedInstruction* ix,
                                          const uint8_t* signer) {
  switch (ix->type) {
    case SOL_INSTR_ATA_CREATE:
      return solana_signerInTx(ix->from, tx) &&
             memcmp(ix->authority, signer, SOL_PUBKEY_SIZE) == 0;
    case SOL_INSTR_TOKEN_SYNC_NATIVE:
      return true;
    case SOL_INSTR_TOKEN_CLOSE_ACCOUNT:
      return memcmp(ix->to, signer, SOL_PUBKEY_SIZE) == 0 &&
             memcmp(ix->authority, signer, SOL_PUBKEY_SIZE) == 0;
    default:
      return false;
  }
}

/* `signer` (the device key) is set only on the certified tier. */
static bool schema_applies(const SolanaInstrSchema* schema,
                           const SolanaParsedTx* tx, const uint8_t* signer,
                           uint8_t* out_index) {
  if (!schema || !tx || !out_index) return false;
  const bool certified = signer != NULL;
  if (tx->has_lookup_tables) return false;

  bool found = false;
  uint8_t match = 0;
  for (uint8_t i = 0; i < tx->num_instructions; i++) {
    const SolanaParsedInstruction* ix = &tx->instructions[i];
    if (ix->external) continue; /* accounts not in the signed message */
    /* Schemas never override a native decoder. */
    if (ix->type != SOL_INSTR_UNKNOWN) continue;
    if (memcmp(ix->program_id, schema->program_id, SOL_PUBKEY_SIZE) != 0) {
      continue;
    }
    if (!ix->data || ix->data_len < schema->disc_len ||
        memcmp(ix->data, schema->disc, schema->disc_len) != 0) {
      continue;
    }

    /* Discriminator + args must consume the data EXACTLY: leftover bytes
     * could carry an unshown effect. */
    uint32_t consumed = schema->disc_len;
    for (uint8_t a = 0; a < schema->num_args; a++) {
      consumed += solana_schemaArgWidth(schema->args[a].type);
    }
    if (consumed != ix->data_len) continue;

    /* Every displayed account must actually exist in this instruction. */
    bool accounts_ok = true;
    for (uint8_t a = 0; a < schema->num_accounts; a++) {
      if (schema->accounts[a].index >= ix->num_acct_indices) {
        accounts_ok = false;
        break;
      }
    }
    for (uint8_t a = 0; accounts_ok && a < schema->num_args; a++) {
      if (schema->args[a].type == SOL_SCHEMA_ARG_TOKEN_AMOUNT &&
          schema->args[a].mint_account >= ix->num_acct_indices) {
        accounts_ok = false;
      }
    }
    if (!accounts_ok) continue;

    if (found) return false; /* ambiguous: two instructions match */
    found = true;
    match = i;
  }
  if (!found) return false;

  /* Every other instruction must be inert (or, certified, a static
   * Transfer): see solana_schemaCompanionIsInert. */
  for (uint8_t i = 0; i < tx->num_instructions; i++) {
    if (i == match) continue;
    const SolanaParsedInstruction* companion = &tx->instructions[i];
    if (companion->external) return false;
    if (solana_schemaCompanionIsInert(companion->type)) continue;
    if (certified && schema_signerAccountCompanion(tx, companion, signer)) {
      continue;
    }
    if (!certified || companion->type != SOL_INSTR_SYSTEM_TRANSFER ||
        !schema_transferIsStatic(tx, companion)) {
      return false;
    }
  }

  *out_index = match;
  return true;
}

bool solana_schemaApplies(const SolanaInstrSchema* schema,
                          const SolanaParsedTx* tx, uint8_t* out_index) {
  return schema_applies(schema, tx, NULL, out_index);
}

bool solana_schemaAppliesCertified(const SolanaInstrSchema* schema,
                                   const SolanaParsedTx* tx,
                                   const uint8_t signer[SOL_PUBKEY_SIZE],
                                   uint8_t* out_index) {
  return schema_applies(schema, tx, signer, out_index);
}

bool solana_messageCarriesKey(const uint8_t* msg, size_t len,
                              const uint8_t pubkey[SOL_PUBKEY_SIZE]) {
  for (size_t i = 0; i + SOL_PUBKEY_SIZE <= len; i++) {
    if (memcmp(msg + i, pubkey, SOL_PUBKEY_SIZE) == 0) return true;
  }
  return false;
}

bool solana_rawMessageIsPlainText(const uint8_t* msg, size_t len,
                                  const uint8_t pubkey[SOL_PUBKEY_SIZE]) {
  if (!msg || !pubkey || len == 0) return false;
  /* ponytail: '\r' / '\t' / UTF-8 fall back to the AdvancedMode path. */
  for (size_t i = 0; i < len; i++) {
    if ((msg[i] < 0x20 || msg[i] > 0x7e) && msg[i] != '\n') return false;
  }
  return !solana_messageCarriesKey(msg, len, pubkey);
}

bool solana_parseTx(const uint8_t* raw, size_t raw_len, SolanaParsedTx* tx) {
  return solana_inspectTx(raw, raw_len, tx) == SOL_TX_REVIEW_VERIFIED;
}

/* ------------------------------------------------------------------ */
/*  Formatting                                                         */
/* ------------------------------------------------------------------ */

/* The runtime requests 200,000 CUs per non-builtin instruction and, under
 * SIMD-0170, 3,000 per builtin; ComputeBudget instructions are builtins and
 * were free before it. Counting every non-ComputeBudget instruction at 200,000
 * and every ComputeBudget one at 3,000 is >= the request under either rule (a
 * builtin counted at 200,000 only widens the margin), so the fee shown stays
 * an upper bound without quoting the 1.4M cap the transaction cannot reach.
 * num_instructions is a uint8_t, so this cannot overflow. */
uint64_t solana_defaultComputeUnitLimit(const SolanaParsedTx* tx) {
  uint64_t limit = 0;
  for (uint8_t i = 0; i < tx->num_instructions; i++) {
    const SolanaInstrType t = tx->instructions[i].type;
    const bool budget = t == SOL_INSTR_COMPUTE_BUDGET_HEAP_FRAME ||
                        t == SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT ||
                        t == SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE ||
                        t == SOL_INSTR_COMPUTE_BUDGET_LOADED_ACCOUNTS_SIZE;
    limit += budget ? 3000u : 200000u;
  }
  return limit;
}

bool solana_priority_fee_lamports(uint64_t price, uint64_t limit,
                                  uint64_t* out) {
  /* ceil(price * limit / 1e6), every step overflow-checked; false (never
   * saturate) if the result exceeds UINT64_MAX. */
  const uint64_t D = 1000000u;
  if (limit > SOL_MAX_COMPUTE_UNITS) limit = SOL_MAX_COMPUTE_UNITS;
  uint64_t q = price / D;
  uint64_t r = price % D;
  if (limit != 0 && r > UINT64_MAX / limit) {
    return false; /* r*limit overflows (only for absurd limits) */
  }
  uint64_t rl = r * limit;
  uint64_t lamports = rl / D;
  bool ceil_up = (rl % D) != 0;
  if (q != 0 && limit != 0) {
    if (q > UINT64_MAX / limit) {
      return false;
    }
    uint64_t ql = q * limit;
    if (ql > UINT64_MAX - lamports) {
      return false;
    }
    lamports += ql;
  }
  if (ceil_up) {
    if (lamports == UINT64_MAX) {
      return false;
    }
    lamports++;
  }
  *out = lamports;
  return true;
}

void solana_formatAmount(char* buf, size_t len, uint64_t lamports) {
  uint64_t whole = lamports / SOL_LAMPORTS_DIVISOR;
  uint64_t frac = lamports % SOL_LAMPORTS_DIVISOR;
  snprintf(buf, len, "%llu.%09llu SOL", (unsigned long long)whole,
           (unsigned long long)frac);
}

void solana_formatTokenAmount(char* buf, size_t len, uint64_t amount,
                              const char* symbol, uint8_t decimals) {
  if (decimals == 0) {
    snprintf(buf, len, "%llu %s", (unsigned long long)amount, symbol);
    return;
  }

  /* A mint's decimals field is an unrestricted uint8_t. Preserve both signed
   * values exactly when the scale exceeds this formatter's arithmetic range
   * instead of dropping the scale. */
  if (decimals > SOL_MAX_TOKEN_DECIMALS) {
    snprintf(buf, len, "%llu base units (%u decimals) %s",
             (unsigned long long)amount, (unsigned)decimals, symbol);
    return;
  }

  uint64_t divisor = 1;
  for (uint8_t i = 0; i < decimals; i++) divisor *= 10;

  uint64_t whole = amount / divisor;
  uint64_t frac = amount % divisor;

  /* Format with appropriate decimal places (max 9 shown).
   *
   * Truncating to nine places used to be silent, which meant a real transfer
   * could render as zero: amount=1 with decimals=18 divided down to
   * show_frac=0 and the screen read "0.000000000 tokens" while the signed
   * instruction moved one base unit. A screen that says zero for a nonzero
   * transfer is worse than one that says nothing.
   *
   * So truncate only when the digits being dropped are all zero. If any of
   * them is nonzero, the decimal form cannot be shown honestly at this width
   * -- fall back to the exact base-unit count, which is the number actually
   * present in the instruction being signed. */
  uint8_t show_dec =
      decimals > SOL_MAX_DISPLAY_DECIMALS ? SOL_MAX_DISPLAY_DECIMALS : decimals;
  uint64_t show_frac = frac;
  if (decimals > SOL_MAX_DISPLAY_DECIMALS) {
    uint64_t drop_div = 1;
    for (uint8_t i = 0; i < decimals - SOL_MAX_DISPLAY_DECIMALS; i++)
      drop_div *= 10;
    if (frac % drop_div != 0) {
      snprintf(buf, len, "%llu base units (%u decimals) %s",
               (unsigned long long)amount, (unsigned)decimals, symbol);
      return;
    }
    show_frac = frac / drop_div;
  }

  char frac_str[10];
  for (int8_t i = (int8_t)show_dec - 1; i >= 0; i--) {
    frac_str[i] = '0' + (show_frac % 10);
    show_frac /= 10;
  }
  frac_str[show_dec] = '\0';
  while (show_dec > 0 && frac_str[show_dec - 1] == '0') {
    frac_str[--show_dec] = '\0';
  }
  if (show_dec == 0) {
    snprintf(buf, len, "%llu %s", (unsigned long long)whole, symbol);
  } else {
    snprintf(buf, len, "%llu.%s %s", (unsigned long long)whole, frac_str,
             symbol);
  }
}

const SolanaKnownToken* solana_findKnownToken(
    const uint8_t mint[SOL_PUBKEY_SIZE]) {
  for (size_t i = 0; i < sizeof(SOL_KNOWN_TOKENS) / sizeof(SOL_KNOWN_TOKENS[0]);
       i++) {
    if (memcmp(SOL_KNOWN_TOKENS[i].mint, mint, SOL_PUBKEY_SIZE) == 0) {
      return &SOL_KNOWN_TOKENS[i];
    }
  }
  return NULL;
}

bool solana_deriveAssociatedTokenAddress(
    const uint8_t owner[SOL_PUBKEY_SIZE],
    const uint8_t token_program[SOL_PUBKEY_SIZE],
    const uint8_t mint[SOL_PUBKEY_SIZE], uint8_t out[SOL_PUBKEY_SIZE]) {
  /* find_program_address: bump 255 down; PDA must be off the Ed25519 curve. */
  for (int bump = 255; bump >= 0; bump--) {
    SHA256_CTX ctx = {0};
    uint8_t candidate[SHA256_DIGEST_LENGTH];
    uint8_t bump_seed = (uint8_t)bump;
    sha256_Init(&ctx);
    sha256_Update(&ctx, owner, SOL_PUBKEY_SIZE);
    sha256_Update(&ctx, token_program, SOL_PUBKEY_SIZE);
    sha256_Update(&ctx, mint, SOL_PUBKEY_SIZE);
    sha256_Update(&ctx, &bump_seed, 1);
    sha256_Update(&ctx, SOL_ATA_PROGRAM, SOL_PUBKEY_SIZE);
    sha256_Update(&ctx, (const uint8_t*)SOL_PDA_MARKER,
                  sizeof(SOL_PDA_MARKER) - 1);
    sha256_Final(&ctx, candidate);

    ge25519 point;
    if (ge25519_unpack_vartime(&point, candidate) == 0) {
      memcpy(out, candidate, SOL_PUBKEY_SIZE);
      return true;
    }
  }
  return false;
}

bool solana_findTokenRecipientOwner(
    const SolanaSignTx* msg, const uint8_t token_program[SOL_PUBKEY_SIZE],
    const uint8_t mint[SOL_PUBKEY_SIZE],
    const uint8_t destination[SOL_PUBKEY_SIZE], uint8_t out[SOL_PUBKEY_SIZE]) {
  if (!msg) return false;
  for (size_t i = 0; i < msg->token_recipient_owner_count; i++) {
    if (msg->token_recipient_owner[i].size != SOL_PUBKEY_SIZE) continue;
    uint8_t derived[SOL_PUBKEY_SIZE];
    if (solana_deriveAssociatedTokenAddress(msg->token_recipient_owner[i].bytes,
                                            token_program, mint, derived) &&
        memcmp(derived, destination, SOL_PUBKEY_SIZE) == 0) {
      memcpy(out, msg->token_recipient_owner[i].bytes, SOL_PUBKEY_SIZE);
      return true;
    }
  }
  return false;
}

const SolanaTokenInfo* solana_findTokenInfo(
    const SolanaSignTx* msg, const uint8_t mint[SOL_PUBKEY_SIZE]) {
  for (size_t i = 0; i < msg->token_info_count; i++) {
    if (msg->token_info[i].has_mint &&
        msg->token_info[i].mint.size == SOL_PUBKEY_SIZE &&
        memcmp(msg->token_info[i].mint.bytes, mint, SOL_PUBKEY_SIZE) == 0) {
      return &msg->token_info[i];
    }
  }
  return NULL;
}

bool solana_token_info_trusted(const SolanaTokenInfo* ti) {
  if (!ti || !ti->has_signature || !ti->has_signer_key_id || !ti->has_mint ||
      ti->mint.size != SOL_PUBKEY_SIZE || !ti->has_symbol ||
      !ti->has_decimals) {
    return false;
  }
  /* uint32 field: reject out-of-range slots BEFORE narrowing to the uint8 the
   * keyring uses, so key_id 256 can't alias slot 0. */
  if (ti->signer_key_id >= METADATA_MAX_KEYS) {
    return false;
  }
  size_t sym_len = strnlen(ti->symbol, sizeof(ti->symbol));
  if (sym_len == 0) {
    return false;
  }
  /* Domain tag blocks cross-purpose replay. Preimage: tag || mint(32) ||
   * decimals(le32) || symbol. */
  static const char kTag[] = "KeepKeySolanaTokenDef/1";
  uint8_t blob[sizeof(kTag) - 1 + SOL_PUBKEY_SIZE + 4 + sizeof(ti->symbol)];
  size_t n = 0;
  memcpy(blob + n, kTag, sizeof(kTag) - 1);
  n += sizeof(kTag) - 1;
  memcpy(blob + n, ti->mint.bytes, SOL_PUBKEY_SIZE);
  n += SOL_PUBKEY_SIZE;
  uint32_t dec = ti->decimals;
  blob[n++] = (uint8_t)dec;
  blob[n++] = (uint8_t)(dec >> 8);
  blob[n++] = (uint8_t)(dec >> 16);
  blob[n++] = (uint8_t)(dec >> 24);
  memcpy(blob + n, ti->symbol, sym_len);
  n += sym_len;
  return signed_metadata_verify_attestation((uint8_t)ti->signer_key_id, blob, n,
                                            ti->signature.bytes,
                                            ti->signature.size);
}

/* Never the bare SolanaSignTx.token_info.symbol: matching the host's decimals
 * to the signed ones authenticates the exponent, not the identity -- an
 * attacker picks a mint whose decimals already match and the label rides
 * through as fact, and a caveat cannot help when the host writes the 12
 * characters beside it. Unattested => NULL: the caller scales the amount by
 * the signed decimals, labels it "tokens" and shows the full mint. */
const char* solana_displaySymbol(const SolanaTokenInfo* ti,
                                 const SolanaKnownToken* known,
                                 uint8_t signed_decimals) {
  if (known) return known->symbol;
  if (!solana_token_info_trusted(ti) || ti->decimals != signed_decimals) {
    return NULL;
  }
  /* Letters and digits, with . _ - inside: a signed label is drawn beside the
   * amount, so it may not hold a space or anything that reads as part of it. */
  size_t len = 0;
  for (const char* p = ti->symbol; *p; p++, len++) {
    const char c = *p;
    const bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9');
    if (!alnum && (len == 0 || (c != '.' && c != '_' && c != '-'))) return NULL;
  }
  if (len == 0) return NULL;
  /* Nor a symbol this firmware owns: on another mint it would draw the very
   * amount screen the real token gets. */
  for (size_t i = 0; i < sizeof(SOL_KNOWN_TOKENS) / sizeof(SOL_KNOWN_TOKENS[0]);
       i++) {
    const char* owned = SOL_KNOWN_TOKENS[i].symbol;
    size_t j = 0;
    while (owned[j] && ti->symbol[j] &&
           (owned[j] | 0x20) == (ti->symbol[j] | 0x20)) {
      j++;
    }
    if (!owned[j] && !ti->symbol[j]) return NULL;
  }
  return ti->symbol;
}

/* Bare ticker only: nothing that could continue the surrounding sentence. */
static bool solana_tokenSymbolOk(const SolanaTokenInfo* ti) {
  if (!ti->has_symbol) return false;
  const size_t len = strnlen(ti->symbol, sizeof(ti->symbol));
  if (len == 0 || len >= sizeof(ti->symbol)) return false;
  for (size_t i = 0; i < len; i++) {
    const char c = ti->symbol[i];
    const bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9');
    if (!alnum && (i == 0 || (c != '.' && c != '_' && c != '-'))) {
      return false;
    }
  }
  return true;
}

/* Certified token definition, signed by the Solana cert's delegate:
 *   "KeepKeySolanaTokenDef/2" || mint(32) || token_program(32)
 *     || decimals(le32) || symbol
 * Either SPL token program is accepted. */
static bool solana_tokenDefCertified(const SolanaSignTx* msg,
                                     const SolanaTokenInfo* ti) {
  if (!msg->has_clearsign_certificate || !ti->has_signature ||
      ti->signature.size != 64 || !ti->has_signer_key_id ||
      ti->signer_key_id != METADATA_KEYID_DELEGATE) {
    return false;
  }
  static const char kTag[] = "KeepKeySolanaTokenDef/2";
  static const uint8_t* const kPrograms[2] = {SOL_TOKEN_2022_PROGRAM,
                                              SOL_TOKEN_PROGRAM};
  const size_t sym_len = strnlen(ti->symbol, sizeof(ti->symbol));
  uint8_t blob[sizeof(kTag) - 1 + 2 * SOL_PUBKEY_SIZE + 4 + sizeof(ti->symbol)];
  size_t n = 0;
  memcpy(blob + n, kTag, sizeof(kTag) - 1);
  n += sizeof(kTag) - 1;
  memcpy(blob + n, ti->mint.bytes, SOL_PUBKEY_SIZE);
  n += SOL_PUBKEY_SIZE;
  const size_t program_at = n;
  n += SOL_PUBKEY_SIZE;
  const uint32_t dec = ti->decimals;
  blob[n++] = (uint8_t)dec;
  blob[n++] = (uint8_t)(dec >> 8);
  blob[n++] = (uint8_t)(dec >> 16);
  blob[n++] = (uint8_t)(dec >> 24);
  memcpy(blob + n, ti->symbol, sym_len);
  n += sym_len;
  for (size_t p = 0; p < 2; p++) {
    memcpy(blob + program_at, kPrograms[p], SOL_PUBKEY_SIZE);
    if (clearsign_root_verify_delegate_attestation(
            msg->clearsign_certificate.bytes, msg->clearsign_certificate.size,
            CLEARSIGN_SCOPE_SOLANA, blob, n, ti->signature.bytes,
            ti->signature.size)) {
      return true;
    }
  }
  return false;
}

/* A signed definition must not borrow a symbol the firmware binds to another
 * mint ("USDC", any case). */
static bool solana_symbolNamesOtherKnownToken(
    const char* symbol, const uint8_t mint[SOL_PUBKEY_SIZE]) {
  for (size_t i = 0; i < sizeof(SOL_KNOWN_TOKENS) / sizeof(SOL_KNOWN_TOKENS[0]);
       i++) {
    const SolanaKnownToken* k = &SOL_KNOWN_TOKENS[i];
    if (memcmp(k->mint, mint, SOL_PUBKEY_SIZE) == 0) continue;
    for (size_t j = 0;; j++) {
      char a = symbol[j];
      char b = k->symbol[j];
      if (a >= 'a' && a <= 'z') a = (char)(a - 'a' + 'A');
      if (b >= 'a' && b <= 'z') b = (char)(b - 'a' + 'A');
      if (a != b) break;
      if (a == '\0') return true;
    }
  }
  return false;
}

const SolanaTokenInfo* solana_schemaTrustedToken(
    const SolanaSignTx* msg, const uint8_t mint[SOL_PUBKEY_SIZE],
    bool certified) {
  if (!msg || !mint) return NULL;
  const SolanaTokenInfo* ti = solana_findTokenInfo(msg, mint);
  if (!ti || !ti->has_decimals || ti->decimals > SOL_MAX_DISPLAY_DECIMALS ||
      !solana_tokenSymbolOk(ti) ||
      solana_symbolNamesOtherKnownToken(ti->symbol, mint)) {
    return NULL;
  }
  /* Never across tiers. */
  if (certified) return solana_tokenDefCertified(msg, ti) ? ti : NULL;
  /* Only the schema's own signer, which the review names. */
  if (!msg->has_schema_signer_key_id ||
      ti->signer_key_id != msg->schema_signer_key_id) {
    return NULL;
  }
  return solana_token_info_trusted(ti) ? ti : NULL;
}

bool solana_formatSchemaTokenAmount(char* buf, size_t len, uint64_t amount,
                                    const uint8_t mint[SOL_PUBKEY_SIZE],
                                    const SolanaTokenInfo* trusted) {
  char mint_str[45];
  size_t mint_len = sizeof(mint_str);
  if (!b58enc(mint_str, &mint_len, mint, SOL_PUBKEY_SIZE)) return false;
  /* Mint always shown (anyone can mint a "USDC"), on its own row so it does
   * not wrap into the footer. */
  if (trusted) {
    char scaled[48];
    solana_formatTokenAmount(scaled, sizeof(scaled), amount, trusted->symbol,
                             (uint8_t)trusted->decimals);
    snprintf(buf, len, "%s\n%s", scaled, mint_str);
  } else {
    snprintf(buf, len, "%llu base units of mint\n%s",
             (unsigned long long)amount, mint_str);
  }
  return true;
}

bool solana_schemaArgValue(const SolanaSignTx* msg, bool certified,
                           const SolanaParsedTx* parsed,
                           const SolanaParsedInstruction* ix,
                           const SolanaSchemaArg* arg, const uint8_t* data,
                           SolanaSchemaTokenCache* cache, char* buf,
                           size_t len) {
  if (!parsed || !ix || !arg || !data || !cache || !buf || len == 0) {
    return false;
  }
  switch (arg->type) {
    case SOL_SCHEMA_ARG_U8:
      snprintf(buf, len, "%u", (unsigned)data[0]);
      return true;
    case SOL_SCHEMA_ARG_U64:
      snprintf(buf, len, "%llu", (unsigned long long)read_le64(data));
      return true;
    case SOL_SCHEMA_ARG_LAMPORTS:
      solana_formatAmount(buf, len, read_le64(data));
      return true;
    case SOL_SCHEMA_ARG_DURATION:
      solana_formatDuration(buf, len, read_le64(data));
      return true;
    case SOL_SCHEMA_ARG_PUBKEY: {
      size_t enc = len;
      return b58enc(buf, &enc, data, SOL_PUBKEY_SIZE);
    }
    case SOL_SCHEMA_ARG_TOKEN_AMOUNT: {
      /* mint_account indexes THIS instruction's accounts. */
      if (arg->mint_account >= ix->num_acct_indices) return false;
      const uint8_t mint_index = ix->acct_indices[arg->mint_account];
      if (mint_index >= parsed->num_accounts) return false;
      const uint8_t* mint = parsed->accounts[mint_index];
      if (mint != cache->mint) { /* verify each mint's definition once */
        cache->mint = mint;
        cache->token = solana_schemaTrustedToken(msg, mint, certified);
      }
      return solana_formatSchemaTokenAmount(buf, len, read_le64(data), mint,
                                            cache->token);
    }
    case SOL_SCHEMA_ARG_OPAQUE32:
      break; /* no text form: the caller pages the bytes */
  }
  return false;
}

void solana_formatDuration(char* buf, size_t len, uint64_t seconds) {
  static const uint32_t kSeconds[] = {86400, 3600, 60, 1};
  static const char* const kUnits[] = {"d", "h", "min", "s"};
  size_t i = 0;
  while (seconds % kSeconds[i] != 0) i++; /* ends at 1 s at the latest */
  snprintf(buf, len, "%llu %s", (unsigned long long)(seconds / kSeconds[i]),
           kUnits[i]);
}

/* Verify `sig` over the lookup-account preimage: under the root-certified
 * delegate when `certificate` is set, else under runtime signer slot
 * `signer_key_id`. */
static bool solana_lut_accounts_verify(
    const uint8_t* raw_tx, size_t raw_len, const uint8_t (*accounts)[32],
    size_t num_accounts, uint32_t signer_key_id, const uint8_t* certificate,
    size_t certificate_len, const uint8_t* sig, size_t sig_len) {
  if (!raw_tx || !accounts || !sig || num_accounts == 0) return false;
  if (num_accounts > SOL_MAX_LUT_ACCOUNTS) return false;

  /* Bind to the transaction: sha256 of the exact bytes being signed. */
  const uint8_t* signed_message = raw_tx;
  size_t signed_message_len = raw_len;
  if (signed_message_len > 1 && signed_message[0] == 0) {
    signed_message++;
    signed_message_len--;
  }
  uint8_t msg_hash[SHA256_DIGEST_LENGTH];
  sha256_Raw(signed_message, signed_message_len, msg_hash);

  /* Preimage passed RAW (the verifier hashes it). Max 317 bytes. */
  static const char kTag[] = "KeepKeySolanaTxAccounts/1";
  uint8_t blob[sizeof(kTag) - 1 + SHA256_DIGEST_LENGTH + 4 +
               SOL_MAX_LUT_ACCOUNTS * SOL_PUBKEY_SIZE];
  size_t n = 0;
  memcpy(blob + n, kTag, sizeof(kTag) - 1);
  n += sizeof(kTag) - 1;
  memcpy(blob + n, msg_hash, sizeof(msg_hash));
  n += sizeof(msg_hash);
  uint32_t count = (uint32_t)num_accounts;
  blob[n++] = (uint8_t)count;
  blob[n++] = (uint8_t)(count >> 8);
  blob[n++] = (uint8_t)(count >> 16);
  blob[n++] = (uint8_t)(count >> 24);
  for (size_t i = 0; i < num_accounts; i++) {
    memcpy(blob + n, accounts[i], SOL_PUBKEY_SIZE);
    n += SOL_PUBKEY_SIZE;
  }

  if (certificate) {
    return clearsign_root_verify_delegate_attestation(
        certificate, certificate_len, CLEARSIGN_SCOPE_SOLANA, blob, n, sig,
        sig_len);
  }
  return signed_metadata_verify_attestation((uint8_t)signer_key_id, blob, n,
                                            sig, sig_len);
}

bool solana_lut_attestation_complete(const SolanaParsedTx* tx,
                                     size_t attested) {
  return tx && attested > 0 && attested == tx->num_loaded_accounts;
}

bool solana_lut_accounts_trusted(const uint8_t* raw_tx, size_t raw_len,
                                 const uint8_t (*accounts)[32],
                                 size_t num_accounts, uint32_t signer_key_id,
                                 const uint8_t* sig, size_t sig_len) {
  return signer_key_id < METADATA_MAX_KEYS &&
         solana_lut_accounts_verify(raw_tx, raw_len, accounts, num_accounts,
                                    signer_key_id, NULL, 0, sig, sig_len);
}

bool solana_lut_accounts_certified(const uint8_t* raw_tx, size_t raw_len,
                                   const uint8_t (*accounts)[32],
                                   size_t num_accounts,
                                   const uint8_t* certificate,
                                   size_t certificate_len, const uint8_t* sig,
                                   size_t sig_len) {
  return certificate &&
         solana_lut_accounts_verify(raw_tx, raw_len, accounts, num_accounts, 0,
                                    certificate, certificate_len, sig, sig_len);
}

/* ------------------------------------------------------------------ */
/*  Signing                                                            */
/* ------------------------------------------------------------------ */

bool solana_signTx(const HDNode* node, const SolanaSignTx* msg,
                   SolanaSignedTx* resp) {
  if (!msg->has_raw_tx || msg->raw_tx.size == 0) return false;

  /* Sign the exact same message slice that solana_inspectTx parsed and the user
   * approved (Solana signs the serialized message, not a hash of it). */
  const uint8_t* message;
  size_t message_len;
  solana_message_slice(msg->raw_tx.bytes, msg->raw_tx.size, &message,
                       &message_len);

  uint8_t sig[SOL_SIG_SIZE];
  ed25519_sign(message, message_len, node->private_key, sig);

#if !ZCASH_PRIVACY
  /* Defense-in-depth self-verify; compiled out on zcash-privacy (ROM). */
  if (ed25519_sign_open(message, message_len, node->public_key + 1, sig) != 0) {
    memzero(sig, sizeof(sig));
    return false;
  }
#endif

  resp->has_signature = true;
  resp->signature.size = SOL_SIG_SIZE;
  memcpy(resp->signature.bytes, sig, SOL_SIG_SIZE);

  return true;
}

/* ------------------------------------------------------------------ */
/*  Off-chain message signing (domain-separated)                       */
/* ------------------------------------------------------------------ */

/* Per the Solana off-chain message spec, the device signs over the
 * envelope:
 *
 *   "\xff" || "solana offchain" || version:u8 || format:u8
 *           || length:u16 LE || message bytes
 *
 * The 0xff lead byte is invalid as a Solana transaction prefix, so a
 * signed off-chain message can NEVER be replayed as a transaction —
 * this is the domain separation that bare SolanaSignMessage lacks. */

#define SOL_OFFCHAIN_PREFIX_LEN 1
#define SOL_OFFCHAIN_TAG "solana offchain"
#define SOL_OFFCHAIN_TAG_LEN 15
#define SOL_OFFCHAIN_HEADER_LEN                                   \
  (SOL_OFFCHAIN_PREFIX_LEN + SOL_OFFCHAIN_TAG_LEN + 1 /*version*/ \
   + 1 /*format*/ + 2 /*length*/)

#define SOL_OFFCHAIN_FORMAT_ASCII 0
#define SOL_OFFCHAIN_FORMAT_UTF8_LIMITED 1
#define SOL_OFFCHAIN_FORMAT_UTF8_EXTENDED 2 /* not supported on this device */
#define SOL_OFFCHAIN_MAX_MSG_LEN 1212       /* spec ceiling for fmt 0 / 1 */

#define SOL_OFFCHAIN_ENVELOPE_MAX \
  (SOL_OFFCHAIN_HEADER_LEN + SOL_OFFCHAIN_MAX_MSG_LEN)

bool solana_offchain_message_sign(const HDNode* node,
                                  const SolanaSignOffchainMessage* msg,
                                  SolanaOffchainMessageSignature* resp) {
  if (!node || !msg || !resp) return false;
  if (!msg->has_message || msg->message.size == 0) return false;
  if (msg->message.size > SOL_OFFCHAIN_MAX_MSG_LEN) return false;

  /* Reject format 2 — extended UTF-8 mode is Ledger-only blind-sign and
   * the proto's max_size cap (1212) wouldn't permit its real ceiling
   * anyway. Force callers onto format 0 or 1. */
  uint8_t format = msg->has_message_format
                       ? (uint8_t)(msg->message_format & 0xFF)
                       : SOL_OFFCHAIN_FORMAT_ASCII;
  if (format != SOL_OFFCHAIN_FORMAT_ASCII &&
      format != SOL_OFFCHAIN_FORMAT_UTF8_LIMITED) {
    return false;
  }

  uint8_t version = msg->has_version ? (uint8_t)(msg->version & 0xFF) : 0;
  if (version != 0) return false; /* spec: only version 0 defined */

  uint8_t envelope[SOL_OFFCHAIN_ENVELOPE_MAX];
  size_t off = 0;
  envelope[off++] = 0xFF;
  memcpy(&envelope[off], SOL_OFFCHAIN_TAG, SOL_OFFCHAIN_TAG_LEN);
  off += SOL_OFFCHAIN_TAG_LEN;
  envelope[off++] = version;
  envelope[off++] = format;
  /* length is u16 little-endian */
  envelope[off++] = (uint8_t)(msg->message.size & 0xFF);
  envelope[off++] = (uint8_t)((msg->message.size >> 8) & 0xFF);
  memcpy(&envelope[off], msg->message.bytes, msg->message.size);
  off += msg->message.size;

  uint8_t sig[SOL_SIG_SIZE];
  ed25519_sign(envelope, off, node->private_key, sig);

  resp->has_public_key = true;
  resp->public_key.size = SOL_PUBKEY_SIZE;
  memcpy(resp->public_key.bytes, node->public_key + 1, SOL_PUBKEY_SIZE);

  resp->has_signature = true;
  resp->signature.size = SOL_SIG_SIZE;
  memcpy(resp->signature.bytes, sig, SOL_SIG_SIZE);

  memzero(envelope, sizeof(envelope));
  memzero(sig, sizeof(sig));
  return true;
}

/* ------------------------------------------------------------------ */
/*  Human-readable intent review (SRS-7.16 §3.7, SRS-7.15 R-1.5)       */
/* ------------------------------------------------------------------ */

/* So11111111111111111111111111111111111111112: the native (wrapped SOL)
 * mint. A fixed protocol constant, so its unit is a firmware fact. */
static const uint8_t SOL_NATIVE_MINT[SOL_PUBKEY_SIZE] = {
    0x06, 0x9b, 0x88, 0x57, 0xfe, 0xab, 0x81, 0x84, 0xfb, 0x68, 0x7f,
    0x63, 0x46, 0x18, 0xc0, 0x35, 0xda, 0xc4, 0x39, 0xdc, 0x1a, 0xeb,
    0x3b, 0x55, 0x98, 0xa0, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x01};

static void review_b58(const uint8_t key[SOL_PUBKEY_SIZE], char* out,
                       size_t len) {
  size_t enc = len;
  if (!b58enc(out, &enc, key, SOL_PUBKEY_SIZE)) snprintf(out, len, "?");
}

/* "ABCD...WXYZ": only inside the sentence; the full form is always shown on
 * a later screen (truncation alone would be a spoofing vector). */
static void review_short(const uint8_t key[SOL_PUBKEY_SIZE], char* out,
                         size_t len) {
  char full[48];
  review_b58(key, full, sizeof(full));
  size_t n = strlen(full);
  if (n <= 11) {
    snprintf(out, len, "%s", full);
  } else {
    snprintf(out, len, "%.4s...%s", full, full + n - 4);
  }
}

static const uint8_t* review_ix_account(const SolanaParsedTx* tx,
                                        const SolanaParsedInstruction* ix,
                                        uint8_t slot) {
  if (slot >= ix->num_acct_indices) return NULL;
  const uint8_t index = ix->acct_indices[slot];
  return index < tx->num_accounts ? tx->accounts[index] : NULL;
}

/* An amount argument: in_sentence picks the one-line form; otherwise the
 * limits form, where a token keeps its full mint on its own line. */
static bool review_amount(const SolanaSignTx* msg, const SolanaParsedTx* tx,
                          const SolanaParsedInstruction* ix,
                          const SolanaSchemaArg* arg, const uint8_t* data,
                          bool certified, bool in_sentence, char* out,
                          size_t len) {
  const uint64_t v = read_le64(data);
  if (arg->type == SOL_SCHEMA_ARG_LAMPORTS) {
    solana_formatAmount(out, len, v);
    return true;
  }
  const uint8_t* mint = review_ix_account(tx, ix, arg->mint_account);
  if (!mint) return false;
  if (memcmp(mint, SOL_NATIVE_MINT, SOL_PUBKEY_SIZE) == 0) {
    solana_formatAmount(out, len, v);
    return true;
  }
  const SolanaTokenInfo* ti = solana_schemaTrustedToken(msg, mint, certified);
  char scaled[64];
  if (ti) {
    solana_formatTokenAmount(scaled, sizeof(scaled), v, ti->symbol,
                             (uint8_t)ti->decimals);
  } else {
    snprintf(scaled, sizeof(scaled), "%llu base units", (unsigned long long)v);
  }
  if (in_sentence) {
    snprintf(out, len, "%s", scaled);
    return true;
  }
  char mint_str[48];
  review_b58(mint, mint_str, sizeof(mint_str));
  snprintf(out, len, "%s\n%s%s", scaled, ti ? "" : "of mint ", mint_str);
  return true;
}

static const uint8_t* review_arg_data(const SolanaInstrSchema* s,
                                      const SolanaParsedInstruction* ix,
                                      uint8_t arg) {
  uint16_t off = s->disc_len;
  for (uint8_t a = 0; a < arg; a++)
    off += solana_schemaArgWidth(s->args[a].type);
  return ix->data + off;
}

typedef struct {
  const SolanaSignTx* msg;
  const SolanaParsedTx* tx;
  const SolanaInstrSchema* s;
  const SolanaParsedInstruction* ix;
  bool certified;
} IntentSrc;

static bool intent_fill_visit(void* ctx, bool placeholder, bool account,
                              uint8_t index, const char* lit, size_t lit_len) {
  IntentFill* f = (IntentFill*)ctx;
  const IntentSrc* c = (const IntentSrc*)f->src;
  if (!placeholder) {
    intent_fill_append(f, lit, lit_len);
    return f->ok;
  }
  char v[96] = {0};
  if (account) {
    const uint8_t* key =
        review_ix_account(c->tx, c->ix, c->s->accounts[index].index);
    if (!key) return false;
    review_short(key, v, sizeof(v));
  } else {
    const SolanaSchemaArg* arg = &c->s->args[index];
    const uint8_t* data = review_arg_data(c->s, c->ix, index);
    switch (arg->type) {
      case SOL_SCHEMA_ARG_LAMPORTS:
      case SOL_SCHEMA_ARG_TOKEN_AMOUNT:
        if (!review_amount(c->msg, c->tx, c->ix, arg, data, c->certified, true,
                           v, sizeof(v))) {
          return false;
        }
        break;
      case SOL_SCHEMA_ARG_U8:
        snprintf(v, sizeof(v), "%u", (unsigned)data[0]);
        break;
      case SOL_SCHEMA_ARG_U64:
        snprintf(v, sizeof(v), "%llu", (unsigned long long)read_le64(data));
        break;
      case SOL_SCHEMA_ARG_DURATION:
        solana_formatDuration(v, sizeof(v), read_le64(data));
        break;
      case SOL_SCHEMA_ARG_PUBKEY:
        review_short(data, v, sizeof(v));
        break;
      default:
        return false;
    }
  }
  intent_fill_append(f, v, strlen(v));
  return f->ok;
}

static bool solana_fillIntent(const SolanaSignTx* msg, const SolanaParsedTx* tx,
                              const SolanaInstrSchema* s, uint8_t ix_index,
                              bool certified, char* out, size_t len) {
  if (!tx || !s || !out || len == 0 || ix_index >= tx->num_instructions) {
    return false;
  }
  out[0] = '\0';
  if (s->intent[0] == '\0') {
    snprintf(out, len, "%s", s->instruction_name);
    return true;
  }
  const IntentSrc src = {msg, tx, s, &tx->instructions[ix_index], certified};
  IntentFill f = {&src, out, len, 0, true};
  return intent_walk(s, intent_fill_visit, &f) && f.ok;
}

static bool review_limits(const SolanaSignTx* msg, const SolanaParsedTx* tx,
                          const SolanaInstrSchema* s, uint8_t ix_index,
                          const uint8_t signer[SOL_PUBKEY_SIZE], bool certified,
                          ReviewEmit emit, void* ctx) {
  const SolanaParsedInstruction* ix = &tx->instructions[ix_index];
  char body[BODY_CHAR_MAX];
  for (uint8_t a = 0; a < s->num_args; a++) {
    const char* role = intent_role_text(s->args[a].role);
    if (!role) continue;
    char v[160];
    if (!review_amount(msg, tx, ix, &s->args[a], review_arg_data(s, ix, a),
                       certified, false, v, sizeof(v))) {
      return false;
    }
    snprintf(body, sizeof(body), "%s\n%s", role, v);
    if (!emit(ctx, "Limits", body, NULL, 0)) return false;
  }
  /* Every native SOL transfer the device decodes beside the action. */
  for (uint8_t i = 0; i < tx->num_instructions; i++) {
    const SolanaParsedInstruction* pi = &tx->instructions[i];
    if (i == ix_index || pi->type != SOL_INSTR_SYSTEM_TRANSFER) continue;
    char amount[40], to[48];
    solana_formatAmount(amount, sizeof(amount), pi->lamports);
    review_b58(pi->to, to, sizeof(to));
    if (memcmp(pi->from, signer, SOL_PUBKEY_SIZE) == 0) {
      snprintf(body, sizeof(body), "Also sends %s to\n%s", amount, to);
    } else {
      char from[48];
      review_b58(pi->from, from, sizeof(from));
      snprintf(body, sizeof(body), "%s\nsends %s to\n%s", from, amount, to);
    }
    if (!emit(ctx, "Limits", body, NULL, 0)) return false;
  }
  /* Network fee bound: base fee per signature plus the maximum priority fee
   * (1.4M-CU cap when no limit is set; never an understatement). */
  uint64_t price = 0, limit = 1400000u;
  for (uint8_t i = 0; i < tx->num_instructions; i++) {
    const SolanaParsedInstruction* pi = &tx->instructions[i];
    if (pi->type == SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE)
      price = pi->extra_value;
    if (pi->type == SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT &&
        pi->extra_value < limit) {
      limit = pi->extra_value;
    }
  }
  uint64_t priority = 0;
  if (price && !solana_priority_fee_lamports(price, limit, &priority)) {
    return false; /* would wrap: refuse, never show a wrong bound */
  }
  const uint64_t base = 5000ULL * tx->num_required_sigs;
  if (priority > UINT64_MAX - base) return false; /* bound would wrap */
  char fee[40];
  solana_formatAmount(fee, sizeof(fee), base + priority);
  if (tx->num_accounts > 0 &&
      memcmp(tx->accounts[0], signer, SOL_PUBKEY_SIZE) != 0) {
    char payer[48];
    review_b58(tx->accounts[0], payer, sizeof(payer));
    snprintf(body, sizeof(body), "Network fee up to %s\npaid by\n%s", fee,
             payer);
  } else {
    snprintf(body, sizeof(body), "Network fee up to %s", fee);
  }
  return emit(ctx, "Limits", body, NULL, 0);
}

static bool review_side_effects(const SolanaParsedTx* tx, uint8_t ix_index,
                                const uint8_t signer[SOL_PUBKEY_SIZE],
                                ReviewEmit emit, void* ctx) {
  char body[BODY_CHAR_MAX];
  bool close_shown[SOL_MAX_INSTRUCTIONS] = {false};
  for (uint8_t i = 0; i < tx->num_instructions; i++) {
    const SolanaParsedInstruction* pi = &tx->instructions[i];
    if (i == ix_index) continue;
    switch (pi->type) {
      case SOL_INSTR_ATA_CREATE: {
        if (!pi->has_mint) return false; /* never render a zeroed mint */
        /* "your" only when the device key owns it; a co-signer's account
         * is named by its owner. */
        const bool mine = memcmp(pi->authority, signer, SOL_PUBKEY_SIZE) == 0;
        char acct[48], owner[48];
        review_b58(pi->to, acct, sizeof(acct));
        review_b58(pi->authority, owner, sizeof(owner));
        if (memcmp(pi->mint, SOL_NATIVE_MINT, SOL_PUBKEY_SIZE) == 0) {
          int8_t closed = -1;
          for (uint8_t j = 0; j < tx->num_instructions; j++) {
            const SolanaParsedInstruction* c = &tx->instructions[j];
            if (c->type == SOL_INSTR_TOKEN_CLOSE_ACCOUNT &&
                memcmp(c->from, pi->to, SOL_PUBKEY_SIZE) == 0 &&
                memcmp(c->to, signer, SOL_PUBKEY_SIZE) == 0) {
              closed = (int8_t)j;
            }
          }
          if (closed >= 0 && mine) {
            close_shown[closed] = true;
            snprintf(body, sizeof(body),
                     "Creates a temporary wSOL account, closed back to you");
          } else if (mine) {
            snprintf(body, sizeof(body), "Creates your wSOL account\n%s", acct);
          } else {
            snprintf(body, sizeof(body), "Creates a wSOL account\n%s\nfor\n%s",
                     acct, owner);
          }
        } else {
          char mint[48];
          review_b58(pi->mint, mint, sizeof(mint));
          if (mine) {
            snprintf(body, sizeof(body),
                     "Creates your token account for mint\n%s", mint);
          } else {
            snprintf(body, sizeof(body),
                     "Creates a token account for mint\n%s"
                     "\nfor\n%s",
                     mint, owner);
          }
        }
        if (!emit(ctx, "Side effects", body, NULL, 0)) return false;
        break;
      }
      case SOL_INSTR_TOKEN_CLOSE_ACCOUNT:
        break; /* after the loop, unless paired with a wSOL create */
      case SOL_INSTR_MEMO:
        if (!emit(ctx, "Memo", NULL, pi->data, pi->data_len)) return false;
        break;
      case SOL_INSTR_SYSTEM_TRANSFER:   /* on the limits screen */
      case SOL_INSTR_TOKEN_SYNC_NATIVE: /* moves nothing */
      case SOL_INSTR_COMPUTE_BUDGET_HEAP_FRAME:
      case SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT:
      case SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE:
      case SOL_INSTR_COMPUTE_BUDGET_LOADED_ACCOUNTS_SIZE:
        break;
      default:
        return false; /* schema_applies admits nothing else */
    }
  }
  for (uint8_t i = 0; i < tx->num_instructions; i++) {
    const SolanaParsedInstruction* pi = &tx->instructions[i];
    if (i == ix_index || pi->type != SOL_INSTR_TOKEN_CLOSE_ACCOUNT ||
        close_shown[i]) {
      continue;
    }
    char acct[48];
    review_b58(pi->from, acct, sizeof(acct));
    if (memcmp(pi->authority, signer, SOL_PUBKEY_SIZE) == 0 &&
        memcmp(pi->to, signer, SOL_PUBKEY_SIZE) == 0) {
      snprintf(body, sizeof(body),
               "Closes your token account\n%s\nrent back to you", acct);
    } else {
      char to[48];
      review_b58(pi->to, to, sizeof(to));
      snprintf(body, sizeof(body), "Closes token account\n%s\nrent to\n%s",
               acct, to);
    }
    if (!emit(ctx, "Side effects", body, NULL, 0)) return false;
  }
  return true;
}

/* Full forms of everything the sentence shortened, then (pre-template
 * schemas) every labelled value as before. */
static bool review_details(const SolanaSignTx* msg, const SolanaParsedTx* tx,
                           const SolanaInstrSchema* s, uint8_t ix_index,
                           bool certified, ReviewEmit emit, void* ctx) {
  const SolanaParsedInstruction* ix = &tx->instructions[ix_index];
  char body[BODY_CHAR_MAX];
  /* Nothing is hidden: a value the sentence does not state, or states only
   * in short form (an address), gets its own screen. */
  uint8_t in_sentence[SOL_SCHEMA_MAX_ARGS] = {0};
  if (s->intent[0] != '\0' && !intent_walk(s, intent_mark, in_sentence)) {
    return false;
  }
  for (uint8_t a = 0; a < s->num_args; a++) {
    const SolanaSchemaArg* arg = &s->args[a];
    if (arg->role != METADATA_ROLE_NONE) continue; /* on the limits screen */
    if (in_sentence[a] && arg->type != SOL_SCHEMA_ARG_PUBKEY) continue;
    if (arg->type == SOL_SCHEMA_ARG_OPAQUE32) {
      if (!emit(ctx, arg->label, NULL, review_arg_data(s, ix, a), 32)) {
        return false;
      }
      continue;
    }
    SolanaSchemaTokenCache cache = {NULL, NULL};
    char v[160];
    if (!solana_schemaArgValue(msg, certified, tx, ix, arg,
                               review_arg_data(s, ix, a), &cache, v,
                               sizeof(v))) {
      return false;
    }
    if (!emit(ctx, arg->label, v, NULL, 0)) return false;
  }
  for (uint8_t a = 0; a < s->num_accounts; a++) {
    const uint8_t* key = review_ix_account(tx, ix, s->accounts[a].index);
    if (!key) return false;
    review_b58(key, body, sizeof(body));
    if (!emit(ctx, s->accounts[a].label, body, NULL, 0)) return false;
  }
  return true;
}

bool solana_buildIntentReview(const SolanaSignTx* msg, const SolanaParsedTx* tx,
                              const SolanaInstrSchema* s, uint8_t ix_index,
                              const uint8_t signer[SOL_PUBKEY_SIZE],
                              const char* alias, const char* fp, bool certified,
                              ReviewEmit emit, void* ctx) {
  if (!tx || !s || !signer || !emit || ix_index >= tx->num_instructions) {
    return false;
  }
  char intent[SOL_INTENT_TEXT_MAX + 1];
  if (!solana_fillIntent(msg, tx, s, ix_index, certified, intent,
                         sizeof(intent))) {
    return false;
  }
  if (!certified) {
    /* Runtime (SRS-7.15 R-1.5): a heading plus limits; the caller's full raw
     * review follows unchanged. */
    return intent_emit_unverified(emit, ctx, alias, intent) &&
           review_limits(msg, tx, s, ix_index, signer, false, emit, ctx);
  }
  if (!emit(ctx, s->program_name, intent, NULL, 0) ||
      !review_limits(msg, tx, s, ix_index, signer, true, emit, ctx) ||
      !review_side_effects(tx, ix_index, signer, emit, ctx) ||
      !review_details(msg, tx, s, ix_index, true, emit, ctx)) {
    return false;
  }
  return intent_emit_provenance(emit, ctx, alias, fp);
}
