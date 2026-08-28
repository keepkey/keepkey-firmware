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

#include "trezor/crypto/memzero.h"

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

static int parse_instruction_section(const uint8_t* raw, size_t raw_len,
                                     size_t* pos_io, SolanaParsedTx* tx,
                                     uint16_t num_accounts, bool* has_unknown,
                                     bool* force_opaque) {
  size_t pos = *pos_io;
  uint16_t num_instructions;
  int n = read_compact_u16(raw + pos, raw_len - pos, &num_instructions);
  if (n < 0) return -1;
  pos += n;

  if (num_instructions > SOL_MAX_INSTRUCTIONS) {
    *force_opaque = true;
    tx->num_instructions = 0;
    /* Don't attempt to parse instruction data — treat as opaque. */
    *pos_io = raw_len;
    return 0;
  } else {
    tx->num_instructions = (uint8_t)num_instructions;
  }

  for (uint16_t i = 0; i < num_instructions; i++) {
    if (pos >= raw_len) return -1;
    uint8_t program_idx = raw[pos++];
    if (program_idx >= num_accounts) return -1;

    uint16_t num_acct_indices;
    n = read_compact_u16(raw + pos, raw_len - pos, &num_acct_indices);
    if (n < 0) return -1;
    pos += n;

    if (pos + num_acct_indices > raw_len) return -1;
    const uint8_t* acct_indices = raw + pos;
    pos += num_acct_indices;

    for (uint16_t j = 0; j < num_acct_indices; j++) {
      if (acct_indices[j] >= num_accounts) return -1;
    }

    uint16_t data_len;
    n = read_compact_u16(raw + pos, raw_len - pos, &data_len);
    if (n < 0) return -1;
    pos += n;

    if (pos + data_len > raw_len) return -1;
    const uint8_t* instr_data = raw + pos;
    pos += data_len;

    if (i >= SOL_MAX_INSTRUCTIONS) {
      continue;
    }

    SolanaParsedInstruction* pi = &tx->instructions[i];
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
      bool is_token_2022 =
          memcmp(pi->program_id, SOL_TOKEN_2022_PROGRAM, SOL_PUBKEY_SIZE) == 0;
      /* Token-2022 extensions (fees, hooks and their extra accounts) are not
       * authenticated or displayed by this decoder. Never present any
       * Token-2022 operation as verified; AdvancedMode remains available for
       * an explicit opaque signature. */
      if (is_token_2022) *force_opaque = true;
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
      if ((data_len == 0 || (data_len == 1 && instr_data[0] == 0)) &&
          num_acct_indices >= 6) {
        pi->type = SOL_INSTR_ATA_CREATE;
        copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
        copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
        copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
        copy_account(pi->mint, tx, acct_indices, num_acct_indices, 3);
        pi->has_mint = true;
        /* Canonical ATA Create then names the System and Token programs. A
         * Token-2022 program here creates a materially different account even
         * though the instruction itself targets the ATA program. Until the
         * Token-2022 semantics can be disclosed, only the exact legacy pair is
         * clear-signed. */
        if (memcmp(tx->accounts[acct_indices[4]], SOL_SYSTEM_PROGRAM,
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
          pi->type = SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT;
          pi->extra_value = read_le32(instr_data + 1);
        } else if (cb_instr == SOL_CB_SET_COMPUTE_UNIT_PRICE && data_len == 9) {
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

  if (num_accounts > SOL_MAX_ACCOUNTS) return SOL_TX_REVIEW_OPAQUE;
  tx->num_accounts = (uint8_t)num_accounts;

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

  n = parse_instruction_section(raw, raw_len, &pos, tx, num_accounts,
                                &has_unknown, &force_opaque);
  if (n < 0) return SOL_TX_REVIEW_MALFORMED;

  /* Reject if there are unconsumed bytes — prevents hidden trailing data */
  if (pos != raw_len) return SOL_TX_REVIEW_MALFORMED;

  if (tx->num_instructions == 0 || has_unknown || force_opaque) {
    return SOL_TX_REVIEW_OPAQUE;
  }
  return SOL_TX_REVIEW_VERIFIED;
}

static SolanaTxReview solana_parseVersionedTx(const uint8_t* raw,
                                              size_t raw_len,
                                              SolanaParsedTx* tx) {
  memset(tx, 0, sizeof(*tx));
  size_t pos = 0;
  bool has_unknown = false;
  bool force_opaque = true;

  if (raw_len < 1) return SOL_TX_REVIEW_MALFORMED;
  uint8_t version_prefix = raw[pos++];
  if ((version_prefix & SOL_VERSION_FLAG) == 0) return SOL_TX_REVIEW_MALFORMED;
  if ((version_prefix & SOL_VERSION_MASK) != 0) return SOL_TX_REVIEW_OPAQUE;

  if (raw_len - pos < 3) return SOL_TX_REVIEW_MALFORMED;
  tx->num_required_sigs = raw[pos++];
  tx->num_readonly_signed = raw[pos++];
  tx->num_readonly_unsigned = raw[pos++];

  uint16_t num_accounts;
  int n = read_compact_u16(raw + pos, raw_len - pos, &num_accounts);
  if (n < 0) return SOL_TX_REVIEW_MALFORMED;
  pos += n;

  if (num_accounts > SOL_MAX_ACCOUNTS) return SOL_TX_REVIEW_OPAQUE;
  tx->num_accounts = (uint8_t)num_accounts;

  for (uint16_t i = 0; i < num_accounts; i++) {
    if (pos + SOL_PUBKEY_SIZE > raw_len) return SOL_TX_REVIEW_MALFORMED;
    memcpy(tx->accounts[i], raw + pos, SOL_PUBKEY_SIZE);
    pos += SOL_PUBKEY_SIZE;
  }

  if (pos + SOL_PUBKEY_SIZE > raw_len) return SOL_TX_REVIEW_MALFORMED;
  memcpy(tx->recent_blockhash, raw + pos, SOL_PUBKEY_SIZE);
  pos += SOL_PUBKEY_SIZE;

  n = parse_instruction_section(raw, raw_len, &pos, tx, num_accounts,
                                &has_unknown, &force_opaque);
  if (n < 0) return SOL_TX_REVIEW_MALFORMED;

  uint16_t lookup_table_count;
  n = read_compact_u16(raw + pos, raw_len - pos, &lookup_table_count);
  if (n < 0) return SOL_TX_REVIEW_MALFORMED;
  pos += n;

  for (uint16_t i = 0; i < lookup_table_count; i++) {
    uint16_t writable_count, readonly_count;
    if (pos + SOL_PUBKEY_SIZE > raw_len) return SOL_TX_REVIEW_MALFORMED;
    pos += SOL_PUBKEY_SIZE; /* lookup table account key */

    n = read_compact_u16(raw + pos, raw_len - pos, &writable_count);
    if (n < 0) return SOL_TX_REVIEW_MALFORMED;
    pos += n;
    if (pos + writable_count > raw_len) return SOL_TX_REVIEW_MALFORMED;
    pos += writable_count;

    n = read_compact_u16(raw + pos, raw_len - pos, &readonly_count);
    if (n < 0) return SOL_TX_REVIEW_MALFORMED;
    pos += n;
    if (pos + readonly_count > raw_len) return SOL_TX_REVIEW_MALFORMED;
    pos += readonly_count;
  }

  if (pos != raw_len) return SOL_TX_REVIEW_MALFORMED;
  return SOL_TX_REVIEW_OPAQUE;
}

static bool solana_messageBytes(const uint8_t* raw, size_t raw_len,
                                const uint8_t** message, size_t* message_len) {
  if (!raw || raw_len == 0 || !message || !message_len) return false;
  if (raw[0] == 0) {
    if (raw_len == 1) return false;
    raw++;
    raw_len--;
  }
  *message = raw;
  *message_len = raw_len;
  return true;
}

SolanaTxReview solana_inspectTx(const uint8_t* raw, size_t raw_len,
                                SolanaParsedTx* tx) {
  const uint8_t* message;
  size_t message_len;
  if (!solana_messageBytes(raw, raw_len, &message, &message_len)) {
    memset(tx, 0, sizeof(*tx));
    return SOL_TX_REVIEW_MALFORMED;
  }

  /* Clients may send either a serialized message or a full unsigned
   * transaction whose compact-u16 signature count is zero. Solana signatures
   * cover the message, not that transaction prefix. solana_signTx() performs
   * the identical normalization before signing. */
  raw = message;
  raw_len = message_len;

  /* Versioned Solana messages set the top bit in byte 0.
   * Parse them structurally so malformed v0/ALT payloads fail closed,
   * but keep the result opaque until the firmware can verify semantics. */
  if (raw[0] & SOL_VERSION_FLAG) {
    return solana_parseVersionedTx(raw, raw_len, tx);
  }

  return solana_parseLegacyTx(raw, raw_len, tx);
}

bool solana_parseTx(const uint8_t* raw, size_t raw_len, SolanaParsedTx* tx) {
  return solana_inspectTx(raw, raw_len, tx) == SOL_TX_REVIEW_VERIFIED;
}

/* ------------------------------------------------------------------ */
/*  Formatting                                                         */
/* ------------------------------------------------------------------ */

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
  snprintf(buf, len, "%llu.%s %s", (unsigned long long)whole, frac_str, symbol);
}

/* Solana's own default when a transaction carries no SetComputeUnitLimit:
   200,000 compute units per non-ComputeBudget instruction, capped at
   1,400,000. See the runtime's compute_budget_processor. */
#define SOL_DEFAULT_CU_PER_INSTRUCTION 200000u
#define SOL_MAX_CU_LIMIT 1400000u

static bool solana_isComputeBudgetInstruction(uint8_t type) {
  return type == SOL_INSTR_COMPUTE_BUDGET_HEAP_FRAME ||
         type == SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT ||
         type == SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE ||
         type == SOL_INSTR_COMPUTE_BUDGET_LOADED_ACCOUNTS_SIZE;
}

bool solana_calculatePriorityFee(const SolanaParsedTx* tx, uint64_t* fee_out,
                                 bool* has_fee) {
  const uint64_t divisor = 1000000u;
  uint64_t price = 0;
  uint64_t limit = 0;
  bool seen_price = false;
  bool seen_limit = false;
  uint64_t non_budget_instructions = 0;
  *has_fee = false;

  for (uint8_t i = 0; i < tx->num_instructions; i++) {
    const SolanaParsedInstruction* pi = &tx->instructions[i];
    if (!solana_isComputeBudgetInstruction((uint8_t)pi->type)) {
      non_budget_instructions++;
    }
    if (pi->type == SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE) {
      if (seen_price) return false;
      seen_price = true;
      price = pi->extra_value;
    } else if (pi->type == SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT) {
      if (seen_limit) return false;
      seen_limit = true;
      limit = pi->extra_value;
    }
  }

  if (!seen_limit) {
    /* Not the 1,400,000 cap.
     *
     * Assuming the cap whenever SetComputeUnitLimit was absent overstated the
     * screen badly: a transfer plus a unit-price instruction is charged on
     * 200,000 CUs, and the device showed seven times that as the "Maximum
     * priority fee". It is an upper bound, so nothing was ever understated --
     * but a maximum the runtime will never reach is not the transaction's
     * maximum, and this release line is about screens that describe the thing
     * being signed. num_instructions is a uint8_t, so this cannot overflow. */
    limit = non_budget_instructions * SOL_DEFAULT_CU_PER_INSTRUCTION;
    if (limit > SOL_MAX_CU_LIMIT) limit = SOL_MAX_CU_LIMIT;
  }

  if (!seen_price || price == 0) return true;

  uint64_t whole = price / divisor;
  uint64_t remainder = price % divisor;
  if (limit != 0 && whole > UINT64_MAX / limit) return false;
  uint64_t base = whole * limit;
  uint64_t remainder_product = remainder * limit;
  uint64_t rounded = remainder_product / divisor;
  if (remainder_product % divisor != 0) rounded++;
  if (base > UINT64_MAX - rounded) return false;

  *fee_out = base + rounded;
  *has_fee = true;
  return true;
}

/* ------------------------------------------------------------------ */
/*  Signing                                                            */
/* ------------------------------------------------------------------ */

bool solana_signTx(const HDNode* node, const SolanaSignTx* msg,
                   SolanaSignedTx* resp) {
  if (!msg->has_raw_tx || msg->raw_tx.size == 0) return false;

  const uint8_t* message;
  size_t message_len;
  if (!solana_messageBytes(msg->raw_tx.bytes, msg->raw_tx.size, &message,
                           &message_len)) {
    return false;
  }

  /* Ed25519 signs the serialized message directly, never the full
   * transaction's compact-u16 signature-count prefix. */
  uint8_t sig[SOL_SIG_SIZE];
  ed25519_sign(message, message_len, node->private_key, sig);

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
