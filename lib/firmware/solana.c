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

#include "keepkey/firmware/signed_metadata.h"
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

/* allow_external_indices: versioned (v0) messages may reference accounts
 * loaded from address lookup tables — indices at or beyond the static
 * account list. Those accounts are not present in the message, so an
 * instruction touching them cannot be verified on-device: it is left
 * SOL_INSTR_UNKNOWN and the whole tx is forced opaque instead of being
 * rejected as malformed. Legacy messages must never contain such indices. */
static int parse_instruction_section(const uint8_t* raw, size_t raw_len,
                                     size_t* pos_io, SolanaParsedTx* tx,
                                     uint16_t num_accounts, bool* has_unknown,
                                     bool* force_opaque,
                                     bool allow_external_indices) {
  size_t pos = *pos_io;
  uint16_t num_instructions;
  int n = read_compact_u16(raw + pos, raw_len - pos, &num_instructions);
  if (n < 0) return -1;
  pos += n;

  if (num_instructions > SOL_MAX_INSTRUCTIONS) {
    /* Too many to display — opaque. Keep walking the section so the
     * structural checks (and any trailing sections) stay meaningful. */
    *force_opaque = true;
    tx->num_instructions = 0;
  } else {
    tx->num_instructions = (uint8_t)num_instructions;
  }

  for (uint16_t i = 0; i < num_instructions; i++) {
    if (pos >= raw_len) return -1;
    uint8_t program_idx = raw[pos++];
    bool external = false;
    if (program_idx >= num_accounts) {
      if (!allow_external_indices) return -1;
      external = true;
    }

    uint16_t num_acct_indices;
    n = read_compact_u16(raw + pos, raw_len - pos, &num_acct_indices);
    if (n < 0) return -1;
    pos += n;

    if (pos + num_acct_indices > raw_len) return -1;
    const uint8_t* acct_indices = raw + pos;
    pos += num_acct_indices;

    for (uint16_t j = 0; j < num_acct_indices; j++) {
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

    /* Retain the raw payload and account index list for EVERY instruction: a
     * KKSOLSC1 schema reads its args out of `data` and resolves its labelled
     * accounts through `acct_indices`. Both point into the caller's raw
     * message buffer and share its lifetime. (The memo path below also sets
     * data/data_len; assigning here first is harmless and covers the rest.) */
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

    /* Classify and decode.  A verified instruction must match the exact wire
     * shape whose fields the confirmation path displays.  Prefix matches are
     * opaque: trailing bytes are signed semantics, not ignorable padding. */
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
      /* Token-2022 transfers can invoke a configured transfer-hook program with
       * extra accounts and arbitrary logic (and levy transfer fees) that we can
       * neither authenticate nor display. Treat them as opaque (AdvancedMode)
       * rather than clear-sign only source/mint/dest/amount. */
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
          /* Unchecked Transfer carries no signed mint, so the device cannot
           * prove which token is moving — a host can pick any signer-controlled
           * account. Force the AdvancedMode blind-sign gate; only the *Checked
           * variant (mint signed + displayed) clear-signs. */
          *force_opaque = true;
        } else if (token_instr == SOL_TOKEN_TRANSFER_CHECKED_IX &&
                   data_len == 10 && num_acct_indices >= 4) {
          /* Canonical TransferChecked ONLY: opcode + amount(8) + decimals(1)
           * and all four accounts [source, mint, dest, authority]. A 9-byte
           * encoding (no decimals) or a short account list would otherwise
           * classify VERIFIED while skipping the mint screen and showing a
           * zeroed destination — such non-canonical shapes fall through to
           * UNKNOWN and force the whole tx opaque.
           *
           * This is the strict form of the 7.14.2 rule that a TransferChecked
           * shorter than 10 bytes must not classify as checked: the decimals
           * byte is the only authoritative scale for the transfer, so a
           * missing one may never be fabricated as 0. It additionally rejects
           * data_len > 10 and short account lists, which 7.14.2 still let
           * through. */
          pi->type = SOL_INSTR_TOKEN_TRANSFER_CHECKED;
          pi->amount = read_le64(instr_data + 1);
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->mint, tx, acct_indices, num_acct_indices, 1);
          pi->has_mint = true;
          copy_account(pi->to, tx, acct_indices, num_acct_indices, 2);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 3);
          /* Decimals live in the signed instruction bytes and are the only
           * authoritative scale for this transfer, so they must never be
           * fabricated. The data_len == 10 guard above is what makes this read
           * unconditional and in-bounds; a short encoding falls through to
           * SOL_INSTR_UNKNOWN and the transaction is treated as opaque. */
          pi->extra_u8 = instr_data[9];
          /* Token-2022 checked transfers may carry an undisclosed transfer hook
           * / fee — do not clear-sign them. */
          if (is_token2022) {
            *force_opaque = true;
          }
        } else if (token_instr == SOL_TOKEN_APPROVE_IX && data_len == 9 &&
                   num_acct_indices >= 3) {
          pi->type = SOL_INSTR_TOKEN_APPROVE;
          pi->amount = read_le64(instr_data + 1);
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
          /* Unchecked Approve hides the mint (which token is being delegated),
           * same as unchecked Transfer — require AdvancedMode. */
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
          pi->type = SOL_INSTR_TOKEN_SET_AUTHORITY;
          pi->extra_u8 = instr_data[1];
          copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
          copy_account(pi->authority, tx, acct_indices, num_acct_indices, 1);
          if (instr_data[2] == 1) {
            memcpy(pi->extra, instr_data + 3, SOL_PUBKEY_SIZE);
          }
          /* Authority handover (owner/close/mint/freeze) is an account-takeover
           * vector, and the "set to None" (clear) case is not distinguished
           * from an all-zero authority in the parsed struct. Require
           * AdvancedMode until a full screen (authority type + target +
           * new/None) exists. */
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
              token_instr == SOL_TOKEN_MINT_TO_CHECKED_IX ? instr_data[9] : 0;
          /* Checked and unchecked minting share one confirmation today, so
           * the signed opcode/scale is not fully represented. */
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
              token_instr == SOL_TOKEN_BURN_CHECKED_IX ? instr_data[9] : 0;
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
          /* UpdateValidatorIdentity has NO data payload: the new validator is
           * account index 1. Reading 32 bytes from the data would display
           * attacker-supplied trailing bytes instead of the account actually
           * used, so require the canonical 4-byte encoding and read account 1.
           */
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
      /* 0 = Create, 1 = CreateIdempotent, and empty data is the legacy
       * encoding of Create. Idempotent takes the SAME accounts in the same
       * order and creates the same account — it merely succeeds instead of
       * failing when one already exists — so it displays identically. Wallets
       * emit it by default (a token transfer whose recipient may lack an ATA),
       * and rejecting it forced the whole transaction opaque: an SPL transfer
       * that is otherwise fully decodable would blind-sign. */
      if ((data_len == 0 ||
           (data_len == 1 && (instr_data[0] == 0 || instr_data[0] == 1))) &&
          num_acct_indices >= 6) {
        pi->type = SOL_INSTR_ATA_CREATE;
        copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
        copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
        copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
        copy_account(pi->mint, tx, acct_indices, num_acct_indices, 3);
        pi->has_mint = true;
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
                                &has_unknown, &force_opaque,
                                /*allow_external_indices=*/false);
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
  bool force_opaque = false;

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
                                &has_unknown, &force_opaque,
                                /*allow_external_indices=*/true);
  if (n < 0) return SOL_TX_REVIEW_MALFORMED;

  uint16_t lookup_table_count;
  n = read_compact_u16(raw + pos, raw_len - pos, &lookup_table_count);
  if (n < 0) return SOL_TX_REVIEW_MALFORMED;
  pos += n;
  if (lookup_table_count != 0) {
    /* Clear-signing is intentionally limited to self-contained v0 messages.
     * Even if current instructions appear to use only static accounts, an ALT
     * section requires chain state that this firmware does not resolve. */
    force_opaque = true;
  }

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

  /* A zero-LUT v0 message is self-contained and can be verified like legacy.
   * Any lookup-table section remains available only through the AdvancedMode
   * opaque path until firmware can resolve and authenticate chain state. */
  if (tx->num_instructions == 0 || has_unknown || force_opaque) {
    return SOL_TX_REVIEW_OPAQUE;
  }
  return SOL_TX_REVIEW_VERIFIED;
}

/* Normalize the bytes that are actually signed. Solana signs the serialized
 * MESSAGE. Clients may send either the bare message (byte 0 = num_required_sigs
 * >= 1) or a full unsigned transaction whose byte 0 is a compact-u16 signature
 * count of 0. Strip that single prefix byte so parsing (solana_inspectTx) and
 * signing (solana_signTx) operate on the IDENTICAL slice — otherwise the device
 * would display one message but sign 0x00||message, which never verifies. */
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
  if (raw_len == 0) {
    memset(tx, 0, sizeof(*tx));
    return SOL_TX_REVIEW_MALFORMED;
  }

  const uint8_t* msg;
  size_t msg_len;
  solana_message_slice(raw, raw_len, &msg, &msg_len);

  /* Versioned Solana messages set the top bit in byte 0.
   * Parse them structurally so malformed v0/ALT payloads fail closed,
   * but keep the result opaque until the firmware can verify semantics. */
  if (msg[0] & SOL_VERSION_FLAG) {
    return solana_parseVersionedTx(msg, msg_len, tx);
  }

  return solana_parseLegacyTx(msg, msg_len, tx);
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

/* Byte width an arg consumes in the instruction data. */
uint16_t solana_schemaArgWidth(SolanaSchemaArgType t) {
  switch (t) {
    case SOL_SCHEMA_ARG_U64:
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
  if (*cur++ != 1) return false; /* version */

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
  if (out->num_args > SOL_SCHEMA_MAX_ARGS) return false;
  for (uint8_t i = 0; i < out->num_args; i++) {
    if (cur >= end) return false;
    uint8_t type = *cur++;
    if (solana_schemaArgWidth((SolanaSchemaArgType)type) == 0) return false;
    out->args[i].type = (SolanaSchemaArgType)type;
    if (!schema_read_text(&cur, end, out->args[i].label,
                          SOL_SCHEMA_LABEL_MAX)) {
      return false;
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

  return cur == end; /* no trailing bytes */
}

bool solana_schemaApplies(const SolanaInstrSchema* schema,
                          const SolanaParsedTx* tx, uint8_t* out_index) {
  if (!schema || !tx || !out_index) return false;

  bool found = false;
  uint8_t match = 0;
  for (uint8_t i = 0; i < tx->num_instructions; i++) {
    const SolanaParsedInstruction* ix = &tx->instructions[i];
    if (ix->external) continue; /* accounts not in the signed message */
    if (memcmp(ix->program_id, schema->program_id, SOL_PUBKEY_SIZE) != 0) {
      continue;
    }
    if (!ix->data || ix->data_len < schema->disc_len ||
        memcmp(ix->data, schema->disc, schema->disc_len) != 0) {
      continue;
    }

    /* Structural completeness: the discriminator plus every declared arg must
     * account for the instruction data EXACTLY. Leftover bytes could carry an
     * effect the screens never mention. */
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
    if (!accounts_ok) continue;

    if (found) return false; /* ambiguous: two instructions match */
    found = true;
    match = i;
  }
  if (!found) return false;

  /* A schema explains ONE instruction. Every other instruction must be one
   * firmware already decodes, or the message could move funds through a path
   * no screen described. */
  for (uint8_t i = 0; i < tx->num_instructions; i++) {
    if (i == match) continue;
    if (tx->instructions[i].external ||
        tx->instructions[i].type == SOL_INSTR_UNKNOWN) {
      return false;
    }
  }

  *out_index = match;
  return true;
}

bool solana_parseTx(const uint8_t* raw, size_t raw_len, SolanaParsedTx* tx) {
  return solana_inspectTx(raw, raw_len, tx) == SOL_TX_REVIEW_VERIFIED;
}

/* ------------------------------------------------------------------ */
/*  Formatting                                                         */
/* ------------------------------------------------------------------ */

bool solana_priority_fee_lamports(uint64_t price, uint64_t limit,
                                  uint64_t* out) {
  /* ceil(price * limit / 1e6) with no overflow and no silent wrap. price/limit
   * are u64; the product can exceed u64, and even ceil(product/1e6) can exceed
   * u64. Split price = q*D + r and accumulate so every step is checked; return
   * false (do NOT saturate) if the true lamport value exceeds UINT64_MAX. */
  const uint64_t D = 1000000u;
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

bool solana_calculatePriorityFee(const SolanaParsedTx* tx, uint64_t* fee_out,
                                 bool* has_fee) {
  if (!tx || !fee_out || !has_fee) return false;

  uint64_t price = 0;
  uint64_t limit = 0;
  uint64_t non_budget_instructions = 0;
  bool seen_price = false;
  bool seen_limit = false;
  *fee_out = 0;
  *has_fee = false;

  for (uint8_t i = 0; i < tx->num_instructions; i++) {
    const SolanaParsedInstruction* instruction = &tx->instructions[i];
    if (instruction->type != SOL_INSTR_COMPUTE_BUDGET_HEAP_FRAME &&
        instruction->type != SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT &&
        instruction->type != SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE &&
        instruction->type != SOL_INSTR_COMPUTE_BUDGET_LOADED_ACCOUNTS_SIZE) {
      non_budget_instructions++;
    }
    if (instruction->type == SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE) {
      if (seen_price) return false;
      seen_price = true;
      price = instruction->extra_value;
    } else if (instruction->type == SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT) {
      if (seen_limit) return false;
      seen_limit = true;
      limit = instruction->extra_value;
    }
  }

  if (!seen_limit) {
    /* Solana's runtime default is 200,000 compute units per non-budget
     * instruction, capped at 1,400,000. Derive the actual implicit limit
     * instead of overstating every transaction as though it used the cap. */
    limit = non_budget_instructions * 200000u;
    if (limit > 1400000u) limit = 1400000u;
  }

  if (!seen_price || price == 0) return true;
  if (!solana_priority_fee_lamports(price, limit, fee_out)) return false;
  *has_fee = true;
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
  if (decimals == 0 || decimals > SOL_MAX_TOKEN_DECIMALS) {
    snprintf(buf, len, "%llu %s", (unsigned long long)amount, symbol);
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
  /* Every fractional place is shown, trailing zeros included. Trimming them
   * ("1.000000000" -> "1") hides the scale the signed base-unit count was
   * divided by, which is the one thing this screen exists to disclose. */
  snprintf(buf, len, "%llu.%s %s", (unsigned long long)whole, frac_str, symbol);
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
  /* Solana find_program_address searches bump seeds from 255 down. A valid PDA
   * is SHA256(seeds..., bump, program_id, "ProgramDerivedAddress") that does
   * NOT decompress to an Ed25519 curve point. */
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
  /* Domain tag prevents a signature made for any other purpose (e.g. an EVM
   * metadata blob signed by the same key) from being replayed as a token def.
   * Preimage: tag || mint(32) || decimals(le32) || symbol. */
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

bool solana_lut_accounts_trusted(const uint8_t* raw_tx, size_t raw_len,
                                 const uint8_t (*accounts)[32],
                                 size_t num_accounts, uint32_t signer_key_id,
                                 const uint8_t* sig, size_t sig_len) {
  if (!raw_tx || !accounts || !sig || num_accounts == 0) return false;
  if (num_accounts > SOL_MAX_LUT_ACCOUNTS) return false;
  /* uint32 field: reject out-of-range slots BEFORE narrowing to the uint8 the
   * keyring uses, so key_id 256 cannot alias slot 0. Same reasoning as
   * solana_token_info_trusted(). */
  if (signer_key_id >= METADATA_MAX_KEYS) return false;

  /* Bind to the transaction by hashing the exact bytes being signed. Solana
     signs the message directly, so a sha256 over it is ours alone and never
     collides with the ed25519 signature the device is about to produce. */
  uint8_t msg_hash[SHA256_DIGEST_LENGTH];
  sha256_Raw(raw_tx, raw_len, msg_hash);

  /* Build the preimage in full and hand it over RAW: verify_attestation()
     hashes what it is given, so passing a digest here would verify over
     sha256(sha256(preimage)) and no honest signer could ever match it. Same
     shape as solana_token_info_trusted(). Bounded by SOL_MAX_LUT_ACCOUNTS, so
     the worst case is 25 + 32 + 4 + 8*32 = 317 bytes. */
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

  return signed_metadata_verify_attestation((uint8_t)signer_key_id, blob, n,
                                            sig, sig_len);
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
  /* Defense-in-depth: refuse to emit a signature that does not verify over
   * those exact bytes. solana_message_slice() already guarantees parsing and
   * signing operate on the identical message, so this is a redundant check;
   * it is compiled out on the ROM-tight zcash-privacy variant, where pulling in
   * the ed25519 verification path would overflow flash. */
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
