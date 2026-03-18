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
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93,
    0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91,
    0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9
};

/* TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb */
const uint8_t SOL_TOKEN_2022_PROGRAM[SOL_PUBKEY_SIZE] = {
    0x06, 0xdd, 0xf6, 0xe1, 0xee, 0x75, 0x8f, 0xde,
    0x18, 0x42, 0x5d, 0xbc, 0xe4, 0x6c, 0xcd, 0xda,
    0xb6, 0x1a, 0xfc, 0x4d, 0x83, 0xb9, 0x0d, 0x27,
    0xfe, 0xbd, 0xf9, 0x28, 0xd8, 0xa1, 0x8b, 0xfc
};

/* Stake11111111111111111111111111111111111111 */
const uint8_t SOL_STAKE_PROGRAM[SOL_PUBKEY_SIZE] = {
    0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x2a,
    0x98, 0x34, 0x37, 0xbd, 0xfe, 0x2a, 0x7a, 0xb2,
    0x55, 0x7f, 0x53, 0x5c, 0x8a, 0x78, 0x72, 0x2b,
    0x68, 0xa4, 0x9d, 0xc0, 0x00, 0x00, 0x00, 0x00
};

/* Vote111111111111111111111111111111111111111 */
const uint8_t SOL_VOTE_PROGRAM[SOL_PUBKEY_SIZE] = {
    0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb,
    0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd, 0xb3,
    0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc,
    0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00
};

/* ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL */
const uint8_t SOL_ATA_PROGRAM[SOL_PUBKEY_SIZE] = {
    0x8c, 0x97, 0x25, 0x8f, 0x4e, 0x24, 0x89, 0xf1,
    0xbb, 0x3d, 0x10, 0x29, 0x14, 0x8e, 0x0d, 0x83,
    0x0b, 0x5a, 0x13, 0x99, 0xda, 0xff, 0x10, 0x84,
    0x04, 0x8e, 0x7b, 0xd8, 0xdb, 0xe9, 0xf8, 0x59
};

/* ComputeBudget111111111111111111111111111111 */
const uint8_t SOL_COMPUTE_BUDGET_PROGRAM[SOL_PUBKEY_SIZE] = {
    0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32,
    0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, 0x9b, 0xe7,
    0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7, 0x12, 0x6b,
    0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, 0x00, 0x00
};

/* MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr */
const uint8_t SOL_MEMO_PROGRAM[SOL_PUBKEY_SIZE] = {
    0x05, 0x4a, 0x53, 0x5a, 0x99, 0x29, 0x21, 0x06,
    0x4d, 0x24, 0xe8, 0x71, 0x60, 0xda, 0x38, 0x7c,
    0x7c, 0x35, 0xb5, 0xdd, 0xbc, 0x92, 0xbb, 0x81,
    0xe4, 0x1f, 0xa8, 0x40, 0x41, 0x05, 0x44, 0x8d
};

/* ------------------------------------------------------------------ */
/*  Compact-u16 decoder (Solana transaction format)                    */
/* ------------------------------------------------------------------ */

static int read_compact_u16(const uint8_t *data, size_t len, uint16_t *out) {
    if (len < 1) return -1;

    if (data[0] < 0x80) {
        *out = data[0];
        return 1;
    }

    if (len < 2) return -1;
    if (data[1] < 0x80) {
        *out = (uint16_t)((data[0] & 0x7F) | ((uint16_t)data[1] << 7));
        return 2;
    }

    if (len < 3) return -1;
    /* Third byte uses bits 14-15, so only values 0-3 are valid
     * (max compact-u16 value is 0xFFFF = 65535). */
    if (data[2] > 3) return -1;
    *out = (uint16_t)((data[0] & 0x7F) | ((data[1] & 0x7F) << 7) |
                       ((uint16_t)data[2] << 14));
    return 3;
}

static uint64_t read_le64(const uint8_t *p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void copy_account(uint8_t out[SOL_PUBKEY_SIZE],
                         const SolanaParsedTx *tx,
                         const uint8_t *acct_indices,
                         uint16_t num_acct_indices,
                         uint16_t idx) {
    if (idx < num_acct_indices) {
        memcpy(out, tx->accounts[acct_indices[idx]], SOL_PUBKEY_SIZE);
    }
}

static int parse_instruction_section(const uint8_t *raw, size_t raw_len,
                                     size_t *pos_io, SolanaParsedTx *tx,
                                     uint16_t num_accounts, bool *has_unknown,
                                     bool *force_opaque) {
    size_t pos = *pos_io;
    uint16_t num_instructions;
    int n = read_compact_u16(raw + pos, raw_len - pos, &num_instructions);
    if (n < 0) return -1;
    pos += n;

    if (num_instructions > 8) {
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
        const uint8_t *acct_indices = raw + pos;
        pos += num_acct_indices;

        for (uint16_t j = 0; j < num_acct_indices; j++) {
            if (acct_indices[j] >= num_accounts) return -1;
        }

        uint16_t data_len;
        n = read_compact_u16(raw + pos, raw_len - pos, &data_len);
        if (n < 0) return -1;
        pos += n;

        if (pos + data_len > raw_len) return -1;
        const uint8_t *instr_data = raw + pos;
        pos += data_len;

        if (i >= 8) {
            continue;
        }

        SolanaParsedInstruction *pi = &tx->instructions[i];
        memcpy(pi->program_id, tx->accounts[program_idx], SOL_PUBKEY_SIZE);

        /* Classify and decode */
        if (memcmp(pi->program_id, SOL_SYSTEM_PROGRAM,
                   SOL_PUBKEY_SIZE) == 0) {
            /* System program */
            if (data_len >= 4) {
                uint32_t instr_type = read_le32(instr_data);
                if (instr_type == 2 && data_len >= 12) {
                    pi->type = SOL_INSTR_SYSTEM_TRANSFER;
                    pi->lamports = read_le64(instr_data + 4);
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
                } else if (instr_type == 0 && data_len >= 12) {
                    pi->type = SOL_INSTR_SYSTEM_CREATE_ACCOUNT;
                    pi->lamports = read_le64(instr_data + 4);
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
                } else if (instr_type == 4) {
                    pi->type = SOL_INSTR_SYSTEM_ADVANCE_NONCE;
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
                } else if (instr_type == 5 && data_len >= 12) {
                    pi->type = SOL_INSTR_SYSTEM_WITHDRAW_NONCE;
                    pi->lamports = read_le64(instr_data + 4);
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 4);
                } else if (instr_type == 6 && data_len >= 36) {
                    pi->type = SOL_INSTR_SYSTEM_INITIALIZE_NONCE;
                    memcpy(pi->authority, instr_data + 4, SOL_PUBKEY_SIZE);
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                } else if (instr_type == 7 && data_len >= 36) {
                    pi->type = SOL_INSTR_SYSTEM_AUTHORIZE_NONCE;
                    memcpy(pi->extra, instr_data + 4, SOL_PUBKEY_SIZE);
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 1);
                } else if (instr_type == 1 && data_len >= 36) {
                    pi->type = SOL_INSTR_SYSTEM_ASSIGN;
                    memcpy(pi->extra, instr_data + 4, SOL_PUBKEY_SIZE);
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                } else if (instr_type == 8 && data_len >= 12) {
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
        } else if (memcmp(pi->program_id, SOL_TOKEN_PROGRAM,
                          SOL_PUBKEY_SIZE) == 0 ||
                   memcmp(pi->program_id, SOL_TOKEN_2022_PROGRAM,
                          SOL_PUBKEY_SIZE) == 0) {
            if (data_len >= 1) {
                uint8_t token_instr = instr_data[0];
                if (token_instr == 3 && data_len >= 9) {
                    pi->type = SOL_INSTR_TOKEN_TRANSFER;
                    pi->amount = read_le64(instr_data + 1);
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
                } else if (token_instr == 12 && data_len >= 9) {
                    pi->type = SOL_INSTR_TOKEN_TRANSFER_CHECKED;
                    pi->amount = read_le64(instr_data + 1);
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->mint, tx, acct_indices, num_acct_indices, 1);
                    pi->has_mint = (num_acct_indices >= 2);
                    copy_account(pi->to, tx, acct_indices, num_acct_indices, 2);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 3);
                    pi->extra_u8 = data_len >= 10 ? instr_data[9] : 0;
                } else if (token_instr == 4 && data_len >= 9) {
                    pi->type = SOL_INSTR_TOKEN_APPROVE;
                    pi->amount = read_le64(instr_data + 1);
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
                } else if (token_instr == 5) {
                    pi->type = SOL_INSTR_TOKEN_REVOKE;
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 1);
                } else if (token_instr == 6 && data_len >= 2) {
                    pi->type = SOL_INSTR_TOKEN_SET_AUTHORITY;
                    pi->extra_u8 = instr_data[1];
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 1);
                    if (data_len >= 35 && instr_data[2] == 1) {
                        memcpy(pi->extra, instr_data + 3, SOL_PUBKEY_SIZE);
                    }
                } else if ((token_instr == 7 || token_instr == 14) && data_len >= 9) {
                    pi->type = SOL_INSTR_TOKEN_MINT_TO;
                    pi->amount = read_le64(instr_data + 1);
                    copy_account(pi->mint, tx, acct_indices, num_acct_indices, 0);
                    pi->has_mint = (num_acct_indices >= 1);
                    copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
                    pi->extra_u8 = (token_instr == 14 && data_len >= 10) ? instr_data[9] : 0;
                } else if ((token_instr == 8 || token_instr == 15) && data_len >= 9) {
                    pi->type = SOL_INSTR_TOKEN_BURN;
                    pi->amount = read_le64(instr_data + 1);
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->mint, tx, acct_indices, num_acct_indices, 1);
                    pi->has_mint = (num_acct_indices >= 2);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
                    pi->extra_u8 = (token_instr == 15 && data_len >= 10) ? instr_data[9] : 0;
                } else if (token_instr == 9) {
                    pi->type = SOL_INSTR_TOKEN_CLOSE_ACCOUNT;
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
                } else if (token_instr == 10) {
                    pi->type = SOL_INSTR_TOKEN_FREEZE_ACCOUNT;
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->mint, tx, acct_indices, num_acct_indices, 1);
                    pi->has_mint = (num_acct_indices >= 2);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
                } else if (token_instr == 11) {
                    pi->type = SOL_INSTR_TOKEN_THAW_ACCOUNT;
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->mint, tx, acct_indices, num_acct_indices, 1);
                    pi->has_mint = (num_acct_indices >= 2);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
                } else if (token_instr == 17) {
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
        } else if (memcmp(pi->program_id, SOL_STAKE_PROGRAM,
                          SOL_PUBKEY_SIZE) == 0) {
            if (data_len >= 4) {
                uint32_t stake_instr = read_le32(instr_data);
                if (stake_instr == 2) {
                    pi->type = SOL_INSTR_STAKE_DELEGATE;
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 5);
                    copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
                } else if (stake_instr == 4 && data_len >= 12) {
                    pi->type = SOL_INSTR_STAKE_WITHDRAW;
                    pi->lamports = read_le64(instr_data + 4);
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 4);
                } else if (stake_instr == 1 && data_len >= 36) {
                    pi->type = SOL_INSTR_STAKE_AUTHORIZE;
                    memcpy(pi->extra, instr_data + 4, SOL_PUBKEY_SIZE);
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 1);
                    pi->extra_u8 = (uint8_t)read_le32(instr_data + 36);
                } else if (stake_instr == 3 && data_len >= 12) {
                    pi->type = SOL_INSTR_STAKE_SPLIT;
                    pi->lamports = read_le64(instr_data + 4);
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
                } else if (stake_instr == 5) {
                    pi->type = SOL_INSTR_STAKE_DEACTIVATE;
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
                } else if (stake_instr == 7) {
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
        } else if (memcmp(pi->program_id, SOL_VOTE_PROGRAM,
                          SOL_PUBKEY_SIZE) == 0) {
            if (data_len >= 4) {
                uint32_t vote_instr = read_le32(instr_data);
                if (vote_instr == 1 && data_len >= 40) {
                    pi->type = SOL_INSTR_VOTE_AUTHORIZE;
                    memcpy(pi->extra, instr_data + 4, SOL_PUBKEY_SIZE);
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 1);
                    pi->extra_u8 = (uint8_t)read_le32(instr_data + 36);
                } else if (vote_instr == 3 && data_len >= 12) {
                    pi->type = SOL_INSTR_VOTE_WITHDRAW;
                    pi->lamports = read_le64(instr_data + 4);
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
                } else if (vote_instr == 4 && data_len >= 36) {
                    pi->type = SOL_INSTR_VOTE_UPDATE_VALIDATOR;
                    memcpy(pi->extra, instr_data + 4, SOL_PUBKEY_SIZE);
                    copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                    copy_account(pi->authority, tx, acct_indices, num_acct_indices, 1);
                } else if (vote_instr == 5 && data_len >= 5) {
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
        } else if (memcmp(pi->program_id, SOL_ATA_PROGRAM,
                          SOL_PUBKEY_SIZE) == 0) {
            if (data_len == 0 || (data_len == 1 && instr_data[0] == 0)) {
                pi->type = SOL_INSTR_ATA_CREATE;
                copy_account(pi->from, tx, acct_indices, num_acct_indices, 0);
                copy_account(pi->to, tx, acct_indices, num_acct_indices, 1);
                copy_account(pi->authority, tx, acct_indices, num_acct_indices, 2);
                copy_account(pi->mint, tx, acct_indices, num_acct_indices, 3);
                pi->has_mint = (num_acct_indices >= 4);
            } else {
                pi->type = SOL_INSTR_UNKNOWN;
                *has_unknown = true;
            }
        } else if (memcmp(pi->program_id, SOL_COMPUTE_BUDGET_PROGRAM,
                          SOL_PUBKEY_SIZE) == 0) {
            if (data_len >= 1) {
                uint8_t cb_instr = instr_data[0];
                if (cb_instr == 1 && data_len >= 5) {
                    pi->type = SOL_INSTR_COMPUTE_BUDGET_HEAP_FRAME;
                    pi->extra_value = read_le32(instr_data + 1);
                } else if (cb_instr == 2 && data_len >= 5) {
                    pi->type = SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT;
                    pi->extra_value = read_le32(instr_data + 1);
                } else if (cb_instr == 3 && data_len >= 9) {
                    pi->type = SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE;
                    pi->extra_value = read_le64(instr_data + 1);
                } else if (cb_instr == 4 && data_len >= 5) {
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
        } else if (memcmp(pi->program_id, SOL_MEMO_PROGRAM,
                          SOL_PUBKEY_SIZE) == 0) {
            pi->type = SOL_INSTR_MEMO;
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

static SolanaTxReview solana_parseLegacyTx(const uint8_t *raw, size_t raw_len,
                                           SolanaParsedTx *tx) {
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

    if (num_accounts > 32) return SOL_TX_REVIEW_OPAQUE;
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

static SolanaTxReview solana_parseVersionedTx(const uint8_t *raw, size_t raw_len,
                                              SolanaParsedTx *tx) {
    memset(tx, 0, sizeof(*tx));
    size_t pos = 0;
    bool has_unknown = false;
    bool force_opaque = true;

    if (raw_len < 1) return SOL_TX_REVIEW_MALFORMED;
    uint8_t version_prefix = raw[pos++];
    if ((version_prefix & 0x80) == 0) return SOL_TX_REVIEW_MALFORMED;
    if ((version_prefix & 0x7f) != 0) return SOL_TX_REVIEW_OPAQUE;

    if (raw_len - pos < 3) return SOL_TX_REVIEW_MALFORMED;
    tx->num_required_sigs = raw[pos++];
    tx->num_readonly_signed = raw[pos++];
    tx->num_readonly_unsigned = raw[pos++];

    uint16_t num_accounts;
    int n = read_compact_u16(raw + pos, raw_len - pos, &num_accounts);
    if (n < 0) return SOL_TX_REVIEW_MALFORMED;
    pos += n;

    if (num_accounts > 32) return SOL_TX_REVIEW_OPAQUE;
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

SolanaTxReview solana_inspectTx(const uint8_t *raw, size_t raw_len,
                                SolanaParsedTx *tx) {
    if (raw_len == 0) {
        memset(tx, 0, sizeof(*tx));
        return SOL_TX_REVIEW_MALFORMED;
    }

    /* Versioned Solana messages set the top bit in byte 0.
     * Parse them structurally so malformed v0/ALT payloads fail closed,
     * but keep the result opaque until the firmware can verify semantics. */
    if (raw[0] & 0x80) {
        return solana_parseVersionedTx(raw, raw_len, tx);
    }

    return solana_parseLegacyTx(raw, raw_len, tx);
}

bool solana_parseTx(const uint8_t *raw, size_t raw_len, SolanaParsedTx *tx) {
    return solana_inspectTx(raw, raw_len, tx) == SOL_TX_REVIEW_VERIFIED;
}

/* ------------------------------------------------------------------ */
/*  Formatting                                                         */
/* ------------------------------------------------------------------ */

void solana_formatAmount(char *buf, size_t len, uint64_t lamports) {
    uint64_t whole = lamports / 1000000000ULL;
    uint64_t frac  = lamports % 1000000000ULL;
    snprintf(buf, len, "%llu.%09llu SOL",
             (unsigned long long)whole, (unsigned long long)frac);
}

void solana_formatTokenAmount(char *buf, size_t len, uint64_t amount,
                              const char *symbol, uint8_t decimals) {
    if (decimals == 0 || decimals > 18) {
        snprintf(buf, len, "%llu %s", (unsigned long long)amount, symbol);
        return;
    }

    uint64_t divisor = 1;
    for (uint8_t i = 0; i < decimals; i++) divisor *= 10;

    uint64_t whole = amount / divisor;
    uint64_t frac  = amount % divisor;

    /* Format with appropriate decimal places (max 9 shown) */
    uint8_t show_dec = decimals > 9 ? 9 : decimals;
    uint64_t show_div = 1;
    for (uint8_t i = 0; i < show_dec; i++) show_div *= 10;
    (void)show_div;
    uint64_t show_frac = frac;
    if (decimals > 9) {
        for (uint8_t i = 0; i < decimals - 9; i++) show_frac /= 10;
    }

    char frac_str[10];
    for (int8_t i = (int8_t)show_dec - 1; i >= 0; i--) {
        frac_str[i] = '0' + (show_frac % 10);
        show_frac /= 10;
    }
    frac_str[show_dec] = '\0';
    snprintf(buf, len, "%llu.%s %s", (unsigned long long)whole, frac_str,
             symbol);
}

const SolanaTokenInfo *solana_findTokenInfo(const SolanaSignTx *msg,
                                            const uint8_t mint[SOL_PUBKEY_SIZE]) {
    for (size_t i = 0; i < msg->token_info_count; i++) {
        if (msg->token_info[i].has_mint &&
            msg->token_info[i].mint.size == SOL_PUBKEY_SIZE &&
            memcmp(msg->token_info[i].mint.bytes, mint, SOL_PUBKEY_SIZE) == 0) {
            return &msg->token_info[i];
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Signing                                                            */
/* ------------------------------------------------------------------ */

bool solana_signTx(const HDNode *node, const SolanaSignTx *msg,
                   SolanaSignedTx *resp) {
    if (!msg->has_raw_tx || msg->raw_tx.size == 0) return false;

    /* Ed25519 sign the raw transaction message directly
     * (Solana signs the serialized message, not a hash of it) */
    uint8_t sig[SOL_SIG_SIZE];
    ed25519_sign(msg->raw_tx.bytes, msg->raw_tx.size,
                 node->private_key, node->public_key + 1, sig);

    resp->has_signature = true;
    resp->signature.size = SOL_SIG_SIZE;
    memcpy(resp->signature.bytes, sig, SOL_SIG_SIZE);

    return true;
}
