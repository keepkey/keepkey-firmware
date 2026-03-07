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

#include "keepkey/firmware/solana_tx.h"
#include "keepkey/firmware/solana.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/layout.h"
#include "trezor/crypto/memzero.h"

#include <string.h>
#include <stdio.h>

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

// Compact-u16 encoding used by Solana (little-endian varint, bit 7 = continuation)
bool read_compact_u16(const uint8_t **data, size_t *remaining, uint16_t *out) {
    if (*remaining < 1) return false;
    uint16_t val = 0;
    int shift = 0;
    for (int i = 0; i < 3; i++) {
        if (*remaining < 1) return false;
        uint8_t b = (*data)[0];
        (*data)++; (*remaining)--;
        val |= (uint16_t)(b & 0x7F) << shift;
        if ((b & 0x80) == 0) { *out = val; return true; }
        shift += 7;
    }
    return false; // too many continuation bytes
}

bool solana_parseTransaction(const uint8_t *raw_tx, size_t tx_size,
                              SolanaParsedTransaction *parsed) {
    if (!raw_tx || !parsed || tx_size < 3) {
        return false;
    }

    memzero(parsed, sizeof(*parsed));

    const uint8_t *data = raw_tx;
    size_t remaining = tx_size;

    // Read number of signatures (compact-u16)
    uint16_t num_sigs;
    if (!read_compact_u16(&data, &remaining, &num_sigs)) return false;
    parsed->num_signatures = num_sigs;

    // Skip signatures (64 bytes each)
    size_t sigs_size = num_sigs * 64;
    if (remaining < sigs_size) return false;
    data += sigs_size;
    remaining -= sigs_size;

    // Check for v0 versioned transaction (version byte = 0x80)
    bool is_versioned = false;
    if (remaining > 0 && data[0] == 0x80) {
        is_versioned = true;
        data++;  // Skip version byte
        remaining--;
    }

    // Read message header (3 bytes)
    if (remaining < 3) return false;
    parsed->num_required_signatures = data[0];
    parsed->num_readonly_signed = data[1];
    parsed->num_readonly_unsigned = data[2];
    data += 3;
    remaining -= 3;

    // Read account keys (store up to 16, but advance past ALL of them)
    uint16_t num_accounts;
    if (!read_compact_u16(&data, &remaining, &num_accounts)) return false;
    parsed->num_accounts = MIN(num_accounts, 16);

    for (int i = 0; i < num_accounts; i++) {
        if (remaining < 32) return false;
        if (i < 16) {
            memcpy(parsed->account_keys[i], data, 32);
        }
        data += 32;
        remaining -= 32;
    }

    // Read recent blockhash
    if (remaining < 32) return false;
    memcpy(parsed->recent_blockhash, data, 32);
    data += 32;
    remaining -= 32;

    // Read instructions (store up to 8, but parse ALL to advance data pointer)
    uint16_t num_instructions;
    if (!read_compact_u16(&data, &remaining, &num_instructions)) return false;
    parsed->num_instructions = MIN(num_instructions, 8);

    for (int i = 0; i < num_instructions; i++) {
        // Use a stack variable for instructions beyond our storage limit
        SolanaInstruction overflow_instr;
        SolanaInstruction *instr = (i < 8) ? &parsed->instructions[i] : &overflow_instr;
        memzero(instr, sizeof(SolanaInstruction));

        // Read program ID index
        if (remaining < 1) return false;
        uint8_t program_idx = data[0];
        data++;
        remaining--;

        // Check if program_idx references an account we have stored
        if (program_idx < parsed->num_accounts) {
            memcpy(instr->program_id, parsed->account_keys[program_idx], 32);
        } else if (program_idx < num_accounts || is_versioned) {
            // Index beyond stored accounts (but valid in static list) or ALT reference
            memzero(instr->program_id, 32);
            instr->type = SOLANA_INSTRUCTION_UNKNOWN;
        } else {
            // Invalid index for legacy transactions
            return false;
        }

        // Read account indices (store up to 16, but advance past ALL of them)
        uint16_t num_acct_indices;
        if (!read_compact_u16(&data, &remaining, &num_acct_indices)) return false;
        instr->num_accounts = MIN(num_acct_indices, 16);

        if (remaining < num_acct_indices) return false;
        for (int j = 0; j < instr->num_accounts; j++) {
            instr->account_indices[j] = data[j];
        }
        data += num_acct_indices;
        remaining -= num_acct_indices;

        // Read instruction data
        uint16_t data_len;
        if (!read_compact_u16(&data, &remaining, &data_len)) return false;

        if (remaining < data_len) return false;
        instr->data = data;
        instr->data_len = data_len;
        data += data_len;
        remaining -= data_len;

        // Identify instruction type
        if (instr->type != SOLANA_INSTRUCTION_UNKNOWN) {
            instr->type = solana_identifyInstruction(instr->program_id,
                                                       instr->data, instr->data_len);
        }
    }

    // For v0 transactions, skip Address Lookup Tables section
    if (is_versioned && remaining > 0) {
        // Read number of address table lookups
        uint16_t num_alt;
        if (!read_compact_u16(&data, &remaining, &num_alt)) return false;

        // Skip each lookup table entry
        for (int i = 0; i < num_alt; i++) {
            // Skip account key (32 bytes)
            if (remaining < 32) return false;
            data += 32;
            remaining -= 32;

            // Skip writable indexes array
            uint16_t num_writable;
            if (!read_compact_u16(&data, &remaining, &num_writable)) return false;
            if (remaining < num_writable) return false;
            data += num_writable;
            remaining -= num_writable;

            // Skip readonly indexes array
            uint16_t num_readonly;
            if (!read_compact_u16(&data, &remaining, &num_readonly)) return false;
            if (remaining < num_readonly) return false;
            data += num_readonly;
            remaining -= num_readonly;
        }
    }

    return true;
}

SolanaInstructionType solana_identifyInstruction(const uint8_t *program_id,
                                                   const uint8_t *data,
                                                   size_t data_len) {
    if (!program_id || !data || data_len < 4) {
        return SOLANA_INSTRUCTION_UNKNOWN;
    }

    // System Program
    if (memcmp(program_id, SOLANA_SYSTEM_PROGRAM_ID, 32) == 0) {
        uint32_t discriminator = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);

        if (discriminator == 2 && data_len == 12) {
            return SOLANA_INSTRUCTION_SYSTEM_TRANSFER;
        }
        if (discriminator == 0) {
            return SOLANA_INSTRUCTION_SYSTEM_CREATE_ACCOUNT;
        }
    }

    // Token Program
    if (memcmp(program_id, SOLANA_TOKEN_PROGRAM_ID, 32) == 0) {
        if (data_len < 1) return SOLANA_INSTRUCTION_UNKNOWN;

        uint8_t instruction_type = data[0];

        if (instruction_type == 3) {  // Transfer
            return SOLANA_INSTRUCTION_TOKEN_TRANSFER;
        }
        if (instruction_type == 12) {  // TransferChecked
            return SOLANA_INSTRUCTION_TOKEN_TRANSFER_CHECKED;
        }
        if (instruction_type == 4) {  // Approve
            return SOLANA_INSTRUCTION_TOKEN_APPROVE;
        }
    }

    // Stake Program
    if (memcmp(program_id, SOLANA_STAKE_PROGRAM_ID, 32) == 0) {
        if (data_len < 4) return SOLANA_INSTRUCTION_UNKNOWN;

        uint32_t instruction_type = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);

        if (instruction_type == 2) {
            return SOLANA_INSTRUCTION_STAKE_DELEGATE;
        }
        if (instruction_type == 4) {
            return SOLANA_INSTRUCTION_STAKE_WITHDRAW;
        }
    }

    return SOLANA_INSTRUCTION_UNKNOWN;
}

bool solana_parseSystemTransfer(const uint8_t *data, size_t len,
                                 SolanaSystemTransfer *transfer) {
    if (!data || !transfer || len < 12) {
        return false;
    }

    // Skip discriminator (4 bytes), read lamports (8 bytes, little-endian)
    const uint8_t *lamports_ptr = data + 4;
    transfer->lamports = 0;
    for (int i = 0; i < 8; i++) {
        transfer->lamports |= ((uint64_t)lamports_ptr[i]) << (i * 8);
    }

    return true;
}

bool solana_parseTokenTransfer(const uint8_t *data, size_t len,
                                SolanaTokenTransfer *transfer) {
    if (!data || !transfer || len < 9) {
        return false;
    }

    // Parse amount (bytes 1-8, little-endian) — common to both Transfer and TransferChecked
    transfer->amount = 0;
    for (int i = 0; i < 8; i++) {
        transfer->amount |= ((uint64_t)data[1 + i]) << (i * 8);
    }

    // TransferChecked (instruction_type 12): has extra decimals byte at offset 9
    if (len >= 10 && data[0] == 12) {
        transfer->decimals = data[9];
    } else {
        transfer->decimals = 9;  // Default for SPL tokens
    }
    return true;
}

void solana_formatLamports(uint64_t lamports, char *out, size_t out_len) {
    if (!out || out_len < 30) return;

    // Convert lamports to SOL (1 SOL = 1,000,000,000 lamports)
    uint64_t sol = lamports / 1000000000;
    uint64_t remainder = lamports % 1000000000;

    if (remainder == 0) {
        snprintf(out, out_len, "%llu SOL", (unsigned long long)sol);
    } else {
        // Remove trailing zeros
        char frac[10];
        snprintf(frac, sizeof(frac), "%09llu", (unsigned long long)remainder);
        int len = 9;
        while (len > 0 && frac[len - 1] == '0') {
            frac[--len] = '\0';
        }
        snprintf(out, out_len, "%llu.%s SOL", (unsigned long long)sol, frac);
    }
}

bool solana_confirmTransaction(const SolanaParsedTransaction *tx,
                                const uint8_t *signer_pubkey) {
    (void)signer_pubkey;  // Reserved for future use in multi-sig validation

    if (!tx || tx->num_instructions == 0) {
        return false;
    }

    // For now, handle simple single-instruction transactions
    const SolanaInstruction *instr = &tx->instructions[0];

    if (instr->type == SOLANA_INSTRUCTION_SYSTEM_TRANSFER) {
        SolanaSystemTransfer transfer;
        if (!solana_parseSystemTransfer(instr->data, instr->data_len, &transfer)) {
            return false;
        }

        // Get recipient address (account index 1 for System Transfer)
        if (instr->num_accounts < 2) return false;
        uint8_t to_idx = instr->account_indices[1];
        if (to_idx >= tx->num_accounts) return false;

        char to_address[SOLANA_ADDRESS_SIZE];
        if (!solana_publicKeyToAddress(tx->account_keys[to_idx],
                                        to_address, sizeof(to_address))) {
            return false;
        }

        char amount_str[32];
        solana_formatLamports(transfer.lamports, amount_str, sizeof(amount_str));

        return confirm(ButtonRequestType_ButtonRequest_SignTx,
                       "Solana Transfer",
                       "Send %s to\n%s?",
                       amount_str, to_address);
    }

    // Unknown or complex transaction - show warning
    return confirm(ButtonRequestType_ButtonRequest_SignTx,
                   "Solana Transaction",
                   "Sign transaction with %d instruction(s)?",
                   tx->num_instructions);
}
