extern "C" {
#include "keepkey/firmware/solana.h"
#include "trezor/crypto/memzero.h"
}

#include "gtest/gtest.h"
#include <cstring>

TEST(Solana, FormatAmount) {
    char buf[32];

    solana_formatAmount(buf, sizeof(buf), 1000000000ULL);
    EXPECT_STREQ(buf, "1.000000000 SOL");

    solana_formatAmount(buf, sizeof(buf), 0);
    EXPECT_STREQ(buf, "0.000000000 SOL");

    solana_formatAmount(buf, sizeof(buf), 2500000000ULL);
    EXPECT_STREQ(buf, "2.500000000 SOL");
}

TEST(Solana, ParseSystemTransfer) {
    /* Construct a minimal Solana transaction with a system transfer.
     *
     * Format:
     *   [header: 3 bytes]
     *   [compact-u16: num_accounts]
     *   [account keys: N * 32 bytes]
     *   [recent_blockhash: 32 bytes]
     *   [compact-u16: num_instructions]
     *   [instruction: program_idx, compact-u16 acct_count, acct_indices,
     *                 compact-u16 data_len, data]
     */
    uint8_t raw[256];
    size_t pos = 0;

    /* Header */
    raw[pos++] = 1; /* num_required_sigs */
    raw[pos++] = 0; /* num_readonly_signed */
    raw[pos++] = 1; /* num_readonly_unsigned (system program) */

    /* 3 accounts: sender, recipient, system program */
    raw[pos++] = 3; /* compact-u16 */

    /* Account 0: sender (32 bytes of 0x11) */
    memset(raw + pos, 0x11, 32); pos += 32;
    /* Account 1: recipient (32 bytes of 0x22) */
    memset(raw + pos, 0x22, 32); pos += 32;
    /* Account 2: system program (all zeros) */
    memset(raw + pos, 0x00, 32); pos += 32;

    /* Recent blockhash (32 bytes) */
    memset(raw + pos, 0xBB, 32); pos += 32;

    /* 1 instruction */
    raw[pos++] = 1; /* compact-u16 */

    /* Instruction: system transfer */
    raw[pos++] = 2; /* program_id index (system program) */
    raw[pos++] = 2; /* compact-u16: 2 account indices */
    raw[pos++] = 0; /* from (account 0) */
    raw[pos++] = 1; /* to (account 1) */
    raw[pos++] = 12; /* compact-u16: data length */

    /* System transfer instruction data:
     * u32 LE instruction type (2 = Transfer)
     * u64 LE lamports */
    raw[pos++] = 2; raw[pos++] = 0; raw[pos++] = 0; raw[pos++] = 0;
    /* 1 SOL = 1000000000 = 0x3B9ACA00 */
    raw[pos++] = 0x00; raw[pos++] = 0xCA; raw[pos++] = 0x9A; raw[pos++] = 0x3B;
    raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0x00;

    SolanaParsedTx tx;
    EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_VERIFIED);
    ASSERT_TRUE(solana_parseTx(raw, pos, &tx));

    EXPECT_EQ(tx.num_accounts, 3);
    EXPECT_EQ(tx.num_instructions, 1);
    EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_SYSTEM_TRANSFER);
    EXPECT_EQ(tx.instructions[0].lamports, 1000000000ULL);

    /* Verify from/to accounts */
    uint8_t expected_from[32], expected_to[32];
    memset(expected_from, 0x11, 32);
    memset(expected_to, 0x22, 32);
    EXPECT_TRUE(memcmp(tx.instructions[0].from, expected_from, 32) == 0);
    EXPECT_TRUE(memcmp(tx.instructions[0].to, expected_to, 32) == 0);
}

TEST(Solana, ParseMultiInstruction) {
    /* Transaction with 2 system transfers */
    uint8_t raw[512];
    size_t pos = 0;

    /* Header */
    raw[pos++] = 1; raw[pos++] = 0; raw[pos++] = 1;

    /* 4 accounts */
    raw[pos++] = 4;
    memset(raw + pos, 0x11, 32); pos += 32; /* account 0: sender */
    memset(raw + pos, 0x22, 32); pos += 32; /* account 1: recipient 1 */
    memset(raw + pos, 0x33, 32); pos += 32; /* account 2: recipient 2 */
    memset(raw + pos, 0x00, 32); pos += 32; /* account 3: system program */

    /* Blockhash */
    memset(raw + pos, 0xBB, 32); pos += 32;

    /* 2 instructions */
    raw[pos++] = 2;

    /* Instruction 1: transfer 1 SOL to acct 1 */
    raw[pos++] = 3; /* program = system */
    raw[pos++] = 2; raw[pos++] = 0; raw[pos++] = 1;
    raw[pos++] = 12;
    raw[pos++] = 2; raw[pos++] = 0; raw[pos++] = 0; raw[pos++] = 0;
    raw[pos++] = 0x00; raw[pos++] = 0xCA; raw[pos++] = 0x9A; raw[pos++] = 0x3B;
    raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0x00;

    /* Instruction 2: transfer 2 SOL to acct 2 */
    raw[pos++] = 3;
    raw[pos++] = 2; raw[pos++] = 0; raw[pos++] = 2;
    raw[pos++] = 12;
    raw[pos++] = 2; raw[pos++] = 0; raw[pos++] = 0; raw[pos++] = 0;
    raw[pos++] = 0x00; raw[pos++] = 0x94; raw[pos++] = 0x35; raw[pos++] = 0x77;
    raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0x00;

    SolanaParsedTx tx;
    EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_VERIFIED);
    ASSERT_TRUE(solana_parseTx(raw, pos, &tx));

    EXPECT_EQ(tx.num_instructions, 2);
    EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_SYSTEM_TRANSFER);
    EXPECT_EQ(tx.instructions[0].lamports, 1000000000ULL);
    EXPECT_EQ(tx.instructions[1].type, SOL_INSTR_SYSTEM_TRANSFER);
    EXPECT_EQ(tx.instructions[1].lamports, 2000000000ULL);
}

TEST(Solana, ParseSPLTokenTransfer) {
    /* Transaction with a SPL token transfer instruction */
    uint8_t raw[512];
    size_t pos = 0;

    /* Header */
    raw[pos++] = 1; raw[pos++] = 0; raw[pos++] = 1;

    /* 4 accounts: source_ata, dest_ata, authority, token_program */
    raw[pos++] = 4;
    memset(raw + pos, 0x11, 32); pos += 32; /* account 0: source ATA */
    memset(raw + pos, 0x22, 32); pos += 32; /* account 1: dest ATA */
    memset(raw + pos, 0x33, 32); pos += 32; /* account 2: authority */
    /* account 3: SPL Token program */
    memcpy(raw + pos, SOL_TOKEN_PROGRAM, 32); pos += 32;

    /* Blockhash */
    memset(raw + pos, 0xBB, 32); pos += 32;

    /* 1 instruction */
    raw[pos++] = 1;

    /* SPL Token Transfer */
    raw[pos++] = 3; /* program index = token program */
    raw[pos++] = 3; /* 3 accounts */
    raw[pos++] = 0; /* source */
    raw[pos++] = 1; /* dest */
    raw[pos++] = 2; /* authority */
    raw[pos++] = 9; /* data length */
    raw[pos++] = 3; /* instruction type = Transfer */
    /* amount: 1000000 (1 USDC) in LE */
    raw[pos++] = 0x40; raw[pos++] = 0x42; raw[pos++] = 0x0F; raw[pos++] = 0x00;
    raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0x00;

    SolanaParsedTx tx;
    EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_VERIFIED);
    ASSERT_TRUE(solana_parseTx(raw, pos, &tx));

    EXPECT_EQ(tx.num_instructions, 1);
    EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_TRANSFER);
    EXPECT_EQ(tx.instructions[0].amount, 1000000ULL);
}

TEST(Solana, ParseAssociatedTokenAccountCreate) {
    uint8_t raw[512];
    size_t pos = 0;

    raw[pos++] = 1; raw[pos++] = 0; raw[pos++] = 1;

    raw[pos++] = 5;
    memset(raw + pos, 0x11, 32); pos += 32; /* funder */
    memset(raw + pos, 0x22, 32); pos += 32; /* ata */
    memset(raw + pos, 0x33, 32); pos += 32; /* owner */
    memset(raw + pos, 0x44, 32); pos += 32; /* mint */
    memcpy(raw + pos, SOL_ATA_PROGRAM, 32); pos += 32; /* program */

    memset(raw + pos, 0xBB, 32); pos += 32;

    raw[pos++] = 1;
    raw[pos++] = 4; /* ata program */
    raw[pos++] = 4; /* 4 account indices */
    raw[pos++] = 0;
    raw[pos++] = 1;
    raw[pos++] = 2;
    raw[pos++] = 3;
    raw[pos++] = 0; /* empty data */

    SolanaParsedTx tx;
    EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_VERIFIED);
    ASSERT_TRUE(solana_parseTx(raw, pos, &tx));
    EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_ATA_CREATE);
    EXPECT_TRUE(tx.instructions[0].has_mint);
}

TEST(Solana, ParseComputeBudgetUnitPrice) {
    uint8_t raw[256];
    size_t pos = 0;

    raw[pos++] = 1; raw[pos++] = 0; raw[pos++] = 1;

    raw[pos++] = 2;
    memset(raw + pos, 0x11, 32); pos += 32;
    memcpy(raw + pos, SOL_COMPUTE_BUDGET_PROGRAM, 32); pos += 32;

    memset(raw + pos, 0xBB, 32); pos += 32;

    raw[pos++] = 1;
    raw[pos++] = 1; /* compute budget program */
    raw[pos++] = 0; /* no account indices */
    raw[pos++] = 9; /* data length */
    raw[pos++] = 3; /* SetComputeUnitPrice */
    raw[pos++] = 0x40; raw[pos++] = 0x42; raw[pos++] = 0x0F; raw[pos++] = 0x00;
    raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0x00;

    SolanaParsedTx tx;
    EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_VERIFIED);
    ASSERT_TRUE(solana_parseTx(raw, pos, &tx));
    EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE);
    EXPECT_EQ(tx.instructions[0].extra_value, 1000000ULL);
}

TEST(Solana, UnknownProgram) {
    uint8_t raw[256];
    size_t pos = 0;

    /* Header */
    raw[pos++] = 1; raw[pos++] = 0; raw[pos++] = 1;

    /* 2 accounts */
    raw[pos++] = 2;
    memset(raw + pos, 0x11, 32); pos += 32;
    memset(raw + pos, 0xFF, 32); pos += 32; /* unknown program */

    /* Blockhash */
    memset(raw + pos, 0xBB, 32); pos += 32;

    /* 1 instruction */
    raw[pos++] = 1;
    raw[pos++] = 1; /* program index = 1 (unknown) */
    raw[pos++] = 1; raw[pos++] = 0; /* 1 account */
    raw[pos++] = 4; /* data length */
    raw[pos++] = 0xDE; raw[pos++] = 0xAD; raw[pos++] = 0xBE; raw[pos++] = 0xEF;

    SolanaParsedTx tx;
    EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
    ASSERT_FALSE(solana_parseTx(raw, pos, &tx));
    EXPECT_EQ(tx.num_instructions, 1);
    EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);
}

TEST(Solana, ParseTxTooShort) {
    uint8_t raw[2] = {0, 0};
    SolanaParsedTx tx;
    EXPECT_EQ(solana_inspectTx(raw, sizeof(raw), &tx), SOL_TX_REVIEW_MALFORMED);
    EXPECT_FALSE(solana_parseTx(raw, sizeof(raw), &tx));
}

TEST(Solana, RejectsTrailingBytes) {
    /* Build a valid 1-instruction system transfer, then append extra bytes */
    uint8_t raw[256];
    size_t pos = 0;

    /* Header */
    raw[pos++] = 1; raw[pos++] = 0; raw[pos++] = 1;

    /* 3 accounts */
    raw[pos++] = 3;
    memset(raw + pos, 0x11, 32); pos += 32;
    memset(raw + pos, 0x22, 32); pos += 32;
    memset(raw + pos, 0x00, 32); pos += 32;

    /* Blockhash */
    memset(raw + pos, 0xBB, 32); pos += 32;

    /* 1 instruction */
    raw[pos++] = 1;
    raw[pos++] = 2; /* program = system */
    raw[pos++] = 2; raw[pos++] = 0; raw[pos++] = 1;
    raw[pos++] = 12;
    raw[pos++] = 2; raw[pos++] = 0; raw[pos++] = 0; raw[pos++] = 0;
    raw[pos++] = 0x00; raw[pos++] = 0xCA; raw[pos++] = 0x9A; raw[pos++] = 0x3B;
    raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0x00;

    /* Verify the base transaction parses OK */
    SolanaParsedTx tx;
    EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_VERIFIED);
    ASSERT_TRUE(solana_parseTx(raw, pos, &tx));

    /* Append trailing garbage */
    raw[pos++] = 0xDE;
    raw[pos++] = 0xAD;

    EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_MALFORMED);
    EXPECT_FALSE(solana_parseTx(raw, pos, &tx));
}

TEST(Solana, RejectsOOBAccountIndex) {
    /* Transaction with acct_indices[0] = 99 (> num_accounts) */
    uint8_t raw[256];
    size_t pos = 0;

    /* Header */
    raw[pos++] = 1; raw[pos++] = 0; raw[pos++] = 1;

    /* 3 accounts */
    raw[pos++] = 3;
    memset(raw + pos, 0x11, 32); pos += 32;
    memset(raw + pos, 0x22, 32); pos += 32;
    memset(raw + pos, 0x00, 32); pos += 32;

    /* Blockhash */
    memset(raw + pos, 0xBB, 32); pos += 32;

    /* 1 instruction */
    raw[pos++] = 1;
    raw[pos++] = 2; /* program = system */
    raw[pos++] = 2; /* 2 account indices */
    raw[pos++] = 99; /* OOB: only 3 accounts exist */
    raw[pos++] = 1;
    raw[pos++] = 12;
    raw[pos++] = 2; raw[pos++] = 0; raw[pos++] = 0; raw[pos++] = 0;
    raw[pos++] = 0x00; raw[pos++] = 0xCA; raw[pos++] = 0x9A; raw[pos++] = 0x3B;
    raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0x00;

    SolanaParsedTx tx;
    EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_MALFORMED);
    EXPECT_FALSE(solana_parseTx(raw, pos, &tx));
}

TEST(Solana, RejectsExcessInstructions) {
    /* Transaction with num_instructions = 9 (max is 8) */
    uint8_t raw[256];
    size_t pos = 0;

    /* Header */
    raw[pos++] = 1; raw[pos++] = 0; raw[pos++] = 1;

    /* 2 accounts */
    raw[pos++] = 2;
    memset(raw + pos, 0x11, 32); pos += 32;
    memset(raw + pos, 0x00, 32); pos += 32;

    /* Blockhash */
    memset(raw + pos, 0xBB, 32); pos += 32;

    /* 9 instructions (exceeds limit of 8) */
    raw[pos++] = 9;

    SolanaParsedTx tx;
    EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
    EXPECT_FALSE(solana_parseTx(raw, pos, &tx));
}

TEST(Solana, VersionedMessageIsOpaque) {
    uint8_t raw[256];
    size_t pos = 0;

    raw[pos++] = 0x80; /* v0 prefix */
    raw[pos++] = 1;    /* num_required_sigs */
    raw[pos++] = 0;    /* num_readonly_signed */
    raw[pos++] = 1;    /* num_readonly_unsigned */

    raw[pos++] = 3; /* static accounts */
    memset(raw + pos, 0x11, 32); pos += 32;
    memset(raw + pos, 0x22, 32); pos += 32;
    memset(raw + pos, 0x00, 32); pos += 32; /* system program */

    memset(raw + pos, 0xBB, 32); pos += 32; /* blockhash */

    raw[pos++] = 1; /* instructions */
    raw[pos++] = 2; /* program = system */
    raw[pos++] = 2; raw[pos++] = 0; raw[pos++] = 1; /* account indices */
    raw[pos++] = 12; /* data length */
    raw[pos++] = 2; raw[pos++] = 0; raw[pos++] = 0; raw[pos++] = 0;
    raw[pos++] = 0x00; raw[pos++] = 0xCA; raw[pos++] = 0x9A; raw[pos++] = 0x3B;
    raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0x00;

    raw[pos++] = 0; /* zero lookup tables */

    SolanaParsedTx tx;
    EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
    EXPECT_FALSE(solana_parseTx(raw, pos, &tx));
}

TEST(Solana, VersionedMessageWithLookupTableIsOpaque) {
    uint8_t raw[256];
    size_t pos = 0;

    raw[pos++] = 0x80; /* v0 prefix */
    raw[pos++] = 1;
    raw[pos++] = 0;
    raw[pos++] = 1;

    raw[pos++] = 3;
    memset(raw + pos, 0x11, 32); pos += 32;
    memset(raw + pos, 0x22, 32); pos += 32;
    memset(raw + pos, 0x00, 32); pos += 32;

    memset(raw + pos, 0xBB, 32); pos += 32;

    raw[pos++] = 1;
    raw[pos++] = 2;
    raw[pos++] = 2; raw[pos++] = 0; raw[pos++] = 1;
    raw[pos++] = 12;
    raw[pos++] = 2; raw[pos++] = 0; raw[pos++] = 0; raw[pos++] = 0;
    raw[pos++] = 0x00; raw[pos++] = 0xCA; raw[pos++] = 0x9A; raw[pos++] = 0x3B;
    raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0x00;

    raw[pos++] = 1; /* one lookup table */
    memset(raw + pos, 0x55, 32); pos += 32; /* table key */
    raw[pos++] = 1; /* writable indexes count */
    raw[pos++] = 0; /* writable index */
    raw[pos++] = 2; /* readonly indexes count */
    raw[pos++] = 1;
    raw[pos++] = 2;

    SolanaParsedTx tx;
    EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
    EXPECT_FALSE(solana_parseTx(raw, pos, &tx));
}

TEST(Solana, MalformedVersionedLookupTableRejects) {
    uint8_t raw[256];
    size_t pos = 0;

    raw[pos++] = 0x80;
    raw[pos++] = 1;
    raw[pos++] = 0;
    raw[pos++] = 1;

    raw[pos++] = 3;
    memset(raw + pos, 0x11, 32); pos += 32;
    memset(raw + pos, 0x22, 32); pos += 32;
    memset(raw + pos, 0x00, 32); pos += 32;

    memset(raw + pos, 0xBB, 32); pos += 32;

    raw[pos++] = 0; /* zero instructions */
    raw[pos++] = 1; /* one lookup table */
    memset(raw + pos, 0x55, 16); pos += 16; /* truncated table key */

    SolanaParsedTx tx;
    EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_MALFORMED);
    EXPECT_FALSE(solana_parseTx(raw, pos, &tx));
}
