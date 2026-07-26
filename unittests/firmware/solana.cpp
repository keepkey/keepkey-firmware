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
  memset(raw + pos, 0x11, 32);
  pos += 32;
  /* Account 1: recipient (32 bytes of 0x22) */
  memset(raw + pos, 0x22, 32);
  pos += 32;
  /* Account 2: system program (all zeros) */
  memset(raw + pos, 0x00, 32);
  pos += 32;

  /* Recent blockhash (32 bytes) */
  memset(raw + pos, 0xBB, 32);
  pos += 32;

  /* 1 instruction */
  raw[pos++] = 1; /* compact-u16 */

  /* Instruction: system transfer */
  raw[pos++] = 2;  /* program_id index (system program) */
  raw[pos++] = 2;  /* compact-u16: 2 account indices */
  raw[pos++] = 0;  /* from (account 0) */
  raw[pos++] = 1;  /* to (account 1) */
  raw[pos++] = 12; /* compact-u16: data length */

  /* System transfer instruction data:
   * u32 LE instruction type (2 = Transfer)
   * u64 LE lamports */
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  /* 1 SOL = 1000000000 = 0x3B9ACA00 */
  raw[pos++] = 0x00;
  raw[pos++] = 0xCA;
  raw[pos++] = 0x9A;
  raw[pos++] = 0x3B;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;

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
  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;

  /* 4 accounts */
  raw[pos++] = 4;
  memset(raw + pos, 0x11, 32);
  pos += 32; /* account 0: sender */
  memset(raw + pos, 0x22, 32);
  pos += 32; /* account 1: recipient 1 */
  memset(raw + pos, 0x33, 32);
  pos += 32; /* account 2: recipient 2 */
  memset(raw + pos, 0x00, 32);
  pos += 32; /* account 3: system program */

  /* Blockhash */
  memset(raw + pos, 0xBB, 32);
  pos += 32;

  /* 2 instructions */
  raw[pos++] = 2;

  /* Instruction 1: transfer 1 SOL to acct 1 */
  raw[pos++] = 3; /* program = system */
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 12;
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0x00;
  raw[pos++] = 0xCA;
  raw[pos++] = 0x9A;
  raw[pos++] = 0x3B;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;

  /* Instruction 2: transfer 2 SOL to acct 2 */
  raw[pos++] = 3;
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 2;
  raw[pos++] = 12;
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0x00;
  raw[pos++] = 0x94;
  raw[pos++] = 0x35;
  raw[pos++] = 0x77;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;

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
  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;

  /* 4 accounts: source_ata, dest_ata, authority, token_program */
  raw[pos++] = 4;
  memset(raw + pos, 0x11, 32);
  pos += 32; /* account 0: source ATA */
  memset(raw + pos, 0x22, 32);
  pos += 32; /* account 1: dest ATA */
  memset(raw + pos, 0x33, 32);
  pos += 32; /* account 2: authority */
  /* account 3: SPL Token program */
  memcpy(raw + pos, SOL_TOKEN_PROGRAM, 32);
  pos += 32;

  /* Blockhash */
  memset(raw + pos, 0xBB, 32);
  pos += 32;

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
  raw[pos++] = 0x40;
  raw[pos++] = 0x42;
  raw[pos++] = 0x0F;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;

  SolanaParsedTx tx;
  /* Unchecked SPL Transfer carries no signed mint (the token being moved is not
   * provable), so the transaction is now OPAQUE — it requires AdvancedMode
   * blind-signing rather than clear-signing. The instruction is still parsed.
   */
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);

  EXPECT_EQ(tx.num_instructions, 1);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_TRANSFER);
  EXPECT_EQ(tx.instructions[0].amount, 1000000ULL);
}

TEST(Solana, Token2022TransferCheckedIsOpaque) {
  /* A Token-2022 TransferChecked can invoke an undisclosed transfer hook / fee,
   * so it must NOT clear-sign (only legacy SPL Token TransferChecked does). */
  uint8_t raw[512];
  size_t pos = 0;
  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 5; /* source, mint, dest, authority, token-2022 program */
  memset(raw + pos, 0x11, 32);
  pos += 32;
  memset(raw + pos, 0x22, 32);
  pos += 32;
  memset(raw + pos, 0x33, 32);
  pos += 32;
  memset(raw + pos, 0x44, 32);
  pos += 32;
  memcpy(raw + pos, SOL_TOKEN_2022_PROGRAM, 32);
  pos += 32;
  memset(raw + pos, 0xBB, 32);
  pos += 32;
  raw[pos++] = 1; /* 1 instruction */
  raw[pos++] = 4; /* program index = token-2022 */
  raw[pos++] = 4; /* 4 accounts */
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 2;
  raw[pos++] = 3;
  raw[pos++] = 10; /* data length */
  raw[pos++] = 12; /* TransferChecked */
  raw[pos++] = 0x40;
  raw[pos++] = 0x42;
  raw[pos++] = 0x0F;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 6; /* decimals */

  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
}

/* Helper: build a Vote UpdateValidatorIdentity tx with the given instruction
 * data length (4 = canonical; >4 = trailing bytes). Accounts: vote(0),
 * new-validator(1), authority(2), vote-program. */
static size_t build_vote_update_validator(uint8_t* raw, uint16_t data_len) {
  size_t pos = 0;
  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 4;
  memset(raw + pos, 0x11, 32);
  pos += 32; /* vote account (idx 0) */
  memset(raw + pos, 0x22, 32);
  pos += 32; /* new validator (idx 1) */
  memset(raw + pos, 0x33, 32);
  pos += 32; /* authority (idx 2) */
  memcpy(raw + pos, SOL_VOTE_PROGRAM, 32);
  pos += 32;
  memset(raw + pos, 0xBB, 32);
  pos += 32; /* blockhash */
  raw[pos++] = 1;
  raw[pos++] = 3; /* program index = vote */
  raw[pos++] = 3; /* 3 accounts */
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 2;
  raw[pos++] = (uint8_t)data_len;
  raw[pos++] = 4; /* UpdateValidatorIdentity discriminator (le32) */
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  for (uint16_t i = 4; i < data_len; i++) raw[pos++] = 0x77; /* trailing */
  return pos;
}

TEST(Solana, VoteUpdateValidatorReadsAccountNotData) {
  uint8_t raw[512];
  size_t pos = build_vote_update_validator(raw, 4); /* canonical */
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_VERIFIED);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_VOTE_UPDATE_VALIDATOR);
  /* The new validator must be account index 1 (0x22..), never fabricated data.
   */
  uint8_t expected[32];
  memset(expected, 0x22, 32);
  EXPECT_EQ(0, memcmp(tx.instructions[0].extra, expected, 32));
}

TEST(Solana, VoteUpdateValidatorRejectsTrailingBytes) {
  uint8_t raw[512];
  /* 4-byte discriminator + 32 fabricated bytes — used to be displayed as a
   * fake validator; now non-canonical, so the tx is opaque (blind-sign only).
   */
  size_t pos = build_vote_update_validator(raw, 36);
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
}

TEST(Solana, PriorityFeeOverflowSafe) {
  uint64_t fee = 0;
  /* The wrap-to-zero case: price=UINT64_MAX, limit=1. A naive
   * (price*limit + 999999)/1e6 wraps to 0; the real fee is 18446.744073710 SOL
   * (= 18446744073710 lamports) and must be shown, not hidden. */
  EXPECT_TRUE(solana_priority_fee_lamports(UINT64_MAX, 1, &fee));
  EXPECT_EQ(fee, 18446744073710ULL);

  /* Typical fee: 1000 micro-lamports/CU * 200000 CU / 1e6 = 200 lamports. */
  EXPECT_TRUE(solana_priority_fee_lamports(1000, 200000, &fee));
  EXPECT_EQ(fee, 200ULL);

  /* Sub-lamport fee rounds UP (fees are charged even for one CU). */
  EXPECT_TRUE(solana_priority_fee_lamports(1, 1, &fee));
  EXPECT_EQ(fee, 1ULL);

  /* A fee that truly exceeds u64 lamports is rejected, never saturated. */
  EXPECT_FALSE(solana_priority_fee_lamports(UINT64_MAX, UINT64_MAX, &fee));
}

TEST(Solana, ParseAssociatedTokenAccountCreate) {
  uint8_t raw[512];
  size_t pos = 0;

  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;

  raw[pos++] = 5;
  memset(raw + pos, 0x11, 32);
  pos += 32; /* funder */
  memset(raw + pos, 0x22, 32);
  pos += 32; /* ata */
  memset(raw + pos, 0x33, 32);
  pos += 32; /* owner */
  memset(raw + pos, 0x44, 32);
  pos += 32; /* mint */
  memcpy(raw + pos, SOL_ATA_PROGRAM, 32);
  pos += 32; /* program */

  memset(raw + pos, 0xBB, 32);
  pos += 32;

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

  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;

  raw[pos++] = 2;
  memset(raw + pos, 0x11, 32);
  pos += 32;
  memcpy(raw + pos, SOL_COMPUTE_BUDGET_PROGRAM, 32);
  pos += 32;

  memset(raw + pos, 0xBB, 32);
  pos += 32;

  raw[pos++] = 1;
  raw[pos++] = 1; /* compute budget program */
  raw[pos++] = 0; /* no account indices */
  raw[pos++] = 9; /* data length */
  raw[pos++] = 3; /* SetComputeUnitPrice */
  raw[pos++] = 0x40;
  raw[pos++] = 0x42;
  raw[pos++] = 0x0F;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;

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
  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;

  /* 2 accounts */
  raw[pos++] = 2;
  memset(raw + pos, 0x11, 32);
  pos += 32;
  memset(raw + pos, 0xFF, 32);
  pos += 32; /* unknown program */

  /* Blockhash */
  memset(raw + pos, 0xBB, 32);
  pos += 32;

  /* 1 instruction */
  raw[pos++] = 1;
  raw[pos++] = 1; /* program index = 1 (unknown) */
  raw[pos++] = 1;
  raw[pos++] = 0; /* 1 account */
  raw[pos++] = 4; /* data length */
  raw[pos++] = 0xDE;
  raw[pos++] = 0xAD;
  raw[pos++] = 0xBE;
  raw[pos++] = 0xEF;

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
  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;

  /* 3 accounts */
  raw[pos++] = 3;
  memset(raw + pos, 0x11, 32);
  pos += 32;
  memset(raw + pos, 0x22, 32);
  pos += 32;
  memset(raw + pos, 0x00, 32);
  pos += 32;

  /* Blockhash */
  memset(raw + pos, 0xBB, 32);
  pos += 32;

  /* 1 instruction */
  raw[pos++] = 1;
  raw[pos++] = 2; /* program = system */
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 12;
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0x00;
  raw[pos++] = 0xCA;
  raw[pos++] = 0x9A;
  raw[pos++] = 0x3B;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;

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
  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;

  /* 3 accounts */
  raw[pos++] = 3;
  memset(raw + pos, 0x11, 32);
  pos += 32;
  memset(raw + pos, 0x22, 32);
  pos += 32;
  memset(raw + pos, 0x00, 32);
  pos += 32;

  /* Blockhash */
  memset(raw + pos, 0xBB, 32);
  pos += 32;

  /* 1 instruction */
  raw[pos++] = 1;
  raw[pos++] = 2;  /* program = system */
  raw[pos++] = 2;  /* 2 account indices */
  raw[pos++] = 99; /* OOB: only 3 accounts exist */
  raw[pos++] = 1;
  raw[pos++] = 12;
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0x00;
  raw[pos++] = 0xCA;
  raw[pos++] = 0x9A;
  raw[pos++] = 0x3B;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;

  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_MALFORMED);
  EXPECT_FALSE(solana_parseTx(raw, pos, &tx));
}

TEST(Solana, RejectsExcessInstructions) {
  /* Transaction with num_instructions = 9 (max is 8) */
  uint8_t raw[256];
  size_t pos = 0;

  /* Header */
  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;

  /* 2 accounts */
  raw[pos++] = 2;
  memset(raw + pos, 0x11, 32);
  pos += 32;
  memset(raw + pos, 0x00, 32);
  pos += 32;

  /* Blockhash */
  memset(raw + pos, 0xBB, 32);
  pos += 32;

  /* 9 instructions (exceeds limit of 8), each minimal but well-formed:
   * program_idx + zero account indices + zero data bytes */
  raw[pos++] = 9;
  for (int i = 0; i < 9; i++) {
    raw[pos++] = 1; /* program = account 1 */
    raw[pos++] = 0; /* no account indices */
    raw[pos++] = 0; /* no data */
  }

  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_FALSE(solana_parseTx(raw, pos, &tx));

  /* A claimed instruction count with truncated bodies is malformed */
  uint8_t truncated[256];
  memcpy(truncated, raw, pos - 27);
  EXPECT_EQ(solana_inspectTx(truncated, pos - 27, &tx),
            SOL_TX_REVIEW_MALFORMED);
}

TEST(Solana, VersionedMessageNoLookupTablesIsVerified) {
  uint8_t raw[256];
  size_t pos = 0;

  raw[pos++] = 0x80; /* v0 prefix */
  raw[pos++] = 1;    /* num_required_sigs */
  raw[pos++] = 0;    /* num_readonly_signed */
  raw[pos++] = 1;    /* num_readonly_unsigned */

  raw[pos++] = 3; /* static accounts */
  memset(raw + pos, 0x11, 32);
  pos += 32;
  memset(raw + pos, 0x22, 32);
  pos += 32;
  memset(raw + pos, 0x00, 32);
  pos += 32; /* system program */

  memset(raw + pos, 0xBB, 32);
  pos += 32; /* blockhash */

  raw[pos++] = 1; /* instructions */
  raw[pos++] = 2; /* program = system */
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 1;  /* account indices */
  raw[pos++] = 12; /* data length */
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0x00;
  raw[pos++] = 0xCA;
  raw[pos++] = 0x9A;
  raw[pos++] = 0x3B;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;

  raw[pos++] = 0; /* zero lookup tables */

  /* A v0 message whose instructions touch only static accounts is as
   * verifiable as a legacy message — swap providers build these. */
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_VERIFIED);
  EXPECT_TRUE(solana_parseTx(raw, pos, &tx));
  ASSERT_EQ(tx.num_instructions, 1);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_SYSTEM_TRANSFER);
  EXPECT_EQ(tx.instructions[0].lamports, 1000000000ULL);
  uint8_t expected_to[32];
  memset(expected_to, 0x22, 32);
  EXPECT_EQ(memcmp(tx.instructions[0].to, expected_to, 32), 0);
}

TEST(Solana, VersionedMessageWithUnreferencedLookupTableIsVerified) {
  uint8_t raw[256];
  size_t pos = 0;

  raw[pos++] = 0x80; /* v0 prefix */
  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;

  raw[pos++] = 3;
  memset(raw + pos, 0x11, 32);
  pos += 32;
  memset(raw + pos, 0x22, 32);
  pos += 32;
  memset(raw + pos, 0x00, 32);
  pos += 32;

  memset(raw + pos, 0xBB, 32);
  pos += 32;

  raw[pos++] = 1;
  raw[pos++] = 2;
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 12;
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0x00;
  raw[pos++] = 0xCA;
  raw[pos++] = 0x9A;
  raw[pos++] = 0x3B;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;

  raw[pos++] = 1; /* one lookup table */
  memset(raw + pos, 0x55, 32);
  pos += 32;      /* table key */
  raw[pos++] = 1; /* writable indexes count */
  raw[pos++] = 0; /* writable index */
  raw[pos++] = 2; /* readonly indexes count */
  raw[pos++] = 1;
  raw[pos++] = 2;

  /* Table attached but no instruction reaches into it: every displayed
   * field is decoded from static accounts, so it stays verifiable. */
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_VERIFIED);
  EXPECT_TRUE(solana_parseTx(raw, pos, &tx));
}

TEST(Solana, VersionedInstructionUsingLookupAccountIsOpaque) {
  uint8_t raw[256];
  size_t pos = 0;

  raw[pos++] = 0x80; /* v0 prefix */
  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;

  raw[pos++] = 3; /* static accounts */
  memset(raw + pos, 0x11, 32);
  pos += 32;
  memset(raw + pos, 0x22, 32);
  pos += 32;
  memset(raw + pos, 0x00, 32);
  pos += 32;

  memset(raw + pos, 0xBB, 32);
  pos += 32;

  raw[pos++] = 1; /* instructions */
  raw[pos++] = 2; /* program = system (static) */
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 3; /* index 3 = first lookup-table account */
  raw[pos++] = 12;
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0x00;
  raw[pos++] = 0xCA;
  raw[pos++] = 0x9A;
  raw[pos++] = 0x3B;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;

  raw[pos++] = 1; /* one lookup table */
  memset(raw + pos, 0x55, 32);
  pos += 32;
  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 0;

  /* The recipient lives in a lookup table the device cannot resolve —
   * must be opaque (blind-signable under AdvancedMode), NOT malformed,
   * and NEVER verified. */
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_FALSE(solana_parseTx(raw, pos, &tx));
}

TEST(Solana, MemoBodyCaptured) {
  /* Legacy tx: system transfer + memo instruction (THORChain-style swap
   * memo). The parser must expose the memo bytes for display. */
  const char* memo = "=:ETH.ETH:0x1234:0/1/0:kk:75";
  uint8_t raw[512];
  size_t pos = 0;

  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 2; /* system + memo programs readonly */

  raw[pos++] = 4; /* accounts: sender, recipient, system, memo */
  memset(raw + pos, 0x11, 32);
  pos += 32;
  memset(raw + pos, 0x22, 32);
  pos += 32;
  memset(raw + pos, 0x00, 32); /* system program */
  pos += 32;
  memcpy(raw + pos, SOL_MEMO_PROGRAM, 32);
  pos += 32;

  memset(raw + pos, 0xBB, 32); /* blockhash */
  pos += 32;

  raw[pos++] = 2; /* two instructions */

  /* transfer */
  raw[pos++] = 2;
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 12;
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0x00;
  raw[pos++] = 0xCA;
  raw[pos++] = 0x9A;
  raw[pos++] = 0x3B;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;
  raw[pos++] = 0x00;

  /* memo */
  raw[pos++] = 3; /* program = memo */
  raw[pos++] = 0; /* no accounts */
  raw[pos++] = (uint8_t)strlen(memo);
  memcpy(raw + pos, memo, strlen(memo));
  pos += strlen(memo);

  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_VERIFIED);
  ASSERT_EQ(tx.num_instructions, 2);
  EXPECT_EQ(tx.instructions[1].type, SOL_INSTR_MEMO);
  ASSERT_EQ(tx.instructions[1].data_len, strlen(memo));
  EXPECT_EQ(memcmp(tx.instructions[1].data, memo, strlen(memo)), 0);
}

TEST(Solana, MalformedVersionedLookupTableRejects) {
  uint8_t raw[256];
  size_t pos = 0;

  raw[pos++] = 0x80;
  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;

  raw[pos++] = 3;
  memset(raw + pos, 0x11, 32);
  pos += 32;
  memset(raw + pos, 0x22, 32);
  pos += 32;
  memset(raw + pos, 0x00, 32);
  pos += 32;

  memset(raw + pos, 0xBB, 32);
  pos += 32;

  raw[pos++] = 0; /* zero instructions */
  raw[pos++] = 1; /* one lookup table */
  memset(raw + pos, 0x55, 16);
  pos += 16; /* truncated table key */

  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_MALFORMED);
  EXPECT_FALSE(solana_parseTx(raw, pos, &tx));
}

/* =====================================================================
 *  Review-round-12 regression tests: the forced-opaque set and the
 *  canonical-shape guards. A future refactor that silently drops any of
 *  these gates fails here, not in the field.
 * ===================================================================== */

/* Build a single-instruction tx over `program`, with `n_accounts` distinct
 * accounts fed to the instruction, plus a fee-payer signer and the program
 * account. instr_data holds the opcode + operands. Returns the byte length. */
static size_t build_single_instr_tx(uint8_t* raw, const uint8_t* program,
                                    int n_accounts, const uint8_t* instr_data,
                                    uint8_t data_len) {
  size_t pos = 0;
  raw[pos++] = 1; /* num_required_sigs */
  raw[pos++] = 0; /* num_readonly_signed */
  raw[pos++] = 1; /* num_readonly_unsigned (program) */
  const int total_accts = n_accounts + 1 /* program */;
  raw[pos++] = (uint8_t)total_accts;     /* compact-u16 account count */
  for (int i = 0; i < n_accounts; i++) { /* instruction accounts */
    memset(raw + pos, 0x11 + i, 32);
    pos += 32;
  }
  memcpy(raw + pos, program, 32); /* program account (last) */
  pos += 32;
  memset(raw + pos, 0xBB, 32); /* recent blockhash */
  pos += 32;
  raw[pos++] = 1;                        /* 1 instruction */
  raw[pos++] = (uint8_t)n_accounts;      /* program index (last account) */
  raw[pos++] = (uint8_t)n_accounts;      /* account-index count */
  for (int i = 0; i < n_accounts; i++) { /* account indices 0..n-1 */
    raw[pos++] = (uint8_t)i;
  }
  raw[pos++] = data_len;
  memcpy(raw + pos, instr_data, data_len);
  pos += data_len;
  return pos;
}

/* Legacy SPL TransferChecked with the canonical 10-byte data (opcode + amount
 * + decimals) and all four accounts clear-signs. */
TEST(Solana, TransferCheckedCanonicalIsVerified) {
  uint8_t d[10] = {
      SOL_TOKEN_TRANSFER_CHECKED_IX, 0x40, 0x42, 0x0F, 0, 0, 0, 0, 6};
  uint8_t raw[512];
  size_t pos = build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 4, d, sizeof(d));
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_VERIFIED);
}

/* A 9-byte TransferChecked (no decimals byte) is non-canonical: it must NOT
 * classify VERIFIED (which would skip the mint screen) — force opaque. */
TEST(Solana, TransferCheckedShortDataIsOpaque) {
  uint8_t d[9] = {SOL_TOKEN_TRANSFER_CHECKED_IX, 0x40, 0x42, 0x0F, 0, 0, 0, 0};
  uint8_t raw[512];
  size_t pos = build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 4, d, sizeof(d));
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
}

/* A TransferChecked with fewer than 4 accounts would read a zeroed mint /
 * destination (displayed as 1111..) — force opaque instead of clear-signing a
 * fabricated recipient. */
TEST(Solana, TransferCheckedShortAccountsIsOpaque) {
  uint8_t d[10] = {
      SOL_TOKEN_TRANSFER_CHECKED_IX, 0x40, 0x42, 0x0F, 0, 0, 0, 0, 6};
  uint8_t raw[512];
  size_t pos = build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 3, d, sizeof(d));
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
}

/* StakeAuthorize needs >= 40 data bytes (type(4) + new-authority(32) +
 * role(4)); a 36-byte encoding would read the role word out of bounds, so it
 * must not be accepted as a canonical authorize. */
TEST(Solana, StakeAuthorizeShortDataIsOpaque) {
  uint8_t d[36] = {SOL_STAKE_AUTHORIZE_IX, 0, 0, 0};
  memset(d + 4, 0x77, 32); /* new authority, role word missing */
  uint8_t raw[512];
  size_t pos = build_single_instr_tx(raw, SOL_STAKE_PROGRAM, 3, d, sizeof(d));
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
}

/* The same StakeAuthorize with the full 40-byte canonical encoding clear-signs
 * (role = staker), proving the rejection above is the length guard. */
TEST(Solana, StakeAuthorizeCanonicalIsVerified) {
  uint8_t d[40] = {SOL_STAKE_AUTHORIZE_IX, 0, 0, 0};
  memset(d + 4, 0x77, 32); /* new authority */
  /* d[36..39] = role 0 (staker), already zero */
  uint8_t raw[512];
  size_t pos = build_single_instr_tx(raw, SOL_STAKE_PROGRAM, 3, d, sizeof(d));
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_VERIFIED);
}
