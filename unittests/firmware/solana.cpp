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

/* The property here is that the amount is scaled by the decimals carried in
   the signed instruction -- not that trailing zeros are trimmed. Trimming was
   an older rendering detail on one branch; it is gone, because "1 USDC" hides
   the scale the base-unit count was divided by while "1.000000 USDC" states
   it. Every fractional place the scale produces is now shown. */
TEST(Solana, FormatTokenAmountUsesSignedDecimals) {
  char buf[48];

  solana_formatTokenAmount(buf, sizeof(buf), 2000, "USDC", 6);
  EXPECT_STREQ(buf, "0.002000 USDC");

  solana_formatTokenAmount(buf, sizeof(buf), 1000000, "USDC", 6);
  EXPECT_STREQ(buf, "1.000000 USDC");

  solana_formatTokenAmount(buf, sizeof(buf), 2000, "tokens", 2);
  EXPECT_STREQ(buf, "20.00 tokens");
}

TEST(Solana, MainnetUsdcIsFirmwareKnown) {
  const uint8_t usdc_mint[32] = {
      0xc6, 0xfa, 0x7a, 0xf3, 0xbe, 0xdb, 0xad, 0x3a, 0x3d, 0x65, 0xf3,
      0x6a, 0xab, 0xc9, 0x74, 0x31, 0xb1, 0xbb, 0xe4, 0xc2, 0xd2, 0xf6,
      0xe0, 0xe4, 0x7c, 0xa6, 0x02, 0x03, 0x45, 0x2f, 0x5d, 0x61};
  const SolanaKnownToken* token = solana_findKnownToken(usdc_mint);
  ASSERT_NE(token, nullptr);
  EXPECT_STREQ(token->symbol, "USDC");
  EXPECT_EQ(token->decimals, 6);

  uint8_t unknown[32] = {0};
  EXPECT_EQ(solana_findKnownToken(unknown), nullptr);
}

TEST(Solana, DerivesAndMatchesAssociatedTokenRecipientOwner) {
  /* Vector independently produced by @solana/web3.js
   * PublicKey.findProgramAddressSync with bump 251. */
  const uint8_t owner[32] = {0xea, 0x4a, 0x6c, 0x63, 0xe2, 0x9c, 0x52, 0x0a,
                             0xbe, 0xf5, 0x50, 0x7b, 0x13, 0x2e, 0xc5, 0xf9,
                             0x95, 0x47, 0x76, 0xae, 0xbe, 0xbe, 0x7b, 0x92,
                             0x42, 0x1e, 0xea, 0x69, 0x14, 0x46, 0xd2, 0x2c};
  const uint8_t mint[32] = {0xc6, 0xfa, 0x7a, 0xf3, 0xbe, 0xdb, 0xad, 0x3a,
                            0x3d, 0x65, 0xf3, 0x6a, 0xab, 0xc9, 0x74, 0x31,
                            0xb1, 0xbb, 0xe4, 0xc2, 0xd2, 0xf6, 0xe0, 0xe4,
                            0x7c, 0xa6, 0x02, 0x03, 0x45, 0x2f, 0x5d, 0x61};
  const uint8_t expected_ata[32] = {
      0x67, 0x30, 0x2e, 0x49, 0x18, 0x94, 0xd7, 0x49, 0x2e, 0xa6, 0xbe,
      0x4f, 0x91, 0x4e, 0xa4, 0xf4, 0x5f, 0xa1, 0x42, 0xe6, 0x45, 0x86,
      0x7c, 0x91, 0x64, 0xa2, 0x76, 0xd5, 0xdd, 0x76, 0xf0, 0x76};

  uint8_t derived[32] = {0};
  ASSERT_TRUE(solana_deriveAssociatedTokenAddress(owner, SOL_TOKEN_PROGRAM,
                                                  mint, derived));
  EXPECT_EQ(memcmp(derived, expected_ata, sizeof(derived)), 0);

  SolanaSignTx msg = SolanaSignTx_init_zero;
  msg.token_recipient_owner_count = 1;
  msg.token_recipient_owner[0].size = sizeof(owner);
  memcpy(msg.token_recipient_owner[0].bytes, owner, sizeof(owner));
  uint8_t matched[32] = {0};
  ASSERT_TRUE(solana_findTokenRecipientOwner(&msg, SOL_TOKEN_PROGRAM, mint,
                                             expected_ata, matched));
  EXPECT_EQ(memcmp(matched, owner, sizeof(matched)), 0);

  uint8_t wrong_destination[32];
  memset(wrong_destination, 0x44, sizeof(wrong_destination));
  memset(matched, 0xaa, sizeof(matched));
  EXPECT_FALSE(solana_findTokenRecipientOwner(&msg, SOL_TOKEN_PROGRAM, mint,
                                              wrong_destination, matched));
  for (uint8_t byte : matched) EXPECT_EQ(byte, 0xaa);
}

TEST(Solana, FormatTokenAmountNeverShowsZeroForNonzero) {
  char buf[64];

  /* The defect: at more than nine decimals the formatter divided the fraction
     down and printed the result, so a real transfer could render as zero.
     amount=1 decimals=18 became "0.000000000 tokens" while the signed
     instruction moved one base unit. */
  solana_formatTokenAmount(buf, sizeof(buf), 1, "tokens", 18);
  EXPECT_STRNE(buf, "0.000000000 tokens");
  EXPECT_NE(nullptr, strstr(buf, "1"));

  /* 18 decimals, value below the display resolution -> exact base units. */
  EXPECT_STREQ(buf, "1 base units (18 decimals) tokens");

  /* 10 decimals, one digit past the limit, and that digit is nonzero. */
  solana_formatTokenAmount(buf, sizeof(buf), 1, "tokens", 10);
  EXPECT_STREQ(buf, "1 base units (10 decimals) tokens");

  /* 10 decimals where the dropped digit IS zero: the decimal form is exact,
     so it is still used. 10 base units at 10dp = 0.000000001. */
  solana_formatTokenAmount(buf, sizeof(buf), 10, "tokens", 10);
  EXPECT_STREQ(buf, "0.000000001 tokens");

  /* 9 decimals is the boundary -- nothing is dropped, decimal form always. */
  solana_formatTokenAmount(buf, sizeof(buf), 1, "tokens", 9);
  EXPECT_STREQ(buf, "0.000000001 tokens");

  solana_formatTokenAmount(buf, sizeof(buf), 1000000000ULL, "tokens", 9);
  EXPECT_STREQ(buf, "1.000000000 tokens");

  /* A whole-number amount at 18 decimals still divides exactly. */
  solana_formatTokenAmount(buf, sizeof(buf), 1000000000000000000ULL, "tokens",
                           18);
  EXPECT_STREQ(buf, "1.000000000 tokens");

  /* Zero really is zero, at any scale. */
  solana_formatTokenAmount(buf, sizeof(buf), 0, "tokens", 18);
  EXPECT_STREQ(buf, "0.000000000 tokens");
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

TEST(Solana, X402ZeroLookupV0UsdcPaymentIsVerified) {
  /* Self-contained x402 shape: sponsor fee payer + user authority, compute
   * limit, compute price, SPL TransferChecked, memo, and zero ALT entries. */
  const uint8_t usdc_mint[32] = {
      0xc6, 0xfa, 0x7a, 0xf3, 0xbe, 0xdb, 0xad, 0x3a, 0x3d, 0x65, 0xf3,
      0x6a, 0xab, 0xc9, 0x74, 0x31, 0xb1, 0xbb, 0xe4, 0xc2, 0xd2, 0xf6,
      0xe0, 0xe4, 0x7c, 0xa6, 0x02, 0x03, 0x45, 0x2f, 0x5d, 0x61};
  const uint8_t destination_ata[32] = {
      0x67, 0x30, 0x2e, 0x49, 0x18, 0x94, 0xd7, 0x49, 0x2e, 0xa6, 0xbe,
      0x4f, 0x91, 0x4e, 0xa4, 0xf4, 0x5f, 0xa1, 0x42, 0xe6, 0x45, 0x86,
      0x7c, 0x91, 0x64, 0xa2, 0x76, 0xd5, 0xdd, 0x76, 0xf0, 0x76};
  uint8_t raw[512];
  size_t pos = 0;
  raw[pos++] = 0x80; /* v0 */
  raw[pos++] = 2;    /* sponsor + token authority */
  raw[pos++] = 0;
  raw[pos++] = 3; /* compute, token and memo programs are readonly */

  raw[pos++] = 8;
  memset(raw + pos, 0x10, 32); /* sponsor / fee payer */
  pos += 32;
  memset(raw + pos, 0x20, 32); /* user token authority */
  pos += 32;
  memset(raw + pos, 0x30, 32); /* source token account */
  pos += 32;
  memcpy(raw + pos, destination_ata, 32);
  pos += 32;
  memcpy(raw + pos, usdc_mint, 32);
  pos += 32;
  memcpy(raw + pos, SOL_COMPUTE_BUDGET_PROGRAM, 32);
  pos += 32;
  memcpy(raw + pos, SOL_TOKEN_PROGRAM, 32);
  pos += 32;
  memcpy(raw + pos, SOL_MEMO_PROGRAM, 32);
  pos += 32;
  memset(raw + pos, 0xbb, 32); /* recent blockhash */
  pos += 32;

  raw[pos++] = 4; /* instructions */

  raw[pos++] = 5; /* ComputeBudget::SetComputeUnitLimit */
  raw[pos++] = 0;
  raw[pos++] = 5;
  raw[pos++] = SOL_CB_SET_COMPUTE_UNIT_LIMIT;
  raw[pos++] = 0xc0;
  raw[pos++] = 0xd4;
  raw[pos++] = 0x01;
  raw[pos++] = 0x00; /* 120000 */

  raw[pos++] = 5; /* ComputeBudget::SetComputeUnitPrice */
  raw[pos++] = 0;
  raw[pos++] = 9;
  raw[pos++] = SOL_CB_SET_COMPUTE_UNIT_PRICE;
  raw[pos++] = 0xe8;
  raw[pos++] = 0x03;
  for (int i = 0; i < 6; i++) raw[pos++] = 0; /* 1000 micro-lamports */

  raw[pos++] = 6; /* SPL Token::TransferChecked */
  raw[pos++] = 4;
  raw[pos++] = 2; /* source */
  raw[pos++] = 4; /* mint */
  raw[pos++] = 3; /* destination ATA */
  raw[pos++] = 1; /* authority */
  raw[pos++] = 10;
  raw[pos++] = SOL_TOKEN_TRANSFER_CHECKED_IX;
  raw[pos++] = 0xd0;
  raw[pos++] = 0x07;
  for (int i = 0; i < 6; i++) raw[pos++] = 0; /* amount 2000 */
  raw[pos++] = 6;                             /* decimals */

  raw[pos++] = 7; /* Memo */
  raw[pos++] = 1;
  raw[pos++] = 1; /* authority signer */
  const char* x402_memo = "00112233445566778899aabbccddeeff";
  const size_t x402_memo_len = strlen(x402_memo);
  raw[pos++] = (uint8_t)x402_memo_len;
  memcpy(raw + pos, x402_memo, x402_memo_len);
  pos += x402_memo_len;

  raw[pos++] = 0; /* zero address-lookup tables */

  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_VERIFIED);
  ASSERT_EQ(tx.num_instructions, 4);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT);
  EXPECT_EQ(tx.instructions[1].type, SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE);
  ASSERT_EQ(tx.instructions[2].type, SOL_INSTR_TOKEN_TRANSFER_CHECKED);
  EXPECT_EQ(tx.instructions[2].amount, 2000);
  EXPECT_EQ(tx.instructions[2].extra_u8, 6);
  EXPECT_EQ(memcmp(tx.instructions[2].mint, usdc_mint, 32), 0);
  EXPECT_EQ(memcmp(tx.instructions[2].to, destination_ata, 32), 0);
  EXPECT_EQ(tx.instructions[3].type, SOL_INSTR_MEMO);
}

TEST(Solana, VersionedMessageWithUnreferencedLookupTableIsOpaque) {
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

  /* x402 clear-sign support is deliberately zero-LUT only. Even an
   * unreferenced table keeps the message behind the opaque AdvancedMode gate
   * until the device can resolve and authenticate lookup-table state. */
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_FALSE(solana_parseTx(raw, pos, &tx));
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

/* ── KKSOLSC1 reusable instruction schemas ────────────────────────────
 *
 * Vector is the real Relay bridge deposit captured from api.relay.link on
 * 2026-07-27: program 99vQwtBwYtrqqD9YSXbdum3KBdxPAVxYTaQ3cfnJSrN2, 48 bytes
 * of data = 8-byte discriminator + u64 amount + 32-byte order id. The amount
 * word tracked the requested input exactly across three different quotes.
 */
static const uint8_t kRelayDisc[8] = {0x0d, 0x9e, 0x0d, 0xdf,
                                      0x5f, 0xd5, 0x1c, 0x06};

/* Build a KKSOLSC1 payload: one u64 arg ("Amount") and one account ("Vault").
 */
static size_t build_relay_schema(uint8_t* out, const uint8_t* program,
                                 uint8_t n_args = 1) {
  size_t p = 0;
  memcpy(out + p, "KKSOLSC1", 8);
  p += 8;
  out[p++] = 1; /* version */
  memcpy(out + p, program, 32);
  p += 32;
  out[p++] = 8; /* disc_len */
  memcpy(out + p, kRelayDisc, 8);
  p += 8;
  out[p++] = 5;
  memcpy(out + p, "Relay", 5);
  p += 5; /* program name */
  out[p++] = 7;
  memcpy(out + p, "deposit", 7);
  p += 7; /* instruction name */
  out[p++] = n_args;
  if (n_args >= 1) {
    out[p++] = SOL_SCHEMA_ARG_U64;
    out[p++] = 6;
    memcpy(out + p, "Amount", 6);
    p += 6;
  }
  if (n_args >= 2) {
    out[p++] = SOL_SCHEMA_ARG_OPAQUE32;
    out[p++] = 5;
    memcpy(out + p, "Order", 5);
    p += 5;
  }
  out[p++] = 1; /* one displayed account */
  out[p++] = 0; /* index 0 */
  out[p++] = 5;
  memcpy(out + p, "Vault", 5);
  p += 5;
  return p;
}

/* Relay's instruction data: discriminator + amount + 32-byte order id. */
static void build_relay_data(uint8_t* d, uint64_t amount) {
  memcpy(d, kRelayDisc, 8);
  for (int i = 0; i < 8; i++) d[8 + i] = (uint8_t)(amount >> (8 * i));
  memset(d + 16, 0xAB, 32);
}

TEST(Solana, SchemaParsesCanonicalPayload) {
  uint8_t program[32];
  memset(program, 0x42, sizeof(program));
  uint8_t blob[256];
  size_t len = build_relay_schema(blob, program, 2);
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob, len, &s));
  EXPECT_EQ(s.disc_len, 8);
  EXPECT_EQ(s.num_args, 2);
  EXPECT_EQ(s.num_accounts, 1);
  EXPECT_STREQ(s.program_name, "Relay");
  EXPECT_STREQ(s.instruction_name, "deposit");
  EXPECT_STREQ(s.args[0].label, "Amount");
}

TEST(Solana, SchemaRejectsTrailingBytes) {
  uint8_t program[32];
  memset(program, 0x42, sizeof(program));
  uint8_t blob[256];
  size_t len = build_relay_schema(blob, program, 2);
  blob[len] = 0x00; /* one byte too many */
  SolanaInstrSchema s;
  EXPECT_FALSE(solana_parseInstrSchema(blob, len + 1, &s));
}

TEST(Solana, SchemaRejectsUnsafeLabel) {
  uint8_t program[32];
  memset(program, 0x42, sizeof(program));
  uint8_t blob[256];
  size_t len = build_relay_schema(blob, program, 1);
  /* Corrupt the "Amount" label with a format specifier. */
  for (size_t i = 0; i + 6 <= len; i++) {
    if (memcmp(blob + i, "Amount", 6) == 0) {
      blob[i] = '%';
      break;
    }
  }
  SolanaInstrSchema s;
  EXPECT_FALSE(solana_parseInstrSchema(blob, len, &s));
}

/* The core safety property: a schema that does not account for every byte of
 * the instruction data must NOT apply. Here the data is Relay's real 48 bytes
 * but the schema declares only the 8-byte amount, leaving 32 bytes unexplained.
 */
TEST(Solana, SchemaRejectsIncompleteCoverage) {
  uint8_t program[32];
  memset(program, 0x42, sizeof(program));
  uint8_t d[48];
  build_relay_data(d, 526490980ULL);
  uint8_t raw[512];
  size_t pos = build_single_instr_tx(raw, program, 2, d, sizeof(d));
  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);

  uint8_t blob[256];
  size_t len =
      build_relay_schema(blob, program, 1); /* amount only: 8+8 != 48 */
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob, len, &s));
  uint8_t idx = 0xFF;
  EXPECT_FALSE(solana_schemaApplies(&s, &tx, &idx));
}

/* Full coverage (8 disc + 8 amount + 32 order = 48) applies, and the amount is
 * readable straight out of the signed bytes. */
TEST(Solana, SchemaAppliesWithFullCoverage) {
  uint8_t program[32];
  memset(program, 0x42, sizeof(program));
  uint8_t d[48];
  build_relay_data(d, 526490980ULL);
  uint8_t raw[512];
  size_t pos = build_single_instr_tx(raw, program, 2, d, sizeof(d));
  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);

  uint8_t blob[256];
  size_t len = build_relay_schema(blob, program, 2);
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob, len, &s));
  uint8_t idx = 0xFF;
  ASSERT_TRUE(solana_schemaApplies(&s, &tx, &idx));
  EXPECT_EQ(idx, 0);

  uint64_t amount = 0;
  const SolanaParsedInstruction* ix = &tx.instructions[idx];
  for (int i = 0; i < 8; i++) {
    amount |= ((uint64_t)ix->data[s.disc_len + i]) << (8 * i);
  }
  EXPECT_EQ(amount, 526490980ULL);
}

/* A schema for a different program must never match. */
TEST(Solana, SchemaRejectsProgramMismatch) {
  uint8_t program[32], other[32];
  memset(program, 0x42, sizeof(program));
  memset(other, 0x43, sizeof(other));
  uint8_t d[48];
  build_relay_data(d, 1ULL);
  uint8_t raw[512];
  size_t pos = build_single_instr_tx(raw, program, 2, d, sizeof(d));
  SolanaParsedTx tx;
  solana_inspectTx(raw, pos, &tx);

  uint8_t blob[256];
  size_t len = build_relay_schema(blob, other, 2);
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob, len, &s));
  uint8_t idx = 0xFF;
  EXPECT_FALSE(solana_schemaApplies(&s, &tx, &idx));
}

/* An account index the instruction doesn't have must not be displayable. */
TEST(Solana, SchemaRejectsOutOfRangeAccount) {
  uint8_t program[32];
  memset(program, 0x42, sizeof(program));
  uint8_t d[48];
  build_relay_data(d, 1ULL);
  uint8_t raw[512];
  /* Only ONE instruction account, but the schema displays index 0..; bump the
   * schema's account index past the end. */
  size_t pos = build_single_instr_tx(raw, program, 1, d, sizeof(d));
  SolanaParsedTx tx;
  solana_inspectTx(raw, pos, &tx);

  uint8_t blob[256];
  size_t len = build_relay_schema(blob, program, 2);
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob, len, &s));
  s.accounts[0].index = 9; /* beyond this instruction's account list */
  uint8_t idx = 0xFF;
  EXPECT_FALSE(solana_schemaApplies(&s, &tx, &idx));
}

/* Cross-language parity: these exact bytes are emitted by the KeepKey SDK's
 * KKSOLSC1 serializer (keepkey-sdk tests/fixtures/solana-schema.js, catalog
 * entries relayDepositNative / relayDepositToken). The SDK and this parser are
 * independent implementations of the same format — if either drifts, the host
 * ships a schema the device refuses, or worse renders differently than the
 * signer intended. Regenerate with:
 *   node -e "const f=require('./tests/fixtures/solana-schema');
 *            console.log(f.serializeSchema(f.CATALOG.relayDepositNative).toString('hex'))"
 */
static size_t hex_to_bytes(const char* hex, uint8_t* out, size_t out_max) {
  size_t n = strlen(hex) / 2;
  if (n > out_max) return 0;
  for (size_t i = 0; i < n; i++) {
    unsigned v = 0;
    sscanf(hex + 2 * i, "%2x", &v);
    out[i] = (uint8_t)v;
  }
  return n;
}

TEST(Solana, SchemaParsesSdkSerializedPayloadNative) {
  /* Verbatim output of the SDK serializer — do not hand-edit. */
  const char* kSdkHex =
      "4b4b534f4c53433101792689378ecd51d80406eb0caa3b62795beb10b6c5dc96bc2e0df0"
      "3cbfee1abf"
      "080d9e0ddf5fd51c06"
      "0c52656c617920427269646765"
      "0d6465706f7369744e6174697665"
      "020106416d6f756e7404054f7264657201"
      "03055661756c74";
  uint8_t blob[256];
  size_t len = hex_to_bytes(kSdkHex, blob, sizeof(blob));
  ASSERT_EQ(len, 101u);

  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob, len, &s));
  EXPECT_STREQ(s.program_name, "Relay Bridge");
  EXPECT_STREQ(s.instruction_name, "depositNative");
  EXPECT_EQ(s.disc_len, 8);
  EXPECT_EQ(s.num_args, 2);
  EXPECT_EQ(s.args[0].type, SOL_SCHEMA_ARG_U64);
  EXPECT_STREQ(s.args[0].label, "Amount");
  EXPECT_EQ(s.args[1].type, SOL_SCHEMA_ARG_OPAQUE32);
  EXPECT_STREQ(s.args[1].label, "Order");
  EXPECT_EQ(s.num_accounts, 1);
  EXPECT_EQ(s.accounts[0].index, 3);
  EXPECT_STREQ(s.accounts[0].label, "Vault");

  /* Coverage must equal Relay's real 48-byte instruction data. */
  uint32_t covered = s.disc_len;
  for (uint8_t i = 0; i < s.num_args; i++) {
    covered += solana_schemaArgWidth(s.args[i].type);
  }
  EXPECT_EQ(covered, 48u);
}

/* An SPL token transfer whose recipient may not have an associated token
 * account: wallets prepend CreateAssociatedTokenAccountIdempotent (data [1]),
 * then TransferChecked. This is what Pioneer builds for a USDT swap deposit,
 * and it is the ordinary shape of a token send to a fresh address.
 *
 * Idempotent takes the SAME accounts as Create in the same order and creates
 * the same account — it only declines to fail when one already exists — so it
 * displays identically. Rejecting it made ONE unrecognised instruction force
 * the entire transaction opaque, so a fully decodable SPL transfer
 * blind-signed ("Enable AdvancedMode to blind-sign").
 */
static size_t build_ata_then_transfer_tx(uint8_t* raw, uint8_t ata_ix_byte,
                                         bool include_ata_byte) {
  /* accounts: 0..3 instruction accounts, 4 = ATA program, 5 = token program */
  const int n_accounts = 4;
  size_t pos = 0;
  raw[pos++] = 1; /* num_required_sigs */
  raw[pos++] = 0;
  raw[pos++] = 2;                         /* two readonly unsigned (programs) */
  raw[pos++] = (uint8_t)(n_accounts + 2); /* total accounts */
  for (int i = 0; i < n_accounts; i++) {
    memset(raw + pos, 0x11 + i, 32);
    pos += 32;
  }
  memcpy(raw + pos, SOL_ATA_PROGRAM, 32);
  pos += 32;
  memcpy(raw + pos, SOL_TOKEN_PROGRAM, 32);
  pos += 32;
  memset(raw + pos, 0xBB, 32); /* recent blockhash */
  pos += 32;

  raw[pos++] = 2; /* two instructions */

  /* 1) ATA create (idempotent or classic) — accounts 0..3 */
  raw[pos++] = (uint8_t)n_accounts; /* ATA program index */
  raw[pos++] = (uint8_t)n_accounts;
  for (int i = 0; i < n_accounts; i++) raw[pos++] = (uint8_t)i;
  if (include_ata_byte) {
    raw[pos++] = 1; /* data_len */
    raw[pos++] = ata_ix_byte;
  } else {
    raw[pos++] = 0; /* empty data = legacy Create */
  }

  /* 2) TransferChecked: [12, amount u64 LE, decimals] over 4 accounts */
  raw[pos++] = (uint8_t)(n_accounts + 1); /* token program index */
  raw[pos++] = (uint8_t)n_accounts;
  for (int i = 0; i < n_accounts; i++) raw[pos++] = (uint8_t)i;
  raw[pos++] = 10; /* data_len */
  raw[pos++] = SOL_TOKEN_TRANSFER_CHECKED_IX;
  for (int i = 0; i < 8; i++) raw[pos++] = (i == 0) ? 0x40 : 0x00; /* amount */
  raw[pos++] = 6; /* decimals (USDT) */
  return pos;
}

TEST(Solana, AtaCreateIdempotentThenTransferIsVerified) {
  uint8_t raw[1024];
  size_t len =
      build_ata_then_transfer_tx(raw, 1, true); /* 1 = CreateIdempotent */
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_VERIFIED);
  ASSERT_EQ(tx.num_instructions, 2);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_ATA_CREATE);
  EXPECT_EQ(tx.instructions[1].type, SOL_INSTR_TOKEN_TRANSFER_CHECKED);
}

TEST(Solana, AtaCreateClassicStillVerified) {
  uint8_t raw[1024];
  size_t len = build_ata_then_transfer_tx(raw, 0, true); /* 0 = Create */
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_VERIFIED);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_ATA_CREATE);

  len = build_ata_then_transfer_tx(raw, 0, false); /* legacy empty data */
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_VERIFIED);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_ATA_CREATE);
}

/* RecoverNested (2) and anything else stays unknown: different accounts and
 * different meaning, so it must not borrow the create screens. */
TEST(Solana, AtaUnknownInstructionStillOpaque) {
  uint8_t raw[1024];
  size_t len = build_ata_then_transfer_tx(raw, 2, true); /* RecoverNested */
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
}
