extern "C" {
#include "keepkey/firmware/solana.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/ed25519-donna/ed25519.h"
}

#include "gtest/gtest.h"
#include <cstring>
#include <vector>

TEST(Solana, FormatAmount) {
  char buf[32];

  solana_formatAmount(buf, sizeof(buf), 1000000000ULL);
  EXPECT_STREQ(buf, "1.000000000 SOL");

  solana_formatAmount(buf, sizeof(buf), 0);
  EXPECT_STREQ(buf, "0.000000000 SOL");

  solana_formatAmount(buf, sizeof(buf), 2500000000ULL);
  EXPECT_STREQ(buf, "2.500000000 SOL");
}

TEST(Solana, FormatTokenAmountUsesSignedDecimalsAndTrimsZeros) {
  char buf[48];

  solana_formatTokenAmount(buf, sizeof(buf), 2000, "USDC", 6);
  EXPECT_STREQ(buf, "0.002 USDC");

  solana_formatTokenAmount(buf, sizeof(buf), 1000000, "USDC", 6);
  EXPECT_STREQ(buf, "1 USDC");

  solana_formatTokenAmount(buf, sizeof(buf), 2000, "tokens", 2);
  EXPECT_STREQ(buf, "20 tokens");
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

TEST(Solana, PriorityFeeCalculationIsRoundedAndOverflowSafe) {
  uint64_t fee = 0;
  ASSERT_TRUE(solana_priority_fee_lamports(50000000, 1400000, &fee));
  EXPECT_EQ(fee, 70000000ULL);

  /* Solana caps even an explicit request above 1.4M CU; the raw UINT32_MAX
   * request must not be multiplied by the price. */
  ASSERT_TRUE(solana_priority_fee_lamports(2000000, UINT32_MAX, &fee));
  EXPECT_EQ(fee, 2800000ULL);
  ASSERT_TRUE(solana_priority_fee_lamports(1, UINT64_MAX, &fee));
  EXPECT_EQ(fee, 2ULL); /* ceil(1.4) */
}

// Without SetComputeUnitLimit the fee is charged on the runtime's default
// request, not the 1.4M cap: [SetComputeUnitPrice, Transfer] is 203,000 CUs.
TEST(Solana, PriorityFeeWithoutExplicitLimitUsesDerivedDefault) {
  SolanaParsedTx tx = {};
  tx.num_instructions = 2;
  tx.instructions[0].type = SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE;
  tx.instructions[1].type = SOL_INSTR_SYSTEM_TRANSFER;
  EXPECT_EQ(203000u, solana_defaultComputeUnitLimit(&tx));
  uint64_t fee = 0;
  ASSERT_TRUE(solana_priority_fee_lamports(
      1000000, solana_defaultComputeUnitLimit(&tx), &fee));
  EXPECT_EQ(203000u, fee);

  // Many instructions still stop at the per-transaction cap.
  tx.num_instructions = SOL_MAX_INSTRUCTIONS;
  for (uint8_t i = 1; i < tx.num_instructions; i++) {
    tx.instructions[i].type = SOL_INSTR_SYSTEM_TRANSFER;
  }
  ASSERT_GT(solana_defaultComputeUnitLimit(&tx), SOL_MAX_COMPUTE_UNITS);
  ASSERT_TRUE(solana_priority_fee_lamports(
      1000000, solana_defaultComputeUnitLimit(&tx), &fee));
  EXPECT_EQ(1400000u, fee);
}

TEST(Solana, ParseAssociatedTokenAccountCreate) {
  uint8_t raw[512];
  size_t pos = 0;

  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 3;

  raw[pos++] = 7;
  memset(raw + pos, 0x11, 32);
  pos += 32; /* funder */
  memset(raw + pos, 0x22, 32);
  pos += 32; /* ata */
  memset(raw + pos, 0x33, 32);
  pos += 32; /* owner */
  memset(raw + pos, 0x44, 32);
  pos += 32; /* mint */
  memcpy(raw + pos, SOL_SYSTEM_PROGRAM, 32);
  pos += 32; /* system program */
  memcpy(raw + pos, SOL_TOKEN_PROGRAM, 32);
  pos += 32; /* token program */
  memcpy(raw + pos, SOL_ATA_PROGRAM, 32);
  pos += 32; /* program */

  memset(raw + pos, 0xBB, 32);
  pos += 32;

  raw[pos++] = 1;
  raw[pos++] = 6; /* ata program */
  raw[pos++] = 6; /* 6 account indices */
  for (int i = 0; i < 6; i++) raw[pos++] = (uint8_t)i;
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

TEST(Solana, NullTransactionIsMalformed) {
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(nullptr, 64, &tx), SOL_TX_REVIEW_MALFORMED);
  EXPECT_FALSE(solana_parseTx(nullptr, 64, &tx));
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

// A zero-LUT v0 message can verify, so its header must pass Solana's own
// sanitize rules first: a writable fee payer, and signer plus read-only
// unsigned ranges inside the three static keys.
TEST(Solana, VersionedMessageWithInvalidHeaderIsMalformed) {
  struct Header {
    uint8_t sigs, ro_signed, ro_unsigned;
    SolanaTxReview review;
  };
  const Header headers[] = {
      {1, 0, 1, SOL_TX_REVIEW_VERIFIED},  /* control */
      {1, 0, 2, SOL_TX_REVIEW_VERIFIED},  /* 1 + 2 == 3 static keys */
      {0, 0, 1, SOL_TX_REVIEW_MALFORMED}, /* no signer */
      {1, 1, 1, SOL_TX_REVIEW_MALFORMED}, /* no writable signer */
      {4, 0, 0, SOL_TX_REVIEW_MALFORMED}, /* more signers than keys */
      {1, 0, 3, SOL_TX_REVIEW_MALFORMED}, /* ranges overlap */
  };
  for (const Header& h : headers) {
    SCOPED_TRACE(testing::Message() << int(h.sigs) << "," << int(h.ro_signed)
                                    << "," << int(h.ro_unsigned));
    uint8_t raw[256];
    size_t pos = 0;
    raw[pos++] = 0x80; /* v0 prefix */
    raw[pos++] = h.sigs;
    raw[pos++] = h.ro_signed;
    raw[pos++] = h.ro_unsigned;
    raw[pos++] = 3; /* static accounts */
    memset(raw + pos, 0x11, 32);
    pos += 32;
    memset(raw + pos, 0x22, 32);
    pos += 32;
    memset(raw + pos, 0x00, 32); /* system program */
    pos += 32;
    memset(raw + pos, 0xBB, 32); /* blockhash */
    pos += 32;
    raw[pos++] = 1; /* instructions */
    raw[pos++] = 2; /* program = system */
    raw[pos++] = 2;
    raw[pos++] = 0;
    raw[pos++] = 1;
    raw[pos++] = 12;
    const uint8_t transfer[12] = {2, 0, 0, 0, 0x00, 0xCA, 0x9A, 0x3B};
    memcpy(raw + pos, transfer, sizeof(transfer));
    pos += sizeof(transfer);
    raw[pos++] = 0; /* zero lookup tables */
    SolanaParsedTx tx;
    EXPECT_EQ(solana_inspectTx(raw, pos, &tx), h.review);
  }
}

// Legacy messages get the same header sanitize rules as v0, before any
// review classification, including the opaque path for too many accounts.
TEST(Solana, LegacyMessageWithInvalidHeaderIsMalformed) {
  struct Header {
    uint8_t sigs, ro_signed, ro_unsigned, accounts;
    SolanaTxReview review;
  };
  const Header headers[] = {
      {1, 0, 1, 3, SOL_TX_REVIEW_VERIFIED},  /* control */
      {1, 0, 2, 3, SOL_TX_REVIEW_VERIFIED},  /* 1 + 2 == 3 static keys */
      {0, 0, 1, 3, SOL_TX_REVIEW_MALFORMED}, /* no signer */
      {1, 1, 1, 3, SOL_TX_REVIEW_MALFORMED}, /* no writable signer */
      {4, 0, 0, 3, SOL_TX_REVIEW_MALFORMED}, /* more signers than keys */
      {1, 0, 3, 3, SOL_TX_REVIEW_MALFORMED}, /* ranges overlap */
      {1, 0, 1, SOL_MAX_ACCOUNTS + 1, SOL_TX_REVIEW_OPAQUE}, /* control */
      {1, 1, 1, SOL_MAX_ACCOUNTS + 1, SOL_TX_REVIEW_MALFORMED},
  };
  for (const Header& h : headers) {
    SCOPED_TRACE(testing::Message()
                 << int(h.sigs) << "," << int(h.ro_signed) << ","
                 << int(h.ro_unsigned) << "," << int(h.accounts));
    std::vector<uint8_t> raw = {h.sigs, h.ro_signed, h.ro_unsigned, h.accounts};
    raw.insert(raw.end(), 32, 0x11);
    raw.insert(raw.end(), 32, 0x22);
    for (uint8_t i = 2; i < h.accounts; i++) raw.insert(raw.end(), 32, 0x00);
    raw.insert(raw.end(), 32, 0xBB); /* blockhash */
    raw.insert(raw.end(), {1, 2, 2, 0, 1, 12, 2, 0, 0, 0});
    raw.insert(raw.end(), {0x00, 0xCA, 0x9A, 0x3B, 0, 0, 0, 0});
    SolanaParsedTx tx;
    EXPECT_EQ(h.review, solana_inspectTx(raw.data(), raw.size(), &tx));
  }
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

// Three static keys (payer, recipient, system program) and one SystemTransfer
// whose program and recipient indices the caller chooses. `instructions`
// repeats it, so a count past SOL_MAX_INSTRUCTIONS walks the unretained path.
// `loaded` is the number of accounts one lookup table loads (-1: no table).
static std::vector<uint8_t> v0_transfer(uint8_t program, uint8_t to, int loaded,
                                        uint8_t instructions = 1) {
  std::vector<uint8_t> raw = {0x80, 1, 0, 1, 3};
  for (uint8_t fill : {0x11, 0x22, 0x00, 0xBB}) raw.insert(raw.end(), 32, fill);
  raw.push_back(instructions);
  for (uint8_t i = 0; i < instructions; i++) {
    raw.insert(raw.end(), {program, 2, 0, to, 12, 2, 0, 0, 0});
    raw.insert(raw.end(), {0x00, 0xCA, 0x9A, 0x3B, 0, 0, 0, 0});
  }
  if (loaded < 0) {
    raw.push_back(0);
  } else {
    raw.push_back(1);
    raw.insert(raw.end(), 32, 0x55);
    raw.push_back((uint8_t)loaded);
    for (int i = 0; i < loaded; i++) raw.push_back((uint8_t)i);
    raw.push_back(0);
  }
  return raw;
}

// An operand may name a lookup-table account, but only one that a table
// actually loads; past static + loaded keys the account does not exist.
TEST(Solana, VersionedOperandPastLoadedAccountsIsMalformed) {
  struct Case {
    uint8_t to;
    int loaded;
    uint8_t instructions;
    SolanaTxReview review;
  };
  const Case cases[] = {
      {1, -1, 1, SOL_TX_REVIEW_VERIFIED}, /* control: static recipient */
      {3, 1, 1, SOL_TX_REVIEW_OPAQUE},    /* control: first loaded account */
      {4, 2, 1, SOL_TX_REVIEW_OPAQUE},    /* control: last loaded account */
      {3, -1, 1, SOL_TX_REVIEW_MALFORMED},
      {3, 0, 1, SOL_TX_REVIEW_MALFORMED},
      {4, 1, 1, SOL_TX_REVIEW_MALFORMED},
      {255, 2, 1, SOL_TX_REVIEW_MALFORMED},
      /* Also checked for instructions too many to retain. */
      {3, -1, SOL_MAX_INSTRUCTIONS + 1, SOL_TX_REVIEW_MALFORMED},
  };
  for (const Case& c : cases) {
    SCOPED_TRACE(testing::Message()
                 << int(c.to) << "," << c.loaded << "," << int(c.instructions));
    const auto raw = v0_transfer(2, c.to, c.loaded, c.instructions);
    SolanaParsedTx tx;
    EXPECT_EQ(c.review, solana_inspectTx(raw.data(), raw.size(), &tx));
  }
}

// A program id must be a static key; lookup tables supply operands only.
TEST(Solana, VersionedProgramIndexMustBeStatic) {
  SolanaParsedTx tx;
  auto raw = v0_transfer(2, 1, 1); /* control: static system program */
  EXPECT_EQ(SOL_TX_REVIEW_OPAQUE,
            solana_inspectTx(raw.data(), raw.size(), &tx));
  raw = v0_transfer(3, 1, 1); /* program = the loaded account */
  EXPECT_EQ(SOL_TX_REVIEW_MALFORMED,
            solana_inspectTx(raw.data(), raw.size(), &tx));
  raw = v0_transfer(3, 1, 1, SOL_MAX_INSTRUCTIONS + 1);
  EXPECT_EQ(SOL_TX_REVIEW_MALFORMED,
            solana_inspectTx(raw.data(), raw.size(), &tx));
}

// The KKSOLSW1 annotation is offered only when the message's lookup tables
// load accounts, so the parser reports how many they load.
TEST(Solana, ParserCountsLookupLoadedAccounts) {
  uint8_t raw[256];
  size_t pos = 0;
  raw[pos++] = 0x80; /* v0 prefix */
  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 2; /* static accounts */
  memset(raw + pos, 0x11, 32);
  pos += 32;
  memset(raw + pos, 0x00, 32); /* system program */
  pos += 32;
  memset(raw + pos, 0xBB, 32); /* blockhash */
  pos += 32;
  raw[pos++] = 1; /* instructions */
  raw[pos++] = 1; /* program = system */
  raw[pos++] = 2;
  raw[pos++] = 0;
  const size_t recipient_at = pos;
  raw[pos++] = 2; /* first loaded address */
  raw[pos++] = 12;
  const uint8_t transfer[12] = {2, 0, 0, 0, 0x00, 0xCA, 0x9A, 0x3B};
  memcpy(raw + pos, transfer, sizeof(transfer));
  pos += sizeof(transfer);
  const size_t lut_count_at = pos;
  raw[pos++] = 1; /* one table: two writable, one readonly */
  memset(raw + pos, 0x55, 32);
  pos += 32;
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 1;
  raw[pos++] = 2;
  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(3u, tx.num_loaded_accounts);

  /* The same transfer to a static account, with no lookup table, is a valid
   * v0 message that loads nothing. */
  raw[recipient_at] = 1;
  raw[lut_count_at] = 0;
  ASSERT_EQ(solana_inspectTx(raw, lut_count_at + 1, &tx),
            SOL_TX_REVIEW_VERIFIED);
  EXPECT_EQ(0u, tx.num_loaded_accounts);
}

// A lookup-account attestation is shown only when it attests as many accounts
// as the message loads: a partial or padded list would mislead. Only the count
// is checked here; the account keys are bound by the attestation signature
// check, solana_lut_accounts_trusted().
TEST(Solana, LookupAttestationMustCoverEveryLoadedAccount) {
  SolanaParsedTx tx;
  memset(&tx, 0, sizeof(tx));
  tx.num_loaded_accounts = 3;
  EXPECT_TRUE(solana_lut_attestation_complete(&tx, 3));
  EXPECT_FALSE(solana_lut_attestation_complete(&tx, 1));
  EXPECT_FALSE(solana_lut_attestation_complete(&tx, 4));
  EXPECT_FALSE(solana_lut_attestation_complete(&tx, 0));
  tx.num_loaded_accounts = 0;
  EXPECT_FALSE(solana_lut_attestation_complete(&tx, 0));
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

static size_t BuildMemoTx(uint8_t* raw, const uint8_t* memo, size_t memo_len) {
  size_t pos = 0;
  raw[pos++] = 1; /* one required signer */
  raw[pos++] = 0;
  raw[pos++] = 1; /* memo program is readonly */
  raw[pos++] = 2; /* signer + memo program */
  memset(raw + pos, 0x11, SOL_PUBKEY_SIZE);
  pos += SOL_PUBKEY_SIZE;
  memcpy(raw + pos, SOL_MEMO_PROGRAM, SOL_PUBKEY_SIZE);
  pos += SOL_PUBKEY_SIZE;
  memset(raw + pos, 0xbb, SOL_PUBKEY_SIZE);
  pos += SOL_PUBKEY_SIZE;
  raw[pos++] = 1; /* one instruction */
  raw[pos++] = 1; /* memo program */
  raw[pos++] = 0; /* no account indices */
  raw[pos++] = (uint8_t)memo_len;
  memcpy(raw + pos, memo, memo_len);
  pos += memo_len;
  return pos;
}

TEST(Solana, MemoRetainsEverySignedByteForReview) {
  uint8_t memo_a[80];
  uint8_t memo_b[80];
  memset(memo_a, 'A', sizeof(memo_a));
  memcpy(memo_b, memo_a, sizeof(memo_b));
  memo_b[64] = 'B'; /* same length and first 32 bytes, different signed tail */

  uint8_t raw_a[256];
  uint8_t raw_b[256];
  const size_t len_a = BuildMemoTx(raw_a, memo_a, sizeof(memo_a));
  const size_t len_b = BuildMemoTx(raw_b, memo_b, sizeof(memo_b));
  ASSERT_EQ(len_a, len_b);

  SolanaParsedTx tx_a;
  SolanaParsedTx tx_b;
  ASSERT_EQ(solana_inspectTx(raw_a, len_a, &tx_a), SOL_TX_REVIEW_VERIFIED);
  ASSERT_EQ(solana_inspectTx(raw_b, len_b, &tx_b), SOL_TX_REVIEW_VERIFIED);
  ASSERT_EQ(tx_a.instructions[0].type, SOL_INSTR_MEMO);
  ASSERT_EQ(tx_b.instructions[0].type, SOL_INSTR_MEMO);
  ASSERT_EQ(tx_a.instructions[0].data_len, sizeof(memo_a));
  ASSERT_EQ(tx_b.instructions[0].data_len, sizeof(memo_b));
  EXPECT_EQ(0, memcmp(tx_a.instructions[0].data, memo_a, sizeof(memo_a)));
  EXPECT_EQ(0, memcmp(tx_b.instructions[0].data, memo_b, sizeof(memo_b)));
  EXPECT_NE(0, memcmp(tx_a.instructions[0].data, tx_b.instructions[0].data,
                      sizeof(memo_a)));
}

TEST(Solana, CreateAccountRetainsEveryDisplayedSecurityField) {
  uint8_t raw[256];
  size_t pos = 0;

  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 3;
  memset(raw + pos, 0x11, 32);
  pos += 32;
  memset(raw + pos, 0x22, 32);
  pos += 32;
  memset(raw + pos, 0, 32);
  pos += 32;
  memset(raw + pos, 0xbb, 32);
  pos += 32;

  raw[pos++] = 1;
  raw[pos++] = 2;
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 52;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0x00;
  raw[pos++] = 0xca;
  raw[pos++] = 0x9a;
  raw[pos++] = 0x3b;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0x00;
  raw[pos++] = 0x02;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  memset(raw + pos, 0x33, 32);
  pos += 32;

  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_VERIFIED);
  ASSERT_EQ(tx.instructions[0].type, SOL_INSTR_SYSTEM_CREATE_ACCOUNT);
  EXPECT_EQ(tx.instructions[0].lamports, 1000000000ULL);
  EXPECT_EQ(tx.instructions[0].extra_value, 512ULL);
  EXPECT_EQ(0, memcmp(tx.instructions[0].to, raw + 4 + 32, 32));
  uint8_t owner[32];
  memset(owner, 0x33, sizeof(owner));
  EXPECT_EQ(0, memcmp(tx.instructions[0].extra, owner, sizeof(owner)));

  uint8_t prefixed[257];
  prefixed[0] = 0;
  memcpy(prefixed + 1, raw, pos);
  EXPECT_EQ(solana_inspectTx(prefixed, pos + 1, &tx), SOL_TX_REVIEW_VERIFIED);

  HDNode node = {};
  node.private_key[0] = 1;
  ed25519_publickey(node.private_key, node.public_key + 1);
  SolanaSignTx msg = {};
  msg.has_raw_tx = true;
  msg.raw_tx.size = pos + 1;
  memcpy(msg.raw_tx.bytes, prefixed, msg.raw_tx.size);
  SolanaSignedTx resp = {};
  ASSERT_TRUE(solana_signTx(&node, &msg, &resp));
  EXPECT_EQ(0, ed25519_sign_open(raw, pos, node.public_key + 1,
                                 resp.signature.bytes));
  EXPECT_NE(0, ed25519_sign_open(prefixed, pos + 1, node.public_key + 1,
                                 resp.signature.bytes));
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

/* Never render a nonzero amount as zero. The assembly's formatter also trims
 * trailing zeros, so exact-decimal cases read "1 tokens", not "1.000000000". */
TEST(Solana, FormatTokenAmountNeverShowsZeroForNonzero) {
  char buf[64];

  solana_formatTokenAmount(buf, sizeof(buf), 1, "tokens", 0);
  EXPECT_STREQ(buf, "1 tokens");

  /* amount=1 decimals=18 used to render "0 tokens" while the signed
     instruction moved one base unit. */
  solana_formatTokenAmount(buf, sizeof(buf), 1, "tokens", 18);
  EXPECT_STREQ(buf, "1 base units (18 decimals) tokens");

  /* One digit past the display limit, and that digit is nonzero. */
  solana_formatTokenAmount(buf, sizeof(buf), 1, "tokens", 10);
  EXPECT_STREQ(buf, "1 base units (10 decimals) tokens");

  /* Dropped digit is zero: the decimal form is exact and still used. */
  solana_formatTokenAmount(buf, sizeof(buf), 10, "tokens", 10);
  EXPECT_STREQ(buf, "0.000000001 tokens");

  /* Nine decimals: nothing is dropped. */
  solana_formatTokenAmount(buf, sizeof(buf), 1, "tokens", 9);
  EXPECT_STREQ(buf, "0.000000001 tokens");

  solana_formatTokenAmount(buf, sizeof(buf), 1000000000000000000ULL, "tokens",
                           18);
  EXPECT_STREQ(buf, "1 tokens");

  /* Zero is zero at any scale in range. */
  solana_formatTokenAmount(buf, sizeof(buf), 0, "tokens", 18);
  EXPECT_STREQ(buf, "0 tokens");

  /* decimals is an unrestricted uint8_t: beyond 18 keep the signed scale. */
  solana_formatTokenAmount(buf, sizeof(buf), 1, "tokens", 19);
  EXPECT_STREQ(buf, "1 base units (19 decimals) tokens");

  solana_formatTokenAmount(buf, sizeof(buf), UINT64_MAX, "tokens", 255);
  EXPECT_STREQ(buf, "18446744073709551615 base units (255 decimals) tokens");
}

/* A recognised instruction whose data is LONGER than its on-chain layout must
 * not decode: the tail would be signed but never displayed, and has_unknown
 * would stay unset so the tx would classify VERIFIED. */
TEST(Solana, OverlongFixedLayoutInstructionIsOpaque) {
  SolanaParsedTx tx;
  uint8_t raw[512];
  size_t len;

  static const uint8_t kExact[10] = {12, 0x40, 0x42, 0x0F, 0, 0, 0, 0, 0, 6};
  len = build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 4, kExact,
                              sizeof(kExact));
  ASSERT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_VERIFIED);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_TRANSFER_CHECKED);

  static const uint8_t kOverlong[11] = {12, 0x40, 0x42, 0x0F, 0,   0,
                                        0,  0,    0,    6,    0xAB};
  len = build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 4, kOverlong,
                              sizeof(kOverlong));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);

  /* Unchecked Transfer is exactly 9 bytes; 10 is UNKNOWN. */
  static const uint8_t kTransfer10[10] = {3, 0x40, 0x42, 0x0F, 0,
                                          0, 0,    0,    0,    0x99};
  len = build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 4, kTransfer10,
                              sizeof(kTransfer10));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);

  /* Revoke is a tag and nothing else. */
  static const uint8_t kRevoke[1] = {5};
  len = build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 2, kRevoke,
                              sizeof(kRevoke));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_VERIFIED);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_REVOKE);

  static const uint8_t kRevokePadded[2] = {5, 0x00};
  len = build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 2, kRevokePadded,
                              sizeof(kRevokePadded));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);

  /* SetAuthority: COption discriminant and length must agree. Well-formed
     shapes decode (and are forced opaque); mismatches are UNKNOWN. */
  static const uint8_t kSetAuthNone[3] = {6, 2, 0};
  len = build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 2, kSetAuthNone,
                              sizeof(kSetAuthNone));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_SET_AUTHORITY);

  uint8_t set_auth_some[35] = {6, 2, 1};
  memset(set_auth_some + 3, 0x77, 32);
  len = build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 2, set_auth_some,
                              sizeof(set_auth_some));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_SET_AUTHORITY);

  static const uint8_t kSetAuthSomeNoKey[3] = {6, 2, 1};
  len = build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 2, kSetAuthSomeNoKey,
                              sizeof(kSetAuthSomeNoKey));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);

  uint8_t set_auth_none_with_key[35] = {6, 2, 0};
  memset(set_auth_none_with_key + 3, 0x77, 32);
  len = build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 2, set_auth_none_with_key,
                              sizeof(set_auth_none_with_key));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);

  /* System Transfer is exactly 12 bytes. */
  uint8_t sys_ok[12] = {SOL_SYS_TRANSFER, 0, 0, 0, 1};
  len = build_single_instr_tx(raw, SOL_SYSTEM_PROGRAM, 2, sys_ok,
                              sizeof(sys_ok));
  ASSERT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_VERIFIED);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_SYSTEM_TRANSFER);

  uint8_t sys_long[13] = {SOL_SYS_TRANSFER, 0, 0, 0, 1};
  len = build_single_instr_tx(raw, SOL_SYSTEM_PROGRAM, 2, sys_long,
                              sizeof(sys_long));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);

  /* Stake Authorize is exactly 40 bytes. */
  uint8_t stake_long[41] = {SOL_STAKE_AUTHORIZE_IX, 0, 0, 0};
  len = build_single_instr_tx(raw, SOL_STAKE_PROGRAM, 3, stake_long,
                              sizeof(stake_long));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);

  /* Compute-budget SetComputeUnitLimit is exactly 5 bytes. */
  static const uint8_t kCbLong[6] = {SOL_CB_SET_COMPUTE_UNIT_LIMIT, 1, 0, 0, 0,
                                     0xEE};
  len = build_single_instr_tx(raw, SOL_COMPUTE_BUDGET_PROGRAM, 1, kCbLong,
                              sizeof(kCbLong));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);
}

/* A recognised instruction with fewer accounts than its layout needs would
 * display a zeroed address: it must be UNKNOWN and force opaque. */
TEST(Solana, TokenMintAndBurnRemainOpaqueWithoutOpcodeBoundDisplay) {
  uint8_t raw[512];
  SolanaParsedTx tx;

  static const uint8_t kMintUnchecked[9] = {7, 1, 0, 0, 0, 0, 0, 0, 0};
  size_t len = build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 3, kMintUnchecked,
                                     sizeof(kMintUnchecked));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_MINT_TO);

  static const uint8_t kMintChecked[10] = {14, 1, 0, 0, 0, 0, 0, 0, 0, 6};
  len = build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 3, kMintChecked,
                              sizeof(kMintChecked));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_MINT_TO);
  EXPECT_EQ(tx.instructions[0].extra_u8, 6);

  static const uint8_t kBurnUnchecked[9] = {8, 1, 0, 0, 0, 0, 0, 0, 0};
  len = build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 3, kBurnUnchecked,
                              sizeof(kBurnUnchecked));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_BURN);

  static const uint8_t kBurnChecked[10] = {15, 1, 0, 0, 0, 0, 0, 0, 0, 6};
  len = build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 3, kBurnChecked,
                              sizeof(kBurnChecked));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_BURN);
  EXPECT_EQ(tx.instructions[0].extra_u8, 6);
}

TEST(Solana, RecognizedInstructionMissingAccountsIsOpaque) {
  SolanaParsedTx tx;
  uint8_t raw[512];
  size_t len;

  /* System Transfer with only the source account. */
  uint8_t sys[12] = {SOL_SYS_TRANSFER, 0, 0, 0, 1};
  len = build_single_instr_tx(raw, SOL_SYSTEM_PROGRAM, 1, sys, sizeof(sys));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);

  /* Stake Delegate needs 6 accounts. */
  static const uint8_t kDelegate[4] = {SOL_STAKE_DELEGATE_IX, 0, 0, 0};
  len = build_single_instr_tx(raw, SOL_STAKE_PROGRAM, 5, kDelegate,
                              sizeof(kDelegate));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);
  len = build_single_instr_tx(raw, SOL_STAKE_PROGRAM, 6, kDelegate,
                              sizeof(kDelegate));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_VERIFIED);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_STAKE_DELEGATE);

  /* Token Close needs 3 accounts, Revoke 2. */
  static const uint8_t kClose[1] = {SOL_TOKEN_CLOSE_ACCOUNT_IX};
  len = build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 2, kClose, sizeof(kClose));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);

  static const uint8_t kRevoke[1] = {SOL_TOKEN_REVOKE_IX};
  len = build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 1, kRevoke,
                              sizeof(kRevoke));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);
}

/* Authorize reads the current authority from account 2 (stake/vote, clock
 * sysvar, authority) -- not the clock sysvar at account 1 -- and an
 * authorize-type outside {0,1} is not decoded. */
TEST(Solana, AuthorizeUsesAuthorityNotClockSysvar) {
  SolanaParsedTx tx;
  uint8_t raw[512];
  uint8_t expected[32];
  memset(expected, 0x13, sizeof(expected)); /* account 2 in the helper */

  uint8_t d[40] = {SOL_STAKE_AUTHORIZE_IX, 0, 0, 0};
  memset(d + 4, 0x77, 32);
  size_t len = build_single_instr_tx(raw, SOL_STAKE_PROGRAM, 3, d, sizeof(d));
  ASSERT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_VERIFIED);
  EXPECT_EQ(0,
            memcmp(tx.instructions[0].authority, expected, sizeof(expected)));

  uint8_t v[40] = {SOL_VOTE_AUTHORIZE_IX, 0, 0, 0};
  memset(v + 4, 0x77, 32);
  len = build_single_instr_tx(raw, SOL_VOTE_PROGRAM, 3, v, sizeof(v));
  ASSERT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_VERIFIED);
  EXPECT_EQ(0,
            memcmp(tx.instructions[0].authority, expected, sizeof(expected)));

  /* Unknown authorize type. */
  d[36] = 2;
  len = build_single_instr_tx(raw, SOL_STAKE_PROGRAM, 3, d, sizeof(d));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);
  v[36] = 2;
  len = build_single_instr_tx(raw, SOL_VOTE_PROGRAM, 3, v, sizeof(v));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);
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
  for (size_t cut = 0; cut < len; cut++) {
    EXPECT_FALSE(solana_parseInstrSchema(blob, cut, &s)) << cut;
  }
}

TEST(Solana, SchemaV2ParsesTokenDurationAndEightArgs) {
  uint8_t blob[256] = {};
  size_t p = 0;
  memcpy(blob + p, "KKSOLSC1", 8);
  p += 8;
  blob[p++] = 2;
  memset(blob + p, 0x42, 32);
  p += 32;
  blob[p++] = 1;
  blob[p++] = 0xaa;
  blob[p++] = 1;
  blob[p++] = 'P';
  blob[p++] = 1;
  blob[p++] = 'I';
  blob[p++] = 8;
  for (uint8_t i = 0; i < 8; i++) {
    blob[p++] = i == 0   ? SOL_SCHEMA_ARG_TOKEN_AMOUNT
                : i == 1 ? SOL_SCHEMA_ARG_DURATION
                         : SOL_SCHEMA_ARG_U8;
    blob[p++] = 1;
    blob[p++] = (uint8_t)('A' + i);
    if (i == 0) blob[p++] = 1;
  }
  blob[p++] = 0;

  SolanaInstrSchema schema{};
  ASSERT_TRUE(solana_parseInstrSchema(blob, p, &schema));
  EXPECT_EQ(schema.num_args, 8);
  EXPECT_EQ(schema.args[0].type, SOL_SCHEMA_ARG_TOKEN_AMOUNT);
  EXPECT_EQ(schema.args[0].mint_account, 1);
  EXPECT_EQ(schema.args[1].type, SOL_SCHEMA_ARG_DURATION);

  for (size_t cut = 0; cut < p; cut++) {
    EXPECT_FALSE(solana_parseInstrSchema(blob, cut, &schema)) << cut;
  }

  blob[8] = 1;
  EXPECT_FALSE(solana_parseInstrSchema(blob, p, &schema));
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

/* A v0 message with an address-table section never takes the schema path,
 * even when no instruction names a loaded account. */
TEST(Solana, SchemaRejectsAnyLookupTable) {
  uint8_t program[32];
  memset(program, 0x42, sizeof(program));
  uint8_t d[48];
  build_relay_data(d, 1ULL);
  uint8_t blob[256];
  size_t len = build_relay_schema(blob, program, 2);
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob, len, &s));

  for (bool table : {false, true}) {
    SCOPED_TRACE(table);
    std::vector<uint8_t> raw = {0x80, 1, 0, 1, 3};
    raw.insert(raw.end(), 32, 0x11);
    raw.insert(raw.end(), 32, 0x22);
    raw.insert(raw.end(), program, program + 32);
    raw.insert(raw.end(), 32, 0xBB); /* recent blockhash */
    raw.insert(raw.end(), {1, 2, 2, 0, 1, sizeof(d)});
    raw.insert(raw.end(), d, d + sizeof(d));
    if (table) {
      raw.push_back(1);
      raw.insert(raw.end(), 32, 0x55);
      raw.insert(raw.end(), {1, 0, 0}); /* loads one account, unused */
    } else {
      raw.push_back(0);
    }
    SolanaParsedTx tx;
    ASSERT_NE(SOL_TX_REVIEW_MALFORMED,
              solana_inspectTx(raw.data(), raw.size(), &tx));
    uint8_t idx = 0xFF;
    EXPECT_EQ(!table, solana_schemaApplies(&s, &tx, &idx));
  }
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
  /* accounts: 0..3 transfer accounts, 4 = System, 5 = Token, 6 = ATA */
  const int transfer_accounts = 4;
  const int total_accounts = 7;
  size_t pos = 0;
  raw[pos++] = 1; /* num_required_sigs */
  raw[pos++] = 0;
  raw[pos++] = 3; /* System, Token and ATA programs are readonly unsigned */
  raw[pos++] = (uint8_t)total_accounts;
  for (int i = 0; i < transfer_accounts; i++) {
    memset(raw + pos, 0x11 + i, 32);
    pos += 32;
  }
  memcpy(raw + pos, SOL_SYSTEM_PROGRAM, 32);
  pos += 32;
  memcpy(raw + pos, SOL_TOKEN_PROGRAM, 32);
  pos += 32;
  memcpy(raw + pos, SOL_ATA_PROGRAM, 32);
  pos += 32;
  memset(raw + pos, 0xBB, 32); /* recent blockhash */
  pos += 32;

  raw[pos++] = 2; /* two instructions */

  /* 1) ATA create (idempotent or classic) — canonical six accounts */
  raw[pos++] = 6; /* ATA program index */
  raw[pos++] = 6;
  for (int i = 0; i < 6; i++) raw[pos++] = (uint8_t)i;
  if (include_ata_byte) {
    raw[pos++] = 1; /* data_len */
    raw[pos++] = ata_ix_byte;
  } else {
    raw[pos++] = 0; /* empty data = legacy Create */
  }

  /* 2) TransferChecked: [12, amount u64 LE, decimals] over 4 accounts */
  raw[pos++] = 5; /* token program index */
  raw[pos++] = (uint8_t)transfer_accounts;
  for (int i = 0; i < transfer_accounts; i++) raw[pos++] = (uint8_t)i;
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

/* Plain SolanaSignMessage payloads skip AdvancedMode only when they cannot be
 * transaction messages for the signing key. */
TEST(Solana, RawMessagePlainTextNeedsNoAdvancedMode) {
  uint8_t key[SOL_PUBKEY_SIZE];
  memset(key, 0xAB, sizeof(key));

  const std::string login =
      "SoltoshiDICE wallet\n"
      "Network: mainnet-beta:CuTLp7pDmNGkFgi4aoh8Ef1YSjc2BzECQRLzYqaoVWBR:"
      "4nCmpwne7hCoWTSpAd54uENmCgHJrHTyn4DMPCEMpump\n"
      "Session: ca5ed7a8-5df1-41bf-91ca-c3de4c1c56f6\n"
      "Nonce: 37c40667-576d-4054-9064-618614ab88c1";
  EXPECT_EQ(login.size(), 221u);
  EXPECT_TRUE(solana_rawMessageIsPlainText((const uint8_t*)login.data(),
                                           login.size(), key));

  const std::string siws =
      "soltoshidice.wtf wants you to sign in with your Solana account:\n"
      "Gu83nVMD8qh948D1vqe8UPoUHaFuSwcHrvNHetcM4Xux\n\n"
      "Sign in to Hash Holdem.\n\n"
      "URI: https://soltoshidice.wtf\nVersion: 1\n"
      "Nonce: 9d9972a1f2ed0aaa6a86be6734139e69\n"
      "Issued At: 2026-09-18T01:04:18.687Z";
  EXPECT_TRUE(solana_rawMessageIsPlainText((const uint8_t*)siws.data(),
                                           siws.size(), key));
}

TEST(Solana, RawMessageNotPlainTextKeepsAdvancedMode) {
  uint8_t key[SOL_PUBKEY_SIZE];
  memset(key, 0xAB, sizeof(key));

  const uint8_t tx_header[] = {0x01, 0x00, 0x01, 0x02, 0x00, 0x00};
  EXPECT_FALSE(solana_rawMessageIsPlainText(tx_header, sizeof(tx_header), key));
  EXPECT_FALSE(solana_rawMessageIsPlainText((const uint8_t*)"a\tb", 3, key));
  EXPECT_FALSE(solana_rawMessageIsPlainText((const uint8_t*)"a\rb", 3, key));
  EXPECT_FALSE(solana_rawMessageIsPlainText((const uint8_t*)"a\x7f", 2, key));
  EXPECT_FALSE(
      solana_rawMessageIsPlainText((const uint8_t*)"caf\xc3\xa9", 5, key));
  EXPECT_FALSE(solana_rawMessageIsPlainText(nullptr, 3, key));
  EXPECT_FALSE(solana_rawMessageIsPlainText((const uint8_t*)"a", 0, key));
}

TEST(Solana, RawMessageContainingSignerKeyKeepsAdvancedMode) {
  uint8_t key[SOL_PUBKEY_SIZE];
  memset(key, 'K', sizeof(key));
  const std::string k(32, 'K');

  for (const std::string& text :
       {k, k + " tail", "head " + k, "head " + k + " tail"}) {
    EXPECT_FALSE(solana_rawMessageIsPlainText((const uint8_t*)text.data(),
                                              text.size(), key))
        << text;
  }
  const std::string near(31, 'K');
  EXPECT_TRUE(solana_rawMessageIsPlainText((const uint8_t*)near.data(),
                                           near.size(), key));
}
