extern "C" {
#include "keepkey/firmware/clearsign_root.h"
#include "keepkey/firmware/solana.h"
#include "trezor/crypto/base58.h"
#include "trezor/crypto/curves.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"
#include "trezor/crypto/ed25519-donna/ed25519-donna.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/ed25519-donna/ed25519.h"
}

#include "clearsign_test_cert.h"
#include "gtest/gtest.h"
#include <algorithm>
#include <cstring>
#include <string>
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

/* #550 boundary regressions, requested by independent review before PR #557
 * merged (and only added afterward, in round 4's remediation, per #583).
 * tx->accounts[] has exactly SOL_MAX_ACCOUNTS(32) entries; num_accounts must
 * never be stored or used as a loop bound, whether it's a small overage
 * (33..255, which would read past accounts[31] as a uint16_t loop bound) or a
 * value that silently wraps to a small/zero uint8_t (256, 512, ...), which
 * would have reintroduced the original signer-check bypass this fix closed.
 * A key list that is not all there is MALFORMED. */
TEST(Solana, RejectsAccountCountsAboveTheLimitOrWrapping) {
  /* Header (1 signer, 0 readonly signed, 1 readonly unsigned), then the
   * compact-u16 account count: 33, 256 (0x80 0x02) and 512 (0x80 0x04). */
  const std::vector<std::vector<uint8_t>> counts = {
      {33}, {0x80, 0x02}, {0x80, 0x04}};
  for (const auto& count : counts) {
    std::vector<uint8_t> raw = {1, 0, 1};
    raw.insert(raw.end(), count.begin(), count.end());
    SolanaParsedTx tx;
    EXPECT_EQ(solana_inspectTx(raw.data(), raw.size(), &tx),
              SOL_TX_REVIEW_MALFORMED)
        << (int)count.back();
  }
}

/* F-715-1: a complete oversized key list blind-signs (OPAQUE) with only the
 * signers loaded, so the fsm still requires the derived key to be a signer.
 * Legacy and v0, including counts that would wrap a uint8_t. */
TEST(Solana, OversizedAccountListsAreOpaqueWithTheSignersLoaded) {
  const std::vector<std::vector<uint8_t>> counts = {
      {33}, {0x80, 0x02}, {0x80, 0x04}};
  const size_t num_keys[] = {33, 256, 512};
  for (bool v0 : {false, true}) {
    for (size_t c = 0; c < counts.size(); c++) {
      SCOPED_TRACE(testing::Message() << "v0=" << v0 << " keys=" << num_keys[c]);
      std::vector<uint8_t> raw;
      if (v0) raw.push_back(0x80);
      raw.insert(raw.end(), {2, 0, 1}); /* two signers */
      raw.insert(raw.end(), counts[c].begin(), counts[c].end());
      for (size_t k = 0; k < num_keys[c]; k++) {
        raw.insert(raw.end(), 32, k < 3 ? (uint8_t)(0x11 * (k + 1)) : 0x77);
      }
      raw.insert(raw.end(), 32, 0xBB); /* blockhash */

      SolanaParsedTx tx;
      ASSERT_EQ(solana_inspectTx(raw.data(), raw.size(), &tx),
                SOL_TX_REVIEW_OPAQUE);
      EXPECT_EQ(tx.num_accounts, 2);
      EXPECT_EQ(tx.num_static_accounts, 2);
      uint8_t key[32];
      memset(key, 0x11, sizeof(key));
      EXPECT_TRUE(solana_signerInTx(key, &tx));
      memset(key, 0x22, sizeof(key));
      EXPECT_TRUE(solana_signerInTx(key, &tx));
      memset(key, 0x33, sizeof(key)); /* third key: not a signer */
      EXPECT_FALSE(solana_signerInTx(key, &tx));

      raw.pop_back(); /* blockhash one byte short */
      EXPECT_EQ(solana_inspectTx(raw.data(), raw.size(), &tx),
                SOL_TX_REVIEW_MALFORMED);
    }
  }

  /* More signers than accounts[] holds cannot fit a Solana packet. */
  std::vector<uint8_t> raw = {SOL_MAX_ACCOUNTS + 1, 0, 0, 40};
  raw.insert(raw.end(), 41 * 32, 0x11);
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw.data(), raw.size(), &tx),
            SOL_TX_REVIEW_MALFORMED);
}

/* The 0xFF off-chain message envelope is never a transaction, with or
 * without the 0x00 signature-count prefix. A later version stays opaque with
 * no keys loaded: the fsm then needs the derived key inside the message. */
TEST(Solana, OffchainEnvelopeIsMalformedLaterVersionsOpaque) {
  const std::string envelope =
      std::string("\xff" "solana offchain", 16) + std::string("\0\0\x05\0hello", 9);
  std::vector<uint8_t> raw(envelope.begin(), envelope.end());
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw.data(), raw.size(), &tx),
            SOL_TX_REVIEW_MALFORMED);
  raw.insert(raw.begin(), 0x00);
  EXPECT_EQ(solana_inspectTx(raw.data(), raw.size(), &tx),
            SOL_TX_REVIEW_MALFORMED);

  for (uint8_t version : {0x81, 0xFE}) {
    std::vector<uint8_t> later = {version, 1, 0, 0};
    later.insert(later.end(), 64, 0x22);
    EXPECT_EQ(solana_inspectTx(later.data(), later.size(), &tx),
              SOL_TX_REVIEW_OPAQUE);
    EXPECT_EQ(tx.num_accounts, 0);
  }

  uint8_t key[32];
  memset(key, 0x22, sizeof(key));
  std::vector<uint8_t> msg(40, 0x00);
  EXPECT_FALSE(solana_messageCarriesKey(msg.data(), msg.size(), key));
  memset(msg.data() + 8, 0x22, 32); /* the last possible offset */
  EXPECT_TRUE(solana_messageCarriesKey(msg.data(), msg.size(), key));
  EXPECT_FALSE(solana_messageCarriesKey(msg.data(), 39, key));
}

/* Certified lookup material that cannot fit stays refused when the static
 * list alone is oversized (SRS R-1.4: honoured fully or refused). */
TEST(Solana, OversizedStaticListWithTrustedLutIsMalformed) {
  std::vector<uint8_t> raw = {0x80, 1, 0, 1, 33};
  raw.insert(raw.end(), 33 * 32, 0x11);
  raw.insert(raw.end(), 32, 0xBB); /* blockhash */
  raw.insert(raw.end(), {0, 1});   /* 0 instructions, 1 lookup table */
  raw.insert(raw.end(), 32, 0x55);
  raw.insert(raw.end(), {1, 0, 0}); /* one writable index */
  const uint8_t lut[1][SOL_PUBKEY_SIZE] = {{0x44}};
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTxWithTrustedLut(raw.data(), raw.size(), lut, 1, &tx),
            SOL_TX_REVIEW_MALFORMED);
  EXPECT_EQ(solana_inspectTx(raw.data(), raw.size(), &tx),
            SOL_TX_REVIEW_OPAQUE);
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
  EXPECT_FALSE(tx.has_address_lookups);
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
      /* F-715-1: an oversized list blind-signs, signers still checked. */
      {1, 0, 1, SOL_MAX_ACCOUNTS + 1, SOL_TX_REVIEW_OPAQUE},
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

/* SRS R-5.1: more lookup entries than a certified proof may bind still makes
 * an UNcertified message opaque, but its tail must be parsed first -- a
 * malformed message is refused, never handed to the blind-sign path. */
/* The certified LUT proof, built here from its documented preimage rather
 * than by the code under test: "KeepKeySolanaTxAccounts/1" || sha256(message)
 * || count(le32) || keys, signed by a delegate the (test) root certified for
 * Solana. It binds the message, the keys, their order and their count. */
TEST(Solana, CertifiedLookupProofBindsMessageKeysOrderAndScope) {
  static const uint8_t root_priv[32] = {
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
      0xcc, 0xdd, 0xee, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11};
  static const uint8_t delegate_priv[32] = {7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
                                            7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
                                            7, 7, 7, 7, 7, 7, 7, 7, 7, 7};
  uint8_t root_pub[33], delegate_pub[33];
  ecdsa_get_public_key33(&secp256k1, root_priv, root_pub);
  ecdsa_get_public_key33(&secp256k1, delegate_priv, delegate_pub);
  clearsign_root_set_test_root(root_pub);

  auto mint = [&](uint32_t scope) {
    return rootCert(root_priv, delegate_pub, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW,
                    scope, 1818806400u, "Test Delegate");
  };
  const std::vector<uint8_t> cert = mint(CLEARSIGN_SCOPE_SOLANA);

  const std::vector<uint8_t> message = {1, 0, 1, 2, 0xAA, 0xBB, 0xCC};
  uint8_t keys[2][32];
  memset(keys[0], 0x41, 32);
  memset(keys[1], 0x42, 32);
  std::vector<uint8_t> pre((const uint8_t*)"KeepKeySolanaTxAccounts/1",
                           (const uint8_t*)"KeepKeySolanaTxAccounts/1" + 25);
  uint8_t h[32];
  sha256_Raw(message.data(), message.size(), h);
  pre.insert(pre.end(), h, h + 32);
  pre.insert(pre.end(), {2, 0, 0, 0});
  pre.insert(pre.end(), keys[0], keys[0] + 32);
  pre.insert(pre.end(), keys[1], keys[1] + 32);
  uint8_t digest[32], sig[64];
  sha256_Raw(pre.data(), pre.size(), digest);
  ASSERT_EQ(
      0, ecdsa_sign_digest(&secp256k1, delegate_priv, digest, sig, NULL, NULL));

  auto ok = [&](const std::vector<uint8_t>& raw, const uint8_t (*k)[32],
                size_t n, const std::vector<uint8_t>& c, const uint8_t* sg) {
    return solana_lut_accounts_certified(raw.data(), raw.size(), k, n, c.data(),
                                         c.size(), sg, 64);
  };
  EXPECT_TRUE(ok(message, keys, 2, cert, sig));
  std::vector<uint8_t> unsigned_tx(1, 0); /* zero signature count prefix */
  unsigned_tx.insert(unsigned_tx.end(), message.begin(), message.end());
  EXPECT_TRUE(ok(unsigned_tx, keys, 2, cert, sig));

  std::vector<uint8_t> other = message;
  other.back() ^= 1;
  EXPECT_FALSE(ok(other, keys, 2, cert, sig)) << "another message";
  uint8_t swapped[2][32];
  memcpy(swapped[0], keys[1], 32);
  memcpy(swapped[1], keys[0], 32);
  EXPECT_FALSE(ok(message, swapped, 2, cert, sig)) << "reordered keys";
  EXPECT_FALSE(ok(message, keys, 1, cert, sig)) << "dropped key";
  EXPECT_FALSE(ok(message, keys, 2, mint(1), sig)) << "EVM-scoped certificate";
  uint8_t bad[64];
  memcpy(bad, sig, 64);
  bad[10] ^= 1;
  EXPECT_FALSE(ok(message, keys, 2, cert, bad)) << "altered signature";

  clearsign_root_set_test_root(NULL);
}

TEST(Solana, OversizedLookupSectionStillRefusesAMalformedTail) {
  uint8_t raw[256];
  size_t pos = 0;
  raw[pos++] = 0x80; /* v0 prefix */
  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 3; /* static accounts: payer, recipient, system program */
  memset(raw + pos, 0x11, 32);
  pos += 32;
  memset(raw + pos, 0x22, 32);
  pos += 32;
  memset(raw + pos, 0x00, 32);
  pos += 32;
  memset(raw + pos, 0xBB, 32); /* blockhash */
  pos += 32;
  raw[pos++] = 1; /* one system transfer, static accounts only */
  raw[pos++] = 2;
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 12;
  const uint8_t transfer[12] = {2, 0, 0, 0, 0x00, 0xCA, 0x9A, 0x3B};
  memcpy(raw + pos, transfer, sizeof(transfer));
  pos += sizeof(transfer);
  raw[pos++] = 1; /* one lookup table */
  memset(raw + pos, 0x55, 32);
  pos += 32;
  raw[pos++] = SOL_MAX_LUT_ACCOUNTS + 1; /* writable indexes */
  for (int i = 0; i <= SOL_MAX_LUT_ACCOUNTS; i++) raw[pos++] = (uint8_t)i;
  raw[pos++] = 0; /* readonly indexes */

  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
  raw[pos] = 0xEE; /* one trailing byte */
  EXPECT_EQ(solana_inspectTx(raw, pos + 1, &tx), SOL_TX_REVIEW_MALFORMED);
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

  uint8_t resolved[1][SOL_PUBKEY_SIZE];
  memset(resolved[0], 0x44, SOL_PUBKEY_SIZE);
  ASSERT_EQ(solana_inspectTxWithTrustedLut(raw, pos, resolved, 1, &tx),
            SOL_TX_REVIEW_VERIFIED);
  ASSERT_EQ(tx.num_accounts, 4);
  EXPECT_EQ(memcmp(tx.instructions[0].to, resolved[0], SOL_PUBKEY_SIZE), 0);

  /* The signed lookup section requests exactly one key. A certified host may
   * not append a second key and shift account meanings. */
  uint8_t surplus[2][SOL_PUBKEY_SIZE];
  memset(surplus, 0x45, sizeof(surplus));
  EXPECT_EQ(solana_inspectTxWithTrustedLut(raw, pos, surplus, 2, &tx),
            SOL_TX_REVIEW_MALFORMED);
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
  len =
      build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 4, kExact, sizeof(kExact));
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
  len =
      build_single_instr_tx(raw, SOL_SYSTEM_PROGRAM, 2, sys_ok, sizeof(sys_ok));
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
  static const uint8_t kCbLong[6] = {
      SOL_CB_SET_COMPUTE_UNIT_LIMIT, 1, 0, 0, 0, 0xEE};
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
  len =
      build_single_instr_tx(raw, SOL_TOKEN_PROGRAM, 2, kClose, sizeof(kClose));
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
static size_t build_relay_schema(
    uint8_t* out, const uint8_t* program, uint8_t n_args = 1,
    uint8_t account_index = 0,
    SolanaSchemaArgType amount_type = SOL_SCHEMA_ARG_U64) {
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
    out[p++] = amount_type;
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
  out[p++] = account_index;
  out[p++] = 5;
  memcpy(out + p, "Vault", 5);
  p += 5;
  return p;
}

static std::vector<uint8_t> solana_unhex(const std::string& hex) {
  std::vector<uint8_t> out;
  if ((hex.size() & 1U) != 0) return out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    const auto nibble = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
    };
    const int hi = nibble(hex[i]);
    const int lo = nibble(hex[i + 1]);
    if (hi < 0 || lo < 0) return {};
    out.push_back((uint8_t)((hi << 4) | lo));
  }
  return out;
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

/* Exact message bytes from the real Relay SOL->ETH quote captured
 * 2026-08-24 America/Chicago. The outer signature vector was removed because
 * SolanaSignTx receives the message itself. This is v0 but self-contained:
 * all five accounts are static and the trailing lookup-table count is zero.
 * It is the production shape that exposed the erroneous assumption that every
 * certified Relay schema also needs a LUT proof. */
TEST(Solana, RealRelayV0NoLookupFixtureAcceptsCompleteSchema) {
  const std::vector<uint8_t> raw = solana_unhex(
      "8001000305ec3979a4dc6b401bd045171a189f26856fab9eab75560214f972b2"
      "edc164300f66963b37e581dc14a0f573eeede8e54a257d83d082c54ab208cbff"
      "d1dc2a70ca792689378ecd51d80406eb0caa3b62795beb10b6c5dc96bc2e0df0"
      "3cbfee1abfbe3e6d285d2ee963351b6deeb0a1e96c881435ccd450b2645f24cc"
      "27960bee47000000000000000000000000000000000000000000000000000000"
      "0000000000d96db9f622f840ffda97430208ddbc7950d2c1ea45ecc9c2933151"
      "c02963f3860102050300000104300d9e0ddf5fd51c06f075633b000000000370"
      "4dea2a5eb9cf98e2f625a96080df1f0c5c24ccec3a6d8827b3ab25c0b11800");
  ASSERT_EQ(raw.size(), 255U);

  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw.data(), raw.size(), &tx),
            SOL_TX_REVIEW_OPAQUE);
  EXPECT_FALSE(tx.has_address_lookups);
  ASSERT_EQ(tx.num_accounts, 5);
  ASSERT_EQ(tx.num_instructions, 1);
  const SolanaParsedInstruction* instr = &tx.instructions[0];
  EXPECT_FALSE(instr->external);
  ASSERT_EQ(instr->num_acct_indices, 5);
  EXPECT_EQ(instr->acct_indices[3], 1); /* Vault is signed static account 1. */
  uint64_t amount = 0;
  for (int i = 0; i < 8; i++) {
    amount |= ((uint64_t)instr->data[8 + i]) << (8 * i);
  }
  EXPECT_EQ(amount, 996374000ULL);

  uint8_t schema_blob[256];
  const size_t schema_len = build_relay_schema(schema_blob, instr->program_id,
                                               2, 3, SOL_SCHEMA_ARG_LAMPORTS);
  SolanaInstrSchema schema;
  ASSERT_TRUE(solana_parseInstrSchema(schema_blob, schema_len, &schema));
  ASSERT_EQ(schema.args[0].type, SOL_SCHEMA_ARG_LAMPORTS);
  EXPECT_EQ(solana_schemaArgWidth(schema.args[0].type), 8);
  char amount_display[32];
  solana_formatAmount(amount_display, sizeof(amount_display), amount);
  EXPECT_STREQ(amount_display, "0.996374000 SOL");
  uint8_t schema_ix = 0xFF;
  ASSERT_TRUE(solana_schemaApplies(&schema, &tx, &schema_ix));
  EXPECT_EQ(schema_ix, 0);
  EXPECT_EQ(memcmp(tx.accounts[instr->acct_indices[3]], tx.accounts[1], 32), 0);
}

TEST(Solana, SchemaAppliesToCertifiedLookupResolvedProgramAndAccount) {
  uint8_t program[32];
  memset(program, 0x42, sizeof(program));
  uint8_t data[48];
  build_relay_data(data, 1034498840ULL);

  uint8_t raw[512];
  size_t pos = 0;
  raw[pos++] = 0x80; /* v0 */
  raw[pos++] = 1;    /* required signatures */
  raw[pos++] = 0;
  raw[pos++] = 1; /* one readonly unsigned: the program */
  raw[pos++] = 2; /* static accounts: signer, program */
  memset(raw + pos, 0x11, 32);
  pos += 32;
  memcpy(raw + pos, program, 32);
  pos += 32;
  memset(raw + pos, 0xBB, 32); /* blockhash */
  pos += 32;
  raw[pos++] = 1; /* one instruction */
  raw[pos++] = 1; /* program is static account 1 (never a lookup key) */
  raw[pos++] = 1; /* one instruction account */
  raw[pos++] = 2; /* resolved account 0 */
  raw[pos++] = sizeof(data);
  memcpy(raw + pos, data, sizeof(data));
  pos += sizeof(data);
  raw[pos++] = 1; /* one lookup table */
  memset(raw + pos, 0x55, 32);
  pos += 32;
  raw[pos++] = 1; /* one writable lookup index */
  raw[pos++] = 0;
  raw[pos++] = 0; /* no readonly indices */

  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_TRUE(tx.has_address_lookups);

  uint8_t resolved[1][SOL_PUBKEY_SIZE];
  memset(resolved[0], 0x77, 32);
  ASSERT_EQ(
      solana_inspectTxWithTrustedLut(raw, pos, resolved, 1, &tx),
      SOL_TX_REVIEW_OPAQUE); /* unknown Relay instruction, now resolvable */
  EXPECT_TRUE(tx.has_address_lookups);
  ASSERT_FALSE(tx.instructions[0].external);
  EXPECT_EQ(memcmp(tx.instructions[0].program_id, program, 32), 0);

  uint8_t blob[256];
  const size_t len = build_relay_schema(blob, program, 2);
  SolanaInstrSchema schema;
  ASSERT_TRUE(solana_parseInstrSchema(blob, len, &schema));
  uint8_t ix = 0xFF;
  ASSERT_TRUE(solana_schemaApplies(&schema, &tx, &ix));
  EXPECT_EQ(ix, 0);
  EXPECT_EQ(
      memcmp(tx.accounts[tx.instructions[ix].acct_indices[0]], resolved[0], 32),
      0);
}

/* A certified lookup list never supplies the program id. */
TEST(Solana, CertifiedLookupNeverSuppliesTheProgramId) {
  uint8_t raw[256];
  size_t pos = 0;
  raw[pos++] = 0x80;
  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 1; /* one static account: signer */
  memset(raw + pos, 0x11, 32);
  pos += 32;
  memset(raw + pos, 0xBB, 32);
  pos += 32;
  raw[pos++] = 1;
  raw[pos++] = 1; /* program = resolved account 0 */
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 1;
  memset(raw + pos, 0x55, 32);
  pos += 32;
  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 0;
  uint8_t resolved[1][SOL_PUBKEY_SIZE];
  memset(resolved[0], 0x42, 32);
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_MALFORMED);
  EXPECT_EQ(solana_inspectTxWithTrustedLut(raw, pos, resolved, 1, &tx),
            SOL_TX_REVIEW_MALFORMED);
}

TEST(Solana, SchemaNeverOverridesNativeDecoder) {
  uint8_t transfer_data[12] = {2, 0, 0, 0};
  transfer_data[4] = 0xD2;
  transfer_data[5] = 0x04;
  uint8_t raw[256];
  const size_t len = build_single_instr_tx(
      raw, SOL_SYSTEM_PROGRAM, 2, transfer_data, sizeof(transfer_data));
  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_VERIFIED);

  uint8_t fake_schema_bytes[256];
  size_t schema_len = 0;
  memcpy(fake_schema_bytes + schema_len, "KKSOLSC1", 8);
  schema_len += 8;
  fake_schema_bytes[schema_len++] = 1;
  memcpy(fake_schema_bytes + schema_len, SOL_SYSTEM_PROGRAM, 32);
  schema_len += 32;
  fake_schema_bytes[schema_len++] = 4;
  memcpy(fake_schema_bytes + schema_len, transfer_data, 4);
  schema_len += 4;
  fake_schema_bytes[schema_len++] = 6;
  memcpy(fake_schema_bytes + schema_len, "System", 6);
  schema_len += 6;
  fake_schema_bytes[schema_len++] = 8;
  memcpy(fake_schema_bytes + schema_len, "Transfer", 8);
  schema_len += 8;
  fake_schema_bytes[schema_len++] = 1;
  fake_schema_bytes[schema_len++] = SOL_SCHEMA_ARG_U64;
  fake_schema_bytes[schema_len++] = 6;
  memcpy(fake_schema_bytes + schema_len, "Amount", 6);
  schema_len += 6;
  fake_schema_bytes[schema_len++] = 1;
  fake_schema_bytes[schema_len++] = 1;
  fake_schema_bytes[schema_len++] = 9;
  memcpy(fake_schema_bytes + schema_len, "Recipient", 9);
  schema_len += 9;
  SolanaInstrSchema schema;
  ASSERT_TRUE(solana_parseInstrSchema(fake_schema_bytes, schema_len, &schema));
  uint8_t ix = 0;
  EXPECT_FALSE(solana_schemaApplies(&schema, &tx, &ix));
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

/* Build a two-instruction legacy message: ix0 is the schema-described call on
 * `program` (unknown to the parser, so the message is OPAQUE and the schema
 * review path runs), ix1 is a companion instruction on `companion_program`. */
static size_t build_schema_plus_companion_tx(
    uint8_t* raw, const uint8_t* program, const uint8_t* instr_data,
    uint8_t data_len, const uint8_t* companion_program, uint8_t companion_accts,
    const uint8_t* companion_data, uint8_t companion_len) {
  size_t pos = 0;
  raw[pos++] = 1; /* num_required_sigs */
  raw[pos++] = 0; /* num_readonly_signed */
  raw[pos++] = 2; /* num_readonly_unsigned: both programs */
  raw[pos++] = 4; /* sender, vault, schema program, companion program */
  memset(raw + pos, 0x11, 32);
  pos += 32;
  memset(raw + pos, 0x22, 32);
  pos += 32;
  memcpy(raw + pos, program, 32);
  pos += 32;
  memcpy(raw + pos, companion_program, 32);
  pos += 32;
  memset(raw + pos, 0xBB, 32); /* recent blockhash */
  pos += 32;

  raw[pos++] = 2; /* two instructions */

  raw[pos++] = 2; /* ix0 program index */
  raw[pos++] = 2; /* two account indices */
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = data_len;
  memcpy(raw + pos, instr_data, data_len);
  pos += data_len;

  raw[pos++] = 3; /* ix1 program index */
  raw[pos++] = companion_accts;
  for (uint8_t i = 0; i < companion_accts; i++) raw[pos++] = i;
  raw[pos++] = companion_len;
  memcpy(raw + pos, companion_data, companion_len);
  pos += companion_len;
  return pos;
}

/* SystemProgram Transfer: u32 LE type 2 + u64 LE lamports (1 SOL). */
static const uint8_t kSystemTransfer12[12] = {2,    0,    0,    0, 0x00, 0xCA,
                                              0x9A, 0x3B, 0x00, 0, 0,    0};

/* A schema describes ONE instruction, and the schema review path draws no
 * screen for any other -- it goes from the schema screens straight to the
 * blind-sign warning. So a recognised-but-undescribed instruction must not be
 * allowed to ride along: this SystemProgram Transfer would otherwise be signed
 * without a single screen naming its amount or destination, which is exactly
 * the property solana.h says a schema can never green-light. */
TEST(Solana, SchemaRejectsUndescribedValueInstruction) {
  uint8_t program[32];
  memset(program, 0x42, sizeof(program));
  uint8_t d[48];
  build_relay_data(d, 526490980ULL);

  const uint8_t system_program[32] = {0};
  uint8_t raw[512];
  size_t pos = build_schema_plus_companion_tx(
      raw, program, d, sizeof(d), system_program, 2, kSystemTransfer12,
      sizeof(kSystemTransfer12));
  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
  ASSERT_EQ(tx.num_instructions, 2);
  /* The parser DOES recognise it -- that is the point: recognition alone used
   * to be the whole gate. */
  ASSERT_EQ(tx.instructions[1].type, SOL_INSTR_SYSTEM_TRANSFER);

  uint8_t blob[256];
  size_t len = build_relay_schema(blob, program, 2);
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob, len, &s));
  uint8_t idx = 0xFF;
  EXPECT_FALSE(solana_schemaApplies(&s, &tx, &idx));
}

/* Control: an inert companion (SetComputeUnitPrice moves no value and grants
 * no authority) still applies, so the rejection above is about the unscreened
 * transfer and not about the message simply having two instructions. */
TEST(Solana, SchemaAppliesBesideInertComputeBudget) {
  uint8_t program[32];
  memset(program, 0x42, sizeof(program));
  uint8_t d[48];
  build_relay_data(d, 526490980ULL);

  const uint8_t unit_price[9] = {3, 0x40, 0x42, 0x0F, 0, 0, 0, 0, 0};
  uint8_t raw[512];
  size_t pos = build_schema_plus_companion_tx(raw, program, d, sizeof(d),
                                              SOL_COMPUTE_BUDGET_PROGRAM, 0,
                                              unit_price, sizeof(unit_price));
  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
  ASSERT_EQ(tx.instructions[1].type, SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE);

  uint8_t blob[256];
  size_t len = build_relay_schema(blob, program, 2);
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob, len, &s));
  uint8_t idx = 0xFF;
  ASSERT_TRUE(solana_schemaApplies(&s, &tx, &idx));
  EXPECT_EQ(idx, 0);
}

/* Raw SolanaSignMessage skips AdvancedMode only for printable text that never
   contains the signer's key. The two real messages are dApp logins captured on
   2026-09-17 (soltoshidice.wtf); a transaction signature only verifies when
   the signer's key is in the message, so their absence of the key is the whole
   safety argument. */
TEST(Solana, RawMessagePlainTextNeedsNoAdvancedMode) {
  uint8_t key[SOL_PUBKEY_SIZE];
  memset(key, 0xAB, sizeof(key));  // not printable, like any real key

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
  // 31 matching bytes are not the key.
  const std::string near(31, 'K');
  EXPECT_TRUE(solana_rawMessageIsPlainText((const uint8_t*)near.data(),
                                           near.size(), key));
}

/* ── KKSOLSC1 version 2: token amounts, durations, up to eight args ────
 *
 * Real transaction: SoltoshiDICE "Blackjack join" (program
 * CuTLp7pDmNGkFgi4aoh8Ef1YSjc2BzECQRLzYqaoVWBR, native Rust, no IDL), as Vault
 * received it from soltoshidice.wtf on 2026-09-18. The unsigned signature
 * section was removed because SolanaSignTx receives the message itself.
 * Instructions: [ComputeBudget SetComputeUnitLimit, System Transfer of
 * 2,000,000 lamports to the session key, the 82-byte join].
 */
static const char* kSoltoshiJoinMessageHex =
    "0100060dec3979a4dc6b401bd045171a189f26856fab9eab75560214f972b2ed"
    "c164300f209892e406a5c1bf530d7721f4634090040c3fbe35df3834a2e80d97"
    "bee0620e635230d0ec6d2689ed9f0bf1da57e147ac13babc4430c5af1ade2e40"
    "c9cf3ee577e4b4511f351e94a764bde876019ec3523510049d3b50b3a8c70fd3"
    "8b6007f9847d3c28e2cbbff9e7c4f7cb6d6d71e5bc16d50aa6ed4ffe3aeae6a0"
    "d6c6eaa4a11b0a513ec5310074c9de56117aad169ab339ec9a544b3c4cf33a74"
    "d0cc37c6fc4da258d76a62aa6a0c641d34cefc33c97f0b9424c1678e26ee25b4"
    "c49b7bda00000000000000000000000000000000000000000000000000000000"
    "0000000038278241da03c70dd0fc885f7ad2123bad32b33a5402340739af8ae5"
    "d84cacef8b673cda2e293e0220ab3e01d2b58ed055c9c1b2762dd515612b10ca"
    "cd6e34360306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a"
    "40000000b0e08af4a4fcfad13ef8fcfd9dc70975eb6fc2e04a7c76611540a51c"
    "d5db9ed006ddf6e1ee758fde18425dbce46ccddab61afc4d83b90d27febdf928"
    "d8a18bfcf9adfb23cba734d5c630dc94ffe9bc6964e347bd3af8c3afb795b849"
    "cab5d927030a000502400d0300070200050c0200000080841e00000000000b09"
    "0002040803010c060952515600000000000000d4030000000000000100ca9a3b"
    "00000000a11b0a513ec5310074c9de56117aad169ab339ec9a544b3c4cf33a74"
    "d0cc37c6100e00000000000000ca9a3b0000000000ca9a3b00000000";

/* The catalog schema, serialized from the shared wire spec by a separate
 * (Python) implementation, not by anything in this repository:
 *   SoltoshiDICE / Blackjack join, disc [0x51], args Round U64, Revision U64,
 *   Seat U8, Buy-in TOKEN_AMOUNT(mint 3), Session key PUBKEY, Expires in
 *   DURATION, Allowance TOKEN_AMOUNT(mint 3), Max wager TOKEN_AMOUNT(mint 3);
 *   no accounts. */
static const char* kSoltoshiJoinSchemaHex =
    "4b4b534f4c53433102b0e08af4a4fcfad13ef8fcfd9dc70975eb6fc2e04a7c7661"
    "1540a51cd5db9ed001510c536f6c746f736869444943450e426c61636b6a61636b"
    "206a6f696e080105526f756e6401085265766973696f6e02045365617406064275"
    "792d696e03030b53657373696f6e206b6579070a4578706972657320696e060941"
    "6c6c6f77616e63650306094d61782077616765720300";

/* 4nCmpwne7hCoWTSpAd54uENmCgHJrHTyn4DMPCEMpump: SDICE, Token-2022, 6 dp. */
static const uint8_t kSdiceMint[32] = {
    0x38, 0x27, 0x82, 0x41, 0xda, 0x03, 0xc7, 0x0d, 0xd0, 0xfc, 0x88,
    0x5f, 0x7a, 0xd2, 0x12, 0x3b, 0xad, 0x32, 0xb3, 0x3a, 0x54, 0x02,
    0x34, 0x07, 0x39, 0xaf, 0x8a, 0xe5, 0xd8, 0x4c, 0xac, 0xef};

/* The production ClearSign Worker's certify response for this join
 * (keepkey-clearsign.bithighlander.workers.dev, source ee1488807, version
 * dc2adba8). None of it is secret, and none of it is bound to one
 * transaction: the schema signature covers only kSoltoshiJoinSchemaHex (the
 * Worker returned those exact 154 bytes), and the token signature covers only
 * the SDICE definition.
 *
 * kCert501Hex: the public scope-501 delegate certificate, the same bytes as
 * python-keepkey's CERT_501. Alias "KeepKey Vault", MAY_SUPPRESS_RAW,
 * not_after 1818806400. It verifies only against the alpha root.
 *
 * kSoltoshiJoinSchemaSigHex: the delegate's signature over
 * sha256(kSoltoshiJoinSchemaHex), signer_key_id 0x80.
 *
 * kSdiceTokenDefSigHex: the delegate's signature over sha256 of
 *   "KeepKeySolanaTokenDef/2" || kSdiceMint || Token-2022 program
 *     || le32(6) || "SDICE"
 * signer_key_id 0x80. */
static const char* kCert501Hex =
    "0101000001f56c68c8804b6565704b6579205661756c74000000000000000000"
    "000000000000000000000342f5f9704494b3f9bd72295eecaf29d783d23ea02b"
    "2dc9f48abcd2e46d4850cfa2753fac6068a45747a32a4a39f249af72b55370f3"
    "491913b7fb9a80207d619b3b4fca6750fc1fdc790da5562b42a351e12cde3c0f"
    "084056a24ca8d1bf2c36b5";
static const char* kSoltoshiJoinSchemaSigHex =
    "7302c703ce5fee498427bf87801384c21660f4d3451aef18549f2a31d8cd2561"
    "1d99c94afcaeafcbd6a8d04c3c1b49232a77a2b949451ba84ff217c590c14700";
static const char* kSdiceTokenDefSigHex =
    "36ed412ef38eb9ade9a7ac3e5b60841f9d032ea870c7886b87155c202f2ecfa1"
    "1fc87848280fea855881f9e34127fbd2dfb91c4ed556dbd54cd1fb18e279d41a";

struct SchemaArgSpec {
  uint8_t type;
  const char* label;
  uint8_t mint_account; /* serialized for TOKEN_AMOUNT only */
};

static std::vector<SchemaArgSpec> soltoshi_join_args(uint8_t mint = 3) {
  return {{SOL_SCHEMA_ARG_U64, "Round", 0},
          {SOL_SCHEMA_ARG_U64, "Revision", 0},
          {SOL_SCHEMA_ARG_U8, "Seat", 0},
          {SOL_SCHEMA_ARG_TOKEN_AMOUNT, "Buy-in", mint},
          {SOL_SCHEMA_ARG_PUBKEY, "Session key", 0},
          {SOL_SCHEMA_ARG_DURATION, "Expires in", 0},
          {SOL_SCHEMA_ARG_TOKEN_AMOUNT, "Allowance", mint},
          {SOL_SCHEMA_ARG_TOKEN_AMOUNT, "Max wager", mint}};
}

static std::vector<uint8_t> build_schema(
    uint8_t version, const uint8_t program[32],
    const std::vector<SchemaArgSpec>& args) {
  std::vector<uint8_t> p = {'K', 'K', 'S', 'O', 'L', 'S', 'C', '1', version};
  p.insert(p.end(), program, program + 32);
  p.push_back(1);    /* disc_len */
  p.push_back(0x51); /* join tag */
  const auto text = [&p](const char* s) {
    p.push_back((uint8_t)strlen(s));
    p.insert(p.end(), s, s + strlen(s));
  };
  text("SoltoshiDICE");
  text("Blackjack join");
  p.push_back((uint8_t)args.size());
  for (const SchemaArgSpec& a : args) {
    p.push_back(a.type);
    text(a.label);
    if (a.type == SOL_SCHEMA_ARG_TOKEN_AMOUNT) p.push_back(a.mint_account);
  }
  p.push_back(0); /* no displayed accounts */
  return p;
}

static void put_le64(std::vector<uint8_t>& v, uint64_t x) {
  for (int i = 0; i < 8; i++) v.push_back((uint8_t)(x >> (8 * i)));
}

static uint64_t get_le64(const uint8_t* p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v |= ((uint64_t)p[i]) << (8 * i);
  return v;
}

TEST(Solana, SchemaV2ParsesSoltoshiDiceBlackjackJoin) {
  const std::vector<uint8_t> blob = solana_unhex(kSoltoshiJoinSchemaHex);
  ASSERT_EQ(blob.size(), 154U);
  ASSERT_LE(blob.size(), sizeof(((SolanaSignTx*)0)->schema_payload.bytes));

  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob.data(), blob.size(), &s));
  EXPECT_STREQ(s.program_name, "SoltoshiDICE");
  EXPECT_STREQ(s.instruction_name, "Blackjack join");
  ASSERT_EQ(s.disc_len, 1);
  EXPECT_EQ(s.disc[0], 0x51);
  EXPECT_EQ(s.num_accounts, 0);
  const std::vector<SchemaArgSpec> want = soltoshi_join_args();
  ASSERT_EQ(s.num_args, want.size());
  uint32_t covered = s.disc_len;
  for (size_t i = 0; i < want.size(); i++) {
    EXPECT_EQ(s.args[i].type, want[i].type) << i;
    EXPECT_STREQ(s.args[i].label, want[i].label) << i;
    if (want[i].type == SOL_SCHEMA_ARG_TOKEN_AMOUNT) {
      EXPECT_EQ(s.args[i].mint_account, 3) << i;
    }
    covered += solana_schemaArgWidth(s.args[i].type);
  }
  EXPECT_EQ(covered, 82U); /* the join's exact data length */

  /* The test builder is a second, independent serialization of the same spec
   * entry; both must agree byte for byte. */
  EXPECT_EQ(build_schema(2, s.program_id, want), blob);
}

/* The 82 bytes built from the documented field values are exactly the join
 * instruction in the real message, and only the certified review admits the
 * System Transfer that rides beside it. */
TEST(Solana, SchemaV2RealSoltoshiDiceJoinAppliesOnlyWhenCertified) {
  const std::vector<uint8_t> raw = solana_unhex(kSoltoshiJoinMessageHex);
  ASSERT_EQ(raw.size(), 572U);
  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw.data(), raw.size(), &tx),
            SOL_TX_REVIEW_OPAQUE);
  ASSERT_EQ(tx.num_instructions, 3);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT);
  ASSERT_EQ(tx.instructions[1].type, SOL_INSTR_SYSTEM_TRANSFER);
  EXPECT_EQ(tx.instructions[1].lamports, 2000000ULL);
  const SolanaParsedInstruction* join = &tx.instructions[2];
  ASSERT_EQ(join->type, SOL_INSTR_UNKNOWN);
  ASSERT_EQ(join->num_acct_indices, 9);
  EXPECT_EQ(memcmp(tx.accounts[join->acct_indices[3]], kSdiceMint, 32), 0);
  /* The transfer funds the session key the join names. */
  EXPECT_EQ(memcmp(tx.instructions[1].to, join->data + 26, 32), 0);

  std::vector<uint8_t> want = {0x51};
  put_le64(want, 86);            /* round */
  put_le64(want, 980);           /* revision */
  want.push_back(1);             /* seat */
  put_le64(want, 1000000000ULL); /* buy-in: 1,000 SDICE */
  want.insert(want.end(), tx.instructions[1].to, tx.instructions[1].to + 32);
  put_le64(want, 3600);          /* seconds */
  put_le64(want, 1000000000ULL); /* allowance */
  put_le64(want, 1000000000ULL); /* max wager */
  ASSERT_EQ(want.size(), 82U);
  ASSERT_EQ(join->data_len, 82);
  EXPECT_EQ(std::vector<uint8_t>(join->data, join->data + join->data_len),
            want);

  const std::vector<uint8_t> blob = solana_unhex(kSoltoshiJoinSchemaHex);
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob.data(), blob.size(), &s));
  ASSERT_EQ(memcmp(s.program_id, join->program_id, 32), 0);

  uint8_t idx = 0xFF;
  ASSERT_TRUE(solana_schemaAppliesCertified(&s, &tx, tx.accounts[0], &idx));
  EXPECT_EQ(idx, 2);
  /* Runtime (AdvancedMode) schemas keep the inert-only companion rule. */
  idx = 0xFF;
  EXPECT_FALSE(solana_schemaApplies(&s, &tx, &idx));
  EXPECT_EQ(idx, 0xFF);
}

/* Control for the certified exception: it is the System Transfer, not any
 * recognisable-looking companion. The same message with the System program
 * key replaced by an unknown program is refused on both paths. */
TEST(Solana, SchemaV2UnknownCompanionRejectedEvenWhenCertified) {
  std::vector<uint8_t> raw = solana_unhex(kSoltoshiJoinMessageHex);
  const size_t system_key = 4 + 7 * 32; /* header(3) + count(1) + 7 keys */
  for (size_t i = 0; i < 32; i++) ASSERT_EQ(raw[system_key + i], 0);
  memset(raw.data() + system_key, 0x77, 32);

  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw.data(), raw.size(), &tx),
            SOL_TX_REVIEW_OPAQUE);
  ASSERT_EQ(tx.instructions[1].type, SOL_INSTR_UNKNOWN);

  const std::vector<uint8_t> blob = solana_unhex(kSoltoshiJoinSchemaHex);
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob.data(), blob.size(), &s));
  uint8_t idx = 0xFF;
  EXPECT_FALSE(solana_schemaAppliesCertified(&s, &tx, tx.accounts[0], &idx));
  EXPECT_FALSE(solana_schemaApplies(&s, &tx, &idx));
}

/* mint_account indexes the instruction's own account list; the join has nine
 * (0..8), so 8 applies and 9 does not. */
TEST(Solana, SchemaV2TokenMintOutOfRangeDoesNotApply) {
  const std::vector<uint8_t> raw = solana_unhex(kSoltoshiJoinMessageHex);
  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw.data(), raw.size(), &tx),
            SOL_TX_REVIEW_OPAQUE);
  const uint8_t* program = tx.instructions[2].program_id;

  for (uint8_t mint : {(uint8_t)8, (uint8_t)9, (uint8_t)255}) {
    const std::vector<uint8_t> blob =
        build_schema(2, program, soltoshi_join_args(mint));
    SolanaInstrSchema s;
    ASSERT_TRUE(solana_parseInstrSchema(blob.data(), blob.size(), &s));
    uint8_t idx = 0xFF;
    EXPECT_EQ(solana_schemaAppliesCertified(&s, &tx, tx.accounts[0], &idx),
              mint == 8)
        << (unsigned)mint;
  }
}

TEST(Solana, SchemaV2AcceptsEightArgsRejectsNine) {
  uint8_t program[32];
  memset(program, 0x42, sizeof(program));
  std::vector<SchemaArgSpec> args(8, {SOL_SCHEMA_ARG_U8, "b", 0});
  std::vector<uint8_t> blob = build_schema(2, program, args);
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob.data(), blob.size(), &s));
  EXPECT_EQ(s.num_args, 8);

  args.push_back({SOL_SCHEMA_ARG_U8, "b", 0});
  blob = build_schema(2, program, args);
  EXPECT_FALSE(solana_parseInstrSchema(blob.data(), blob.size(), &s));
}

/* Version 1 keeps exactly its old rules: types 1..5 and at most four args.
 * Each rejection has a version-2 control so the version byte is what
 * decides. */
TEST(Solana, SchemaV1RejectsV2TypesAndLimits) {
  uint8_t program[32];
  memset(program, 0x42, sizeof(program));
  SolanaInstrSchema s;

  const std::vector<std::vector<SchemaArgSpec>> v2_only = {
      {{SOL_SCHEMA_ARG_TOKEN_AMOUNT, "Amount", 0}},
      {{SOL_SCHEMA_ARG_DURATION, "Expires in", 0}},
      std::vector<SchemaArgSpec>(5, {SOL_SCHEMA_ARG_U8, "b", 0}),
  };
  for (const auto& args : v2_only) {
    const std::vector<uint8_t> v1 = build_schema(1, program, args);
    EXPECT_FALSE(solana_parseInstrSchema(v1.data(), v1.size(), &s));
    const std::vector<uint8_t> v2 = build_schema(2, program, args);
    EXPECT_TRUE(solana_parseInstrSchema(v2.data(), v2.size(), &s));
  }

  /* Unknown versions and types stay refused. */
  const std::vector<SchemaArgSpec> one = {{SOL_SCHEMA_ARG_U64, "Amount", 0}};
  for (uint8_t version : {(uint8_t)0, (uint8_t)3, (uint8_t)0xFF}) {
    const std::vector<uint8_t> blob = build_schema(version, program, one);
    EXPECT_FALSE(solana_parseInstrSchema(blob.data(), blob.size(), &s))
        << (unsigned)version;
  }
  for (uint8_t type : {(uint8_t)0, (uint8_t)8}) {
    const std::vector<uint8_t> blob =
        build_schema(2, program, {{type, "Amount", 0}});
    EXPECT_FALSE(solana_parseInstrSchema(blob.data(), blob.size(), &s))
        << (unsigned)type;
  }
}

/* The TOKEN_AMOUNT entry is type, label, then mint_account: a payload that
 * stops before the mint byte, or whose last arg's mint is followed by nothing
 * where n_accounts belongs, is malformed. */
TEST(Solana, SchemaV2RejectsTruncatedTokenAmount) {
  uint8_t program[32];
  memset(program, 0x42, sizeof(program));
  const std::vector<uint8_t> blob =
      build_schema(2, program, {{SOL_SCHEMA_ARG_TOKEN_AMOUNT, "Amount", 3}});
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob.data(), blob.size(), &s));
  EXPECT_EQ(s.args[0].mint_account, 3);
  /* Drop n_accounts: the mint byte is now last. */
  EXPECT_FALSE(solana_parseInstrSchema(blob.data(), blob.size() - 1, &s));
  /* Drop the mint byte too. */
  EXPECT_FALSE(solana_parseInstrSchema(blob.data(), blob.size() - 2, &s));
}

TEST(Solana, SchemaDurationUsesExactUnits) {
  const struct {
    uint64_t seconds;
    const char* shown;
  } cases[] = {
      {3600, "1 h"},
      {86400, "1 d"},
      {172800, "2 d"},
      {90000, "25 h"},
      {5400, "90 min"},
      {60, "1 min"},
      {3660, "61 min"},
      {59, "59 s"},
      {3601, "3601 s"},
      {0, "0 d"},
      {UINT64_MAX, "18446744073709551615 s"},
  };
  for (const auto& c : cases) {
    char buf[32];
    solana_formatDuration(buf, sizeof(buf), c.seconds);
    EXPECT_STREQ(buf, c.shown) << c.seconds;
  }
}

/* Without a trusted definition the device may not guess a scale or a name:
 * it shows the signed integer and the full mint. With one, it scales by the
 * definition's decimals and names its symbol -- and still shows the mint,
 * because a symbol is not an identity. */
TEST(Solana, SchemaTokenAmountTrustedOrRawWithMint) {
  char buf[96];
  ASSERT_TRUE(solana_formatSchemaTokenAmount(buf, sizeof(buf), 1000000000ULL,
                                             kSdiceMint, nullptr));
  EXPECT_STREQ(buf,
               "1000000000 base units of mint\n"
               "4nCmpwne7hCoWTSpAd54uENmCgHJrHTyn4DMPCEMpump");
  ASSERT_TRUE(solana_formatSchemaTokenAmount(buf, sizeof(buf), UINT64_MAX,
                                             kSdiceMint, nullptr));
  EXPECT_STREQ(buf,
               "18446744073709551615 base units of mint\n"
               "4nCmpwne7hCoWTSpAd54uENmCgHJrHTyn4DMPCEMpump");

  SolanaTokenInfo ti;
  memset(&ti, 0, sizeof(ti));
  ti.has_mint = true;
  ti.mint.size = 32;
  memcpy(ti.mint.bytes, kSdiceMint, 32);
  ti.has_symbol = true;
  strcpy(ti.symbol, "SDICE");
  ti.has_decimals = true;
  ti.decimals = 6;
  ASSERT_TRUE(solana_formatSchemaTokenAmount(buf, sizeof(buf), 1000000000ULL,
                                             kSdiceMint, &ti));
  EXPECT_STREQ(buf,
               "1000 SDICE\n"
               "4nCmpwne7hCoWTSpAd54uENmCgHJrHTyn4DMPCEMpump");
  /* The longest trusted text still fits the renderer's 96-byte value. */
  strcpy(ti.symbol, "ABCDEFGHIJKL");
  ti.decimals = 9;
  ASSERT_TRUE(solana_formatSchemaTokenAmount(buf, sizeof(buf), UINT64_MAX,
                                             kSdiceMint, &ti));
  EXPECT_STREQ(buf,
               "18446744073.709551615 ABCDEFGHIJKL\n"
               "4nCmpwne7hCoWTSpAd54uENmCgHJrHTyn4DMPCEMpump");
}

/* Token definitions reach a TOKEN_AMOUNT only through their own tier. A
 * delegate-addressed (0x80) definition needs the request's Solana root
 * certificate; without one nothing is trusted on either path, so the review
 * falls back to the raw amount and mint. (The positive runtime control and the
 * cross-tier refusal live in signed_metadata.cpp beside the signer fixture.) */
TEST(Solana, SchemaTokenTrustNeedsItsTiersRoot) {
  static SolanaSignTx msg;
  memset(&msg, 0, sizeof(msg));
  msg.token_info_count = 1;
  SolanaTokenInfo* ti = &msg.token_info[0];
  ti->has_mint = true;
  ti->mint.size = 32;
  memcpy(ti->mint.bytes, kSdiceMint, 32);
  ti->has_symbol = true;
  strcpy(ti->symbol, "SDICE");
  ti->has_decimals = true;
  ti->decimals = 6;
  ti->has_signature = true;
  ti->signature.size = 64;
  memset(ti->signature.bytes, 0x5A, 64);
  ti->has_signer_key_id = true;
  ti->signer_key_id = 0x80; /* METADATA_KEYID_DELEGATE */

  EXPECT_EQ(solana_findTokenInfo(&msg, kSdiceMint), ti);
  EXPECT_EQ(solana_schemaTrustedToken(&msg, kSdiceMint, true), nullptr);
  EXPECT_EQ(solana_schemaTrustedToken(&msg, kSdiceMint, false), nullptr);

  /* A certificate of the wrong length is no certificate. */
  msg.has_clearsign_certificate = true;
  msg.clearsign_certificate.size = 1;
  EXPECT_EQ(solana_schemaTrustedToken(&msg, kSdiceMint, true), nullptr);

  uint8_t other[32];
  memset(other, 0x42, sizeof(other));
  EXPECT_EQ(solana_schemaTrustedToken(&msg, other, true), nullptr);
  EXPECT_EQ(solana_schemaTrustedToken(nullptr, kSdiceMint, true), nullptr);
}

/* What the review draws for the real join, arg by arg, through the renderer
 * itself, with no token definition supplied. Each TOKEN_AMOUNT's mint is the
 * join's account 3, which is message key 8 (SDICE). Message key 3 is
 * 951nS8NJoi7ajueDo7iztaWQiapUZuHAx5xt3vVApJXa: reading the index against the
 * wrong list would name a different token. */
TEST(Solana, SchemaV2SoltoshiDiceJoinRendersEachArg) {
  const std::vector<uint8_t> raw = solana_unhex(kSoltoshiJoinMessageHex);
  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw.data(), raw.size(), &tx),
            SOL_TX_REVIEW_OPAQUE);
  const std::vector<uint8_t> blob = solana_unhex(kSoltoshiJoinSchemaHex);
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob.data(), blob.size(), &s));
  uint8_t idx = 0xFF;
  ASSERT_TRUE(solana_schemaAppliesCertified(&s, &tx, tx.accounts[0], &idx));
  const SolanaParsedInstruction* ix = &tx.instructions[idx];
  ASSERT_EQ(ix->acct_indices[3], 8);
  ASSERT_NE(memcmp(tx.accounts[3], kSdiceMint, 32), 0);

  const char* raw_sdice =
      "1000000000 base units of mint\n"
      "4nCmpwne7hCoWTSpAd54uENmCgHJrHTyn4DMPCEMpump";
  const char* const want[] = {"86",
                              "980",
                              "1",
                              raw_sdice,
                              "BqtZ8PRQywD9Z5xXeB5112wtPG3xtj7TqF56hroicGjX",
                              "1 h",
                              raw_sdice,
                              raw_sdice};
  ASSERT_EQ(s.num_args, sizeof(want) / sizeof(want[0]));

  static SolanaSignTx msg; /* no token definitions, no certificate */
  memset(&msg, 0, sizeof(msg));
  for (bool certified : {true, false}) {
    SolanaSchemaTokenCache cache = {nullptr, nullptr};
    size_t off = s.disc_len;
    for (uint8_t a = 0; a < s.num_args; a++) {
      char value[96];
      ASSERT_TRUE(solana_schemaArgValue(&msg, certified, &tx, ix, &s.args[a],
                                        ix->data + off, &cache, value,
                                        sizeof(value)))
          << s.args[a].label;
      EXPECT_STREQ(value, want[a]) << s.args[a].label << " " << certified;
      off += solana_schemaArgWidth(s.args[a].type);
    }
    EXPECT_EQ(off, ix->data_len);
  }
}

/* A certified request for the real join as Vault sends it: the Worker's
 * certificate, the schema with its delegate signature, and the SDICE
 * definition addressed to the delegate (0x80, METADATA_KEYID_DELEGATE). */
static void fill_certified_soltoshi_join(SolanaSignTx* msg) {
  memset(msg, 0, sizeof(*msg));
  const std::vector<uint8_t> cert = solana_unhex(kCert501Hex);
  const std::vector<uint8_t> schema = solana_unhex(kSoltoshiJoinSchemaHex);
  const std::vector<uint8_t> schema_sig =
      solana_unhex(kSoltoshiJoinSchemaSigHex);
  const std::vector<uint8_t> token_sig = solana_unhex(kSdiceTokenDefSigHex);
  ASSERT_EQ(cert.size(), (size_t)CLEARSIGN_CERT_LEN);
  ASSERT_EQ(schema.size(), 154U);
  ASSERT_EQ(schema_sig.size(), 64U);
  ASSERT_EQ(token_sig.size(), 64U);

  msg->has_clearsign_certificate = true;
  msg->clearsign_certificate.size = cert.size();
  memcpy(msg->clearsign_certificate.bytes, cert.data(), cert.size());
  msg->has_schema_payload = true;
  msg->schema_payload.size = schema.size();
  memcpy(msg->schema_payload.bytes, schema.data(), schema.size());
  msg->has_schema_signature = true;
  msg->schema_signature.size = schema_sig.size();
  memcpy(msg->schema_signature.bytes, schema_sig.data(), schema_sig.size());
  msg->has_schema_signer_key_id = true;
  msg->schema_signer_key_id = 0x80;

  msg->token_info_count = 1;
  SolanaTokenInfo* ti = &msg->token_info[0];
  ti->has_mint = true;
  ti->mint.size = 32;
  memcpy(ti->mint.bytes, kSdiceMint, 32);
  ti->has_symbol = true;
  strcpy(ti->symbol, "SDICE");
  ti->has_decimals = true;
  ti->decimals = 6;
  ti->has_signature = true;
  ti->signature.size = token_sig.size();
  memcpy(ti->signature.bytes, token_sig.data(), token_sig.size());
  ti->has_signer_key_id = true;
  ti->signer_key_id = 0x80;
}

/* The Worker's schema signature verifies the way fsm_msgSolanaSignTx checks
 * it: clearsign_root_verify_delegate_attestation gets the raw schema_payload
 * and verifies sha256(payload) with the scope-501 certificate's delegate. A
 * flipped byte in the signature or the schema, or another scope, fails. */
TEST(Solana, CertifiedSoltoshiJoinSchemaSignatureVerifies) {
  AlphaTestRoot alpha;
  const std::vector<uint8_t> cert = solana_unhex(kCert501Hex);
  std::vector<uint8_t> schema = solana_unhex(kSoltoshiJoinSchemaHex);
  std::vector<uint8_t> sig = solana_unhex(kSoltoshiJoinSchemaSigHex);
  ASSERT_EQ(cert.size(), (size_t)CLEARSIGN_CERT_LEN);
  ASSERT_EQ(sig.size(), 64U);
  /* The certificate was signed by the alpha root, installed above as the
   * test root (7.16 compiles in the production root). */
  ASSERT_TRUE(clearsign_root_verify_cert(cert.data(), cert.size()));
  const auto verifies = [&](uint32_t scope) {
    return clearsign_root_verify_delegate_attestation(
        cert.data(), cert.size(), scope, schema.data(), schema.size(),
        sig.data(), sig.size());
  };
  EXPECT_TRUE(verifies(501));
  EXPECT_FALSE(verifies(1));

  for (size_t i = 0; i < sig.size(); i++) {
    sig[i] ^= 0x01;
    EXPECT_FALSE(verifies(501)) << "signature byte " << i;
    sig[i] ^= 0x01;
  }
  /* The join's discriminator byte: the same signature over a schema for
   * another instruction of the program. */
  const size_t disc_at = 9 + 32 + 1;
  ASSERT_EQ(schema[disc_at], 0x51);
  schema[disc_at] ^= 0x01;
  EXPECT_FALSE(verifies(501));
  schema[disc_at] ^= 0x01;
  EXPECT_TRUE(verifies(501));
}

/* The Worker's SDICE definition (KeepKeySolanaTokenDef/2, signer 0x80) is
 * trusted on the certified review, through the request's certificate. The
 * same entry is not trusted on the runtime tier, whose signers never include
 * the certificate's delegate. Nor is it trusted under another key id, without
 * the certificate, or after a one-byte change to its signature, symbol,
 * decimals or mint. */
TEST(Solana, CertifiedSdiceTokenDefinitionTrustedOnlyAsSigned) {
  AlphaTestRoot alpha; /* kCert501Hex is signed by the alpha root */
  static SolanaSignTx msg;
  ASSERT_NO_FATAL_FAILURE(fill_certified_soltoshi_join(&msg));
  SolanaTokenInfo* ti = &msg.token_info[0];
  ASSERT_EQ(solana_schemaTrustedToken(&msg, kSdiceMint, true), ti);
  EXPECT_EQ(solana_schemaTrustedToken(&msg, kSdiceMint, false), nullptr);

  for (uint32_t key_id : {0U, 3U, 0x7FU, 0x81U}) {
    ti->signer_key_id = key_id;
    EXPECT_EQ(solana_schemaTrustedToken(&msg, kSdiceMint, true), nullptr)
        << "signer_key_id " << key_id;
  }
  ti->signer_key_id = 0x80;
  ti->has_signer_key_id = false;
  EXPECT_EQ(solana_schemaTrustedToken(&msg, kSdiceMint, true), nullptr);
  ti->has_signer_key_id = true;

  msg.has_clearsign_certificate = false;
  EXPECT_EQ(solana_schemaTrustedToken(&msg, kSdiceMint, true), nullptr);
  msg.has_clearsign_certificate = true;

  for (size_t i = 0; i < ti->signature.size; i++) {
    ti->signature.bytes[i] ^= 0x01;
    EXPECT_EQ(solana_schemaTrustedToken(&msg, kSdiceMint, true), nullptr)
        << "signature byte " << i;
    ti->signature.bytes[i] ^= 0x01;
  }
  /* Each flip leaves a well-formed ticker ("RDICE", "SEICE", ...), so the
   * signature is what refuses it. */
  for (size_t i = 0; i < strlen("SDICE"); i++) {
    ti->symbol[i] ^= 0x01;
    EXPECT_EQ(solana_schemaTrustedToken(&msg, kSdiceMint, true), nullptr)
        << ti->symbol;
    ti->symbol[i] ^= 0x01;
  }
  /* 7, 4 and 2 stay within the display cap of 9 decimals, so again the
   * signature refuses them, not the cap. */
  for (uint32_t flip : {0x01U, 0x02U, 0x04U}) {
    ti->decimals ^= flip;
    EXPECT_EQ(solana_schemaTrustedToken(&msg, kSdiceMint, true), nullptr)
        << "decimals " << ti->decimals;
    ti->decimals ^= flip;
  }
  /* Looked up by the altered mint, so the entry is found and the signature
   * refuses it. */
  for (size_t i = 0; i < SOL_PUBKEY_SIZE; i++) {
    ti->mint.bytes[i] ^= 0x01;
    EXPECT_EQ(solana_schemaTrustedToken(&msg, ti->mint.bytes, true), nullptr)
        << "mint byte " << i;
    ti->mint.bytes[i] ^= 0x01;
  }
  EXPECT_EQ(solana_schemaTrustedToken(&msg, kSdiceMint, true), ti);
}

/* The certified review of the real join with the Worker's envelope, arg by
 * arg, through the renderer. Each TOKEN_AMOUNT is scaled and named by the
 * SDICE definition and still shows the mint. The same request on the runtime
 * tier renders the raw base units. */
TEST(Solana, CertifiedSoltoshiJoinRendersSdiceAmounts) {
  AlphaTestRoot alpha; /* kCert501Hex is signed by the alpha root */
  const std::vector<uint8_t> raw = solana_unhex(kSoltoshiJoinMessageHex);
  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw.data(), raw.size(), &tx),
            SOL_TX_REVIEW_OPAQUE);
  static SolanaSignTx msg;
  ASSERT_NO_FATAL_FAILURE(fill_certified_soltoshi_join(&msg));
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(msg.schema_payload.bytes,
                                      msg.schema_payload.size, &s));
  uint8_t idx = 0xFF;
  ASSERT_TRUE(solana_schemaAppliesCertified(&s, &tx, tx.accounts[0], &idx));
  const SolanaParsedInstruction* ix = &tx.instructions[idx];

  const char* sdice =
      "1000 SDICE\n"
      "4nCmpwne7hCoWTSpAd54uENmCgHJrHTyn4DMPCEMpump";
  const char* raw_sdice =
      "1000000000 base units of mint\n"
      "4nCmpwne7hCoWTSpAd54uENmCgHJrHTyn4DMPCEMpump";
  const char* session = "BqtZ8PRQywD9Z5xXeB5112wtPG3xtj7TqF56hroicGjX";
  const struct {
    const char* label;
    const char* certified;
    const char* runtime;
  } want[] = {
      {"Round", "86", "86"},
      {"Revision", "980", "980"},
      {"Seat", "1", "1"},
      {"Buy-in", sdice, raw_sdice},
      {"Session key", session, session},
      {"Expires in", "1 h", "1 h"},
      {"Allowance", sdice, raw_sdice},
      {"Max wager", sdice, raw_sdice},
  };
  ASSERT_EQ(s.num_args, sizeof(want) / sizeof(want[0]));

  for (bool certified : {true, false}) {
    SolanaSchemaTokenCache cache = {nullptr, nullptr};
    size_t off = s.disc_len;
    for (uint8_t a = 0; a < s.num_args; a++) {
      EXPECT_STREQ(s.args[a].label, want[a].label);
      char value[96];
      ASSERT_TRUE(solana_schemaArgValue(&msg, certified, &tx, ix, &s.args[a],
                                        ix->data + off, &cache, value,
                                        sizeof(value)))
          << want[a].label;
      EXPECT_STREQ(value, certified ? want[a].certified : want[a].runtime)
          << want[a].label << " certified=" << certified;
      off += solana_schemaArgWidth(s.args[a].type);
    }
    EXPECT_EQ(off, ix->data_len);
  }
}

/* The types the join does not use, and what the renderer refuses: OPAQUE32,
 * which the caller pages as bytes, and a mint that is not an account of this
 * instruction or of this message. */
TEST(Solana, SchemaArgValueRemainingTypesAndRefusals) {
  const std::vector<uint8_t> raw = solana_unhex(kSoltoshiJoinMessageHex);
  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw.data(), raw.size(), &tx),
            SOL_TX_REVIEW_OPAQUE);
  const SolanaParsedInstruction* ix = &tx.instructions[2];
  static SolanaSignTx msg;
  memset(&msg, 0, sizeof(msg));
  SolanaSchemaTokenCache cache = {nullptr, nullptr};
  char value[96];

  std::vector<uint8_t> data;
  put_le64(data, 996374000ULL);
  const SolanaSchemaArg lamports = {SOL_SCHEMA_ARG_LAMPORTS, "Amount", 0};
  ASSERT_TRUE(solana_schemaArgValue(&msg, true, &tx, ix, &lamports, data.data(),
                                    &cache, value, sizeof(value)));
  EXPECT_STREQ(value, "0.996374000 SOL");

  const SolanaSchemaArg opaque = {SOL_SCHEMA_ARG_OPAQUE32, "Order", 0};
  EXPECT_FALSE(solana_schemaArgValue(&msg, true, &tx, ix, &opaque, ix->data + 1,
                                     &cache, value, sizeof(value)));

  SolanaSchemaArg token = {SOL_SCHEMA_ARG_TOKEN_AMOUNT, "Buy-in", 8};
  ASSERT_TRUE(solana_schemaArgValue(&msg, true, &tx, ix, &token, data.data(),
                                    &cache, value, sizeof(value)));
  token.mint_account = 9; /* the join has nine accounts, 0..8 */
  EXPECT_FALSE(solana_schemaArgValue(&msg, true, &tx, ix, &token, data.data(),
                                     &cache, value, sizeof(value)));
  token.mint_account = 3; /* message key 8, beyond a shortened key list */
  SolanaParsedTx short_tx = tx;
  short_tx.num_accounts = 8;
  EXPECT_FALSE(
      solana_schemaArgValue(&msg, true, &short_tx, &short_tx.instructions[2],
                            &token, data.data(), &cache, value, sizeof(value)));
}

/* A certified schema of either version admits a SystemProgram Transfer beside
 * the instruction it describes: the certified review renders the transfer in
 * full. Already-certified version 1 schemas (Relay's) gain this too. The
 * runtime (AdvancedMode) path still refuses it. */
TEST(Solana, SchemaV1CertifiedAdmitsStaticTransferCompanion) {
  uint8_t program[32];
  memset(program, 0x42, sizeof(program));
  uint8_t d[48];
  build_relay_data(d, 526490980ULL);
  const uint8_t system_program[32] = {0};
  uint8_t raw[512];
  const size_t pos = build_schema_plus_companion_tx(
      raw, program, d, sizeof(d), system_program, 2, kSystemTransfer12,
      sizeof(kSystemTransfer12));
  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
  ASSERT_EQ(tx.instructions[1].type, SOL_INSTR_SYSTEM_TRANSFER);
  EXPECT_EQ(tx.num_static_accounts, tx.num_accounts);

  uint8_t blob[256];
  const size_t len = build_relay_schema(blob, program, 2);
  ASSERT_EQ(blob[8], 1); /* version 1 */
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob, len, &s));
  uint8_t idx = 0xFF;
  ASSERT_TRUE(solana_schemaAppliesCertified(&s, &tx, tx.accounts[0], &idx));
  EXPECT_EQ(idx, 0);
  idx = 0xFF;
  EXPECT_FALSE(solana_schemaApplies(&s, &tx, &idx));
  EXPECT_EQ(idx, 0xFF);
}

/* Parity with the Vault/Worker (isCertifiedCompanion): a certified Transfer
 * companion names exactly two accounts. The same Transfer with a third static
 * account still parses as a SystemProgram Transfer, and the certified path
 * refuses it; with two it is admitted. */
TEST(Solana, SchemaCertifiedTransferCompanionNeedsExactlyTwoAccounts) {
  uint8_t program[32];
  memset(program, 0x42, sizeof(program));
  uint8_t d[48];
  build_relay_data(d, 526490980ULL);
  const uint8_t system_program[32] = {0};
  uint8_t blob[256];
  const size_t len = build_relay_schema(blob, program, 2);
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob, len, &s));

  for (uint8_t accts : {(uint8_t)3, (uint8_t)2}) {
    uint8_t raw[512];
    const size_t pos = build_schema_plus_companion_tx(
        raw, program, d, sizeof(d), system_program, accts, kSystemTransfer12,
        sizeof(kSystemTransfer12));
    SolanaParsedTx tx;
    ASSERT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
    ASSERT_EQ(tx.instructions[1].type, SOL_INSTR_SYSTEM_TRANSFER);
    ASSERT_EQ(tx.instructions[1].num_acct_indices, accts);
    ASSERT_EQ(tx.num_static_accounts, tx.num_accounts);

    uint8_t idx = 0xFF;
    EXPECT_EQ(solana_schemaAppliesCertified(&s, &tx, tx.accounts[0], &idx),
              accts == 2)
        << (unsigned)accts;
    EXPECT_FALSE(solana_schemaApplies(&s, &tx, &idx)) << (unsigned)accts;
  }
}

/* v0 message: static keys [signer, schema program, System program, 0x33..];
 * one lookup table resolving one key. ix0 is the Relay-shaped call, ix1 a
 * System Transfer from the signer to message key `to_index`. */
static size_t build_lut_transfer_tx(uint8_t* raw, const uint8_t* program,
                                    uint8_t to_index) {
  uint8_t data[48];
  build_relay_data(data, 526490980ULL);
  size_t pos = 0;
  raw[pos++] = 0x80; /* v0 */
  raw[pos++] = 1;    /* required signatures */
  raw[pos++] = 0;
  raw[pos++] = 2;
  raw[pos++] = 4; /* four static keys */
  memset(raw + pos, 0x11, 32);
  pos += 32;
  memcpy(raw + pos, program, 32);
  pos += 32;
  memcpy(raw + pos, SOL_SYSTEM_PROGRAM, 32);
  pos += 32;
  memset(raw + pos, 0x33, 32);
  pos += 32;
  memset(raw + pos, 0xBB, 32); /* blockhash */
  pos += 32;
  raw[pos++] = 2; /* two instructions */
  raw[pos++] = 1; /* ix0: schema program */
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = 3;
  raw[pos++] = sizeof(data);
  memcpy(raw + pos, data, sizeof(data));
  pos += sizeof(data);
  raw[pos++] = 2; /* ix1: System program */
  raw[pos++] = 2;
  raw[pos++] = 0;
  raw[pos++] = to_index;
  raw[pos++] = sizeof(kSystemTransfer12);
  memcpy(raw + pos, kSystemTransfer12, sizeof(kSystemTransfer12));
  pos += sizeof(kSystemTransfer12);
  raw[pos++] = 1; /* one lookup table */
  memset(raw + pos, 0x55, 32);
  pos += 32;
  raw[pos++] = 1; /* one writable index */
  raw[pos++] = 0;
  raw[pos++] = 0; /* no readonly indices */
  return pos;
}

/* A certified lookup-table proof resolves key 4, and the parser then treats
 * a Transfer to it as fully decoded. Its destination would be a key the
 * service attested, not one the user signs, so the certified schema refuses
 * that companion. The same message paying static key 3 is the control. */
TEST(Solana, SchemaCertifiedRefusesTransferToLookupTableKey) {
  uint8_t program[32];
  memset(program, 0x42, sizeof(program));
  uint8_t resolved[1][SOL_PUBKEY_SIZE];
  memset(resolved[0], 0x77, sizeof(resolved[0]));
  uint8_t blob[256];
  const size_t len = build_relay_schema(blob, program, 2);
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob, len, &s));

  for (uint8_t to_index : {(uint8_t)4, (uint8_t)3}) {
    uint8_t raw[512];
    const size_t pos = build_lut_transfer_tx(raw, program, to_index);
    SolanaParsedTx tx;
    ASSERT_EQ(solana_inspectTxWithTrustedLut(raw, pos, resolved, 1, &tx),
              SOL_TX_REVIEW_OPAQUE);
    ASSERT_TRUE(tx.has_address_lookups);
    ASSERT_EQ(tx.num_static_accounts, 4);
    ASSERT_EQ(tx.num_accounts, 5);
    const SolanaParsedInstruction* transfer = &tx.instructions[1];
    ASSERT_EQ(transfer->type, SOL_INSTR_SYSTEM_TRANSFER);
    ASSERT_FALSE(transfer->external);
    EXPECT_EQ(
        memcmp(transfer->to, to_index == 4 ? resolved[0] : tx.accounts[3], 32),
        0);

    uint8_t idx = 0xFF;
    EXPECT_EQ(solana_schemaAppliesCertified(&s, &tx, tx.accounts[0], &idx),
              to_index == 3)
        << (unsigned)to_index;
    EXPECT_FALSE(solana_schemaApplies(&s, &tx, &idx)) << (unsigned)to_index;
  }
}

/* ---- Real mainnet PumpSwap trades (wallet history, 2026-10-01 corpus) ---- */
/* PumpSwap sell, 6 instructions: compute x2, fee transfer, create WSOL account,
 * sell, close WSOL account. Source: vault dev api_log 919632 (2026-10-01) */
static const char kPumpSellMessageHex[] =
    "800100111bec3979a4dc6b401bd045171a189f26856fab9eab75560214f972b2edc16430"
    "0fbc2b57065ef1dd665430be606ba6596c0295301badef8b5afc41014150f412745302eb"
    "9c05fef2f27c336ea5941d578a7c5542d9606be75c2e8f4b01ee7202759668dd5fabab39"
    "2154d1490485b2a92fec5ff91a4f3a686c6f60fb1b4f37a11ffc4da258d76a62aa6a0c64"
    "1d34cefc33c97f0b9424c1678e26ee25b4c49b7bda7b23ea1791a0796c88715deed40e91"
    "27bf56fdcc28de0829063f2e38c3bd1c7f51941d67069bf895e41b0a193e12e269facebf"
    "80ed8888c2d862d95b7c2dda5901c821f3a8f08fef88dc31424a7680ae8c9681704cf1e5"
    "f5c88e2799b7f98221632aa757efcc80c7ff6df799f09cf2a1bd496339047449f36ee0ee"
    "516bb838d30c7d1d9d82d81a12034077d425bfe2c00394d530d828450bb47819aca30023"
    "910306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a400000000af1c3"
    "432188ca3a635135a13a18951acebd29e6ac2dae67ffdb06d7408ea2cf00000000000000"
    "000000000000000000000000000000000000000000000000008c97258f4e2489f1bb3d10"
    "29148e0d830b5a1399daff1084048e7bd8dbe9f859069b8857feab8184fb687f634618c0"
    "35dac439dc1aeb3b5598a0f0000000000106ddf6e1d765a193d9cbe146ceeb79ac1cb485"
    "ed5f5b37913a8cf5857eff00a90c14defc825ec67694250818bb654065f4298d3156d571"
    "b4d4f8090c18e9a863890ba644fe1f55aa19f11cd2d2ec14d3233b6e0a4beaeef72b6985"
    "8e21e170d638278241da03c70dd0fc885f7ad2123bad32b33a5402340739af8ae5d84cac"
    "efd7aa8fb060d8291b4c4d475daff762c96bdc0daceb36c012ead12ed3a948416106ddf6"
    "e1ee758fde18425dbce46ccddab61afc4d83b90d27febdf928d8a18bfce54a709528839f"
    "61c0b9b86079891c139216e47a71b62fb73bec72169458745ecb1f7d18c5d1b3784e72ec"
    "cf5b737f96767ad7fec197df8407b9661a762ac3e741246ecc7d78fe81e41773a4696541"
    "9937923a07644797df6f3eb514426010cb0c35ffa9055a8e568da8f7bc075615274cf1c9"
    "2ca41f40009c516aa414c27c700f61d91ecc71463e7eea4325d604219918fa3804069466"
    "5e7e04089c56ac8f178770157eebeb678a655db99b37f6b1326c7657db90cfb8a87abef8"
    "c7b6f2c869e43b31ad24c0c701bd4f237d8d7d5c03f6ad14be4ac948ce9d1b8ed1b5c9e6"
    "12060a010b0502400d03000a000903404b4c00000000000c0200010c0200000040420f00"
    "000000000d060002000e0c0f01011018030011120e040205061307140f0c0d1510081617"
    "18191a091833e685a4017f83ad3da6e7ab0907000031c934fb010000000f030200000109"
    "00";
/* PumpSwap buy, 8 instructions, mainnet tx
 * tyit2ie4K1xU3Kp3xvCEShfiAbiNkijaJDdU8uvKEnYXnPsDz9vd3QuWuekiZ1f43QabWqepUCgAQgcrV2LTFCv
 */
static const char kPumpBuy8MessageHex[] =
    "800100121dec3979a4dc6b401bd045171a189f26856fab9eab75560214f972b2edc16430"
    "0f78521cb179cebb8589b556a2d5ec94d2498682fdf9bb2af5ad64e491cc4153da5302eb"
    "9c05fef2f27c336ea5941d578a7c5542d9606be75c2e8f4b01ee7202759668dd5fabab39"
    "2154d1490485b2a92fec5ff91a4f3a686c6f60fb1b4f37a11ffc4da258d76a62aa6a0c64"
    "1d34cefc33c97f0b9424c1678e26ee25b4c49b7bda7b23ea1791a0796c88715deed40e91"
    "27bf56fdcc28de0829063f2e38c3bd1c7f51941d67069bf895e41b0a193e12e269facebf"
    "80ed8888c2d862d95b7c2dda59d4117b96463aea6b0dbc831a1e079d81da72bdaa8cb2e6"
    "c87ec2524a88ad5a55632aa757efcc80c7ff6df799f09cf2a1bd496339047449f36ee0ee"
    "516bb838d3bd4a092da8f105904cba6e0a53b7f9eea6721a6e3f8f0740af043136a9e27e"
    "4bf89839a1cb7de9595dcd77d1c285d56a76c8f52b7de42e4f1f78da821f6c4adb030646"
    "6fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a400000000af1c3432188ca"
    "3a635135a13a18951acebd29e6ac2dae67ffdb06d7408ea2cf0000000000000000000000"
    "0000000000000000000000000000000000000000008c97258f4e2489f1bb3d1029148e0d"
    "830b5a1399daff1084048e7bd8dbe9f859069b8857feab8184fb687f634618c035dac439"
    "dc1aeb3b5598a0f0000000000106ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37"
    "913a8cf5857eff00a90c14defc825ec67694250818bb654065f4298d3156d571b4d4f809"
    "0c18e9a863890ba644fe1f55aa19f11cd2d2ec14d3233b6e0a4beaeef72b69858e21e170"
    "d638278241da03c70dd0fc885f7ad2123bad32b33a5402340739af8ae5d84cacef8d181a"
    "0c849fa937a6f34aded3081ef95700aacb0c9bb3d909a4b9147527a4eb06ddf6e1ee758f"
    "de18425dbce46ccddab61afc4d83b90d27febdf928d8a18bfce54a709528839f61c0b9b8"
    "6079891c139216e47a71b62fb73bec72169458745ecb1f7d18c5d1b3784e72eccf5b737f"
    "96767ad7fec197df8407b9661a762ac3e7a3d7bb127e58adc12ca68f83437ec2e1c3f982"
    "0de93e58f9178a2918ddaaf7b441246ecc7d78fe81e41773a46965419937923a07644797"
    "df6f3eb514426010cb0c35ffa9055a8e568da8f7bc075615274cf1c92ca41f40009c516a"
    "a414c27c700f61d91ecc71463e7eea4325d604219918fa38040694665e7e04089c56ac8f"
    "17439e6510c03d65fad931e89d04be0bb70d51971f51c415fb344c07db419f212280a859"
    "6fdc6c089980ecc846bcf37c3b70a2abb6626726ea264ecff4bfc15031080b010c050240"
    "0d03000b000903404b4c00000000000d0200010c0200000040420f00000000000e060002"
    "000f0d1001010d0200020c020000000a501929000000001001020111111a030012130f04"
    "020506140715100d0e161108171809191a1b1c0a1966063d1201daebeab7442f09e20100"
    "000a50192900000000011003020000010900";
/* PumpSwap buy, 9 instructions, mainnet tx
 * 2TVzaEUKCa1HQoPeZLPbYAtwHfeMrP3F7DYsiDvv9FdMTAN9dXe2WcSkgTWuDHgBqHUwrsXUEvdDfQEs2UXjPvxM
 */
static const char kPumpBuy9MessageHex[] =
    "800100121dec3979a4dc6b401bd045171a189f26856fab9eab75560214f972b2edc16430"
    "0fbf971b59108b5b85a04fb093f1e21b4e3fd4c4c8f487dd09b95752769f0dd8c35302eb"
    "9c05fef2f27c336ea5941d578a7c5542d9606be75c2e8f4b01ee720275fc4da258d76a62"
    "aa6a0c641d34cefc33c97f0b9424c1678e26ee25b4c49b7bda9668dd5fabab392154d149"
    "0485b2a92fec5ff91a4f3a686c6f60fb1b4f37a11f7b23ea1791a0796c88715deed40e91"
    "27bf56fdcc28de0829063f2e38c3bd1c7f51941d67069bf895e41b0a193e12e269facebf"
    "80ed8888c2d862d95b7c2dda5977d915955f8880731ceb4a75a0cc96c174fa4095c4e1d9"
    "967acfc42845ae67ae632aa757efcc80c7ff6df799f09cf2a1bd496339047449f36ee0ee"
    "516bb838d3bd4a092da8f105904cba6e0a53b7f9eea6721a6e3f8f0740af043136a9e27e"
    "4b90f794bd351e64fca793a0ad419e94cb252a27b36c1863dc637b3bd3a14664ff030646"
    "6fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a400000000af1c3432188ca"
    "3a635135a13a18951acebd29e6ac2dae67ffdb06d7408ea2cf0000000000000000000000"
    "0000000000000000000000000000000000000000008c97258f4e2489f1bb3d1029148e0d"
    "830b5a1399daff1084048e7bd8dbe9f859069b8857feab8184fb687f634618c035dac439"
    "dc1aeb3b5598a0f0000000000106ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37"
    "913a8cf5857eff00a938278241da03c70dd0fc885f7ad2123bad32b33a5402340739af8a"
    "e5d84cacef06ddf6e1ee758fde18425dbce46ccddab61afc4d83b90d27febdf928d8a18b"
    "fc0c14defc825ec67694250818bb654065f4298d3156d571b4d4f8090c18e9a863890ba6"
    "44fe1f55aa19f11cd2d2ec14d3233b6e0a4beaeef72b69858e21e170d64ac2f8d0dd5cbc"
    "97e3289c197cb5062a54f3d956b9ce6e5115f96567aa5cb3e6e54a709528839f61c0b9b8"
    "6079891c139216e47a71b62fb73bec72169458745ecb1f7d18c5d1b3784e72eccf5b737f"
    "96767ad7fec197df8407b9661a762ac3e7a3d7bb127e58adc12ca68f83437ec2e1c3f982"
    "0de93e58f9178a2918ddaaf7b441246ecc7d78fe81e41773a46965419937923a07644797"
    "df6f3eb514426010cb0c35ffa9055a8e568da8f7bc075615274cf1c92ca41f40009c516a"
    "a414c27c700f61d91ecc71463e7eea4325d604219918fa38040694665e7e04089c56ac8f"
    "17e6a7e22068bb88640aa57f909308c61fef711a0163f5a755c070bc860d1f63674d576c"
    "b8b60d7a171cd404dcbf86eed11586dfdbd602dc0feba2dbec334451b6090b010c050240"
    "0d03000b000903404b4c00000000000d0200010c0200000040420f00000000000e060002"
    "000f0d1001010d0200020c02000000ea71bb1f0000000010010201110e06000300110d12"
    "0101131a040014110f03020506150712100d0e161308171809191a1b1c0a1966063d1201"
    "daebeaefc1aea8b9020000ea71bb1f00000000011003020000010900";
/* ClearSign server catalog entry pumpAmmBuy, serialized */
static const char kPumpAmmBuySchemaHex[] =
    "4b4b534f4c534331010c14defc825ec67694250818bb654065f4298d3156d571b4d4f809"
    "0c18e9a8630866063d1201daebea0850756d7020414d4d0342757903010e426173652075"
    "6e697473206f7574010f4d61782071756f746520756e697473020c547261636b20766f6c"
    "756d6504030e42757920746f6b656e206d696e74040e50617920746f6b656e206d696e74"
    "050f52656365697665206163636f756e74060b506179206163636f756e74";
/* pumpAmmSell (Anchor global:sell, u64 base in, u64 min quote out), serialized
 */
static const char kPumpAmmSellSchemaHex[] =
    "4b4b534f4c534331010c14defc825ec67694250818bb654065f4298d3156d571b4d4f809"
    "0c18e9a8630833e685a4017f83ad0850756d7020414d4d0453656c6c02010d4261736520"
    "756e69747320696e010f4d696e2071756f746520756e69747304030f53656c6c20746f6b"
    "656e206d696e74040e47657420746f6b656e206d696e74050c53656c6c206163636f756e"
    "74060f52656365697665206163636f756e74";

static bool pump_certified(const std::vector<uint8_t>& raw,
                           const char* schema_hex, uint8_t* idx) {
  SolanaParsedTx tx;
  if (solana_inspectTx(raw.data(), raw.size(), &tx) == SOL_TX_REVIEW_MALFORMED)
    return false;
  const std::vector<uint8_t> blob = solana_unhex(schema_hex);
  SolanaInstrSchema s;
  if (!solana_parseInstrSchema(blob.data(), blob.size(), &s)) return false;
  return solana_schemaAppliesCertified(&s, &tx, tx.accounts[0], idx);
}

/* Point account slot `slot` of instruction `ix` at the pool (instruction
 * `pool_ix`'s first account), which is not a signer. */
static void pump_redirect(std::vector<uint8_t>* raw, uint8_t ix, uint8_t slot,
                          uint8_t pool_ix) {
  SolanaParsedTx tx;
  ASSERT_NE(solana_inspectTx(raw->data(), raw->size(), &tx),
            SOL_TX_REVIEW_MALFORMED);
  const uint8_t pool = tx.instructions[pool_ix].acct_indices[0];
  const size_t off = tx.instructions[ix].acct_indices + slot - raw->data();
  (*raw)[off] = pool;
}

TEST(Solana, CertifiedRealPumpSellAdmitsSignerWrapAndUnwrap) {
  std::vector<uint8_t> raw = solana_unhex(kPumpSellMessageHex);
  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw.data(), raw.size(), &tx),
            SOL_TX_REVIEW_OPAQUE);
  ASSERT_EQ(tx.num_instructions, 6);
  EXPECT_EQ(tx.instructions[3].type, SOL_INSTR_ATA_CREATE);
  EXPECT_EQ(tx.instructions[4].type, SOL_INSTR_UNKNOWN);
  EXPECT_EQ(tx.instructions[5].type, SOL_INSTR_TOKEN_CLOSE_ACCOUNT);
  uint8_t idx = 0xFF;
  ASSERT_TRUE(pump_certified(raw, kPumpAmmSellSchemaHex, &idx));
  EXPECT_EQ(idx, 4);
  /* Runtime (uncertified) schemas still refuse any non-inert companion. */
  const std::vector<uint8_t> blob = solana_unhex(kPumpAmmSellSchemaHex);
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob.data(), blob.size(), &s));
  EXPECT_FALSE(solana_schemaApplies(&s, &tx, &idx));
  /* The buy schema does not describe a sell. */
  EXPECT_FALSE(pump_certified(raw, kPumpAmmBuySchemaHex, &idx));

  /* Closing the account to anyone but the signer is refused. */
  std::vector<uint8_t> stolen = raw;
  pump_redirect(&stolen, 5, 1, 4);
  EXPECT_FALSE(pump_certified(stolen, kPumpAmmSellSchemaHex, &idx));
  /* So is creating an account the signer funds for another owner. */
  std::vector<uint8_t> gifted = raw;
  pump_redirect(&gifted, 3, 2, 4);
  EXPECT_FALSE(pump_certified(gifted, kPumpAmmSellSchemaHex, &idx));
}

/* A host that adds its own key as a second signer is not the user. Closing
 * the wSOL account to that key hands it the whole wrapped balance (the screen
 * would say "rent"), and the device must not create an account it owns. A
 * co-signer funding the user's own account is still admitted. */
TEST(Solana, CertifiedPumpSellRefusesCoSignerCloseAndCreate) {
  std::vector<uint8_t> raw = solana_unhex(kPumpSellMessageHex);
  ASSERT_EQ(raw[1], 1);
  raw[1] = 2; /* message key 1 signs too: the host's co-signer */
  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw.data(), raw.size(), &tx),
            SOL_TX_REVIEW_OPAQUE);
  ASSERT_TRUE(solana_signerInTx(tx.accounts[1], &tx));
  ASSERT_EQ(tx.instructions[3].type, SOL_INSTR_ATA_CREATE);
  ASSERT_EQ(tx.instructions[5].type, SOL_INSTR_TOKEN_CLOSE_ACCOUNT);
  ASSERT_NE(tx.instructions[5].acct_indices[0], 1);
  uint8_t idx = 0xFF;
  ASSERT_TRUE(pump_certified(raw, kPumpAmmSellSchemaHex, &idx));
  auto to_cosigner = [&](uint8_t ix, uint8_t slot) {
    std::vector<uint8_t> r = raw;
    r[tx.instructions[ix].acct_indices + slot - raw.data()] = 1;
    return r;
  };
  EXPECT_FALSE(pump_certified(to_cosigner(5, 1), kPumpAmmSellSchemaHex, &idx));
  EXPECT_FALSE(pump_certified(to_cosigner(3, 2), kPumpAmmSellSchemaHex, &idx));
  EXPECT_TRUE(pump_certified(to_cosigner(3, 0), kPumpAmmSellSchemaHex, &idx));
}

TEST(Solana, CertifiedRealPumpBuysAdmitWrapAndUnwrap) {
  uint8_t idx = 0xFF;
  std::vector<uint8_t> buy8 = solana_unhex(kPumpBuy8MessageHex);
  ASSERT_TRUE(pump_certified(buy8, kPumpAmmBuySchemaHex, &idx));
  EXPECT_EQ(idx, 6);

  /* Nine instructions: over the old cap of 8, which parsed none of them. */
  std::vector<uint8_t> buy9 = solana_unhex(kPumpBuy9MessageHex);
  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(buy9.data(), buy9.size(), &tx),
            SOL_TX_REVIEW_OPAQUE);
  ASSERT_EQ(tx.num_instructions, 9);
  idx = 0xFF;
  ASSERT_TRUE(pump_certified(buy9, kPumpAmmBuySchemaHex, &idx));
  EXPECT_EQ(idx, 7);
  EXPECT_FALSE(pump_certified(buy9, kPumpAmmSellSchemaHex, &idx));
}

/* ---- Human-readable intent review (SRS-7.16 §3.7) ---- */

namespace {
const uint8_t kPumpAmmProgram[32] = {
    0x0c, 0x14, 0xde, 0xfc, 0x82, 0x5e, 0xc6, 0x76, 0x94, 0x25, 0x08,
    0x18, 0xbb, 0x65, 0x40, 0x65, 0xf4, 0x29, 0x8d, 0x31, 0x56, 0xd5,
    0x71, 0xb4, 0xd4, 0xf8, 0x09, 0x0c, 0x18, 0xe9, 0xa8, 0x63};

struct V3Arg {
  uint8_t type;
  const char* label;
  int mint;  // -1 = not TOKEN_AMOUNT
  uint8_t role;
};

std::vector<uint8_t> v3_schema(
    const uint8_t program[32], const std::vector<uint8_t>& disc,
    const char* program_name, const char* instr, const std::vector<V3Arg>& args,
    const char* intent,
    const std::vector<std::pair<uint8_t, const char*>>& accounts = {}) {
  std::vector<uint8_t> p = {'K', 'K', 'S', 'O', 'L', 'S', 'C', '1', 3};
  p.insert(p.end(), program, program + 32);
  p.push_back((uint8_t)disc.size());
  p.insert(p.end(), disc.begin(), disc.end());
  auto text = [&](const char* t) {
    p.push_back((uint8_t)strlen(t));
    p.insert(p.end(), t, t + strlen(t));
  };
  text(program_name);
  text(instr);
  p.push_back((uint8_t)args.size());
  for (const V3Arg& a : args) {
    p.push_back(a.type);
    text(a.label);
    if (a.mint >= 0) p.push_back((uint8_t)a.mint);
    p.push_back(a.role);
  }
  p.push_back((uint8_t)accounts.size());
  for (const auto& a : accounts) {
    p.push_back(a.first);
    text(a.second);
  }
  if (intent) {
    text(intent);
  } else {
    p.push_back(0);
  }
  return p;
}

std::vector<uint8_t> pump_sell_v3(const char* intent) {
  return v3_schema(
      kPumpAmmProgram, {0x33, 0xe6, 0x85, 0xa4, 0x01, 0x7f, 0x83, 0xad},
      "Pump.fun", "Sell tokens",
      {{SOL_SCHEMA_ARG_TOKEN_AMOUNT, "You sell", 3, METADATA_ROLE_SPEND_EXACT},
       {SOL_SCHEMA_ARG_TOKEN_AMOUNT, "Receive at least", 4,
        METADATA_ROLE_RECEIVE_MIN}},
      intent);
}

struct Screen {
  std::string title, body;
};

bool collect(void* ctx, const char* title, const char* body,
             const uint8_t* bytes, uint16_t bytes_len) {
  auto* out = static_cast<std::vector<Screen>*>(ctx);
  out->push_back({title, bytes ? std::string((const char*)bytes, bytes_len)
                               : std::string(body)});
  return true;
}
}  // namespace

TEST(Solana, IntentReviewOfRealPumpSellMatchesTheSpec) {
  AlphaTestRoot alpha; /* kCert501Hex is signed by the alpha root */
  const std::vector<uint8_t> raw = solana_unhex(kPumpSellMessageHex);
  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw.data(), raw.size(), &tx),
            SOL_TX_REVIEW_OPAQUE);
  const std::vector<uint8_t> blob = pump_sell_v3("Sell {0} for at least {1}");
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob.data(), blob.size(), &s));
  EXPECT_EQ(s.version, 3);
  EXPECT_STREQ(s.intent, "Sell {0} for at least {1}");
  uint8_t idx = 0xFF;
  ASSERT_TRUE(solana_schemaAppliesCertified(&s, &tx, tx.accounts[0], &idx));
  ASSERT_EQ(idx, 4);

  static SolanaSignTx msg;  // certificate + signed SDICE identity
  ASSERT_NO_FATAL_FAILURE(fill_certified_soltoshi_join(&msg));
  std::vector<Screen> got;
  ASSERT_TRUE(solana_buildIntentReview(&msg, &tx, &s, idx, tx.accounts[0],
                                       "KeepKey Vault", "a9531b9d", true,
                                       collect, &got));
  const Screen want[] = {
      {"Pump.fun", "Sell 7738120.185405 SDICE for at least 8.509507889 SOL"},
      {"Limits",
       "You spend\n7738120.185405 SDICE\n"
       "4nCmpwne7hCoWTSpAd54uENmCgHJrHTyn4DMPCEMpump"},
      {"Limits", "You receive at least\n8.509507889 SOL"},
      {"Limits",
       "Also sends 0.001000000 SOL to\n"
       "DfXygSm4jCyNCybVYYK6DwvWqjKee8pbDmJGcLWNDXjh"},
      {"Limits", "Network fee up to 0.001005000 SOL"},
      {"Side effects", "Creates a temporary wSOL account, closed back to you"},
      {"KeepKey ClearSign",
       "Described by KeepKey Vault a9531b9d\n"
       "certified by KeepKey"},
  };
  ASSERT_EQ(got.size(), sizeof(want) / sizeof(want[0]));
  for (size_t i = 0; i < got.size(); i++) {
    EXPECT_EQ(got[i].title, want[i].title) << i;
    EXPECT_EQ(got[i].body, want[i].body) << i;
  }

  // Without the certified SDICE identity the amount stays raw with its mint.
  static SolanaSignTx bare;
  memset(&bare, 0, sizeof(bare));
  got.clear();
  ASSERT_TRUE(solana_buildIntentReview(&bare, &tx, &s, idx, tx.accounts[0],
                                       "KeepKey Vault", "a9531b9d", true,
                                       collect, &got));
  EXPECT_EQ(got[0].body,
            "Sell 7738120185405 base units for at least 8.509507889 SOL");
  EXPECT_EQ(got[1].body,
            "You spend\n7738120185405 base units\nof mint "
            "4nCmpwne7hCoWTSpAd54uENmCgHJrHTyn4DMPCEMpump");

  // Reviewed as another key (a co-signer's view): the device must not call
  // the wSOL account "yours" or say rent comes "back to you".
  static const uint8_t other[32] = {7};
  got.clear();
  ASSERT_TRUE(solana_buildIntentReview(&msg, &tx, &s, idx, other,
                                       "KeepKey Vault", "a9531b9d", true,
                                       collect, &got));
  for (const Screen& sc : got) {
    EXPECT_EQ(sc.body.find("back to you"), std::string::npos) << sc.body;
    EXPECT_EQ(sc.body.find("your "), std::string::npos) << sc.body;
  }
  // ...and the fee is shown with the full address of the account paying it.
  char payer[64];
  size_t payer_len = sizeof(payer);
  ASSERT_TRUE(b58enc(payer, &payer_len, tx.accounts[0], 32));
  EXPECT_NE(std::find_if(got.begin(), got.end(),
                         [&](const Screen& sc) {
                           return sc.body ==
                                  std::string(
                                      "Network fee up to 0.001005000 "
                                      "SOL\npaid by\n") +
                                      payer;
                         }),
            got.end());

  // Literal digits would be server-written values: refused.
  SolanaInstrSchema digits = s;
  strlcpy(digits.intent, "Sell {0} for at least {1}, about 100 SOL",
          sizeof(digits.intent));
  EXPECT_FALSE(solana_intentTemplateValid(&digits));

  // A template whose widest expansion overflows the summary (280) is refused at
  // parse, never truncated on screen (9 amounts x 34 > 280).
  SolanaInstrSchema wide = s;
  strlcpy(wide.intent, "{0}{1}{0}{1}{0}{1}{0}{1}{0}", sizeof(wide.intent));
  EXPECT_FALSE(solana_intentTemplateValid(&wide));
  strlcpy(wide.intent, "{0}{1}{0}{1}{0}{1}{0}{1}", sizeof(wide.intent));  // 272
  EXPECT_TRUE(solana_intentTemplateValid(&wide));

  // Runtime tier: a NOT-verified heading plus limits; the raw review follows.
  got.clear();
  ASSERT_TRUE(solana_buildIntentReview(&msg, &tx, &s, idx, tx.accounts[0],
                                       "Acme", "0011aabb", false, collect,
                                       &got));
  ASSERT_GE(got.size(), 2u);
  EXPECT_EQ(got[0].title, "Unverified");
  EXPECT_EQ(got[0].body,
            "Acme (NOT verified by KeepKey) says:\n"
            "Sell 7738120185405 base units for at least "
            "8.509507889 SOL");
  for (const Screen& sc : got) EXPECT_NE(sc.title, "KeepKey ClearSign");
}

TEST(Solana, IntentTemplateRejectsBadRolesCoverageAndPlaceholders) {
  SolanaInstrSchema s;
  auto parses = [&](const std::vector<uint8_t>& b) {
    return solana_parseInstrSchema(b.data(), b.size(), &s);
  };
  EXPECT_TRUE(parses(pump_sell_v3("Sell {0} for at least {1}")));
  EXPECT_TRUE(parses(pump_sell_v3(nullptr)));  // no template: generated summary
  EXPECT_FALSE(parses(pump_sell_v3("Sell {0}")));               // {1} uncovered
  EXPECT_FALSE(parses(pump_sell_v3("Sell {0} for {2}")));       // out of range
  EXPECT_FALSE(parses(pump_sell_v3("Sell {0} for {1} }")));     // stray brace
  EXPECT_FALSE(parses(pump_sell_v3("Sell {0} for {1x}")));      // malformed
  EXPECT_FALSE(parses(pump_sell_v3("Sell {0} for {a0} {1}")));  // no accounts
  EXPECT_FALSE(parses(pump_sell_v3("Sell {0} at 100% {1}")));   // '%'
  // An amount without a role, and a role on a non-amount, are rejected.
  const auto disc = std::vector<uint8_t>{1, 2, 3, 4, 5, 6, 7, 8};
  EXPECT_FALSE(parses(v3_schema(kPumpAmmProgram, disc, "P", "I",
                                {{SOL_SCHEMA_ARG_LAMPORTS, "Amount", -1, 0}},
                                "Pay {0}")));
  EXPECT_FALSE(
      parses(v3_schema(kPumpAmmProgram, disc, "P", "I",
                       {{SOL_SCHEMA_ARG_U8, "Seat", -1, 1}}, "Seat {0}")));
  EXPECT_TRUE(
      parses(v3_schema(kPumpAmmProgram, disc, "P", "I",
                       {{SOL_SCHEMA_ARG_U8, "Seat", -1, 0}}, "Seat {0}")));
}

TEST(Solana, IntentReviewCapRoleAndUnstatedValuesOnRealJoin) {
  AlphaTestRoot alpha; /* kCert501Hex is signed by the alpha root */
  const std::vector<uint8_t> raw = solana_unhex(kSoltoshiJoinMessageHex);
  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw.data(), raw.size(), &tx),
            SOL_TX_REVIEW_OPAQUE);
  static SolanaSignTx msg;
  ASSERT_NO_FATAL_FAILURE(fill_certified_soltoshi_join(&msg));
  SolanaInstrSchema v2;
  ASSERT_TRUE(solana_parseInstrSchema(msg.schema_payload.bytes,
                                      msg.schema_payload.size, &v2));
  const std::vector<uint8_t> blob = v3_schema(
      v2.program_id, {0x51}, "SoltoshiDICE", "Blackjack join",
      {{SOL_SCHEMA_ARG_U64, "Round", -1, 0},
       {SOL_SCHEMA_ARG_U64, "Revision", -1, 0},
       {SOL_SCHEMA_ARG_U8, "Seat", -1, 0},
       {SOL_SCHEMA_ARG_TOKEN_AMOUNT, "Buy-in", 3, METADATA_ROLE_SPEND_EXACT},
       {SOL_SCHEMA_ARG_PUBKEY, "Session key", -1, 0},
       {SOL_SCHEMA_ARG_DURATION, "Expires in", -1, 0},
       {SOL_SCHEMA_ARG_TOKEN_AMOUNT, "Allowance", 3, METADATA_ROLE_SPEND_MAX},
       {SOL_SCHEMA_ARG_TOKEN_AMOUNT, "Max wager", 3, METADATA_ROLE_CAP}},
      "Join blackjack seat {2} for {3}; key {4} may bet {7} each, {6} total, "
      "for {5}");
  SolanaInstrSchema s;
  ASSERT_TRUE(solana_parseInstrSchema(blob.data(), blob.size(), &s));
  uint8_t idx = 0xFF;
  ASSERT_TRUE(solana_schemaAppliesCertified(&s, &tx, tx.accounts[0], &idx));
  std::vector<Screen> got;
  ASSERT_TRUE(solana_buildIntentReview(&msg, &tx, &s, idx, tx.accounts[0],
                                       "KeepKey Vault", "a9531b9d", true,
                                       collect, &got));
  std::vector<std::string> bodies;
  for (const Screen& sc : got) bodies.push_back(sc.title + "|" + sc.body);
  auto has = [&](const std::string& line) {
    return std::find(bodies.begin(), bodies.end(), line) != bodies.end();
  };
  EXPECT_TRUE(
      has("SoltoshiDICE|Join blackjack seat 1 for 1000 SDICE; key "
          "BqtZ...cGjX may bet 1000 SDICE each, 1000 SDICE total, "
          "for 1 h"))
      << bodies[0];
  EXPECT_TRUE(
      has("Limits|Each use at most\n1000 SDICE\n"
          "4nCmpwne7hCoWTSpAd54uENmCgHJrHTyn4DMPCEMpump"));
  EXPECT_TRUE(
      has("Limits|You spend\n1000 SDICE\n"
          "4nCmpwne7hCoWTSpAd54uENmCgHJrHTyn4DMPCEMpump"));
  EXPECT_TRUE(
      has("Limits|You spend at most\n1000 SDICE\n"
          "4nCmpwne7hCoWTSpAd54uENmCgHJrHTyn4DMPCEMpump"));
  // Not in the sentence, so on details screens; the short key in full.
  EXPECT_TRUE(has("Round|86"));
  EXPECT_TRUE(has("Revision|980"));
  EXPECT_TRUE(has("Session key|BqtZ8PRQywD9Z5xXeB5112wtPG3xtj7TqF56hroicGjX"));
  EXPECT_FALSE(has("Seat|1"));  // stated in full in the sentence
}

/* Exact-text contract for the remaining review branches, on the real sell. */
TEST(Solana, IntentReviewAccountPlaceholderReceiveExactAndLegacyFallback) {
  AlphaTestRoot alpha; /* kCert501Hex is signed by the alpha root */
  const std::vector<uint8_t> raw = solana_unhex(kPumpSellMessageHex);
  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw.data(), raw.size(), &tx),
            SOL_TX_REVIEW_OPAQUE);
  static SolanaSignTx msg;
  ASSERT_NO_FATAL_FAILURE(fill_certified_soltoshi_join(&msg));
  auto review = [&](const std::vector<uint8_t>& blob) {
    SolanaInstrSchema s;
    std::vector<Screen> got;
    uint8_t idx = 0xFF;
    EXPECT_TRUE(solana_parseInstrSchema(blob.data(), blob.size(), &s));
    EXPECT_TRUE(solana_schemaAppliesCertified(&s, &tx, tx.accounts[0], &idx));
    EXPECT_TRUE(solana_buildIntentReview(&msg, &tx, &s, idx, tx.accounts[0],
                                         "KeepKey Vault", "a9531b9d", true,
                                         collect, &got));
    return got;
  };
  const std::vector<V3Arg> args = {
      {SOL_SCHEMA_ARG_TOKEN_AMOUNT, "You sell", 3, METADATA_ROLE_SPEND_EXACT},
      {SOL_SCHEMA_ARG_TOKEN_AMOUNT, "Receive", 4, METADATA_ROLE_RECEIVE_EXACT}};
  const std::vector<uint8_t> disc = {0x33, 0xe6, 0x85, 0xa4,
                                     0x01, 0x7f, 0x83, 0xad};

  // {aN}: shortened in the sentence, then in full on its own screen.
  std::vector<Screen> got =
      review(v3_schema(kPumpAmmProgram, disc, "Pump.fun", "Sell tokens", args,
                       "Sell {0} of {a0} for {1}", {{3, "Token"}}));
  EXPECT_EQ(got[0].body,
            "Sell 7738120.185405 SDICE of 4nCm...pump for 8.509507889 SOL");
  // RECEIVE_EXACT reads "You receive" with no "at least".
  EXPECT_EQ(got[2].title, "Limits");
  EXPECT_EQ(got[2].body, "You receive\n8.509507889 SOL");
  EXPECT_NE(
      std::find_if(got.begin(), got.end(),
                   [](const Screen& sc) {
                     return sc.title == "Token" &&
                            sc.body ==
                                "4nCmpwne7hCoWTSpAd54uENmCgHJrHTyn4DMPCEMpump";
                   }),
      got.end());

  // No template (every certified v1/v2 schema): the instruction name is the
  // summary and nothing the roles do not state is hidden.
  got = review(v3_schema(kPumpAmmProgram, disc, "Pump.fun", "Sell tokens", args,
                         nullptr));
  EXPECT_EQ(got[0].title, "Pump.fun");
  EXPECT_EQ(got[0].body, "Sell tokens");
  EXPECT_EQ(got[1].body,
            "You spend\n7738120.185405 SDICE\n"
            "4nCmpwne7hCoWTSpAd54uENmCgHJrHTyn4DMPCEMpump");
}
