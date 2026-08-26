extern "C" {
#include "keepkey/firmware/solana.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/ed25519-donna/ed25519.h"
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

TEST(Solana, FormatTokenAmountNeverShowsZeroForNonzero) {
  char buf[64];

  /* Zero decimals is already an exact base-unit/token count. */
  solana_formatTokenAmount(buf, sizeof(buf), 1, "tokens", 0);
  EXPECT_STREQ(buf, "1 tokens");

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

  /* The on-chain decimals field is a uint8_t and is not capped at 18. Values
     outside the formatter's supported range must retain their signed scale. */
  solana_formatTokenAmount(buf, sizeof(buf), 1, "tokens", 19);
  EXPECT_STREQ(buf, "1 base units (19 decimals) tokens");

  solana_formatTokenAmount(buf, sizeof(buf), 0, "tokens", 255);
  EXPECT_STREQ(buf, "0 base units (255 decimals) tokens");

  /* The production caller also uses 64 bytes, so the longest fallback is not
     silently truncated before it reaches the confirmation pager. */
  solana_formatTokenAmount(buf, sizeof(buf), UINT64_MAX, "tokens", 255);
  EXPECT_STREQ(buf, "18446744073709551615 base units (255 decimals) tokens");
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

TEST(Solana, RecognizedInstructionMissingAccountsIsOpaque) {
  uint8_t raw[160];
  size_t pos = 0;
  raw[pos++] = 1; /* one required signer */
  raw[pos++] = 0;
  raw[pos++] = 1; /* system program is readonly */
  raw[pos++] = 2; /* signer + system program */
  memset(raw + pos, 0x11, SOL_PUBKEY_SIZE);
  pos += SOL_PUBKEY_SIZE;
  memcpy(raw + pos, SOL_SYSTEM_PROGRAM, SOL_PUBKEY_SIZE);
  pos += SOL_PUBKEY_SIZE;
  memset(raw + pos, 0xBB, SOL_PUBKEY_SIZE);
  pos += SOL_PUBKEY_SIZE;
  raw[pos++] = 1; /* one instruction */
  raw[pos++] = 1; /* system program */
  raw[pos++] = 1; /* only source; destination is missing */
  raw[pos++] = 0;
  raw[pos++] = 12;
  raw[pos++] = SOL_SYS_TRANSFER;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  memset(raw + pos, 0, 8);
  pos += 8;

  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);
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
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
  ASSERT_FALSE(solana_parseTx(raw, pos, &tx));

  EXPECT_EQ(tx.num_instructions, 1);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_TRANSFER);
  EXPECT_EQ(tx.instructions[0].amount, 1000000ULL);
}

/* Build a one-instruction transaction against the SPL Token program whose
   instruction data is exactly `data`. Returns the raw length. */
static size_t BuildTokenTx(uint8_t* raw, const uint8_t* data, size_t data_len) {
  size_t pos = 0;
  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;

  raw[pos++] = 5; /* 5 accounts */
  memset(raw + pos, 0x11, 32);
  pos += 32; /* source ATA */
  memset(raw + pos, 0x22, 32);
  pos += 32; /* mint */
  memset(raw + pos, 0x33, 32);
  pos += 32; /* dest ATA */
  memset(raw + pos, 0x44, 32);
  pos += 32; /* authority */
  memcpy(raw + pos, SOL_TOKEN_PROGRAM, 32);
  pos += 32; /* token program */

  memset(raw + pos, 0xBB, 32);
  pos += 32; /* blockhash */

  raw[pos++] = 1; /* 1 instruction */
  raw[pos++] = 4; /* program index = token program */
  raw[pos++] = 4; /* 4 account indices */
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 2;
  raw[pos++] = 3;
  raw[pos++] = (uint8_t)data_len;
  memcpy(raw + pos, data, data_len);
  pos += data_len;
  return pos;
}

TEST(Solana, OverlongFixedLayoutInstructionIsOpaque) {
  /* A recognised instruction whose data field is LONGER than its on-chain
     layout used to decode anyway: the prefix was read and confirmed, the tail
     was signed with solana_signTx() covering the whole raw_tx, and -- the part
     that actually mattered -- has_unknown was never set, so the transaction
     was classified VERIFIED and never met the opaque/blind-sign path. The
     appended bytes appeared on no screen and cost the sender nothing, because
     SPL's unpack reads its fields and drops the tail.

     solana_inspectTx() rather than solana_parseTx() throughout: parseTx is
     just `inspectTx == VERIFIED`, so it cannot distinguish "decoded as opaque"
     from "malformed", which is the whole distinction under test here. */
  SolanaParsedTx tx;
  uint8_t raw[512];
  size_t len;

  /* TransferChecked is exactly 10 bytes: tag + u64 amount + decimals. */
  static const uint8_t kExact[10] = {12, 0x40, 0x42, 0x0F, 0, 0, 0, 0, 0, 6};
  len = BuildTokenTx(raw, kExact, sizeof(kExact));
  ASSERT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_VERIFIED);
  ASSERT_EQ(tx.num_instructions, 1);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_TRANSFER_CHECKED);
  EXPECT_EQ(tx.instructions[0].amount, 1000000ULL);
  EXPECT_EQ(tx.instructions[0].extra_u8, 6);

  /* One appended byte. Same displayed amount, same displayed decimals, one
     more signed byte -- and that must be enough to lose clear-signing. */
  static const uint8_t kOverlong[11] = {12, 0x40, 0x42, 0x0F, 0,   0,
                                        0,  0,    0,    6,    0xAB};
  len = BuildTokenTx(raw, kOverlong, sizeof(kOverlong));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);

  /* Short is refused as it always was; the rule is now symmetric. */
  static const uint8_t kShort[9] = {12, 0x40, 0x42, 0x0F, 0, 0, 0, 0, 0};
  len = BuildTokenTx(raw, kShort, sizeof(kShort));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);

  /* Plain Transfer is 9 bytes and follows the same rule. */
  static const uint8_t kTransfer9[9] = {3, 0x40, 0x42, 0x0F, 0, 0, 0, 0, 0};
  len = BuildTokenTx(raw, kTransfer9, sizeof(kTransfer9));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_TRANSFER);

  static const uint8_t kTransfer10[10] = {3, 0x40, 0x42, 0x0F, 0,
                                          0, 0,    0,    0,    0x99};
  len = BuildTokenTx(raw, kTransfer10, sizeof(kTransfer10));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);

  /* Revoke carries a tag and nothing else. */
  static const uint8_t kRevoke[1] = {5};
  len = BuildTokenTx(raw, kRevoke, sizeof(kRevoke));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_VERIFIED);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_REVOKE);

  static const uint8_t kRevokePadded[2] = {5, 0x00};
  len = BuildTokenTx(raw, kRevokePadded, sizeof(kRevokePadded));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);

  /* SetAuthority: the COption discriminant and the length must agree. */
  static const uint8_t kSetAuthNone[3] = {6, 2, 0};
  len = BuildTokenTx(raw, kSetAuthNone, sizeof(kSetAuthNone));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_SET_AUTHORITY);

  uint8_t set_auth_some[35] = {6, 2, 1};
  memset(set_auth_some + 3, 0x77, 32);
  len = BuildTokenTx(raw, set_auth_some, sizeof(set_auth_some));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_SET_AUTHORITY);

  /* "Some" with no key, and "None" carrying one, are both refused. */
  static const uint8_t kSetAuthSomeNoKey[3] = {6, 2, 1};
  len = BuildTokenTx(raw, kSetAuthSomeNoKey, sizeof(kSetAuthSomeNoKey));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);

  uint8_t set_auth_none_with_key[35] = {6, 2, 0};
  memset(set_auth_none_with_key + 3, 0x77, 32);
  len =
      BuildTokenTx(raw, set_auth_none_with_key, sizeof(set_auth_none_with_key));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_UNKNOWN);
}

TEST(Solana, Token2022TransferCheckedIsOpaque) {
  uint8_t raw[512];
  static const uint8_t kChecked[10] = {12, 0x40, 0x42, 0x0F, 0, 0, 0, 0, 0, 6};
  size_t len = BuildTokenTx(raw, kChecked, sizeof(kChecked));
  /* BuildTokenTx stores the program as account index 4. */
  memcpy(raw + 4 + (4 * SOL_PUBKEY_SIZE), SOL_TOKEN_2022_PROGRAM,
         SOL_PUBKEY_SIZE);
  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_TRANSFER_CHECKED);
}

TEST(Solana, TokenMintAndBurnRemainOpaqueWithoutOpcodeBoundDisplay) {
  uint8_t raw[512];
  SolanaParsedTx tx;

  static const uint8_t kMintUnchecked[9] = {7, 1, 0, 0, 0, 0, 0, 0, 0};
  size_t len = BuildTokenTx(raw, kMintUnchecked, sizeof(kMintUnchecked));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_MINT_TO);

  static const uint8_t kMintChecked[10] = {14, 1, 0, 0, 0, 0, 0, 0, 0, 6};
  len = BuildTokenTx(raw, kMintChecked, sizeof(kMintChecked));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_MINT_TO);
  EXPECT_EQ(tx.instructions[0].extra_u8, 6);

  static const uint8_t kBurnUnchecked[9] = {8, 1, 0, 0, 0, 0, 0, 0, 0};
  len = BuildTokenTx(raw, kBurnUnchecked, sizeof(kBurnUnchecked));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_BURN);

  static const uint8_t kBurnChecked[10] = {15, 1, 0, 0, 0, 0, 0, 0, 0, 6};
  len = BuildTokenTx(raw, kBurnChecked, sizeof(kBurnChecked));
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_TOKEN_BURN);
  EXPECT_EQ(tx.instructions[0].extra_u8, 6);
}

static size_t BuildVoteUpdateValidatorTx(uint8_t* raw, uint16_t data_len) {
  size_t pos = 0;
  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 4;
  memset(raw + pos, 0x11, 32);
  pos += 32; /* vote account */
  memset(raw + pos, 0x22, 32);
  pos += 32; /* new validator identity */
  memset(raw + pos, 0x33, 32);
  pos += 32; /* authority */
  memcpy(raw + pos, SOL_VOTE_PROGRAM, 32);
  pos += 32;
  memset(raw + pos, 0xBB, 32);
  pos += 32;
  raw[pos++] = 1;
  raw[pos++] = 3;
  raw[pos++] = 3;
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 2;
  raw[pos++] = (uint8_t)data_len;
  raw[pos++] = 4; /* UpdateValidatorIdentity, little-endian u32 */
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  for (uint16_t i = 4; i < data_len; i++) raw[pos++] = 0x77;
  return pos;
}

TEST(Solana, VoteUpdateValidatorReadsAccountNotData) {
  uint8_t raw[512];
  size_t len = BuildVoteUpdateValidatorTx(raw, 4);
  SolanaParsedTx tx;
  ASSERT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_VERIFIED);
  uint8_t expected[32];
  memset(expected, 0x22, sizeof(expected));
  EXPECT_EQ(0, memcmp(tx.instructions[0].extra, expected, sizeof(expected)));

  len = BuildVoteUpdateValidatorTx(raw, 36);
  EXPECT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_OPAQUE);
}

TEST(Solana, PriorityFeeCalculationIsRoundedAndOverflowSafe) {
  SolanaParsedTx tx;
  memset(&tx, 0, sizeof(tx));
  tx.num_instructions = 2;
  tx.instructions[0].type = SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT;
  tx.instructions[0].extra_value = 1400000;
  tx.instructions[1].type = SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE;
  tx.instructions[1].extra_value = 50000000;
  uint64_t fee = 0;
  bool has_fee = false;
  ASSERT_TRUE(solana_calculatePriorityFee(&tx, &fee, &has_fee));
  EXPECT_TRUE(has_fee);
  EXPECT_EQ(fee, 70000000ULL);

  /* No explicit limit uses the protocol maximum so the displayed liability
     cannot understate the fee. */
  tx.num_instructions = 1;
  tx.instructions[0].type = SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE;
  tx.instructions[0].extra_value = 2000000;
  ASSERT_TRUE(solana_calculatePriorityFee(&tx, &fee, &has_fee));
  EXPECT_TRUE(has_fee);
  EXPECT_EQ(fee, 2800000ULL);

  tx.num_instructions = 2;
  tx.instructions[0].type = SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT;
  tx.instructions[0].extra_value = 1;
  tx.instructions[1].type = SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE;
  tx.instructions[1].extra_value = 1;
  ASSERT_TRUE(solana_calculatePriorityFee(&tx, &fee, &has_fee));
  EXPECT_EQ(fee, 1ULL); /* ceil(1 micro-lamport) */

  tx.instructions[0].extra_value = UINT32_MAX;
  tx.instructions[1].extra_value = UINT64_MAX;
  EXPECT_FALSE(solana_calculatePriorityFee(&tx, &fee, &has_fee));

  tx.instructions[0].type = SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE;
  EXPECT_FALSE(solana_calculatePriorityFee(&tx, &fee, &has_fee));
}

TEST(Solana, ParseAssociatedTokenAccountCreate) {
  uint8_t raw[512];
  size_t pos = 0;

  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;

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
  pos += 32; /* system program account */
  memcpy(raw + pos, SOL_TOKEN_PROGRAM, 32);
  pos += 32; /* legacy token program account */
  memcpy(raw + pos, SOL_ATA_PROGRAM, 32);
  pos += 32; /* program */

  memset(raw + pos, 0xBB, 32);
  pos += 32;

  raw[pos++] = 1;
  raw[pos++] = 6; /* ata program */
  raw[pos++] = 6; /* 6 canonical account indices */
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 2;
  raw[pos++] = 3;
  raw[pos++] = 4;
  raw[pos++] = 5;
  raw[pos++] = 0; /* empty data */

  SolanaParsedTx tx;
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_VERIFIED);
  ASSERT_TRUE(solana_parseTx(raw, pos, &tx));
  EXPECT_EQ(tx.instructions[0].type, SOL_INSTR_ATA_CREATE);
  EXPECT_TRUE(tx.instructions[0].has_mint);

  /* The token-program account is security-relevant even though the invoked
   * instruction belongs to the ATA program. Token-2022 ATA creation is not
   * presented as a verified legacy account creation. */
  memcpy(raw + 4 + (5 * SOL_PUBKEY_SIZE), SOL_TOKEN_2022_PROGRAM,
         SOL_PUBKEY_SIZE);
  EXPECT_EQ(solana_inspectTx(raw, pos, &tx), SOL_TX_REVIEW_OPAQUE);
}

static size_t BuildAuthorizeTx(uint8_t* raw, const uint8_t* program,
                               uint32_t instruction) {
  size_t pos = 0;
  raw[pos++] = 1;
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 4;
  memset(raw + pos, 0x11, 32);
  pos += 32; /* stake/vote account */
  memset(raw + pos, 0x22, 32);
  pos += 32; /* clock sysvar */
  memset(raw + pos, 0x33, 32);
  pos += 32; /* current authority */
  memcpy(raw + pos, program, 32);
  pos += 32;
  memset(raw + pos, 0xBB, 32);
  pos += 32;
  raw[pos++] = 1;
  raw[pos++] = 3;
  raw[pos++] = 3;
  raw[pos++] = 0;
  raw[pos++] = 1;
  raw[pos++] = 2;
  raw[pos++] = 40;
  raw[pos++] = (uint8_t)instruction;
  raw[pos++] = 0;
  raw[pos++] = 0;
  raw[pos++] = 0;
  memset(raw + pos, 0x44, 32); /* new authority */
  pos += 32;
  memset(raw + pos, 0, 4); /* staker/voter role */
  pos += 4;
  return pos;
}

TEST(Solana, AuthorizeUsesAuthorityNotClockSysvar) {
  uint8_t raw[512];
  uint8_t expected[32];
  memset(expected, 0x33, sizeof(expected));
  SolanaParsedTx tx;

  size_t len = BuildAuthorizeTx(raw, SOL_STAKE_PROGRAM, SOL_STAKE_AUTHORIZE_IX);
  ASSERT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_VERIFIED);
  EXPECT_EQ(0,
            memcmp(tx.instructions[0].authority, expected, sizeof(expected)));

  len = BuildAuthorizeTx(raw, SOL_VOTE_PROGRAM, SOL_VOTE_AUTHORIZE_IX);
  ASSERT_EQ(solana_inspectTx(raw, len, &tx), SOL_TX_REVIEW_VERIFIED);
  EXPECT_EQ(0,
            memcmp(tx.instructions[0].authority, expected, sizeof(expected)));
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
