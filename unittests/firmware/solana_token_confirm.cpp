#include "gtest/gtest.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include "keepkey/board/confirm_sm.h"
#include "keepkey/firmware/solana.h"
}

namespace {
std::vector<std::string> screens;
size_t reject_screen;

bool capture_confirm(ButtonRequestType, const char*, const char* format, ...) {
  char body[256];
  va_list args;
  va_start(args, format);
  vsnprintf(body, sizeof(body), format, args);
  va_end(args);
  screens.emplace_back(body);
  return screens.size() != reject_screen;
}
}  // namespace

// Compile the production presenter against a capture of its actual confirm()
// calls. No formatter or expected screen text is substituted by the test.
#define confirm capture_confirm
extern "C" {
#include "solana_token_confirm.h"
}
#undef confirm

class SolanaTokenConfirm : public ::testing::Test {
 protected:
  void SetUp() override {
    screens.clear();
    reject_screen = 0;
    instruction.type = SOL_INSTR_TOKEN_TRANSFER_CHECKED;
    instruction.has_mint = true;
    instruction.amount = 2000;
    instruction.extra_u8 = 6;
    memset(instruction.from, 0x11, 32);
    memset(instruction.mint, 0x22, 32);
    memset(wallet, 0x33, sizeof(wallet));
    ASSERT_TRUE(solana_deriveAssociatedTokenAddress(
        wallet, SOL_TOKEN_PROGRAM, instruction.mint, instruction.to));
    SolanaSignTx msg = SolanaSignTx_init_zero;
    msg.token_recipient_owner_count = 1;
    msg.token_recipient_owner[0].size = sizeof(wallet);
    memcpy(msg.token_recipient_owner[0].bytes, wallet, sizeof(wallet));
    ASSERT_TRUE(solana_findTokenRecipientOwner(
        &msg, SOL_TOKEN_PROGRAM, instruction.mint, instruction.to, matched));
  }

  std::string address(const uint8_t* bytes) {
    char text[45];
    solana_pubkeyToStr(bytes, text, sizeof(text));
    return text;
  }

  SolanaParsedInstruction instruction = {};
  uint8_t wallet[32] = {};
  uint8_t matched[32] = {};
};

TEST_F(SolanaTokenConfirm, AtaDerivationDoesNotAssertCurrentAuthority) {
  // An ATA keeps its address after SetAuthority. Successful PDA matching
  // therefore cannot establish who currently controls the destination.
  ASSERT_TRUE(solana_confirmTokenTransfer(&instruction, "Instr 1/1", matched));
  for (const auto& screen : screens) {
    EXPECT_EQ(std::string::npos, screen.find("Token account of"));
  }
  ASSERT_EQ(5u, screens.size());
  EXPECT_EQ("Source token account\n" + address(instruction.from), screens[0]);
  EXPECT_EQ("Token mint\n" + address(instruction.mint), screens[1]);
  EXPECT_EQ("Address derived for\n" + address(wallet), screens[2]);
  EXPECT_EQ("Current token account owner\nnot verified", screens[3]);
  EXPECT_EQ("Send 0.002000 tokens to " + address(instruction.to) + "?",
            screens[4]);
}

TEST_F(SolanaTokenConfirm, NoMatchingWalletKeepsSignedDestination) {
  ASSERT_TRUE(solana_confirmTokenTransfer(&instruction, "Instr 1/1", nullptr));
  ASSERT_EQ(3u, screens.size());
  EXPECT_EQ("Send 0.002000 tokens to " + address(instruction.to) + "?",
            screens.back());
}

TEST_F(SolanaTokenConfirm, EachTokenScreenCanCancel) {
  for (size_t screen = 1; screen <= 5; ++screen) {
    screens.clear();
    reject_screen = screen;
    EXPECT_FALSE(
        solana_confirmTokenTransfer(&instruction, "Instr 1/1", matched));
    EXPECT_EQ(screen, screens.size());
  }
}
