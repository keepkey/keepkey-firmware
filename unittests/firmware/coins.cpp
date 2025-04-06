extern "C" {
#include "keepkey/firmware/coins.h"
#ifndef BITCOIN_ONLY
#include "keepkey/firmware/ethereum_tokens.h"
#endif // BITCOIN_ONLY
}

#include "gtest/gtest.h"

#include <sstream>
#include <string>
#include <cstring>

static const int MaxLength = 256;

template <int size>
static std::string arrayToStr(const uint32_t (&address_n)[size]) {
  std::string str;
  std::stringstream OS(str);
  OS << "{";
  for (int i = 0; i < size; ++i) {
    OS << address_n[i];
    if (i + 1 != size) OS << ", ";
  }
  OS << "}";
  return OS.str();
}

TEST(Coins, Bip32PathToString) {
  struct {
    uint32_t address_n[10];
    size_t address_n_count;
    std::string expected;
  } vector[] = {
      {{0x80000000 | 44, 0x80000000 | 0, 0x80000000 | 0, 0, 0},
       5,
       "m/44'/0'/0'/0/0"},
      {{0x80000000 | 44, 0x80000000 | 0, 0x80000000 | 0}, 3, "m/44'/0'/0'"},
      {{}, 0, "m/"},
      {{0}, 1, "m/0"},
      {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 10, "m/0/0/0/0/0/0/0/0/0/0"},
      {{0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff},
       10,
       "m/2147483647'/2147483647'/2147483647'/2147483647'/2147483647'/"
       "2147483647'/2147483647'/2147483647'/2147483647'/2147483647'"},
  };

  for (const auto &vec : vector) {
    // Check that we get it right when provided with exactly enough characters.
    std::vector<char> exact_len(vec.expected.size() + 1);
    ASSERT_TRUE(bip32_path_to_string(&exact_len[0], exact_len.size(),
                                     &vec.address_n[0], vec.address_n_count))
        << vec.expected;
    ASSERT_EQ(&exact_len[0], vec.expected)
        << "address_n:       " << arrayToStr(vec.address_n) << "\n"
        << "address_n_count: " << vec.address_n_count << "\n";

    // Check that we report success iff we were able to write the whole string.
    for (int i = 0; i < MaxLength; ++i) {
      char str[MaxLength];
      memset(str, 0, sizeof(str));
      if (bip32_path_to_string(&str[0], i, &vec.address_n[0],
                               vec.address_n_count)) {
        ASSERT_EQ(&str[0], vec.expected)
            << "address_n:       " << arrayToStr(vec.address_n) << "\n"
            << "address_n_count: " << vec.address_n_count << "\n"
            << "i:               " << i << "\n";
      }
    }
  }
}

TEST(Coins, TableSanity) {
  for (int i = 0; i < COINS_COUNT; ++i) {
    const auto &coin = coins[i];

    if (!coin.has_contract_address) continue;
#ifndef BITCOIN_ONLY
    const TokenType *token;
    if (!tokenByTicker(1, coin.coin_shortcut, &token)) {
      EXPECT_TRUE(false) << "Can't uniquely find " << coin.coin_shortcut;
      continue;
    }

    EXPECT_TRUE(memcmp(coin.contract_address.bytes, token->address,
                       coin.contract_address.size) == 0)
        << "Contract address mismatch for " << coin.coin_shortcut;
#endif // BITCOIN_ONLY
  }
}

TEST(Coins, BIP32AccountName) {
  struct {
    const char *coin_name;
    uint32_t address_n[10];
    size_t address_n_count;
    bool expected;
    std::string text;
  } vector[] = {{"Bitcoin",
                 {0x80000000 | 44, 0x80000000 | 0, 0x80000000 | 0, 0, 0},
                 5,
                 true,
                 "Bitcoin Account #0\nAddress #0"},
                {"Bitcoin",
                 {0x80000000 | 44, 0x80000000 | 0, 0x80000000 | 0, 0, 1},
                 5,
                 true,
                 "Bitcoin Account #0\nAddress #1"},
                {"Bitcoin",
                 {0x80000000 | 44, 0x80000000 | 0, 0x80000000 | 0, 1, 0},
                 5,
                 true,
                 "Bitcoin Account #0\nChange Address #0"},
                {"Bitcoin",
                 {0x80000000 | 44, 0x80000000 | 0, 0x80000000 | 0, 1, 1},
                 5,
                 true,
                 "Bitcoin Account #0\nChange Address #1"},
                {"Bitcoin",
                 {0x80000000 | 44, 0x80000000 | 0, 0x80000000 | 1, 2, 0},
                 5,
                 false,
                 ""},
                {"Bitcoin",
                 {0x80000000 | 44, 0x80000000 | 0, 0x80000000 | 1, 2, 1},
                 5,
                 false,
                 ""},
                {"Bitcoin",
                 {0x80000000 | 44, 0x80000000 | 0, 0x80000000 | 1, 1, 1, 1},
                 6,
                 false,
                 ""},
                {"Bitcoin",
                 {0x80000000 | 44, 0x80000000 | 0, 0x80000000 | 1, 1, 1},
                 5,
                 true,
                 "Bitcoin Account #1\nChange Address #1"},
#ifndef  BITCOIN_ONLY
                {"Ethereum",
                 {0x80000000 | 44, 0x80000000 | 60, 0x80000000 | 1, 0, 0},
                 5,
                 true,
                 "Ethereum Account #1"},
                {"SALT",
                 {0x80000000 | 44, 0x80000000 | 60, 0x80000000 | 1, 0, 0},
                 5,
                 true,
                 "Ethereum Account #1"},
                {"Ethereum",
                 {0x80000000 | 44, 0x80000000 | 60, 0x80000000 | 1, 1, 0},
                 5,
                 false,
                 ""},
                {"Ethereum",
                 {0x80000000 | 44, 0x80000000 | 60, 0x80000000 | 1, 0, 1},
                 5,
                 false,
                 ""},
                {"EOS",
                 {0x80000000 | 44, 0x80000000 | 194, 0x80000000 | 0, 0, 0},
                 5,
                 true,
                 "EOS Account #0"},
                {"EOS",
                 {0x80000000 | 44, 0x80000000 | 194, 0x80000000 | 42, 0, 0},
                 5,
                 true,
                 "EOS Account #42"},
                {"Cosmos",
                 {0x80000000 | 44, 0x80000000 | 118, 0x80000000 | 9, 0, 0},
                 5,
                 true,
                 "Cosmos Account #9"},
                {"THORChain",
                 {0x80000000 | 44, 0x80000000 | 931, 0x80000000 | 69, 0, 0},
                 5,
                 true,
                 "THORChain Account #69"},
                {"MAYAChain",
                 {0x80000000 | 44, 0x80000000 | 931, 0x80000000 | 69, 0, 0},
                 5,
                 true,
                 "MAYAChain Account #69"}
#endif // BITCOIN_ONLY
              };

  for (const auto &vec : vector) {
    char node_str[NODE_STRING_LENGTH];
    memset(node_str, 0, sizeof(node_str));
    ASSERT_EQ(bip32_node_to_string(node_str, sizeof(node_str),
                                   coinByName(vec.coin_name), vec.address_n,
                                   vec.address_n_count,
                                   /*whole_account=*/false,
                                   /*show_addridx=*/true),
              vec.expected)
        << "element: " << (&vec - &vector[0]) << "\n"
        << "coin: " << vec.coin_name << "\n"
        << "expected: " << vec.expected << "\n"
        << "text:     \"" << vec.text << "\n"
        << "node_str: \"" << node_str << "\n";
    if (vec.expected) {
      EXPECT_EQ(vec.text, node_str);
    }
  }
}

#ifndef BITCOIN_ONLY
TEST(Coins, CoinByNameOrTicker) {
  const CoinType *ticker = coinByNameOrTicker("ZRX");
  const CoinType *name = coinByNameOrTicker("0x");
  ASSERT_NE(ticker, nullptr);
  ASSERT_NE(name, nullptr);
  ASSERT_EQ(name, ticker);
  EXPECT_EQ(ticker->coin_name, std::string("0x"));
}

TEST(Coins, CoinByChainAddress) {
  const CoinType *zrx = coinByChainAddress(1, (const uint8_t*)"\xE4\x1d\x24\x89\x57\x1d\x32\x21\x89\x24\x6D\xaF\xA5\xeb\xDe\x1F\x46\x99\xF4\x98");
  ASSERT_NE(zrx, nullptr);
  EXPECT_EQ(zrx->coin_name, std::string("0x"));
  EXPECT_EQ(zrx->coin_shortcut, std::string("ZRX"));
}

TEST(Coins, TokenByChainAddress) {
  const TokenType *zrx = tokenByChainAddress(1, (const uint8_t*)"\xE4\x1d\x24\x89\x57\x1d\x32\x21\x89\x24\x6D\xaF\xA5\xeb\xDe\x1F\x46\x99\xF4\x98");
  ASSERT_NE(zrx, nullptr);
  EXPECT_EQ(zrx->ticker, std::string(" ZRX"));
}
#endif // BITCOIN_ONLY