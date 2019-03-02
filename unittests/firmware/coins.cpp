extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/ethereum_tokens.h"
}

#include "gtest/gtest.h"

#include <sstream>
#include <string>
#include <cstring>

static const int MaxLength = 256;

template<int size>
static std::string arrayToStr(const uint32_t (&address_n)[size]) {
    std::string str;
    std::stringstream OS(str);
    OS << "{";
    for (int i = 0; i < size; ++i) {
        OS << address_n[i];
        if (i + 1 != size)
            OS << ", ";
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
        {{ 0x80000000 | 44, 0x80000000 | 0, 0x80000000 | 0, 0, 0 }, 5, "m/44'/0'/0'/0/0"},
        {{ 0x80000000 | 44, 0x80000000 | 0, 0x80000000 | 0 },       3, "m/44'/0'/0'"},
        {{ }, 0, "m/"},
        {{ 0 }, 1, "m/0"},
        {{ 0,0,0,0,0,0,0,0,0,0 }, 10, "m/0/0/0/0/0/0/0/0/0/0" },
        {{ 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
           0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff}, 10,
         "m/2147483647'/2147483647'/2147483647'/2147483647'/2147483647'/2147483647'/2147483647'/2147483647'/2147483647'/2147483647'"},
    };

    for (const auto &vec : vector) {
        // Check that we get it right when provided with exactly enough characters.
        std::vector<char> exact_len(vec.expected.size() + 1);
        ASSERT_TRUE(bip32_path_to_string(&exact_len[0], exact_len.size(), &vec.address_n[0], vec.address_n_count))
            << vec.expected;
        ASSERT_EQ(&exact_len[0], vec.expected)
            << "address_n:       " << arrayToStr(vec.address_n) << "\n"
            << "address_n_count: " << vec.address_n_count << "\n";

        // Check that we report success iff we were able to write the whole string.
        for (int i = 0; i < MaxLength; ++i) {
            char str[MaxLength];
            memset(str, 0, sizeof(str));
            if (bip32_path_to_string(&str[0], i, &vec.address_n[0], vec.address_n_count)) {
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

        if (!coin.has_contract_address)
            continue;

        const TokenType *token;
        if (!tokenByTicker(1, coin.coin_shortcut, &token)) {
            EXPECT_TRUE(false)
                << "Can't uniquely find " << coin.coin_shortcut;
            continue;
        }

        EXPECT_TRUE(memcmp(coin.contract_address.bytes, token->address,
                           coin.contract_address.size) == 0)
            << "Contract address mismatch for " << coin.coin_shortcut;
    }
}

TEST(Coins, SLIP48) {
    struct {
        const char *coin_name;
        uint32_t address_n[10];
        size_t address_n_count;
        SLIP48Role role;
        bool isSLIP48;
        std::string text;
    } vector[] = {
        {
          "EOS",
          { 0x80000000|48, 0x80000000|4, 0x80000000|0, 0x80000000|0, 0x80000000|0 },
          5, SLIP48_owner, true, "EOS Account #0 @owner key #0"
        },
        {
          "EOS",
          { 0x80000000|48, 0x80000000|4, 0x80000000|1, 0x80000000|3, 0x80000000|5 },
          5, SLIP48_active, true, "EOS Account #3 @active key #5"
        },
        {
          "EOS",
          { 0x80000000|48, 0x80000000|4, 0x80000000|1, 0x80000000|7, 0x80000000|0 },
          5, SLIP48_active, true, "EOS Account #7 @active key #0"
        },
        {
          "EOS",
          { 0x80000000|48, 0x80000000|4, 0x80000000|1, 0x80000000|0, 0x80000000|0 },
          4, SLIP48_UNKNOWN, false, ""
        },
    };

    for (const auto &vec : vector) {
        EXPECT_EQ(coin_isSLIP48(coinByName(vec.coin_name), vec.address_n,
                                vec.address_n_count, vec.role), vec.isSLIP48);

        if (vec.isSLIP48) {
            char node_str[NODE_STRING_LENGTH];
            ASSERT_TRUE(bip32_node_to_string(node_str, sizeof(node_str),
                                             coinByName(vec.coin_name),
                                             vec.address_n,
                                             vec.address_n_count,
                                             /*whole_account=*/false,
                                             /*allow_change=*/false,
                                             /*show_addrix=*/true))
                << vec.text;
            EXPECT_EQ(vec.text, node_str);
        }
    }
}

TEST(Coins, BIP32AccountName) {
    struct {
        const char *coin_name;
        uint32_t address_n[10];
        size_t address_n_count;
        bool allow_change;
        bool expected;
        std::string text;
    } vector[] = {
        {
          "Bitcoin",
          { 0x80000000|44, 0x80000000|0, 0x80000000|0, 0, 0 },
          5, false, true, "Bitcoin Account #0\nAddress #0"
        },
        {
          "Bitcoin",
          { 0x80000000|44, 0x80000000|0, 0x80000000|0, 0, 1 },
          5, false, true, "Bitcoin Account #0\nAddress #1"
        },
        {
          "Bitcoin",
          { 0x80000000|44, 0x80000000|0, 0x80000000|1, 0, 0 },
          5, false, true, "Bitcoin Account #1\nAddress #0"
        },
        {
          "Bitcoin",
          { 0x80000000|44, 0x80000000|0, 0x80000000|1, 0, 1 },
          5, false, true, "Bitcoin Account #1\nAddress #1"
        },
        {
          "Bitcoin",
          { 0x80000000|44, 0x80000000|0, 0x80000000|1, 1, 1 },
          5, false, false, ""
        },
        {
          "Bitcoin",
          { 0x80000000|44, 0x80000000|0, 0x80000000|1, 1, 1 },
          5, true, true, "Bitcoin Account #1\nAddress #1"
        },
        {
          "Bitcoin",
          { 0x80000000|44, 0x80000000|0, 0x80000000|1, 1, 1 },
          5, false, false, ""
        },

    };

    for (const auto &vec : vector) {
        char node_str[NODE_STRING_LENGTH];
        ASSERT_EQ(bip32_node_to_string(node_str, sizeof(node_str),
                                       coinByName(vec.coin_name),
                                       vec.address_n,
                                       vec.address_n_count,
                                       /*whole_account=*/false,
                                       vec.allow_change,
                                       /*show_addridx=*/true),
                  vec.expected)
            << vec.text;
        if (vec.expected) {
            EXPECT_EQ(vec.text, node_str);
        }
    }
}

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
