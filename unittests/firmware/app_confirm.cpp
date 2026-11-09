extern "C" {
#include "keepkey/board/layout.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/app_layout.h"
#include "keepkey/firmware/home_sm.h"
}
#include "gtest/gtest.h"
#include "kkconfirm_driver.h"
#include "test_board.h"
#include <string>
#include <vector>

void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);
std::vector<std::string> kkconfirm_captured_titles(void);

TEST(AppConfirm, AllByteValuesHaveAnUnambiguousVisibleRepresentation) {
  for (unsigned value = 0; value < 256; ++value) {
    const uint8_t byte = value;
    char actual[5];
    char expected[5];
    if (value >= 0x21 && value <= 0x7e && value != 0x5c) {
      expected[0] = value;
      expected[1] = 0;
    } else {
      snprintf(expected, sizeof(expected), "\\x%02X", value);
    }
    ASSERT_TRUE(confirm_bytes_escape(&byte, 1, actual, sizeof(actual)));
    EXPECT_STREQ(expected, actual) << value;
  }
}

TEST(AppConfirm, PagesPreserveEveryEscapedByteIncludingHiddenSuffix) {
  kk_test_board_init();
  const std::string input = std::string(200, 'A') + "\n\t\\x00TAIL0199";
  char escaped[1024];
  ASSERT_TRUE(
      confirm_bytes_escape(reinterpret_cast<const uint8_t*>(input.data()),
                           input.size(), escaped, sizeof(escaped)));
  std::string joined;
  size_t offset = 0;
  unsigned pages = 0;
  while (offset < input.size()) {
    char page[128];
    size_t take = confirm_bytes_format_page(
        reinterpret_cast<const uint8_t*>(input.data() + offset),
        input.size() - offset, page, sizeof(page));
    ASSERT_GT(take, 0u);
    offset += take;
    joined += page;
    pages++;
  }
  EXPECT_GT(pages, 1u);
  EXPECT_EQ(escaped, joined);
  EXPECT_NE(std::string::npos, joined.find("TAIL0199"));
}

namespace {
/* Board init for the layout canvas the fit checks measure against, and a
 * reset of confirm and layout state even if a fatal ASSERT_* returns early. */
struct AddressScreenGuard {
  AddressScreenGuard() { kk_test_board_init(); }
  ~AddressScreenGuard() {
    kkconfirm_capture_finish();
    kkconfirm_drain();
    layoutHomeForced();
  }
};

struct Shown {
  std::vector<std::string> titles, bodies;
};

Shown showAddress(const char* desc, const char* address, int screens,
                  bool (*confirmAddress)(const char*, const char*) =
                      confirm_ethereum_address) {
  Shown shown;
  EXPECT_TRUE(kkconfirm_preload(screens, 0));
  kkconfirm_capture_start();
  EXPECT_TRUE(confirmAddress(desc, address));
  shown.bodies = kkconfirm_capture_finish();
  shown.titles = kkconfirm_captured_titles();
  EXPECT_EQ(0, kkconfirm_drain());
  return shown;
}
}  // namespace

/* The single-screen address layout is shared by Ethereum, the Cosmos family,
 * Ripple, Solana, TRON and TON. It holds one title row (ending before the
 * confirm icon) and two address rows; anything more is dropped from the
 * display with no marker. */
TEST(AppConfirm, EthereumLayoutFitChecksMatchRealLabelsAndAddresses) {
  AddressScreenGuard guard;
  /* Every label these handlers produce fits at account #0, so no network's
   * everyday address screen changes. Width depends on the digits, not just
   * how many: every two-digit account fits for every network, and the
   * narrowest margins are ETH Testnet and TON Testnet (some three-digit
   * accounts page) and ETH Classic (some four-digit ones). */
  for (const char* label :
       {"Ethereum Account #0", "Ethereum Account #99999", "ETH Classic Account #0",
        "ETH Classic Account #999", "ETH Testnet Account #0",
        "ETH Testnet Account #99", "Cosmos Account #0", "Osmosis Account #0",
        "THORChain Account #0", "MAYAChain Account #0", "Terra Account #0",
        "Kava Account #0", "Secret Account #0", "Binance Account #0",
        "Ripple Account #0", "TRON Account #0", "TON Account #0",
        "TON Testnet Account #99", "Solana", "m/44'/60'/0'/0/0"}) {
    EXPECT_TRUE(layout_address_title_fits(label)) << label;
  }
  for (const char* network :
       {"Ethereum", "ETH Classic", "ETH Testnet", "Cosmos", "Osmosis",
        "THORChain", "MAYAChain", "Terra", "Kava", "Secret", "Binance",
        "Ripple", "TRON", "TON", "TON Testnet"}) {
    for (int account = 0; account < 100; account++) {
      const std::string label =
          std::string(network) + " Account #" + std::to_string(account);
      EXPECT_TRUE(layout_address_title_fits(label.c_str())) << label;
    }
  }
  for (const char* label :
       {"Ethereum Account #2147483647", "Cosmos Account #2147483647",
        "ETH Classic Account #9999", "ETH Testnet Account #999",
        "TON Testnet Account #999", "m/44'/60'/2147483647'/0/0"}) {
    EXPECT_FALSE(layout_address_title_fits(label)) << label;
  }
  for (const char* address :
       {"0x3f2329C9ADFbcCd9A84f52c906E936A42dA18CB8",
        "rh5ZnEVySAy7oGd3nebT3wrohGHsBxMBM4",
        "cosmos1934nqs0ke73lm5ej8hs9uuawkl3ztesg9jp5c5"}) {
    EXPECT_TRUE(layout_ethereum_address_body_fits(address)) << address;
  }
  /* Rare, but real shapes: these need a third address row. */
  for (const char* address :
       {"cosmos1ctw9ma9xcc2uw2c0xwzwn3d988em3s90ajm2d6",
        "secret1wkvx57p7h8tmvhyn9wqak4cv8mme2weudywaxq",
        "aQDW8fWCKnmJtCFMG1NMwwYynvJzN4TZVPL8MChnB2Hn"}) {
    EXPECT_FALSE(layout_ethereum_address_body_fits(address)) << address;
  }
}

TEST(AppConfirm, EthereumAddressScreenNeverClipsLabelOrAddress) {
  AddressScreenGuard guard;
  const char* eth = "0x3f2329C9ADFbcCd9A84f52c906E936A42dA18CB8";

  /* Everything fits: the usual single screen. */
  Shown shown = showAddress("Ethereum Account #0", eth, 1);
  ASSERT_EQ(1u, shown.titles.size());
  EXPECT_EQ("Ethereum Account #0", shown.titles[0]);

  /* An address needing a third row pages, label first. */
  const char* cosmos = "cosmos1ctw9ma9xcc2uw2c0xwzwn3d988em3s90ajm2d6";
  shown = showAddress("Cosmos Account #0", cosmos, 3);
  ASSERT_EQ(3u, shown.titles.size());
  EXPECT_EQ("Account", shown.titles[0]);
  EXPECT_EQ("Cosmos Account #0", shown.bodies[0]);
  EXPECT_EQ("Address", shown.titles[1]);
  EXPECT_EQ(cosmos, shown.bodies[1]);
  EXPECT_EQ("Address QR", shown.titles[2]);

  /* A label too wide for the row pages too, even though this address would
   * fit both the single screen and confirm_address()'s compact layout: that
   * layout measures only against the display edge, so its title row could
   * still run under the confirm icon. */
  const char* wide = "ETH Classic Account #2147483647";
  ASSERT_TRUE(layout_ethereum_address_body_fits(eth));
  ASSERT_TRUE(layout_address_fits_one_line(eth));
  shown = showAddress(wide, eth, 3);
  ASSERT_EQ(3u, shown.titles.size());
  EXPECT_EQ("Account", shown.titles[0]);
  EXPECT_EQ(wide, shown.bodies[0]);
  EXPECT_EQ("Address", shown.titles[1]);
  EXPECT_EQ(eth, shown.bodies[1]);

  /* A raw path that does not fit is titled as the derivation it is. */
  const char* path = "m/44'/60'/2147483647'/0/0";
  shown = showAddress(path, eth, 3);
  ASSERT_EQ(3u, shown.titles.size());
  EXPECT_EQ("Derivation", shown.titles[0]);
  EXPECT_EQ(path, shown.bodies[0]);

  /* No label and an address that does not fit: no empty label screen. */
  const char* solana = "aQDW8fWCKnmJtCFMG1NMwwYynvJzN4TZVPL8MChnB2Hn";
  shown = showAddress("", solana, 2);
  ASSERT_EQ(2u, shown.titles.size());
  EXPECT_EQ("Address", shown.titles[0]);
  EXPECT_EQ(solana, shown.bodies[0]);
  EXPECT_EQ("Address QR", shown.titles[1]);

  /* Rejecting the first page approves nothing. */
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  EXPECT_FALSE(confirm_ethereum_address("Cosmos Account #0", cosmos));
  EXPECT_EQ(0, kkconfirm_drain());
}

/* Staking transactions confirm each address on the Cosmos or Osmosis
 * layout: a role title beside the QR, the address in rows below it. */
const char* const kCosmosValidator =
    "cosmosvaloper1sjllsnramtg3ewxqwwrwjxfgc4n4ef9u2lcnj0";
const char* const kOsmosisValidator =
    "osmovaloper1sjllsnramtg3ewxqwwrwjxfgc4n4ef9ua8h4lf";

TEST(AppConfirm, StakingAddressScreensFitTheirTitlesAndAddresses) {
  AddressScreenGuard guard;
  /* Every title the Cosmos and Osmosis staking handlers pass. */
  for (const char* title :
       {"Delegator address", "Validator address", "Validator source address",
        "Validator dest. address", "Delegator Address", "Validator Address",
        "Validator Source Address", "Validator Dest. Address"}) {
    EXPECT_TRUE(layout_address_title_fits(title)) << title;
  }
  /* The old delegator titles ran into the confirm icon; the old validator
   * ones cleared it by a few pixels. */
  for (const char* title :
       {"Confirm delegator address", "Confirm Delegator Address"}) {
    EXPECT_FALSE(layout_address_title_fits(title)) << title;
  }
  for (const char* title :
       {"Confirm validator address", "Confirm Validator Address"}) {
    EXPECT_TRUE(layout_address_title_fits(title)) << title;
  }

  /* Any 52-character cosmosvaloper1 address fits the three Cosmos rows,
   * down to the widest bech32 string. */
  for (const std::string& address :
       {std::string("cosmos15cenya0tr7nm3tz2wn3h3zwkht2rxrq7q7h3dj"),
        std::string(kCosmosValidator), std::string(51, 'm') + "1"}) {
    EXPECT_TRUE(layout_cosmos_address_body_fits(address.c_str())) << address;
  }
  /* Osmosis account and validator addresses fit its two 160 px rows. */
  for (const char* address :
       {"osmo15cenya0tr7nm3tz2wn3h3zwkht2rxrq7g9ypmq", kOsmosisValidator}) {
    EXPECT_TRUE(layout_osmosis_address_body_fits(address)) << address;
  }
}

TEST(AppConfirm, StakingAddressScreenNeverClipsTitleOrAddress) {
  AddressScreenGuard guard;
  Shown shown = showAddress("Validator address", kCosmosValidator, 1,
                            confirm_cosmos_address);
  ASSERT_EQ(1u, shown.titles.size());
  EXPECT_EQ("Validator address", shown.titles[0]);

  shown = showAddress("Validator Address", kOsmosisValidator, 1,
                      confirm_osmosis_address);
  ASSERT_EQ(1u, shown.titles.size());
  EXPECT_EQ("Validator Address", shown.titles[0]);

  /* A title that would reach the confirm icon titles a full-width address
   * screen instead. The QR screen draws its title beside the icon, so it
   * does not repeat it. */
  const char* wide = "Confirm delegator address";
  const char* delegator = "cosmos15cenya0tr7nm3tz2wn3h3zwkht2rxrq7q7h3dj";
  shown = showAddress(wide, delegator, 2, confirm_cosmos_address);
  ASSERT_EQ(2u, shown.titles.size());
  EXPECT_EQ(wide, shown.titles[0]);
  EXPECT_EQ(delegator, shown.bodies[0]);
  EXPECT_EQ("Address QR", shown.titles[1]);

  /* So does an address too long for the rows: two 160 px rows cannot hold
   * the widest 52-character string. */
  const std::string long_osmo = std::string(51, 'm') + "1";
  ASSERT_FALSE(layout_osmosis_address_body_fits(long_osmo.c_str()));
  shown = showAddress("Validator Address", long_osmo.c_str(), 2,
                      confirm_osmosis_address);
  ASSERT_EQ(2u, shown.titles.size());
  EXPECT_EQ("Validator Address", shown.titles[0]);
  EXPECT_EQ(long_osmo, shown.bodies[0]);
  EXPECT_EQ("Validator Address", shown.titles[1]);

  ASSERT_TRUE(kkconfirm_preload(0, 1));
  EXPECT_FALSE(confirm_cosmos_address(wide, delegator));
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(AppConfirm, NanoAddressScreenNeverClipsLabelOrAddress) {
  AddressScreenGuard guard;
  const char* xrb =
      "xrb_3h7jxm7r1i6kfxf98hft3okdr8w4gdfozk3kxxa35yixp6r87bs3tw89qkba";
  /* Real addresses fit three rows. The widest possible one (all 'w', the
   * widest glyph in the alphabet) needs a fourth, below the display. */
  const std::string widest = "nano_" + std::string(60, 'w');
  EXPECT_TRUE(layout_nano_address_body_fits(xrb));
  EXPECT_FALSE(layout_nano_address_body_fits(widest.c_str()));

  Shown shown = showAddress("Nano Account #0", xrb, 1, confirm_nano_address);
  ASSERT_EQ(1u, shown.titles.size());
  EXPECT_EQ("Nano Account #0", shown.titles[0]);

  /* Wrapped at 140 px, this label used to run onto the address rows. */
  const char* label = "Nano Account #2147483647";
  shown = showAddress(label, xrb, 3, confirm_nano_address);
  ASSERT_EQ(3u, shown.titles.size());
  EXPECT_EQ("Account", shown.titles[0]);
  EXPECT_EQ(label, shown.bodies[0]);
  EXPECT_EQ("Address", shown.titles[1]);
  EXPECT_EQ(xrb, shown.bodies[1]);
  EXPECT_EQ("Address QR", shown.titles[2]);

  shown = showAddress("Nano Account #0", widest.c_str(), 3,
                      confirm_nano_address);
  ASSERT_EQ(3u, shown.titles.size());
  EXPECT_EQ("Account", shown.titles[0]);
  EXPECT_EQ(widest, shown.bodies[1]);
}
