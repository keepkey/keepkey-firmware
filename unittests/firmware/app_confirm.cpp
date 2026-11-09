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

Shown showAddress(const char* desc, const char* address, int screens) {
  Shown shown;
  EXPECT_TRUE(kkconfirm_preload(screens, 0));
  kkconfirm_capture_start();
  EXPECT_TRUE(confirm_ethereum_address(desc, address));
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
  for (const char* label :
       {"Ethereum Account #0", "Ethereum Account #999", "Cosmos Account #0",
        "THORChain Account #0", "MAYAChain Account #0", "Osmosis Account #0",
        "Ripple Account #0", "Solana", "m/44'/60'/0'/0/0"}) {
    EXPECT_TRUE(layout_ethereum_address_title_fits(label)) << label;
  }
  for (const char* label :
       {"Ethereum Account #2147483647", "Cosmos Account #2147483647",
        "Ethereum Classic Account #0", "Avalanche C-Chain Account #0",
        "m/44'/60'/2147483647'/0/0"}) {
    EXPECT_FALSE(layout_ethereum_address_title_fits(label)) << label;
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
  const char* wide = "Ethereum Classic Account #2147483647";
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
