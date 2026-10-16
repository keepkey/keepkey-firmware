extern "C" {
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/board/layout.h"
bool confirm_zcash_address(const char*, const char*);
void zcash_review_reset(void);
unsigned zcash_review_qr_calls(void);
const char* zcash_review_qr_address(void);
}
#include "gtest/gtest.h"
#include <string>
bool kkconfirm_preload(int, int);
int kkconfirm_drain(void);

TEST(ZcashDisplay, FullAddressPagesThenQrAndCancellation) {
  const std::string address = "u1" + std::string(139, 'q');
  int pages = 0;
  for (size_t offset = 0; offset < address.size(); ++pages) {
    char page[BODY_CHAR_MAX];
    size_t count = confirm_bytes_format_page(
        reinterpret_cast<const uint8_t*>(address.data()) + offset,
        address.size() - offset, page, sizeof(page));
    ASSERT_GT(count, 0u);
    offset += count;
  }
  ASSERT_GT(pages, 1);
  zcash_review_reset();
  ASSERT_TRUE(kkconfirm_preload(pages + 1, 0));
  EXPECT_TRUE(confirm_zcash_address("Zcash account", address.c_str()));
  EXPECT_GT(zcash_review_qr_calls(), 0u);
  EXPECT_STREQ(address.c_str(), zcash_review_qr_address());
  EXPECT_EQ(0, kkconfirm_drain());

  zcash_review_reset();
  ASSERT_TRUE(kkconfirm_preload(pages - 1, 1));
  EXPECT_FALSE(confirm_zcash_address("Zcash account", address.c_str()));
  EXPECT_EQ(0u, zcash_review_qr_calls());
  EXPECT_EQ(0, kkconfirm_drain());

  ASSERT_TRUE(kkconfirm_preload(pages, 1));
  EXPECT_FALSE(confirm_zcash_address("Zcash account", address.c_str()));
  EXPECT_GT(zcash_review_qr_calls(), 0u);
  EXPECT_EQ(0, kkconfirm_drain());
}
