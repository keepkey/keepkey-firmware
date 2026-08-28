extern "C" {
#include <stdint.h>

#include "trezor/crypto/sha2.h"
#include "keepkey/firmware/authenticator.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/storage.h"

void setup(void);
}

#include "gtest/gtest.h"

#include <cstring>

bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

static void ensure_auth_storage_initialized(void) {
  static bool initialized = false;
  if (!initialized) {
    setup();
    storage_init();
    initialized = true;
  }
}

TEST(Authenticator, AuthorizationLossClearsAndReloadsPersistentCache) {
  ensure_auth_storage_initialized();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_EQ(NOERR, wipeAuthData());
  ASSERT_EQ(0, kkconfirm_drain());

  char account_seed[] = "example:alice:JBSWY3DPEHPK3PXP";
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_EQ(NOERR, addAuthAccount(account_seed));
  ASSERT_EQ(0, kkconfirm_drain());
  ASSERT_FALSE(authenticator_cache_is_empty());

  char account[DOMAIN_SIZE + ACCOUNT_SIZE + 2] = {0};
  authenticator_clear_cache();
  ASSERT_TRUE(authenticator_cache_is_empty());
  EXPECT_EQ(NOERR, getAuthAccount("0", account));
  EXPECT_STREQ("example:alice", account);
  EXPECT_FALSE(authenticator_cache_is_empty());

  const struct {
    const char* name;
    void (*revoke)(void);
  } authorization_losses[] = {
      {"ClearSession/lock", [] { session_clear(/*clear_pin=*/true); }},
      {"Initialize", [] { fsm_msgInitialize(nullptr); }},
      {"Cancel", [] { fsm_msgCancel(nullptr); }},
  };

  for (const auto& loss : authorization_losses) {
    SCOPED_TRACE(loss.name);
    authenticator_test_seed_cache();
    ASSERT_FALSE(authenticator_cache_is_empty());
    loss.revoke();
    ASSERT_TRUE(authenticator_cache_is_empty());
  }

  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_EQ(NOERR, wipeAuthData());
  ASSERT_EQ(0, kkconfirm_drain());
}

TEST(Authenticator, RejectedOtpReviewReturnsNoOtp) {
  ensure_auth_storage_initialized();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_EQ(NOERR, wipeAuthData());
  ASSERT_EQ(0, kkconfirm_drain());

  char account_seed[] = "example:alice:JBSWY3DPEHPK3PXP";
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_EQ(NOERR, addAuthAccount(account_seed));
  ASSERT_EQ(0, kkconfirm_drain());

  char request[] = "example:alice:1:30";
  char otp[9];
  memset(otp, 0xA5, sizeof(otp));
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  EXPECT_EQ(CANCELED, generateOTP(request, otp));
  EXPECT_EQ(0, kkconfirm_drain());
  const char zeros[9] = {0};
  EXPECT_EQ(0, memcmp(otp, zeros, sizeof(otp)));

  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_EQ(NOERR, wipeAuthData());
  EXPECT_EQ(0, kkconfirm_drain());
}
