extern "C" {
#include <stdint.h>

#include "trezor/crypto/sha2.h"
#include "keepkey/firmware/authenticator.h"
#include "keepkey/firmware/storage.h"

void setup(void);
}

#include "gtest/gtest.h"

// Shared emulator confirmation driver from thorchain.cpp.
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

TEST(Authenticator, WipeCancellationFailsClosed) {
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  EXPECT_EQ(AUTH_CANCELLED, wipeAuthData());
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(Authenticator, AddAndRemoveCancellationFailsClosed) {
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  setup();
  storage_init();
  EXPECT_EQ(NOERR, wipeAuthData());
  EXPECT_EQ(0, kkconfirm_drain());

  char cancelled_add[] = "example:alice:JBSWY3DPEHPK3PXP";
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  EXPECT_EQ(AUTH_CANCELLED, addAuthAccount(cancelled_add));
  EXPECT_EQ(0, kkconfirm_drain());

  char account[DOMAIN_SIZE + ACCOUNT_SIZE + 2] = {0};
  EXPECT_EQ(NOACC, getAuthAccount("0", account));

  char accepted_add[] = "example:alice:JBSWY3DPEHPK3PXP";
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  EXPECT_EQ(NOERR, addAuthAccount(accepted_add));
  EXPECT_EQ(0, kkconfirm_drain());

  char cancelled_remove[] = "example:alice";
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  EXPECT_EQ(AUTH_CANCELLED, removeAuthAccount(cancelled_remove));
  EXPECT_EQ(0, kkconfirm_drain());
  EXPECT_EQ(NOERR, getAuthAccount("0", account));
  EXPECT_STREQ("example:alice", account);

  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_EQ(NOERR, wipeAuthData());
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(Authenticator, RejectsAmbiguousDisplayFieldsBeforeMutation) {
  char long_domain[] = "domain-is-too-long:alice:JBSWY3DPEHPK3PXP";
  EXPECT_EQ(TOKERR, addAuthAccount(long_domain));

  char control_domain[] = "bad\ndomain:alice:JBSWY3DPEHPK3PXP";
  EXPECT_EQ(TOKERR, addAuthAccount(control_domain));

  char long_account[] = "example:account-is-too-long:JBSWY3DPEHPK3PXP";
  EXPECT_EQ(TOKERR, addAuthAccount(long_account));

  char remove_long[] = "example:account-is-too-long";
  EXPECT_EQ(TOKERR, removeAuthAccount(remove_long));

  char remove_control[] = "example:bad\naccount";
  EXPECT_EQ(TOKERR, removeAuthAccount(remove_control));
}
