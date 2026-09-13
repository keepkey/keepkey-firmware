#include "gtest/gtest.h"

extern "C" {
#include "keepkey/transport/interface.h"
size_t test_eos_authorization_size(const EosAuthorization* auth);
bool test_eos_standard_authorization(const EosAuthorization* auth);
bool test_eos_authorization_key_valid(const EosAuthorizationKey* key);
}

TEST(EOSAuthorization, WaitsAreSizedIndependentlyOfAccounts) {
  EosAuthorization auth = {};
  auth.waits_count = 1;
  auth.waits[0].wait_sec = 60;
  auth.waits[0].weight = 1;
  // threshold + three vector counts + one (uint32 wait, uint16 weight).
  EXPECT_EQ(13u, test_eos_authorization_size(&auth));
  auth.waits_count = 0;
  auth.accounts_count = 1;
  // Account authority is two uint64 names and one uint16 weight; no waits.
  EXPECT_EQ(25u, test_eos_authorization_size(&auth));
}

TEST(EOSAuthorization, DelegationCannotUseSingleKeyConfirmation) {
  EosAuthorization auth = {};
  auth.has_threshold = true;
  auth.threshold = 1;
  auth.keys_count = 1;
  auth.keys[0].address_n_count = 1;
  auth.keys[0].weight = 1;
  ASSERT_TRUE(test_eos_standard_authorization(&auth));
  auth.accounts_count = 1;
  EXPECT_FALSE(test_eos_standard_authorization(&auth));
}

TEST(EOSAuthorization, RawAndDerivedKeysAreMutuallyExclusive) {
  EosAuthorizationKey key = {};
  EXPECT_FALSE(test_eos_authorization_key_valid(&key));
  key.address_n_count = 1;
  EXPECT_TRUE(test_eos_authorization_key_valid(&key));
  for (unsigned size = 1; size <= 33; ++size) {
    key.key.size = size;
    EXPECT_FALSE(test_eos_authorization_key_valid(&key));
  }
  key.address_n_count = 0;
  EXPECT_TRUE(test_eos_authorization_key_valid(&key));
  for (unsigned size = 1; size < 33; ++size) {
    key.key.size = size;
    EXPECT_FALSE(test_eos_authorization_key_valid(&key));
  }
}
