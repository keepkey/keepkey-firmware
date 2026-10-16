#include "gtest/gtest.h"

extern "C" {
#include "keepkey/transport/interface.h"
size_t test_eos_authorization_size(const EosAuthorization* auth);
bool test_eos_standard_authorization(const EosAuthorization* auth);
bool test_eos_authorization_key_valid(const EosAuthorizationKey* key);
bool test_eos_r1_key_string(const uint8_t* key, char* out, size_t len);
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

// EOSIO public_key variant index: K1 = 0, R1 = 1, WA = 2. The index is hashed
// into the signed authority, so it must agree with the key the user is shown.
TEST(EOSAuthorization, DerivedKeyMustBeK1) {
  EosAuthorizationKey key = {};
  key.address_n_count = 5;
  EXPECT_TRUE(test_eos_authorization_key_valid(&key));
  key.has_type = true;
  EXPECT_TRUE(test_eos_authorization_key_valid(&key));
  for (uint32_t type = 1; type <= 3; ++type) {
    key.type = type;
    EXPECT_FALSE(test_eos_authorization_key_valid(&key)) << type;
  }
}

TEST(EOSAuthorization, RawKeyTypeIsK1OrR1) {
  EosAuthorization auth = {};
  auth.keys_count = 1;
  EosAuthorizationKey& key = auth.keys[0];
  key.key.size = 33;
  key.has_type = true;
  // threshold, key count, type, key, weight, account count, wait count.
  const size_t size = 4 + 1 + 1 + 33 + 2 + 1 + 1;
  EXPECT_TRUE(test_eos_authorization_key_valid(&key));
  EXPECT_EQ(size, test_eos_authorization_size(&auth));
  key.type = 1;
  EXPECT_TRUE(test_eos_authorization_key_valid(&key));
  EXPECT_EQ(size, test_eos_authorization_size(&auth));
  key.type = 2;
  EXPECT_FALSE(test_eos_authorization_key_valid(&key));
  EXPECT_EQ(0u, test_eos_authorization_size(&auth));
}

TEST(EOSAuthorization, R1KeyIsShownWithR1Prefix) {
  // eosjs test vector; checksum is ripemd160(key || "R1").
  const uint8_t key[33] = {0x02, 0xb3, 0x23, 0xea, 0x27, 0xd1, 0x91, 0x14, 0x3e,
                           0xb9, 0xad, 0x27, 0xc9, 0x6d, 0xb1, 0x5d, 0x8b, 0x12,
                           0x9d, 0x30, 0x96, 0xa0, 0xcb, 0x17, 0xae, 0x11, 0xae,
                           0x26, 0xab, 0xce, 0x80, 0x33, 0x40};
  char out[65];
  ASSERT_TRUE(test_eos_r1_key_string(key, out, sizeof(out)));
  EXPECT_STREQ("PUB_R1_6FPFZqw5ahYrR9jD96yDbbDNTdKtNqRbze6oTDLntrsANgQKZu",
               out);
}
