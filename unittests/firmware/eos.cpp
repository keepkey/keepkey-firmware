extern "C" {
#include "keepkey/firmware/eos.h"
#include "messages-eos.pb.h"
}

#include "gtest/gtest.h"

#include <string>

TEST(EOS, UnknownActionsRequireAdvancedMode) {
  EXPECT_FALSE(eos_unknownActionPolicyAllows(false));
  EXPECT_TRUE(eos_unknownActionPolicyAllows(true));
}

TEST(EOS, StreamedUnknownActionCommonMustRemainIdentical) {
  EosActionCommon first = {};
  first.has_account = true;
  first.account = 0x1111;
  first.has_name = true;
  first.name = 0x2222;
  first.authorization_count = 1;
  first.authorization[0].has_actor = true;
  first.authorization[0].actor = 0x3333;
  first.authorization[0].has_permission = true;
  first.authorization[0].permission = 0x4444;

  EosActionCommon next = first;
  EXPECT_TRUE(eos_actionCommonEqual(&first, &next));

  next.name++;
  EXPECT_FALSE(eos_actionCommonEqual(&first, &next));
  next = first;
  next.authorization[0].actor++;
  EXPECT_FALSE(eos_actionCommonEqual(&first, &next));
  next = first;
  next.authorization_count = 0;
  EXPECT_FALSE(eos_actionCommonEqual(&first, &next));
}

TEST(EOS, NewAccountCannotDowngradeToUnknownAction) {
  EosActionCommon common = {};
  common.has_account = true;
  common.account = EOS_eosio;
  common.has_name = true;
  common.name = EOS_NewAccount;
  EXPECT_TRUE(eos_isSupportedAction(&common));

  common.account = 0x1111111111111111ULL;
  EXPECT_FALSE(eos_isSupportedAction(&common));
}

TEST(EOS, SupportedActionsArePairsNotEitherContract) {
  /* The classifier used to accept "account is eosio OR eosio.token" for every
     listed action name. Combined with eosio.system.c accepting eosio.token in
     its CHECK_COMMON, a host could compile eosio.token::newaccount through the
     STRUCTURED path: it drew an ordinary "New Account" screen, no confirmation
     in eosio.system.c names the contract, and it never reached
     eos_compileActionUnknown() so the AdvancedMode gate did not apply.

     The pairs below are exactly what eos-contracts/ compiles. */
  EosActionCommon common = {};
  common.has_account = true;
  common.has_name = true;

  /* Transfer belongs to eosio.token, and only there. */
  common.account = EOS_eosio_token;
  common.name = EOS_Transfer;
  EXPECT_TRUE(eos_isSupportedAction(&common));
  common.account = EOS_eosio;
  EXPECT_FALSE(eos_isSupportedAction(&common));

  /* Every system action belongs to eosio, and only there. This is the
     cross-contract case that used to pass. */
  const uint64_t system_actions[] = {
      EOS_DelegateBW,  EOS_UndelegateBW, EOS_Refund,       EOS_BuyRam,
      EOS_BuyRamBytes, EOS_SellRam,      EOS_VoteProducer, EOS_UpdateAuth,
      EOS_DeleteAuth,  EOS_LinkAuth,     EOS_UnlinkAuth,   EOS_NewAccount};
  for (size_t i = 0; i < sizeof(system_actions) / sizeof(system_actions[0]);
       i++) {
    common.name = system_actions[i];
    common.account = EOS_eosio;
    EXPECT_TRUE(eos_isSupportedAction(&common))
        << "eosio action " << i << " should be supported";
    common.account = EOS_eosio_token;
    EXPECT_FALSE(eos_isSupportedAction(&common))
        << "eosio.token action " << i << " must not be a supported pair";
  }

  /* An unrelated contract is unsupported whatever the action name. */
  common.account = 0x1111111111111111ULL;
  common.name = EOS_Transfer;
  EXPECT_FALSE(eos_isSupportedAction(&common));
  common.name = EOS_NewAccount;
  EXPECT_FALSE(eos_isSupportedAction(&common));
}

TEST(EOS, FormatNameVec) {
  struct {
    uint64_t value;
    const char* name;
    bool ret;
  } vec[] = {
      {0x5530ea0000000000, "eosio", true},
      {0x0000000000ea3055, nullptr, true},
      {0x5530ea031ec65520, "eosio.system", true},
      {0xb68d3cbb3e000000, "quantity", true},
      {0x9ab864229a9e4000, "newaccount", true},
      {EOS_Transfer, "transfer", true},
      {0xcdcd3c2d57000000, "transfer", true},
      {0xd4d2a8a986ca8fc0, "undelegatebw", true},
      {0xc2b263b800000000, "setabi", true},
      {0xa726ab8000000000, "owner", true},
      {EOS_Owner, "owner", true},
      {0x3232eda800000000, "active", true},
      {EOS_Active, "active", true},
      {0x5530002eea526920, "eos..freedom", true},
      {0x5530412eea526920, "eos42freedom", true},
      {0x0, "", true},
  };

  for (const auto& v : vec) {
    char str[EOS_NAME_STR_SIZE];
    ASSERT_EQ(v.ret, eos_formatName(v.value, str));
    if (v.name) ASSERT_EQ(v.name, std::string(str));
  }
}

TEST(EOS, FormatAssetVec) {
  struct {
    int64_t amount;
    uint64_t symbol;
    std::string expected;
    bool ret;
  } vec[] = {
      {7654321L, 0x000000534f4504L, "765.4321 EOS", true},
      {42L, 0x004e45584f4600L, "42 FOXEN", true},
      {42L, 0x004e45584f4601L, "4.2 FOXEN", true},
      {42L, 0x004e45584f4602L, "0.42 FOXEN", true},
      {42L, 0x004e45584f4603L, "0.042 FOXEN", true},
      {42L, 0x004e45584f4604L, "0.0042 FOXEN", true},
      {42L, 0x004e45584f4605L, "0.00042 FOXEN", true},
      {42L, 0x004e45584f4606L, "0.000042 FOXEN", true},
      {42L, 0x004e45584f4607L, "0.0000042 FOXEN", true},
      {42L, 0x004e45584f4608L, "0.00000042 FOXEN", true},
      {42L, 0x004e45584f4609L, "0.000000042 FOXEN", true},
      {-10L, 0x00000053595305L, "-0.00010 SYS", true},
      {INT64_MIN, 0x00000053595303L, "-9223372036854775.808 SYS", true},
      {20000L, 0x000000534f4504L, "2.0000 EOS", true},
      {200000L, 0x000000534f4504L, "20.0000 EOS", true},
      {2000000L, 0x000000534f4504L, "200.0000 EOS", true},
      {20000000L, 0x000000534f4504L, "2000.0000 EOS", true},
      {200000000L, 0x000000534f4504L, "20000.0000 EOS", true},
      {2000000000L, 0x000000534f4504L, "200000.0000 EOS", true},
      {20000000000L, 0x000000534f4504L, "2000000.0000 EOS", true},
      {200000000000L, 0x000000534f4504L, "20000000.0000 EOS", true},
      {2000000000000L, 0x000000534f4504L, "200000000.0000 EOS", true},
      {20000000000000L, 0x000000534f4504L, "2000000000.0000 EOS", true},
      {10000L, 0x000000534f4504L, "1.0000 EOS", true},
      {100000L, 0x000000534f4504L, "10.0000 EOS", true},
      {1000000L, 0x000000534f4504L, "100.0000 EOS", true},
      {10000000L, 0x000000534f4504L, "1000.0000 EOS", true},
      {100000000L, 0x000000534f4504L, "10000.0000 EOS", true},
      {1000000000L, 0x000000534f4504L, "100000.0000 EOS", true},
      {10000000000L, 0x000000534f4504L, "1000000.0000 EOS", true},
      {100000000000L, 0x000000534f4504L, "10000000.0000 EOS", true},
      {1000000000000L, 0x000000534f4504L, "100000000.0000 EOS", true},
      {10000000000000L, 0x000000534f4504L, "1000000000.0000 EOS", true},
  };

  for (const auto& v : vec) {
    char str[EOS_ASSET_STR_SIZE];
    EosAsset asset;
    asset.has_amount = true;
    asset.amount = v.amount;
    asset.has_symbol = true;
    asset.symbol = v.symbol;
    EXPECT_EQ(v.ret, eos_formatAsset(&asset, str));
    EXPECT_EQ(v.expected, str);
  }
}

TEST(EOS, PublicKeyToWIF) {
  uint8_t public_key[33];
  memset(public_key, 0, sizeof(public_key));
  char pubkey[64];
  memset(pubkey, 0, sizeof(pubkey));
  ASSERT_FALSE(eos_publicKeyToWif(public_key, (EosPublicKeyKind)42, pubkey,
                                  sizeof(pubkey)));

  ASSERT_TRUE(eos_publicKeyToWif(public_key, EosPublicKeyKind_EOS_K1, pubkey,
                                 sizeof(pubkey)));
  ASSERT_EQ(pubkey,
            std::string("EOS_K1_1111111111111111111111111111111114T1Anm"));
}
