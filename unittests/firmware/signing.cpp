extern "C" {
#include "keepkey/firmware/signing.h"
}

#include "gtest/gtest.h"

#include <cstring>

namespace {

constexpr uint32_t H(uint32_t i) { return 0x80000000 | i; }

// m/<purpose>'/0'/0'/1/0 -- a first change address in the first account.
struct ChangePath {
  uint32_t n[5];
  explicit ChangePath(uint32_t purpose) : n{H(purpose), H(0), H(0), 1, 0} {}
};

bool Forbidden(uint32_t in_purpose, uint32_t out_purpose,
               OutputScriptType out_script_type) {
  ChangePath in(in_purpose), out(out_purpose);
  return isCrossAccountSegwitChangeForbidden(in.n, 5, out.n, 5,
                                             out_script_type);
}

}  // namespace

// Regression: a BIP86 change path paired with any non-taproot script type used
// to fall through to the generic path check, which accepted it as change. That
// suppressed the output confirmation screen while serializing the change to a
// script no BIP86 wallet ever scans for.
TEST(Signing, TaprootChangeMustUseTaprootScriptType) {
  EXPECT_TRUE(Forbidden(86, 86, OutputScriptType_PAYTOADDRESS));
  EXPECT_TRUE(Forbidden(86, 86, OutputScriptType_PAYTOWITNESS));
  EXPECT_TRUE(Forbidden(86, 86, OutputScriptType_PAYTOP2SHWITNESS));
}

TEST(Signing, MatchedPurposeAndScriptTypeAreAllowed) {
  EXPECT_FALSE(Forbidden(86, 86, OutputScriptType_PAYTOTAPROOT));
  EXPECT_FALSE(Forbidden(44, 44, OutputScriptType_PAYTOADDRESS));
  EXPECT_FALSE(Forbidden(49, 49, OutputScriptType_PAYTOP2SHWITNESS));
  EXPECT_FALSE(Forbidden(84, 84, OutputScriptType_PAYTOWITNESS));
}

// The pre-taproot direction of the same rule, kept honest by this test.
TEST(Signing, LegacyChangeMayNotClaimTaprootScriptType) {
  EXPECT_TRUE(Forbidden(44, 44, OutputScriptType_PAYTOTAPROOT));
  EXPECT_TRUE(Forbidden(49, 49, OutputScriptType_PAYTOTAPROOT));
  EXPECT_TRUE(Forbidden(84, 84, OutputScriptType_PAYTOTAPROOT));
}

TEST(Signing, ScriptTypeChecksumEncodingIsCanonicalFourByteLittleEndian) {
  uint8_t encoded[4] = {0};
  signing_checksum_script_type_bytes(static_cast<InputScriptType>(0x01020304),
                                     encoded);
  const uint8_t expected[4] = {0x04, 0x03, 0x02, 0x01};
  EXPECT_EQ(0, memcmp(encoded, expected, sizeof(expected)));
  EXPECT_EQ(4u, sizeof(encoded));
}

TEST(Signing, RejectsInvalidMultisigQuorumOnExternalAndChangeOutputs) {
  for (bool internal : {false, true}) {
    TxOutputType output = TxOutputType_init_zero;
    output.has_multisig = true;
    output.script_type = OutputScriptType_PAYTOMULTISIG;
    output.multisig.has_m = true;
    output.multisig.m = 2;
    output.multisig.pubkeys_count = 3;
    if (internal) {
      output.address_n_count = 1;
      output.address_n[0] = H(0);
    } else {
      output.has_address = true;
      strcpy(output.address, "external");
    }
    EXPECT_TRUE(signing_output_multisig_quorum_is_valid(&output));

    output.multisig.m = 0;
    EXPECT_FALSE(signing_output_multisig_quorum_is_valid(&output));
    output.multisig.m = 4;
    EXPECT_FALSE(signing_output_multisig_quorum_is_valid(&output));
    output.multisig.m = 1;
    output.multisig.pubkeys_count = 0;
    EXPECT_FALSE(signing_output_multisig_quorum_is_valid(&output));
    output.multisig.pubkeys_count = 16;
    EXPECT_FALSE(signing_output_multisig_quorum_is_valid(&output));
  }
}

TEST(Signing, AbortScrubsAllInstrumentedSignerState) {
  signing_test_seed_state();
  ASSERT_FALSE(signing_test_state_is_cleared());
  signing_abort();
  EXPECT_TRUE(signing_test_state_is_cleared());
}

extern "C" {
#include "keepkey/board/layout.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/app_layout.h"
#include "keepkey/firmware/coins.h"
void extract_input_bip32_path(const TxInputType* input);
bool check_change_bip32_path(const TxOutputType* output);
}
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

// A 62-character bech32 address does not fit beside its QR, so it is shown
// after its derivation screen, followed by the QR: three approvals.
TEST(Signing, LongAddressIsShownAsTextThenQr) {
  const char* p2tr =
      "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
  const char* p2pkh = "1JAd7XCBzGudGpJQSDSfpmJhiygtLQWaGL";
  ASSERT_FALSE(layout_address_fits_one_line(p2tr));
  ASSERT_TRUE(layout_address_fits_one_line(p2pkh));

  ASSERT_TRUE(kkconfirm_preload(3, 0));
  EXPECT_TRUE(confirm_address("m/86'/0'/0'/0/0", p2tr));
  EXPECT_EQ(0, kkconfirm_drain());

  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_TRUE(confirm_address("m/44'/0'/0'/0/0", p2pkh));
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(Signing, MixedModeChangeMustPreserveLeadingPathComponents) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  for (uint32_t count = 5; count <= 8; ++count) {
    SignTx request = {};
    request.inputs_count = request.outputs_count = 1;
    request.version = 1;
    signing_init(&request, coin, nullptr);
    struct Abort {
      ~Abort() { signing_abort(); }
    } abort;
    TxInputType input = {};
    input.address_n_count = count;
    for (uint32_t i = 0; i < count - 5; ++i) input.address_n[i] = H(7 + i);
    const uint32_t tail[] = {H(44), H(0), H(0), 0, 0};
    std::memcpy(input.address_n + count - 5, tail, sizeof(tail));
    extract_input_bip32_path(&input);
    TxOutputType output = {};
    output.address_n_count = count;
    output.script_type = OutputScriptType_PAYTOWITNESS;
    std::memcpy(output.address_n, input.address_n, sizeof(input.address_n));
    output.address_n[count - 5] = H(84);
    output.address_n[count - 2] = 1;
    EXPECT_TRUE(check_change_bip32_path(&output));
    if (count > 5) {
      for (uint32_t i = 0; i < count - 5; ++i) {
        output.address_n[i]++;
        EXPECT_FALSE(check_change_bip32_path(&output));
        output.address_n[i]--;
      }
      // A second input from a different leading branch also disables change.
      input.address_n[0]++;
      extract_input_bip32_path(&input);
      EXPECT_FALSE(check_change_bip32_path(&output));
    }
  }
}

void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);
std::vector<std::string> kkconfirm_capture_titles(void);
TEST(Signing, LongDerivationCannotOverlapAddressReview) {
  const char* path = "m/2147483647'/2147483647'/2147483647'/2147483647'";
  ASSERT_GT(calc_str_width(get_title_font(), path), TITLE_WIDTH);
  for (const char* address :
       {"bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
        "1JAd7XCBzGudGpJQSDSfpmJhiygtLQWaGL",
        "tb1qqzv60m9ajw8drqulta4ld4gfx0rdh82un5s65s"}) {
    ASSERT_TRUE(kkconfirm_preload(8, 0));
    kkconfirm_capture_start();
    EXPECT_TRUE(confirm_address(path, address));
    const auto bodies = kkconfirm_capture_finish();
    const auto titles = kkconfirm_capture_titles();
    ASSERT_GE(bodies.size(), 2u);
    ASSERT_EQ(bodies.size(), titles.size());
    std::string derivation, address_text;
    bool whole_address_visible = false;
    for (size_t i = 0; i + 1 < bodies.size(); ++i) {
      EXPECT_LE(calc_str_width(get_title_font(), titles[i].c_str()),
                TITLE_WIDTH);
      EXPECT_TRUE(confirm_body_fits(bodies[i].c_str(), BODY_WIDTH));
      if (titles[i].find("Derivation") == 0) {
        derivation += bodies[i];
      } else {
        EXPECT_EQ(0u, titles[i].find("Address"));
        address_text += bodies[i];
        whole_address_visible |= bodies[i] == address;
      }
    }
    EXPECT_EQ(path, derivation);
    EXPECT_EQ(address, address_text);
    EXPECT_TRUE(whole_address_visible);
    EXPECT_EQ("Address QR", titles.back());
    EXPECT_EQ(address, bodies.back());
    kkconfirm_drain();
  }
}

TEST(Signing, SegwitAddressStartsOnItsOwnScreen) {
  char description[128] = {};
  const uint32_t path[] = {0x80000031, 0x80000001, 0x80000000, 0, 0};
  ASSERT_TRUE(bip32_node_to_string(description, sizeof(description),
                                   coinByName("Testnet"), path, 5, false,
                                   true));
  const char* address = "tb1qqzv60m9ajw8drqulta4ld4gfx0rdh82un5s65s";
  ASSERT_TRUE(kkconfirm_preload(8, 0));
  kkconfirm_capture_start();
  EXPECT_TRUE(confirm_address(description, address));
  const auto bodies = kkconfirm_capture_finish();
  const auto titles = kkconfirm_capture_titles();
  ASSERT_EQ(bodies.size(), titles.size());
  bool complete_address = false;
  for (size_t i = 0; i < bodies.size(); ++i) {
    if (titles[i] == "Address") {
      EXPECT_EQ(address, bodies[i]);
      EXPECT_TRUE(confirm_body_fits(bodies[i].c_str(), BODY_WIDTH));
      complete_address = true;
    }
  }
  EXPECT_TRUE(complete_address);
  kkconfirm_drain();
}
