extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/signing.h"
}

#include "gtest/gtest.h"

void kk_test_board_init(void);

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

TEST(Signing, ScriptTypeChecksumEncodingIsAbiIndependent) {
  uint8_t encoded[4] = {0xff, 0xff, 0xff, 0xff};
  signing_encode_script_type(InputScriptType_SPENDTAPROOT, encoded);
  const uint32_t value = (uint32_t)InputScriptType_SPENDTAPROOT;
  EXPECT_EQ(encoded[0], (uint8_t)value);
  EXPECT_EQ(encoded[1], (uint8_t)(value >> 8));
  EXPECT_EQ(encoded[2], (uint8_t)(value >> 16));
  EXPECT_EQ(encoded[3], (uint8_t)(value >> 24));
  EXPECT_EQ(sizeof(encoded), 4U);
}

extern "C" {
#include "keepkey/firmware/coins.h"
void extract_input_bip32_path(const TxInputType* input);
bool check_change_bip32_path(const TxOutputType* output);
bool signing_input_multisig_quorum_is_valid(const TxInputType* input);
}
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

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

// The input side had no quorum guard at all: m and pubkeys_count arrived
// straight from the wire and reached tx_input_script_size(), whose
// m * (1 + TXSIZE_DER_SIGNATURE) term inflates tx_weight and so raises the
// excessive-fee threshold past any fee a user could be charged. Outputs were
// already guarded; this keeps the two sides symmetric.
/* The predicate cases document its complete input domain. The following test
   also enters the production signing_validate_input() boundary, so removing
   or moving its quorum guard makes the regression fail. */
TEST(Signing, RejectsInvalidMultisigQuorumOnInputs) {
  TxInputType input = {};
  input.script_type = InputScriptType_SPENDADDRESS;

  // No multisig field at all is the single-sig case, not a bad quorum.
  EXPECT_TRUE(signing_input_multisig_quorum_is_valid(&input));

  input.script_type = InputScriptType_SPENDMULTISIG;
  input.has_multisig = true;
  input.multisig.has_m = true;
  input.multisig.m = 2;
  input.multisig.pubkeys_count = 3;
  EXPECT_TRUE(signing_input_multisig_quorum_is_valid(&input));

  input.multisig.has_m = false;
  EXPECT_FALSE(signing_input_multisig_quorum_is_valid(&input));
  input.multisig.has_m = true;

  input.multisig.m = 0;
  EXPECT_FALSE(signing_input_multisig_quorum_is_valid(&input));
  input.multisig.m = 4;
  EXPECT_FALSE(signing_input_multisig_quorum_is_valid(&input));
  // The fee-suppression case: a uint32 m with nothing on the wire bounding it.
  input.multisig.m = 10000000;
  EXPECT_FALSE(signing_input_multisig_quorum_is_valid(&input));

  input.multisig.m = 1;
  input.multisig.pubkeys_count = 0;
  EXPECT_FALSE(signing_input_multisig_quorum_is_valid(&input));
  input.multisig.pubkeys_count = 16;
  EXPECT_FALSE(signing_input_multisig_quorum_is_valid(&input));
}

TEST(Signing, ProductionInputBoundaryRejectsInvalidMultisigQuorum) {
  kk_test_board_init();
  fsm_init();
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  SignTx request = {};
  request.inputs_count = request.outputs_count = 1;
  signing_init(&request, coin, nullptr);

  TxInputType input = {};
  input.prev_hash.size = 32;
  input.script_type = InputScriptType_SPENDMULTISIG;
  input.has_multisig = true;
  input.multisig.has_m = true;
  input.multisig.m = 4;
  input.multisig.pubkeys_count = 3;

  EXPECT_FALSE(signing_test_validate_input(&input));
  EXPECT_FALSE(signing_is_active());
}
