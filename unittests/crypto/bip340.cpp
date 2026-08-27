// Official BIP-340 test vectors, verbatim from
// https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
//
// Vectors with a secret key are signed and the signature compared byte for
// byte (BIP-340 signing is deterministic given aux_rand).  Every vector,
// with or without a secret key, is run through verification.

#include <cstddef>

extern "C" {
#include "trezor/crypto/bip32.h"
#include "trezor/crypto/bip340.h"
#include "trezor/crypto/bip39.h"
#include "trezor/crypto/curves.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/segwit_addr.h"
}

#include "gtest/gtest.h"

#include <algorithm>
#include <cinttypes>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> unhex(const std::string &s) {
  std::vector<uint8_t> out;
  out.reserve(s.size() / 2);
  for (size_t i = 0; i + 1 < s.size(); i += 2) {
    out.push_back((uint8_t)std::stoul(s.substr(i, 2), nullptr, 16));
  }
  return out;
}

std::string hex(const uint8_t *p, size_t len) {
  static const char *digits = "0123456789ABCDEF";
  std::string out;
  for (size_t i = 0; i < len; i++) {
    out += digits[p[i] >> 4];
    out += digits[p[i] & 0x0f];
  }
  return out;
}

struct Vector {
  int index;
  const char *seckey;  // empty when the vector is verify-only
  const char *pubkey;
  const char *aux;
  const char *msg;
  const char *sig;
  bool valid;
  const char *comment;
};

// 100 bytes of 0x99, the message of vector 18.
const char *kMsg100 =
    "9999999999999999999999999999999999999999999999999999999999999999"
    "9999999999999999999999999999999999999999999999999999999999999999"
    "9999999999999999999999999999999999999999999999999999999999999999"
    "99999999";

const Vector kVectors[] = {
    {0, "0000000000000000000000000000000000000000000000000000000000000003",
     "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
     "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
     true, ""},
    {1, "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
     "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "0000000000000000000000000000000000000000000000000000000000000001",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
     "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
     true, ""},
    {2, "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
     "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
     "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
     "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
     "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B"
     "AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
     true, ""},
    {3, "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
     "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
     "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC"
     "97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
     true, "test fails if msg is reduced modulo p or n"},
    {4, "", "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
     "", "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
     "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63"
     "76AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
     true, ""},
    {5, "", "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
     "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
     "69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
     false, "public key not on the curve"},
    {6, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556"
     "3CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
     false, "has_even_y(R) is false"},
    {7, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F"
     "28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
     false, "negated message"},
    {8, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
     "961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
     false, "negated s value"},
    {9, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "0000000000000000000000000000000000000000000000000000000000000000"
     "123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
     false, "sG - eP is infinite, x(inf) as 0"},
    {10, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "0000000000000000000000000000000000000000000000000000000000000001"
     "7615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197",
     false, "sG - eP is infinite, x(inf) as 1"},
    {11, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D"
     "69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
     false, "sig[0:32] is not an X coordinate on the curve"},
    {12, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
     "69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
     false, "sig[0:32] is equal to field size"},
    {13, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
     false, "sig[32:64] is equal to curve order"},
    {14, "", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
     "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
     "69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
     false, "public key exceeds the field size"},
    {15, "0340034003400340034003400340034003400340034003400340034003400340",
     "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
     "0000000000000000000000000000000000000000000000000000000000000000", "",
     "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF"
     "6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63",
     true, "message of size 0"},
    {16, "0340034003400340034003400340034003400340034003400340034003400340",
     "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
     "0000000000000000000000000000000000000000000000000000000000000000", "11",
     "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303"
     "EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF",
     true, "message of size 1"},
    {17, "0340034003400340034003400340034003400340034003400340034003400340",
     "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0102030405060708090A0B0C0D0E0F1011",
     "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370"
     "C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5",
     true, "message of size 17"},
    {18, "0340034003400340034003400340034003400340034003400340034003400340",
     "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
     "0000000000000000000000000000000000000000000000000000000000000000",
     kMsg100,
     "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8"
     "585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367",
     true, "message of size 100"},
};

}  // namespace

// Official BIP-86 test vectors, from
// https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
// (mnemonic "abandon abandon ... about", account m/86'/0'/0').
// HD derivation is covered at the firmware level; what is pinned here is the
// tweak and the bech32m encoding that turn an internal key into an address.
TEST(BIP340, BIP86Vectors) {
  const struct {
    const char *path;
    const char *internal_key;
    const char *output_key;
    const char *address;
  } vectors[] = {
      {"m/86'/0'/0'/0/0",
       "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
       "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
       "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"},
      {"m/86'/0'/0'/0/1",
       "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145",
       "a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb",
       "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"},
      {"m/86'/0'/0'/1/0",
       "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef",
       "882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc",
       "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"},
  };

  for (const auto &v : vectors) {
    std::vector<uint8_t> internal = unhex(v.internal_key);
    uint8_t out[BIP340_XONLY_LENGTH] = {0};

    ASSERT_EQ(0, bip340_tweak_pubkey(&secp256k1, internal.data(), nullptr, out))
        << v.path;

    std::string got = hex(out, sizeof(out));
    std::transform(got.begin(), got.end(), got.begin(), ::tolower);
    ASSERT_EQ(std::string(v.output_key), got) << v.path;

    // Witness version 1 + 32 bytes must come out bech32m, i.e. a bc1p address.
    char address[MAX_ADDR_SIZE] = {0};
    ASSERT_EQ(1, segwit_addr_encode(address, "bc", 1, out, sizeof(out)))
        << v.path;
    ASSERT_EQ(std::string(v.address), std::string(address)) << v.path;
  }
}

// The same BIP-86 vectors driven from the mnemonic, so HD derivation and the
// x-only convention are covered too.  compute_address() feeds
// node->public_key + 1 to bip340_tweak_pubkey(); this pins that the byte after
// the compressed prefix really is the internal key BIP-86 expects, which an
// off-by-one would otherwise turn into a valid-looking wrong address.
TEST(BIP340, BIP86FromMnemonic) {
  const char *mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon about";
  const struct {
    uint32_t change;
    uint32_t index;
    const char *address;
  } vectors[] = {
      {0, 0, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"},
      {0, 1, "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"},
      {1, 0, "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"},
  };

  uint8_t seed[64] = {0};
  mnemonic_to_seed(mnemonic, "", seed, nullptr);

  for (const auto &v : vectors) {
    HDNode node = {0};
    ASSERT_EQ(1, hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &node));
    // m/86'/0'/0'/change/index
    ASSERT_EQ(1, hdnode_private_ckd(&node, 0x80000000 + 86));
    ASSERT_EQ(1, hdnode_private_ckd(&node, 0x80000000 + 0));
    ASSERT_EQ(1, hdnode_private_ckd(&node, 0x80000000 + 0));
    ASSERT_EQ(1, hdnode_private_ckd(&node, v.change));
    ASSERT_EQ(1, hdnode_private_ckd(&node, v.index));
    hdnode_fill_public_key(&node);

    uint8_t out[BIP340_XONLY_LENGTH] = {0};
    ASSERT_EQ(
        0, bip340_tweak_pubkey(&secp256k1, node.public_key + 1, nullptr, out));

    char address[MAX_ADDR_SIZE] = {0};
    ASSERT_EQ(1, segwit_addr_encode(address, "bc", 1, out, sizeof(out)));
    ASSERT_EQ(std::string(v.address), std::string(address))
        << "change=" << v.change << " index=" << v.index;
  }
}

// Official BIP-341 key-path spending vector, input index 4, from
// https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json
//
// This is the only published input that uses SIGHASH_DEFAULT (hashType 0), so
// it is the one that pins our signing configuration end to end.  It carries a
// merkle root, which is why bip340_tweak_seckey/pubkey take one -- without it
// there is no published witness to check the sigmsg field ordering against,
// and a transposed field yields a perfectly valid signature over the wrong
// transaction.
namespace bip341 {
const char *kInternalPrivkey =
    "f36bb07a11e469ce941d16b63b11b9b9120a84d9d87cff2c84a8d4affb438f4e";
const char *kInternalPubkey =
    "e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f";
const char *kMerkleRoot =
    "ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2";
const char *kTweakedPrivkey =
    "a8e7aa924f0d58854185a490e6c41f6efb7b675c0f3331b7f14b549400b4d501";
const char *kSigHash =
    "4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef";
const char *kWitness =
    "b4010dd48a617db09926f729e79c33ae0b4e94b79f04a1ae93ede6315eb3669d"
    "e185a17d2b0ac9ee09fd4c64b678a0b61a0a86fa888a273c8511be83bfd6810f";
const char *kHashPrevouts =
    "e3b33bb4ef3a52ad1fffb555c0d82828eb22737036eaeb02a235d82b909c4c3f";
const char *kHashAmounts =
    "58a6964a4f5f8f0b642ded0a8a553be7622a719da71d1f5befcefcdee8e0fde6";
const char *kHashScriptPubkeys =
    "23ad0f61ad2bca5ba6a7693f50fce988e17c3780bf2b1e720cfbb38fbdd52e21";
const char *kHashSequences =
    "18959c7221ab5ce9e26c3cd67b22c24f8baa54bac281d8e6b05e400e6c3a957e";
const char *kHashOutputs =
    "a2e6dab7c1f0dcd297c8d61647fd17d821541ea69c3cc37dcbad7f90d4eb4bc5";
const uint32_t kVersion = 2;
const uint32_t kLockTime = 500000000;
const uint32_t kInputIndex = 4;

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), ::tolower);
  return s;
}
}  // namespace bip341

TEST(BIP341, TweakSeckey) {
  std::vector<uint8_t> sk = unhex(bip341::kInternalPrivkey);
  std::vector<uint8_t> root = unhex(bip341::kMerkleRoot);
  uint8_t pk[BIP340_XONLY_LENGTH] = {0};
  uint8_t tweaked[32] = {0};

  ASSERT_EQ(0, bip340_get_xonly_pubkey(&secp256k1, sk.data(), pk));
  ASSERT_EQ(std::string(bip341::kInternalPubkey),
            bip341::lower(hex(pk, sizeof(pk))));

  ASSERT_EQ(0,
            bip340_tweak_seckey(&secp256k1, sk.data(), root.data(), tweaked));
  ASSERT_EQ(std::string(bip341::kTweakedPrivkey),
            bip341::lower(hex(tweaked, sizeof(tweaked))));

  // The tweaked private key must correspond to the tweaked public key, or the
  // signature verifies under a key that does not own the output.
  uint8_t from_seckey[BIP340_XONLY_LENGTH] = {0};
  uint8_t from_pubkey[BIP340_XONLY_LENGTH] = {0};
  ASSERT_EQ(0, bip340_get_xonly_pubkey(&secp256k1, tweaked, from_seckey));
  ASSERT_EQ(0, bip340_tweak_pubkey(&secp256k1, pk, root.data(), from_pubkey));
  ASSERT_EQ(0, memcmp(from_seckey, from_pubkey, BIP340_XONLY_LENGTH));
}

TEST(BIP341, Sighash) {
  std::vector<uint8_t> prevouts = unhex(bip341::kHashPrevouts);
  std::vector<uint8_t> amounts = unhex(bip341::kHashAmounts);
  std::vector<uint8_t> spks = unhex(bip341::kHashScriptPubkeys);
  std::vector<uint8_t> seqs = unhex(bip341::kHashSequences);
  std::vector<uint8_t> outs = unhex(bip341::kHashOutputs);
  uint8_t hash[SHA256_DIGEST_LENGTH] = {0};

  bip341_sighash(/*hash_type=*/0, bip341::kVersion, bip341::kLockTime,
                 prevouts.data(), amounts.data(), spks.data(), seqs.data(),
                 outs.data(), bip341::kInputIndex, hash);

  ASSERT_EQ(std::string(bip341::kSigHash),
            bip341::lower(hex(hash, sizeof(hash))));
}

TEST(BIP341, KeyPathSignatureMatchesPublishedWitness) {
  std::vector<uint8_t> sk = unhex(bip341::kInternalPrivkey);
  std::vector<uint8_t> root = unhex(bip341::kMerkleRoot);
  std::vector<uint8_t> sighash = unhex(bip341::kSigHash);
  uint8_t tweaked[32] = {0};
  uint8_t sig[BIP340_SIG_LENGTH] = {0};

  ASSERT_EQ(0,
            bip340_tweak_seckey(&secp256k1, sk.data(), root.data(), tweaked));
  // BIP-341's vectors are generated with an all-zero aux_rand.
  ASSERT_EQ(0, bip340_sign(&secp256k1, tweaked, sighash.data(), sighash.size(),
                           nullptr, sig));
  ASSERT_EQ(std::string(bip341::kWitness),
            bip341::lower(hex(sig, sizeof(sig))));
}

TEST(BIP340, TweakRejectsInvalidInternalKey) {
  // Vector 5's x coordinate, which is not on the curve.
  std::vector<uint8_t> bad =
      unhex("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34");
  // And an x coordinate past the field size (vector 14).
  std::vector<uint8_t> too_big =
      unhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30");
  uint8_t out[BIP340_XONLY_LENGTH] = {0};

  ASSERT_NE(0, bip340_tweak_pubkey(&secp256k1, bad.data(), nullptr, out));
  ASSERT_NE(0, bip340_tweak_pubkey(&secp256k1, too_big.data(), nullptr, out));
}

TEST(BIP340, TaggedHash) {
  // tagged_hash("BIP0340/challenge", "") == SHA256(h || h) where
  // h = SHA256("BIP0340/challenge").  Pins the double-tag construction.
  uint8_t out[SHA256_DIGEST_LENGTH] = {0};
  uint8_t tag_hash[SHA256_DIGEST_LENGTH] = {0};
  uint8_t expected[SHA256_DIGEST_LENGTH] = {0};
  uint8_t doubled[2 * SHA256_DIGEST_LENGTH] = {0};

  bip340_tagged_hash("BIP0340/challenge", nullptr, 0, out);

  sha256_Raw((const uint8_t *)"BIP0340/challenge", 17, tag_hash);
  memcpy(doubled, tag_hash, sizeof(tag_hash));
  memcpy(doubled + sizeof(tag_hash), tag_hash, sizeof(tag_hash));
  sha256_Raw(doubled, sizeof(doubled), expected);

  ASSERT_EQ(0, memcmp(out, expected, sizeof(expected)));
}

TEST(BIP340, XOnlyPubkey) {
  for (const auto &v : kVectors) {
    if (v.seckey[0] == '\0') continue;

    std::vector<uint8_t> sk = unhex(v.seckey);
    uint8_t pk[BIP340_XONLY_LENGTH] = {0};

    ASSERT_EQ(0, bip340_get_xonly_pubkey(&secp256k1, sk.data(), pk))
        << "vector " << v.index;
    ASSERT_EQ(std::string(v.pubkey), hex(pk, sizeof(pk)))
        << "vector " << v.index;
  }
}

TEST(BIP340, Sign) {
  for (const auto &v : kVectors) {
    if (v.seckey[0] == '\0') continue;

    std::vector<uint8_t> sk = unhex(v.seckey);
    std::vector<uint8_t> aux = unhex(v.aux);
    std::vector<uint8_t> msg = unhex(v.msg);
    uint8_t sig[BIP340_SIG_LENGTH] = {0};

    ASSERT_EQ(0, bip340_sign(&secp256k1, sk.data(), msg.data(), msg.size(),
                             aux.data(), sig))
        << "vector " << v.index << ": " << v.comment;
    ASSERT_EQ(std::string(v.sig), hex(sig, sizeof(sig)))
        << "vector " << v.index << ": " << v.comment;
  }
}

TEST(BIP340, Verify) {
  for (const auto &v : kVectors) {
    std::vector<uint8_t> pk = unhex(v.pubkey);
    std::vector<uint8_t> msg = unhex(v.msg);
    std::vector<uint8_t> sig = unhex(v.sig);

    int ret = bip340_verify(&secp256k1, pk.data(), msg.data(), msg.size(),
                            sig.data());
    if (v.valid) {
      ASSERT_EQ(0, ret) << "vector " << v.index << ": " << v.comment;
    } else {
      ASSERT_NE(0, ret) << "vector " << v.index << ": " << v.comment;
    }
  }
}

TEST(BIP340, SignRejectsOutOfRangeKeys) {
  const uint8_t zero[32] = {0};
  // n, the curve order -- the first scalar that is out of range.
  const uint8_t order[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                             0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                             0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};
  const uint8_t msg[32] = {0};
  uint8_t sig[BIP340_SIG_LENGTH] = {0};

  // Pre-fill, so the zero-on-failure check below cannot pass vacuously.
  memset(sig, 0xFF, sizeof(sig));

  ASSERT_NE(0, bip340_sign(&secp256k1, zero, msg, sizeof(msg), nullptr, sig));
  ASSERT_NE(0, bip340_sign(&secp256k1, order, msg, sizeof(msg), nullptr, sig));

  // A rejected signing attempt must not leave anything in the output buffer.
  uint8_t empty[BIP340_SIG_LENGTH] = {0};
  ASSERT_EQ(0, memcmp(sig, empty, sizeof(sig)));
}

TEST(BIP340, XOnlyPubkeyZeroesOnFailure) {
  const uint8_t zero[32] = {0};
  uint8_t pk[BIP340_XONLY_LENGTH];

  memset(pk, 0xFF, sizeof(pk));
  ASSERT_NE(0, bip340_get_xonly_pubkey(&secp256k1, zero, pk));

  uint8_t empty[BIP340_XONLY_LENGTH] = {0};
  ASSERT_EQ(0, memcmp(pk, empty, sizeof(pk)));
}

TEST(BIP340, ZeroSTakesTheSpecPath) {
  // s == 0 is in range per BIP-340 and carries no special guard: verification
  // must compute R = -eP and reject on the x-coordinate comparison, not bail
  // out early.  Pins the absence of a guard that would deviate from the spec.
  std::vector<uint8_t> pk = unhex(kVectors[1].pubkey);
  std::vector<uint8_t> msg = unhex(kVectors[1].msg);
  std::vector<uint8_t> sig = unhex(kVectors[1].sig);
  memset(sig.data() + 32, 0, 32);

  ASSERT_NE(0, bip340_verify(&secp256k1, pk.data(), msg.data(), msg.size(),
                             sig.data()));
}

TEST(BIP340, NullAuxMatchesZeroAux) {
  std::vector<uint8_t> sk = unhex(kVectors[0].seckey);
  std::vector<uint8_t> msg = unhex(kVectors[0].msg);
  uint8_t with_null[BIP340_SIG_LENGTH] = {0};

  ASSERT_EQ(0, bip340_sign(&secp256k1, sk.data(), msg.data(), msg.size(),
                           nullptr, with_null));
  // Vector 0 uses an all-zero aux_rand, so NULL must reproduce it exactly.
  ASSERT_EQ(std::string(kVectors[0].sig), hex(with_null, sizeof(with_null)));
}
