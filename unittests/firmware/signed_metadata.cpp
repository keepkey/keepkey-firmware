/*
 * Unit tests for the EVM clear-signing ("Insight") signed-metadata module.
 *
 * Phase 1 ships with NO built-in verification keys: METADATA_PUBKEYS is all
 * zeros and every signer is loaded at runtime (signed_metadata_store_signer,
 * reached in production through the user-confirmed LoadClearsignSigner FSM
 * handler). The fixture loads the CI test key (02e3b3015c...ab5107) into
 * slot 3 with alias "CI Test"; all vectors are signed in-process with the
 * matching private key (f6d19e15...068a260) and embed key_id=3.
 *
 * No OLED/button I/O is exercised: signed_metadata_process() and
 * signed_metadata_matches_tx() never draw, and signed_metadata_confirm() is
 * only called on its no-I/O early-return guards. The relied-path enforce truth
 * table is tested through the pure, exported signed_metadata_enforce_decision()
 * (see SECTION 2), since relied_on_metadata is only set inside confirm()'s
 * interactive tail.
 */

extern "C" {
#include "messages-ethereum.pb.h"  /* full EthereumSignTx definition */
#include "keepkey/firmware/signed_metadata.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"
}

#include "gtest/gtest.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

/* Test signing key. Its compressed pubkey == firmware METADATA_PUBKEYS[3]. */
const uint8_t TEST_PRIV[32] = {
    0xf6, 0xd1, 0x9e, 0x15, 0xa4, 0x38, 0x5f, 0x03, 0xb7, 0x8b, 0x5a,
    0x1e, 0x16, 0x14, 0xe7, 0xd9, 0xa1, 0x04, 0xd8, 0x1f, 0x73, 0x24,
    0x49, 0x87, 0x56, 0xe5, 0x71, 0x90, 0x40, 0x68, 0xa2, 0x60};

/* Compressed pubkey of TEST_PRIV; loaded into slot 3 by the fixture. */
const uint8_t EXPECTED_SLOT3_PUB[33] = {
    0x02, 0xe3, 0xb3, 0x01, 0x5c, 0x47, 0xdd, 0xca, 0xab, 0xe4, 0xf8,
    0xe8, 0x72, 0xf1, 0xed, 0x8f, 0x09, 0xca, 0x14, 0x5a, 0x8d, 0x81,
    0x77, 0x0d, 0x92, 0x21, 0x3d, 0x56, 0xda, 0x31, 0xab, 0x51, 0x07};

const uint8_t TEST_KEY_ID = 3;

/* Deterministic, opaque test data. Only internal consistency matters. */
const uint8_t CONTRACT_A[20] = {0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b,
                                0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e,
                                0xb0, 0xce, 0x36, 0x06, 0xeb, 0x48};
const uint8_t CONTRACT_B[20] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
const uint8_t SEL_TRANSFER[4] = {0xa9, 0x05, 0x9c, 0xbb};
const uint8_t SEL_APPROVE[4] = {0x09, 0x5e, 0xa7, 0xb3};
const uint8_t TX_HASH[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
const uint8_t RECIPIENT[20] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
                               0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
                               0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53};
const uint8_t AMOUNT32[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    0,
                              0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    0,
                              0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0xe8};

/* ---- byte writers ------------------------------------------------------- */

void put_u8(std::vector<uint8_t> &v, uint8_t x) { v.push_back(x); }
void put_be16(std::vector<uint8_t> &v, uint16_t x) {
  v.push_back((uint8_t)(x >> 8));
  v.push_back((uint8_t)(x & 0xff));
}
void put_be32(std::vector<uint8_t> &v, uint32_t x) {
  v.push_back((uint8_t)(x >> 24));
  v.push_back((uint8_t)(x >> 16));
  v.push_back((uint8_t)(x >> 8));
  v.push_back((uint8_t)(x & 0xff));
}
void put_bytes(std::vector<uint8_t> &v, const uint8_t *b, size_t n) {
  v.insert(v.end(), b, b + n);
}

/* ---- metadata builder --------------------------------------------------- */

struct Arg {
  std::string name;
  uint8_t format;
  std::vector<uint8_t> value;
  int value_len_override;  // -1 => use value.size()
};

Arg mk_arg(const std::string &name, uint8_t format, const uint8_t *value,
           size_t value_len) {
  Arg a;
  a.name = name;
  a.format = format;
  a.value.assign(value, value + value_len);
  a.value_len_override = -1;
  return a;
}

struct Spec {
  uint8_t version;
  uint32_t chain_id;
  std::vector<uint8_t> contract;
  std::vector<uint8_t> selector;
  std::vector<uint8_t> tx_hash;
  std::string method;
  std::vector<Arg> args;
  uint8_t classification;
  uint32_t timestamp;
  uint8_t key_id;
  int method_len_override;  // -1 => use method.size()
  int num_args_override;    // -1 => use args.size()
};

/* Canonical VERIFIED metadata: transfer(to:ADDRESS, amount:AMOUNT) on chain 1. */
Spec base_spec() {
  Spec s;
  s.version = 0x01;
  s.chain_id = 1;
  s.contract.assign(CONTRACT_A, CONTRACT_A + 20);
  s.selector.assign(SEL_TRANSFER, SEL_TRANSFER + 4);
  s.tx_hash.assign(TX_HASH, TX_HASH + 32);
  s.method = "transfer";
  s.args.push_back(mk_arg("to", ARG_FORMAT_ADDRESS, RECIPIENT, 20));
  s.args.push_back(mk_arg("amount", ARG_FORMAT_AMOUNT, AMOUNT32, 32));
  s.classification = METADATA_VERIFIED;
  s.timestamp = 0;
  s.key_id = TEST_KEY_ID;
  s.method_len_override = -1;
  s.num_args_override = -1;
  return s;
}

/* Serialize the signed region (version .. key_id), exactly matching
 * parse_metadata_binary() / serialize_metadata(). */
std::vector<uint8_t> build_body(const Spec &s) {
  std::vector<uint8_t> b;
  put_u8(b, s.version);
  put_be32(b, s.chain_id);
  put_bytes(b, s.contract.data(), s.contract.size());
  put_bytes(b, s.selector.data(), s.selector.size());
  put_bytes(b, s.tx_hash.data(), s.tx_hash.size());

  uint16_t mlen = s.method_len_override >= 0 ? (uint16_t)s.method_len_override
                                             : (uint16_t)s.method.size();
  put_be16(b, mlen);
  put_bytes(b, (const uint8_t *)s.method.data(), s.method.size());

  uint8_t na = s.num_args_override >= 0 ? (uint8_t)s.num_args_override
                                        : (uint8_t)s.args.size();
  put_u8(b, na);
  for (const Arg &a : s.args) {
    put_u8(b, (uint8_t)a.name.size());
    put_bytes(b, (const uint8_t *)a.name.data(), a.name.size());
    put_u8(b, a.format);
    uint16_t vl = a.value_len_override >= 0 ? (uint16_t)a.value_len_override
                                            : (uint16_t)a.value.size();
    put_be16(b, vl);
    put_bytes(b, a.value.data(), a.value.size());
  }

  put_u8(b, s.classification);
  put_be32(b, s.timestamp);
  put_u8(b, s.key_id);
  return b;
}

/* sha256(body) -> ecdsa sign with TEST_PRIV -> append sig(64) + recovery(1).
 * Mirrors signed_metadata_process(): signed_len = payload_len - 64 - 1. */
std::vector<uint8_t> sign_body(std::vector<uint8_t> body) {
  uint8_t digest[32];
  sha256_Raw(body.data(), body.size(), digest);
  uint8_t sig[64];
  uint8_t pby = 0;
  int rc = ecdsa_sign_digest(&secp256k1, TEST_PRIV, digest, sig, &pby, NULL);
  EXPECT_EQ(rc, 0);
  body.insert(body.end(), sig, sig + 64);
  body.push_back((uint8_t)(27 + pby));
  return body;
}

std::vector<uint8_t> base_blob() { return sign_body(build_body(base_spec())); }

void make_msg(EthereumSignTx *msg, const uint8_t contract[20],
              const uint8_t *data, size_t data_len, bool has_chain,
              uint32_t chain) {
  memset(msg, 0, sizeof(*msg));
  msg->has_to = true;
  msg->to.size = 20;
  memcpy(msg->to.bytes, contract, 20);
  msg->has_data_initial_chunk = true;
  msg->data_initial_chunk.size = (pb_size_t)data_len;
  memcpy(msg->data_initial_chunk.bytes, data, data_len);
  msg->has_chain_id = has_chain;
  msg->chain_id = chain;
}

/* A standard transfer() calldata chunk that matches base_spec(). */
void make_matching_msg(EthereumSignTx *msg) {
  uint8_t data[68];
  memcpy(data, SEL_TRANSFER, 4);
  memset(data + 4, 0, sizeof(data) - 4);
  make_msg(msg, CONTRACT_A, data, sizeof(data), /*has_chain=*/true, 1);
}

const char *TEST_ALIAS = "CI Test";

class SignedMetadataTest : public ::testing::Test {
 protected:
  void SetUp() override {
    signed_metadata_clear_signers();
    signed_metadata_store_signer(TEST_KEY_ID, EXPECTED_SLOT3_PUB, TEST_ALIAS);
  }
  void TearDown() override { signed_metadata_clear_signers(); }

  void ExpectMalformed(const std::vector<uint8_t> &blob, uint8_t key_id) {
    EXPECT_EQ(signed_metadata_process(blob.data(), blob.size(), key_id),
              METADATA_MALFORMED);
    EXPECT_FALSE(signed_metadata_available());
    EXPECT_EQ(signed_metadata_get(), nullptr);
  }
};

/* ===================================================================== *
 *  signed_metadata_process — happy path via a runtime-loaded signer
 * ===================================================================== */

TEST_F(SignedMetadataTest, DerivedPubkeyMatchesSlot3) {
  uint8_t pub[33];
  ecdsa_get_public_key33(&secp256k1, TEST_PRIV, pub);
  EXPECT_EQ(memcmp(pub, EXPECTED_SLOT3_PUB, sizeof(pub)), 0)
      << "TEST_PRIV must derive the loaded slot-3 test pubkey";
}

TEST_F(SignedMetadataTest, ValidVerifiedSlot3) {
  std::vector<uint8_t> blob = base_blob();
  EXPECT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EXPECT_TRUE(signed_metadata_available());
  const SignedMetadata *m = signed_metadata_get();
  ASSERT_NE(m, nullptr);
  EXPECT_EQ(m->classification, METADATA_VERIFIED);
  EXPECT_EQ(m->chain_id, 1u);
  EXPECT_STREQ(m->method_name, "transfer");
  EXPECT_EQ(m->num_args, 2);
  EXPECT_EQ(memcmp(m->contract_address, CONTRACT_A, 20), 0);
  EXPECT_EQ(memcmp(m->selector, SEL_TRANSFER, 4), 0);
  EXPECT_EQ(memcmp(m->tx_hash, TX_HASH, 32), 0);
  EXPECT_EQ(m->key_id, TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, ValidOpaqueClassification) {
  Spec s = base_spec();
  s.classification = METADATA_OPAQUE;  // 0
  std::vector<uint8_t> blob = sign_body(build_body(s));
  EXPECT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_OPAQUE);
  EXPECT_TRUE(signed_metadata_available());  // available, but not VERIFIED
  EXPECT_NE(signed_metadata_get(), nullptr);
}

TEST_F(SignedMetadataTest, SelfDeclaredMalformedWithValidSignature) {
  /* A trusted signer can self-declare MALFORMED(2). Signature verifies, so
   * process() returns MALFORMED but leaves the (inert) metadata available. It
   * must never be displayed or relied upon. */
  Spec s = base_spec();
  s.classification = METADATA_MALFORMED;  // 2
  std::vector<uint8_t> blob = sign_body(build_body(s));
  EXPECT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_MALFORMED);
  EXPECT_TRUE(signed_metadata_available());
  EXPECT_NE(signed_metadata_get(), nullptr);

  EthereumSignTx msg;
  make_matching_msg(&msg);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));  // gated on VERIFIED
  EXPECT_FALSE(signed_metadata_confirm());         // gated on VERIFIED
}

/* ===================================================================== *
 *  signed_metadata_process — key-slot guards
 * ===================================================================== */

TEST_F(SignedMetadataTest, KeyIdOutOfRange) {
  ExpectMalformed(base_blob(), /*key_id=*/4);  // >= METADATA_MAX_KEYS
}

TEST_F(SignedMetadataTest, EmptyRotationSlot) {
  Spec s = base_spec();
  s.key_id = 1;  // slot 1: no built-in key, nothing loaded
  ExpectMalformed(sign_body(build_body(s)), /*key_id=*/1);
}

TEST_F(SignedMetadataTest, NullPayload) {
  EXPECT_EQ(signed_metadata_process(nullptr, 200, TEST_KEY_ID),
            METADATA_MALFORMED);
  EXPECT_FALSE(signed_metadata_available());
  EXPECT_EQ(signed_metadata_get(), nullptr);
}

TEST_F(SignedMetadataTest, EmbeddedKeyIdMismatch) {
  Spec s = base_spec();
  s.key_id = 2;  // embedded != protocol key_id (3)
  ExpectMalformed(sign_body(build_body(s)), /*key_id=*/3);
}

TEST_F(SignedMetadataTest, SignatureVerificationFails) {
  std::vector<uint8_t> blob = base_blob();
  blob[146] ^= 0x01;  // flip first signature byte (sig starts after 146B body)
  ExpectMalformed(blob, TEST_KEY_ID);
}

/* ===================================================================== *
 *  signed_metadata_process — length guards
 * ===================================================================== */

TEST_F(SignedMetadataTest, PayloadShorterThan65) {
  std::vector<uint8_t> blob = base_blob();
  blob.resize(64);  // process() early guard: payload_len < 65
  ExpectMalformed(blob, TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, PayloadBetween65And135) {
  std::vector<uint8_t> blob = base_blob();
  blob.resize(100);  // passes <65 guard, fails parser <136 minimum
  ExpectMalformed(blob, TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, TrailingByteAfterRecovery) {
  std::vector<uint8_t> blob = base_blob();
  blob.push_back(0x00);  // cursor != end
  ExpectMalformed(blob, TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, MissingRecoveryByte) {
  std::vector<uint8_t> blob = base_blob();
  blob.pop_back();  // truncated tail: read recovery fails
  ExpectMalformed(blob, TEST_KEY_ID);
}

/* ===================================================================== *
 *  parse_metadata_binary — field guards (all re-signed so the PARSE guard,
 *  not the signature check, is what rejects the blob)
 * ===================================================================== */

TEST_F(SignedMetadataTest, BadVersion) {
  Spec s = base_spec();
  s.version = 0x02;
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, EmptyMethodName) {
  Spec s = base_spec();
  s.method = "";  // 2-byte length prefix == 0
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, MethodNameTooLong) {
  Spec s = base_spec();
  s.method = std::string(65, 'A');  // > METADATA_MAX_METHOD_LEN (64)
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, MethodNameLengthOverrun) {
  /* Length prefix claims 64 but only "transfer" (8B) is the method; the read
   * consumes downstream bytes and parsing misaligns -> MALFORMED. The clean
   * read_string short-read guard is unreachable under the >=136 floor (after
   * the 63-byte fixed prefix at least 73 bytes always remain), so this pins
   * the observable contract rather than a specific internal branch. The
   * corrupted signature byte makes rejection deterministic even in the
   * vanishingly unlikely event the misaligned parse re-aligns to the end. */
  Spec s = base_spec();
  s.method_len_override = 64;
  std::vector<uint8_t> blob = sign_body(build_body(s));
  blob[blob.size() - 2] ^= 0xFF;  // ensure verify cannot pass
  ExpectMalformed(blob, TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, NumArgsTooMany) {
  Spec s = base_spec();
  s.num_args_override = 9;  // > METADATA_MAX_ARGS (8)
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, ArgNameEmpty) {
  Spec s = base_spec();
  s.args[0] = mk_arg("", ARG_FORMAT_ADDRESS, RECIPIENT, 20);  // name_len == 0
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, ArgNameTooLong) {
  Spec s = base_spec();
  std::string long_name(33, 'x');  // > METADATA_MAX_ARG_NAME_LEN (32)
  s.args[0] = mk_arg(long_name, ARG_FORMAT_ADDRESS, RECIPIENT, 20);
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, ArgFormatOutOfRange) {
  Spec s = base_spec();
  s.args[0].format = 4;  // > ARG_FORMAT_BYTES (3)
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, ArgValueTooLong) {
  Spec s = base_spec();
  uint8_t big[33] = {0};
  s.args[0] = mk_arg("to", ARG_FORMAT_BYTES, big, 33);  // > 32
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, ArgValueLengthOverrun) {
  /* value_len prefix claims 32 but only 4 value bytes follow; the read eats
   * into the fixed tail and parsing misaligns -> MALFORMED. As with the method
   * case, the read_bytes short-read guard is dominated by the >=71-byte fixed
   * tail, so this asserts the observable MALFORMED outcome. */
  Spec s = base_spec();
  uint8_t four[4] = {0xde, 0xad, 0xbe, 0xef};
  Arg a = mk_arg("amount", ARG_FORMAT_AMOUNT, four, 4);
  a.value_len_override = 32;
  s.args[1] = a;
  std::vector<uint8_t> blob = sign_body(build_body(s));
  blob[blob.size() - 2] ^= 0xFF;  // ensure verify cannot pass
  ExpectMalformed(blob, TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, ClassificationOutOfRange) {
  Spec s = base_spec();
  s.classification = 3;  // > 2
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
}

/* ===================================================================== *
 *  signed_metadata_matches_tx — display gate
 * ===================================================================== */

TEST_F(SignedMetadataTest, MatchesTxAllBindingsMatch) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  make_matching_msg(&msg);
  EXPECT_TRUE(signed_metadata_matches_tx(&msg));
}

TEST_F(SignedMetadataTest, MatchesTxNotAvailable) {
  signed_metadata_clear();
  EthereumSignTx msg;
  make_matching_msg(&msg);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

TEST_F(SignedMetadataTest, MatchesTxNullMsg) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EXPECT_FALSE(signed_metadata_matches_tx(nullptr));
}

TEST_F(SignedMetadataTest, MatchesTxNotVerifiedClassification) {
  Spec s = base_spec();
  s.classification = METADATA_OPAQUE;
  std::vector<uint8_t> blob = sign_body(build_body(s));
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_OPAQUE);
  EthereumSignTx msg;
  make_matching_msg(&msg);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

TEST_F(SignedMetadataTest, MatchesTxWrongToSize) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  make_matching_msg(&msg);
  msg.to.size = 19;  // not 20 (e.g. contract-create has 0)
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

TEST_F(SignedMetadataTest, MatchesTxDataTooShortForSelector) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  make_matching_msg(&msg);
  msg.data_initial_chunk.size = 3;  // < 4
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

TEST_F(SignedMetadataTest, MatchesTxWrongContract) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  uint8_t data[68];
  memcpy(data, SEL_TRANSFER, 4);
  memset(data + 4, 0, sizeof(data) - 4);
  EthereumSignTx msg;
  make_msg(&msg, CONTRACT_B, data, sizeof(data), true, 1);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

TEST_F(SignedMetadataTest, MatchesTxWrongSelector) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  uint8_t data[68];
  memcpy(data, SEL_APPROVE, 4);  // approve, not transfer
  memset(data + 4, 0, sizeof(data) - 4);
  EthereumSignTx msg;
  make_msg(&msg, CONTRACT_A, data, sizeof(data), true, 1);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

TEST_F(SignedMetadataTest, MatchesTxWrongChainId) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  uint8_t data[68];
  memcpy(data, SEL_TRANSFER, 4);
  memset(data + 4, 0, sizeof(data) - 4);

  EthereumSignTx wrong_chain;
  make_msg(&wrong_chain, CONTRACT_A, data, sizeof(data), true, 137);
  EXPECT_FALSE(signed_metadata_matches_tx(&wrong_chain));

  EthereumSignTx no_chain;
  make_msg(&no_chain, CONTRACT_A, data, sizeof(data), false, 0);  // treated as 0
  EXPECT_FALSE(signed_metadata_matches_tx(&no_chain));
}

/* ===================================================================== *
 *  signed_metadata_confirm — no-I/O early guards
 * ===================================================================== */

TEST_F(SignedMetadataTest, ConfirmNotAvailable) {
  signed_metadata_clear();
  EXPECT_FALSE(signed_metadata_confirm());
}

TEST_F(SignedMetadataTest, ConfirmNotVerified) {
  Spec s = base_spec();
  s.classification = METADATA_OPAQUE;
  std::vector<uint8_t> blob = sign_body(build_body(s));
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_OPAQUE);
  EXPECT_FALSE(signed_metadata_confirm());
}

/* ===================================================================== *
 *  signed_metadata_enforce — module-level not-relied path (reachable
 *  without confirm()'s interactive tail) and clear() reset
 * ===================================================================== */

TEST_F(SignedMetadataTest, EnforceNotReliedAlwaysAllows) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  ASSERT_FALSE(signed_metadata_relied());  // process() never sets relied

  uint8_t wrong[32];
  memcpy(wrong, TX_HASH, 32);
  wrong[0] ^= 0xFF;
  EXPECT_TRUE(signed_metadata_enforce(TX_HASH));
  EXPECT_TRUE(signed_metadata_enforce(wrong));
  EXPECT_TRUE(signed_metadata_enforce(nullptr));
}

TEST_F(SignedMetadataTest, ClearResetsAllState) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  ASSERT_TRUE(signed_metadata_available());

  signed_metadata_clear();
  EXPECT_FALSE(signed_metadata_available());
  EXPECT_FALSE(signed_metadata_relied());
  EXPECT_EQ(signed_metadata_get(), nullptr);
  EXPECT_TRUE(signed_metadata_enforce(TX_HASH));  // not relied
}

/* ===================================================================== *
 *  Runtime signer loading — the phase-1 trust path
 * ===================================================================== */

TEST_F(SignedMetadataTest, NoSignerLoadedRejects) {
  signed_metadata_clear_signers();  // undo the fixture's load
  ExpectMalformed(base_blob(), TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, FromLoadedSignerTracksMetadata) {
  EXPECT_FALSE(signed_metadata_from_loaded_signer());  // nothing processed
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EXPECT_TRUE(signed_metadata_from_loaded_signer());
  signed_metadata_clear();
  EXPECT_FALSE(signed_metadata_from_loaded_signer());
}

TEST_F(SignedMetadataTest, ClearSignersDropsKeyAndMetadata) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  signed_metadata_clear_signers();
  EXPECT_FALSE(signed_metadata_available());
  EXPECT_EQ(signed_metadata_get(), nullptr);
  ExpectMalformed(blob, TEST_KEY_ID);  // the key itself is gone too
}

TEST_F(SignedMetadataTest, StoreSignerReplacementInvalidatesOldKey) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);

  uint8_t priv2[32];
  memcpy(priv2, TEST_PRIV, sizeof(priv2));
  priv2[31] ^= 0x5a;  // a different valid scalar
  uint8_t pub2[33];
  ecdsa_get_public_key33(&secp256k1, priv2, pub2);
  signed_metadata_store_signer(TEST_KEY_ID, pub2, "Replacement");

  /* Replacing a signer drops metadata the old one verified... */
  EXPECT_FALSE(signed_metadata_available());
  /* ...and the old key no longer verifies anything. */
  ExpectMalformed(blob, TEST_KEY_ID);
}

/* ---- signed_metadata_signer_valid (pure) ------------------------------ */

TEST(SignedMetadataSignerValid, AcceptsValidCompressedKeyAllSlots) {
  for (uint8_t slot = 0; slot < METADATA_MAX_KEYS; slot++) {
    EXPECT_TRUE(
        signed_metadata_signer_valid(slot, EXPECTED_SLOT3_PUB, 33, "CI Test"))
        << "slot " << (int)slot;
  }
}

TEST(SignedMetadataSignerValid, RejectsKeyIdOutOfRange) {
  EXPECT_FALSE(signed_metadata_signer_valid(METADATA_MAX_KEYS,
                                            EXPECTED_SLOT3_PUB, 33, "CI Test"));
}

TEST(SignedMetadataSignerValid, RejectsWrongPubkeyLength) {
  EXPECT_FALSE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 32, "CI Test"));
  EXPECT_FALSE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 65, "CI Test"));
  EXPECT_FALSE(signed_metadata_signer_valid(0, nullptr, 33, "CI Test"));
}

TEST(SignedMetadataSignerValid, RejectsNonCompressedPrefix) {
  /* 0x04 would make ecdsa_read_pubkey read 65 bytes from a 33-byte buffer —
   * the prefix guard must reject it before the parser ever runs. */
  uint8_t bad[33];
  memcpy(bad, EXPECTED_SLOT3_PUB, sizeof(bad));
  bad[0] = 0x04;
  EXPECT_FALSE(signed_metadata_signer_valid(0, bad, 33, "CI Test"));
  bad[0] = 0x00;  // the "empty slot" sentinel must never load as a key
  EXPECT_FALSE(signed_metadata_signer_valid(0, bad, 33, "CI Test"));
}

TEST(SignedMetadataSignerValid, RejectsBadAlias) {
  EXPECT_FALSE(signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, nullptr));
  EXPECT_FALSE(signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, ""));
  std::string too_long(METADATA_ALIAS_MAX_LEN + 1, 'a');
  EXPECT_FALSE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, too_long.c_str()));
  std::string max_len(METADATA_ALIAS_MAX_LEN, 'a');
  EXPECT_TRUE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, max_len.c_str()));
  /* Realistic aliases (letters/digits/space/-/_) are accepted. */
  EXPECT_TRUE(signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "Pioneer"));
  EXPECT_TRUE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "KeepKey Swap"));
  EXPECT_TRUE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "my-signer_1"));
  /* Rendered inside quotes on the trust screen — control chars, '%', and
   * semantic-injection punctuation (quote breakout, "." / "(" appending a
   * false "verified by KeepKey." claim) are all rejected. */
  EXPECT_FALSE(signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "a\nb"));
  EXPECT_FALSE(signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "a%sb"));
  EXPECT_FALSE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "a\x7f" "b"));
  EXPECT_FALSE(signed_metadata_signer_valid(
      0, EXPECTED_SLOT3_PUB, 33, "x' verified by KeepKey. Safe ("));
  EXPECT_FALSE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "safe.KeepKey"));
  EXPECT_FALSE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "trust(me)"));
}

/* ---- signed_metadata_pubkey_fingerprint -------------------------------- */

TEST(SignedMetadataFingerprint, IsSha256Prefix) {
  char fp[METADATA_FINGERPRINT_LEN];
  signed_metadata_pubkey_fingerprint(EXPECTED_SLOT3_PUB, fp);

  uint8_t digest[32];
  sha256_Raw(EXPECTED_SLOT3_PUB, 33, digest);
  char expected[METADATA_FINGERPRINT_LEN];
  snprintf(expected, sizeof(expected), "%02X%02X%02X%02X", digest[0], digest[1],
           digest[2], digest[3]);
  EXPECT_STREQ(fp, expected);
}

/* ===================================================================== *
 *  signed_metadata_enforce_decision — pure enforce truth table (SECTION 2).
 *  Exercises the relied==true cases that confirm()'s OLED/button I/O makes
 *  unreachable from the module-state API in a unit test.
 * ===================================================================== */

TEST(SignedMetadataEnforce, NotReliedAlwaysAllow) {
  uint8_t h[32] = {0};
  uint8_t hw[32] = {1};
  EXPECT_TRUE(signed_metadata_enforce_decision(false, true, METADATA_VERIFIED,
                                               h, h));
  EXPECT_TRUE(signed_metadata_enforce_decision(false, false, METADATA_OPAQUE,
                                               nullptr, nullptr));
  EXPECT_TRUE(signed_metadata_enforce_decision(false, true, METADATA_VERIFIED,
                                               h, hw));
}

TEST(SignedMetadataEnforce, ReliedHashMatches) {
  uint8_t h[32];
  memcpy(h, TX_HASH, 32);
  EXPECT_TRUE(signed_metadata_enforce_decision(true, true, METADATA_VERIFIED,
                                               h, h));
}

TEST(SignedMetadataEnforce, ReliedHashMismatch) {
  uint8_t stored[32];
  memcpy(stored, TX_HASH, 32);
  uint8_t got[32];
  memcpy(got, TX_HASH, 32);
  got[0] ^= 0x01;
  EXPECT_FALSE(signed_metadata_enforce_decision(true, true, METADATA_VERIFIED,
                                                stored, got));
}

TEST(SignedMetadataEnforce, ReliedHashNull) {
  uint8_t stored[32];
  memcpy(stored, TX_HASH, 32);
  EXPECT_FALSE(signed_metadata_enforce_decision(true, true, METADATA_VERIFIED,
                                                stored, nullptr));
}

TEST(SignedMetadataEnforce, ReliedNotAvailable) {
  uint8_t h[32];
  memcpy(h, TX_HASH, 32);
  EXPECT_FALSE(signed_metadata_enforce_decision(true, false, METADATA_VERIFIED,
                                                h, h));
}

TEST(SignedMetadataEnforce, ReliedNotVerified) {
  uint8_t h[32];
  memcpy(h, TX_HASH, 32);
  EXPECT_FALSE(signed_metadata_enforce_decision(true, true, METADATA_OPAQUE,
                                                h, h));
  EXPECT_FALSE(signed_metadata_enforce_decision(true, true, METADATA_MALFORMED,
                                                h, h));
}

TEST(SignedMetadataEnforce, ReliedStoredHashNull) {
  uint8_t h[32];
  memcpy(h, TX_HASH, 32);
  EXPECT_FALSE(signed_metadata_enforce_decision(true, true, METADATA_VERIFIED,
                                                nullptr, h));
}

}  // namespace
