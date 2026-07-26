/*
 * Unit tests for the EVM clear-signing ("Insight") signed-metadata module.
 *
 * Phase 1 ships with NO built-in verification keys: every signer is loaded
 * at runtime (signed_metadata_store_signer,
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
#include "messages-ethereum.pb.h" /* full EthereumSignTx definition */
#include "keepkey/board/draw.h"   /* draw_bitmap_mono_rle (icon decoder) */
#include "keepkey/board/layout.h" /* LEFT_MARGIN_WITH_ICON */
#include "keepkey/firmware/signed_metadata.h"
#include "keepkey/firmware/solana.h" /* SolanaTokenInfo, solana_token_info_trusted */
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

/* Test signing key. Its compressed pubkey is loaded into slot 3 by the fixture.
 */
const uint8_t TEST_PRIV[32] = {0xf6, 0xd1, 0x9e, 0x15, 0xa4, 0x38, 0x5f, 0x03,
                               0xb7, 0x8b, 0x5a, 0x1e, 0x16, 0x14, 0xe7, 0xd9,
                               0xa1, 0x04, 0xd8, 0x1f, 0x73, 0x24, 0x49, 0x87,
                               0x56, 0xe5, 0x71, 0x90, 0x40, 0x68, 0xa2, 0x60};

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
const uint8_t TX_HASH[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                             0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                             0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                             0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
const uint8_t RECIPIENT[20] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
                               0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
                               0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53};
const uint8_t AMOUNT32[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0,    0,   0,
                              0, 0, 0, 0, 0, 0, 0, 0, 0,    0,   0,
                              0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0xe8};

/* ---- byte writers ------------------------------------------------------- */

void put_u8(std::vector<uint8_t>& v, uint8_t x) { v.push_back(x); }
void put_be16(std::vector<uint8_t>& v, uint16_t x) {
  v.push_back((uint8_t)(x >> 8));
  v.push_back((uint8_t)(x & 0xff));
}
void put_be32(std::vector<uint8_t>& v, uint32_t x) {
  v.push_back((uint8_t)(x >> 24));
  v.push_back((uint8_t)(x >> 16));
  v.push_back((uint8_t)(x >> 8));
  v.push_back((uint8_t)(x & 0xff));
}
void put_bytes(std::vector<uint8_t>& v, const uint8_t* b, size_t n) {
  v.insert(v.end(), b, b + n);
}

/* ---- metadata builder --------------------------------------------------- */

struct Arg {
  std::string name;
  uint8_t format;
  std::vector<uint8_t> value;
  int value_len_override;  // -1 => use value.size()
};

Arg mk_arg(const std::string& name, uint8_t format, const uint8_t* value,
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

/* Canonical VERIFIED metadata: transfer(to:ADDRESS, amount:AMOUNT) on chain 1.
 */
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
std::vector<uint8_t> build_body(const Spec& s) {
  std::vector<uint8_t> b;
  put_u8(b, s.version);
  put_be32(b, s.chain_id);
  put_bytes(b, s.contract.data(), s.contract.size());
  put_bytes(b, s.selector.data(), s.selector.size());
  put_bytes(b, s.tx_hash.data(), s.tx_hash.size());

  uint16_t mlen = s.method_len_override >= 0 ? (uint16_t)s.method_len_override
                                             : (uint16_t)s.method.size();
  put_be16(b, mlen);
  put_bytes(b, (const uint8_t*)s.method.data(), s.method.size());

  uint8_t na = s.num_args_override >= 0 ? (uint8_t)s.num_args_override
                                        : (uint8_t)s.args.size();
  put_u8(b, na);
  for (const Arg& a : s.args) {
    put_u8(b, (uint8_t)a.name.size());
    put_bytes(b, (const uint8_t*)a.name.data(), a.name.size());
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

void make_msg(EthereumSignTx* msg, const uint8_t contract[20],
              const uint8_t* data, size_t data_len, bool has_chain,
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
void make_matching_msg(EthereumSignTx* msg) {
  uint8_t data[68];
  memcpy(data, SEL_TRANSFER, 4);
  memset(data + 4, 0, sizeof(data) - 4);
  make_msg(msg, CONTRACT_A, data, sizeof(data), /*has_chain=*/true, 1);
}

const char* TEST_ALIAS = "CI Test";

class SignedMetadataTest : public ::testing::Test {
 protected:
  void SetUp() override {
    signed_metadata_clear_signers();
    signed_metadata_store_signer(TEST_KEY_ID, EXPECTED_SLOT3_PUB, TEST_ALIAS,
                                 NULL, 0, 0, 0, false);
  }
  void TearDown() override { signed_metadata_clear_signers(); }

  void ExpectMalformed(const std::vector<uint8_t>& blob, uint8_t key_id) {
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
  const SignedMetadata* m = signed_metadata_get();
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
  s.args[0].format = 6;  // > ARG_FORMAT_TOKEN_AMOUNT (5)
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
}

/* ---- ARG_FORMAT_STRING (attested printable label) ----------------------- */

TEST_F(SignedMetadataTest, StringArgAccepted) {
  Spec s = base_spec();
  const char* label = "Uniswap V2";
  s.args[0] = mk_arg("protocol", ARG_FORMAT_STRING, (const uint8_t*)label,
                     strlen(label));
  std::vector<uint8_t> blob = sign_body(build_body(s));
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  const SignedMetadata* m = signed_metadata_get();
  ASSERT_NE(m, nullptr);
  EXPECT_EQ(m->args[0].format, ARG_FORMAT_STRING);
  EXPECT_EQ(memcmp(m->args[0].value, label, strlen(label)), 0);
}

TEST_F(SignedMetadataTest, StringArgRejectsUnprintableAndPercent) {
  const uint8_t nl[] = {'a', '\n', 'b'};
  Spec s = base_spec();
  s.args[0] = mk_arg("protocol", ARG_FORMAT_STRING, nl, sizeof(nl));
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);

  const uint8_t pct[] = {'a', '%', 's'};
  Spec s2 = base_spec();
  s2.args[0] = mk_arg("protocol", ARG_FORMAT_STRING, pct, sizeof(pct));
  ExpectMalformed(sign_body(build_body(s2)), TEST_KEY_ID);

  Spec s3 = base_spec();
  s3.args[0] = mk_arg("protocol", ARG_FORMAT_STRING, pct, 0);  // empty string
  ExpectMalformed(sign_body(build_body(s3)), TEST_KEY_ID);
}

/* ---- ARG_FORMAT_TOKEN_AMOUNT (decimals + symbol + amount) --------------- */

std::vector<uint8_t> token_amount_value(uint8_t decimals,
                                        const std::string& symbol,
                                        const std::vector<uint8_t>& amount) {
  std::vector<uint8_t> v;
  v.push_back(decimals);
  v.push_back((uint8_t)symbol.size());
  v.insert(v.end(), symbol.begin(), symbol.end());
  v.insert(v.end(), amount.begin(), amount.end());
  return v;
}

TEST_F(SignedMetadataTest, TokenAmountAccepted) {
  /* 1.00 USDC: 1000000 raw, 6 decimals */
  std::vector<uint8_t> amt = {0x0F, 0x42, 0x40};
  std::vector<uint8_t> val = token_amount_value(6, "USDC", amt);
  Spec s = base_spec();
  s.args[1] = mk_arg("amount", ARG_FORMAT_TOKEN_AMOUNT, val.data(), val.size());
  std::vector<uint8_t> blob = sign_body(build_body(s));
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  const SignedMetadata* m = signed_metadata_get();
  ASSERT_NE(m, nullptr);
  EXPECT_EQ(m->args[1].format, ARG_FORMAT_TOKEN_AMOUNT);
  EXPECT_EQ(m->args[1].value_len, val.size());
}

TEST_F(SignedMetadataTest, TokenAmountUnlimited32BytesAccepted) {
  /* UNLIMITED approve: 32 x 0xFF + symbol -> value_len 38 (> old 32 cap) */
  std::vector<uint8_t> amt(32, 0xFF);
  std::vector<uint8_t> val = token_amount_value(6, "USDC", amt);
  EXPECT_EQ(val.size(), 38u);  // 1+1+4+32
  Spec s = base_spec();
  s.args[1] = mk_arg("amount", ARG_FORMAT_TOKEN_AMOUNT, val.data(), val.size());
  std::vector<uint8_t> blob = sign_body(build_body(s));
  EXPECT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
}

TEST_F(SignedMetadataTest, TokenAmountRejectsBadLayout) {
  Spec s = base_spec();
  /* symbol chars outside [A-Za-z0-9] */
  std::vector<uint8_t> bad_sym = token_amount_value(6, "US-C", {0x01});
  s.args[1] =
      mk_arg("amount", ARG_FORMAT_TOKEN_AMOUNT, bad_sym.data(), bad_sym.size());
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);

  /* decimals > 36 */
  Spec s2 = base_spec();
  std::vector<uint8_t> bad_dec = token_amount_value(37, "USDC", {0x01});
  s2.args[1] =
      mk_arg("amount", ARG_FORMAT_TOKEN_AMOUNT, bad_dec.data(), bad_dec.size());
  ExpectMalformed(sign_body(build_body(s2)), TEST_KEY_ID);

  /* symbol_len runs past the value (no amount bytes left) */
  Spec s3 = base_spec();
  std::vector<uint8_t> no_amt = {6, 4, 'U', 'S', 'D', 'C'};
  s3.args[1] =
      mk_arg("amount", ARG_FORMAT_TOKEN_AMOUNT, no_amt.data(), no_amt.size());
  ExpectMalformed(sign_body(build_body(s3)), TEST_KEY_ID);

  /* legacy formats must NOT accept the larger 44-byte cap */
  Spec s4 = base_spec();
  std::vector<uint8_t> big(40, 0xAB);
  s4.args[1] = mk_arg("amount", ARG_FORMAT_AMOUNT, big.data(), big.size());
  ExpectMalformed(sign_body(build_body(s4)), TEST_KEY_ID);
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
  make_msg(&no_chain, CONTRACT_A, data, sizeof(data), false,
           0);  // treated as 0
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
  signed_metadata_store_signer(TEST_KEY_ID, pub2, "Replacement", NULL, 0, 0, 0,
                               false);

  /* Replacing a signer drops metadata the old one verified... */
  EXPECT_FALSE(signed_metadata_available());
  /* ...and the old key no longer verifies anything. */
  ExpectMalformed(blob, TEST_KEY_ID);
}

/* ---- signed_metadata_signer_valid (pure) ------------------------------ */

/*
 * ── Identity-icon decoder hardening ────────────────────────────────────────
 *
 * The clearsign identity icon is HOST-SUPPLIED and is rendered on the trust
 * screen, so the decoder is an attack surface reachable before the user has
 * approved anything. Regression guards for two review findings:
 *
 *  (1) A 0x80 (n = -128) packet is undecodable: draw_bitmap_mono_rle's counter
 *      is int8_t, so -(-128) wraps back to -128 and breaks its `> 0` invariant.
 *      Under NDEBUG the assert is compiled out and decoding proceeded with a
 *      negative counter (signed-overflow UB). Must fail closed instead.
 *  (2) icon_width must not exceed LEFT_MARGIN_WITH_ICON: text starts at x=40
 *      and the icon is drawn AFTER the text, so a wider icon overwrites the
 *      alias / fingerprint / "NOT verified by KeepKey" warning.
 */
namespace {

struct IconCanvas {
  uint8_t buf[64 * 256];
  Canvas canvas;
  IconCanvas() {
    memset(buf, 0, sizeof(buf));
    canvas.buffer = buf;
    canvas.width = 256;
    canvas.height = 64;
    canvas.dirty = false;
  }
};

bool decode_icon(const std::vector<uint8_t>& data, uint16_t w, uint16_t h,
                 IconCanvas* ic) {
  Image img;
  img.w = w;
  img.h = h;
  img.length = (uint32_t)data.size();
  img.data = data.data();
  AnimationFrame frame;
  frame.x = 0;
  frame.y = 0;
  frame.duration = 0;
  frame.color = 100; /* value*100/100 => data bytes land verbatim */
  frame.image = &img;
  return draw_bitmap_mono_rle(&ic->canvas, &frame, /*erase=*/false);
}

}  // namespace

TEST(SignedMetadataIcon, GoldenVectorDecodes) {
  /* The vector published in messages-ethereum.proto: 03 FF FF 00 (w=2,h=2). */
  IconCanvas ic;
  ASSERT_TRUE(decode_icon({0x03, 0xFF, 0xFF, 0x00}, 2, 2, &ic));
  EXPECT_EQ(ic.buf[0 * 256 + 0], 0xFF);
  EXPECT_EQ(ic.buf[0 * 256 + 1], 0xFF);
  EXPECT_EQ(ic.buf[1 * 256 + 0], 0xFF);
  EXPECT_EQ(ic.buf[1 * 256 + 1], 0x00);
}

TEST(SignedMetadataIcon, LiteralOf128IsRejected) {
  /* n = 0x80 = -128. Spec-valid under the old doc, undecodable in fact:
   * previously asserted (debug) or decoded with a negative counter (NDEBUG). */
  std::vector<uint8_t> data;
  data.push_back(0x80);
  for (int i = 0; i < 128; i++) data.push_back(0xAA);
  IconCanvas ic;
  EXPECT_FALSE(decode_icon(data, 128, 1, &ic));
}

TEST(SignedMetadataIcon, ZeroCountIsRejected) {
  /* n == 0 leaves both counters at 0 and hits the same broken invariant. */
  IconCanvas ic;
  EXPECT_FALSE(decode_icon({0x00, 0xFF}, 1, 1, &ic));
}

TEST(SignedMetadataIcon, MaxLiteralOf127Decodes) {
  /* The boundary that IS valid: n = -127 (0x81). */
  std::vector<uint8_t> data;
  data.push_back(0x81);
  for (int i = 0; i < 127; i++) data.push_back((uint8_t)i);
  IconCanvas ic;
  ASSERT_TRUE(decode_icon(data, 127, 1, &ic));
  EXPECT_EQ(ic.buf[0], 0x00);
  EXPECT_EQ(ic.buf[126], 126);
}

TEST(SignedMetadataIcon, MaxRunOf127Decodes) {
  std::vector<uint8_t> data{0x7F, 0x5A};
  IconCanvas ic;
  ASSERT_TRUE(decode_icon(data, 127, 1, &ic));
  EXPECT_EQ(ic.buf[0], 0x5A);
  EXPECT_EQ(ic.buf[126], 0x5A);
}

TEST(SignedMetadataIcon, TruncatedStreamIsRejected) {
  IconCanvas ic;
  EXPECT_FALSE(decode_icon({0x08, 0xFF}, 4, 4, &ic)); /* claims 8, has 2 */
}

/* ── Exact-validation guards (review round 2) ──────────────────────────────
 * The render path is lenient by construction: it fills the canvas and stops,
 * so it cannot reject a final run that straddles the image or trailing packets.
 * Callers gate on the validator, so the validator must be exact. */

TEST(SignedMetadataIcon, StraddlingRunIsRejected) {
  /* 05 FF for a 2x2: a RUN of 5 into a 4-pixel image. The draw loop would fill
   * 4 and report success; the stream is not well-formed. */
  EXPECT_FALSE(draw_bitmap_mono_rle_valid((const uint8_t*)"\x05\xFF", 2, 2, 2));
  IconCanvas ic;
  EXPECT_FALSE(decode_icon({0x05, 0xFF}, 2, 2, &ic));
}

TEST(SignedMetadataIcon, TrailingPacketsAreRejected) {
  /* Exactly fills 2x2, then carries an unread packet. */
  EXPECT_FALSE(
      draw_bitmap_mono_rle_valid((const uint8_t*)"\x04\xFF\x01\xAA", 4, 2, 2));
}

TEST(SignedMetadataIcon, TruncatedLiteralBodyIsRejected) {
  /* n = -3 promises 3 value bytes, only 2 present. */
  EXPECT_FALSE(
      draw_bitmap_mono_rle_valid((const uint8_t*)"\xFD\x01\x02", 3, 3, 1));
}

TEST(SignedMetadataIcon, MissingRunValueByteIsRejected) {
  EXPECT_FALSE(draw_bitmap_mono_rle_valid((const uint8_t*)"\x04", 1, 4, 1));
}

TEST(SignedMetadataIcon, ValidatorAcceptsExactStreams) {
  /* The golden vector, and the valid boundaries. */
  EXPECT_TRUE(
      draw_bitmap_mono_rle_valid((const uint8_t*)"\x03\xFF\xFF\x00", 4, 2, 2));
  EXPECT_TRUE(
      draw_bitmap_mono_rle_valid((const uint8_t*)"\x7F\x5A", 2, 127, 1));
  std::vector<uint8_t> lit;
  lit.push_back(0x81);
  for (int i = 0; i < 127; i++) lit.push_back((uint8_t)i);
  EXPECT_TRUE(
      draw_bitmap_mono_rle_valid(lit.data(), (uint32_t)lit.size(), 127, 1));
}

TEST(SignedMetadataIcon, ValidatorRejectsUndecodableAndZeroCounts) {
  std::vector<uint8_t> lit128;
  lit128.push_back(0x80);
  for (int i = 0; i < 128; i++) lit128.push_back(0xAA);
  EXPECT_FALSE(draw_bitmap_mono_rle_valid(lit128.data(),
                                          (uint32_t)lit128.size(), 128, 1));
  EXPECT_FALSE(draw_bitmap_mono_rle_valid((const uint8_t*)"\x00\xFF", 2, 1, 1));
  /* The 1x1 accept-and-persist case: 80 FF was previously stored despite never
   * rendering, because only size+dims were checked at the trust boundary. */
  EXPECT_FALSE(draw_bitmap_mono_rle_valid((const uint8_t*)"\x80\xFF", 2, 1, 1));
}

TEST(SignedMetadataIcon, ValidatorRejectsDegenerateGeometry) {
  EXPECT_FALSE(draw_bitmap_mono_rle_valid((const uint8_t*)"\x01\xFF", 2, 0, 1));
  EXPECT_FALSE(draw_bitmap_mono_rle_valid((const uint8_t*)"\x01\xFF", 2, 1, 0));
  EXPECT_FALSE(draw_bitmap_mono_rle_valid(NULL, 0, 1, 1));
}

TEST(SignedMetadataIcon, IconColumnCapIsNarrowerThanTheIconHeight) {
  /* The width cap is the 40px text column, NOT the 64px height. A 64px-wide
   * icon at x=0 would span into the text that begins at x=40 and, because the
   * icon is drawn after the text, erase the "NOT verified" warning. */
  EXPECT_EQ(LEFT_MARGIN_WITH_ICON, 40);
  EXPECT_LT(LEFT_MARGIN_WITH_ICON, 64);
}

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
  EXPECT_FALSE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, nullptr));
  EXPECT_FALSE(signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, ""));
  std::string too_long(METADATA_ALIAS_MAX_LEN + 1, 'a');
  EXPECT_FALSE(signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33,
                                            too_long.c_str()));
  std::string max_len(METADATA_ALIAS_MAX_LEN, 'a');
  EXPECT_TRUE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, max_len.c_str()));
  /* Realistic aliases (letters/digits/space/-/_) are accepted. */
  EXPECT_TRUE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "Pioneer"));
  EXPECT_TRUE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "KeepKey Swap"));
  EXPECT_TRUE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "my-signer_1"));
  /* Rendered inside quotes on the trust screen — control chars, '%', and
   * semantic-injection punctuation (quote breakout, "." / "(" appending a
   * false "verified by KeepKey." claim) are all rejected. */
  EXPECT_FALSE(signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "a\nb"));
  EXPECT_FALSE(signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "a%sb"));
  EXPECT_FALSE(signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33,
                                            "a\x7f"
                                            "b"));
  EXPECT_FALSE(signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33,
                                            "x' verified by KeepKey. Safe ("));
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
  EXPECT_TRUE(
      signed_metadata_enforce_decision(false, true, METADATA_VERIFIED, h, h));
  EXPECT_TRUE(signed_metadata_enforce_decision(false, false, METADATA_OPAQUE,
                                               nullptr, nullptr));
  EXPECT_TRUE(
      signed_metadata_enforce_decision(false, true, METADATA_VERIFIED, h, hw));
}

TEST(SignedMetadataEnforce, ReliedHashMatches) {
  uint8_t h[32];
  memcpy(h, TX_HASH, 32);
  EXPECT_TRUE(
      signed_metadata_enforce_decision(true, true, METADATA_VERIFIED, h, h));
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
  EXPECT_FALSE(
      signed_metadata_enforce_decision(true, false, METADATA_VERIFIED, h, h));
}

TEST(SignedMetadataEnforce, ReliedNotVerified) {
  uint8_t h[32];
  memcpy(h, TX_HASH, 32);
  EXPECT_FALSE(
      signed_metadata_enforce_decision(true, true, METADATA_OPAQUE, h, h));
  EXPECT_FALSE(
      signed_metadata_enforce_decision(true, true, METADATA_MALFORMED, h, h));
}

TEST(SignedMetadataEnforce, ReliedStoredHashNull) {
  uint8_t h[32];
  memcpy(h, TX_HASH, 32);
  EXPECT_FALSE(signed_metadata_enforce_decision(true, true, METADATA_VERIFIED,
                                                nullptr, h));
}

/* ===================================================================== *
 *  SECTION 3 — v2 static-schema blobs + on-device calldata decode
 *
 *  v2 carries NO tx_hash and NO argument values. The blob attests only the
 *  static schema (chainId, contract, selector, method, per-arg name + display
 *  format [+ static decimals/symbol]); the device decodes the actual argument
 *  values from the calldata it is about to sign. These tests drive the full
 *  parse -> verify -> signed_metadata_matches_tx (which decodes) path and check
 *  the decoded MetadataArg values, plus the malformed/rejection cases.
 * ===================================================================== */

struct V2Arg {
  std::string name;
  uint8_t format;
  uint8_t decimals;   /* TOKEN_AMOUNT only */
  std::string symbol; /* TOKEN_AMOUNT only */
};

V2Arg v2_addr(const std::string& name) {
  return V2Arg{name, ARG_FORMAT_ADDRESS, 0, ""};
}
V2Arg v2_token(const std::string& name, uint8_t decimals,
               const std::string& symbol) {
  return V2Arg{name, ARG_FORMAT_TOKEN_AMOUNT, decimals, symbol};
}

struct V2Spec {
  uint32_t chain_id;
  std::vector<uint8_t> contract;
  std::vector<uint8_t> selector;
  std::string method;
  std::vector<V2Arg> args;
  uint8_t classification;
  uint8_t key_id;
  int num_args_override;  // -1 => use args.size()
};

V2Spec v2_base_spec() {
  V2Spec s;
  s.chain_id = 1;
  s.contract.assign(CONTRACT_A, CONTRACT_A + 20);
  s.selector.assign(SEL_TRANSFER, SEL_TRANSFER + 4);
  s.method = "transfer";
  s.args.push_back(v2_addr("to"));
  s.args.push_back(v2_token("amount", 6, "USDC"));
  s.classification = METADATA_VERIFIED;
  s.key_id = TEST_KEY_ID;
  s.num_args_override = -1;
  return s;
}

std::vector<uint8_t> build_v2_body(const V2Spec& s) {
  std::vector<uint8_t> b;
  put_u8(b, METADATA_VERSION_SCHEMA);
  put_be32(b, s.chain_id);
  put_bytes(b, s.contract.data(), s.contract.size());
  put_bytes(b, s.selector.data(), s.selector.size());
  put_be16(b, (uint16_t)s.method.size());
  put_bytes(b, (const uint8_t*)s.method.data(), s.method.size());
  put_u8(b, s.num_args_override >= 0 ? (uint8_t)s.num_args_override
                                     : (uint8_t)s.args.size());
  for (const V2Arg& a : s.args) {
    put_u8(b, (uint8_t)a.name.size());
    put_bytes(b, (const uint8_t*)a.name.data(), a.name.size());
    put_u8(b, a.format);
    if (a.format == ARG_FORMAT_TOKEN_AMOUNT) {
      put_u8(b, a.decimals);
      put_u8(b, (uint8_t)a.symbol.size());
      put_bytes(b, (const uint8_t*)a.symbol.data(), a.symbol.size());
    }
  }
  put_u8(b, s.classification);
  put_be32(b, 0);  // timestamp
  put_u8(b, s.key_id);
  return b;
}

std::vector<uint8_t> v2_base_blob() {
  return sign_body(build_v2_body(v2_base_spec()));
}

/* ABI calldata: selector + one 32-byte head word per arg. */
void put_addr_word(std::vector<uint8_t>& d, const uint8_t addr[20]) {
  for (int i = 0; i < 12; i++) d.push_back(0);
  d.insert(d.end(), addr, addr + 20);
}

/* Canonical transfer(to=RECIPIENT, amount=AMOUNT32) calldata (4 + 64 = 68). */
std::vector<uint8_t> v2_transfer_calldata() {
  std::vector<uint8_t> d(SEL_TRANSFER, SEL_TRANSFER + 4);
  put_addr_word(d, RECIPIENT);
  d.insert(d.end(), AMOUNT32, AMOUNT32 + 32);
  return d;
}

void make_v2_msg(EthereumSignTx* msg, const uint8_t contract[20],
                 const std::vector<uint8_t>& data, bool has_len,
                 uint32_t data_length) {
  memset(msg, 0, sizeof(*msg));
  msg->has_to = true;
  msg->to.size = 20;
  memcpy(msg->to.bytes, contract, 20);
  msg->has_data_initial_chunk = true;
  msg->data_initial_chunk.size = (pb_size_t)data.size();
  memcpy(msg->data_initial_chunk.bytes, data.data(), data.size());
  msg->has_chain_id = true;
  msg->chain_id = 1;
  msg->has_data_length = has_len;
  msg->data_length = has_len ? data_length : 0;
}

/* Happy path: parse+verify a v2 blob, then matches_tx decodes the args from the
 * transfer calldata and populates stored_metadata. */
TEST_F(SignedMetadataTest, V2SchemaDecodesTransferArgs) {
  std::vector<uint8_t> blob = v2_base_blob();
  EXPECT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EXPECT_TRUE(signed_metadata_available());

  const SignedMetadata* md = signed_metadata_get();
  ASSERT_NE(md, nullptr);
  EXPECT_EQ(md->version, METADATA_VERSION_SCHEMA);
  EXPECT_EQ(md->num_args, 2);
  EXPECT_EQ(md->args[0].value_len, 0);  // undecoded before matches_tx

  EthereumSignTx msg;
  std::vector<uint8_t> data = v2_transfer_calldata();
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/true, (uint32_t)data.size());
  EXPECT_TRUE(signed_metadata_matches_tx(&msg));

  EXPECT_EQ(md->args[0].format, ARG_FORMAT_ADDRESS);
  EXPECT_EQ(md->args[0].value_len, 20);
  EXPECT_EQ(memcmp(md->args[0].value, RECIPIENT, 20), 0);

  EXPECT_EQ(md->args[1].format, ARG_FORMAT_TOKEN_AMOUNT);
  EXPECT_EQ(md->args[1].value_len, 2 + 4 + 32);
  EXPECT_EQ(md->args[1].value[0], 6);  // decimals
  EXPECT_EQ(md->args[1].value[1], 4);  // symlen
  EXPECT_EQ(memcmp(md->args[1].value + 2, "USDC", 4), 0);
  EXPECT_EQ(memcmp(md->args[1].value + 6, AMOUNT32, 32), 0);
}

/* THE v2 drain preventer: a v2 schema commits to calldata only — never to
 * msg->value — and a v2 match suppresses ethereum.c's native-value confirm
 * screen. A payable method could then clear-sign an arbitrary ETH transfer
 * whose value is never shown. Any nonzero native value must therefore refuse
 * the v2 match and fall to the blind-sign gate. (v1 is safe: tx_hash covers
 * value.) */
TEST_F(SignedMetadataTest, V2SchemaRejectsNonzeroNativeValue) {
  std::vector<uint8_t> blob = v2_base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);

  EthereumSignTx msg;
  std::vector<uint8_t> data = v2_transfer_calldata();
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/true, (uint32_t)data.size());
  msg.has_value = true;
  msg.value.size = 1;
  msg.value.bytes[0] = 0x01;  // 1 wei is enough — any nonzero value refuses
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));

  /* Same tx with zero value clear-signs — proving the refusal above is the
   * value guard, not some other binding. */
  msg.value.size = 0;
  msg.has_value = false;
  EXPECT_TRUE(signed_metadata_matches_tx(&msg));
}

/* Relay solver swap: selector 0x02d5f05f(token address, amount, requestId) —
 * three fixed single words, EXACTLY the shape pulled from real relay traffic
 * (100-byte calldata: 4 + 3*32, zero remainder, verified across 22 live
 * samples). Proves a v2 static schema clear-signs a relay swap: the device
 * decodes token+amount+id from the very calldata it is about to sign — no
 * tx_hash, no per-tx online signer, schema signed once offline. This is the
 * "add a new service via a signed payload" path for a NON-native contract
 * (relay is not in ethereum_contractHandled). */
TEST_F(SignedMetadataTest, V2SchemaDecodesRelaySolverArgs) {
  const uint8_t RELAY_SOLVER[20] = {0x4c, 0xd0, 0x0e, 0x38, 0x76, 0x22, 0xc3,
                                    0x5b, 0xdd, 0xb9, 0xb4, 0x96, 0x2c, 0x13,
                                    0x64, 0x62, 0x33, 0x8b, 0xc3, 0x31};
  const uint8_t SEL_RELAY[4] = {0x02, 0xd5, 0xf0, 0x5f};
  uint8_t REQ_ID[32] = {0};  // requestId 0x...cd7c from a real sample
  REQ_ID[30] = 0xcd;
  REQ_ID[31] = 0x7c;

  V2Spec s = v2_base_spec();
  s.contract.assign(RELAY_SOLVER, RELAY_SOLVER + 20);
  s.selector.assign(SEL_RELAY, SEL_RELAY + 4);
  s.method = "relaySwap";
  s.args.clear();
  s.args.push_back(v2_addr("token"));
  s.args.push_back(v2_token("amount", 6, "USDC"));
  s.args.push_back(V2Arg{"requestId", ARG_FORMAT_AMOUNT, 0, ""});

  std::vector<uint8_t> blob = sign_body(build_v2_body(s));
  EXPECT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);

  const SignedMetadata* md = signed_metadata_get();
  ASSERT_NE(md, nullptr);
  EXPECT_EQ(md->version, METADATA_VERSION_SCHEMA);
  EXPECT_EQ(md->num_args, 3);

  // Real relay calldata: selector + token(USDC=CONTRACT_A) + amount +
  // requestId.
  std::vector<uint8_t> data(SEL_RELAY, SEL_RELAY + 4);
  put_addr_word(data, CONTRACT_A);
  data.insert(data.end(), AMOUNT32, AMOUNT32 + 32);
  data.insert(data.end(), REQ_ID, REQ_ID + 32);
  EXPECT_EQ(data.size(), 100u);

  EthereumSignTx msg;
  make_v2_msg(&msg, RELAY_SOLVER, data, /*has_len=*/true,
              (uint32_t)data.size());
  EXPECT_TRUE(signed_metadata_matches_tx(&msg));

  // token → full 20-byte USDC address (never truncated).
  EXPECT_EQ(md->args[0].format, ARG_FORMAT_ADDRESS);
  EXPECT_EQ(md->args[0].value_len, 20);
  EXPECT_EQ(memcmp(md->args[0].value, CONTRACT_A, 20), 0);

  // amount → TOKEN_AMOUNT [decimals=6, "USDC", 32-byte amount].
  EXPECT_EQ(md->args[1].format, ARG_FORMAT_TOKEN_AMOUNT);
  EXPECT_EQ(md->args[1].value[0], 6);
  EXPECT_EQ(md->args[1].value[1], 4);
  EXPECT_EQ(memcmp(md->args[1].value + 2, "USDC", 4), 0);
  EXPECT_EQ(memcmp(md->args[1].value + 6, AMOUNT32, 32), 0);

  // requestId → raw 32-byte AMOUNT word.
  EXPECT_EQ(md->args[2].format, ARG_FORMAT_AMOUNT);
  EXPECT_EQ(md->args[2].value_len, 32);
  EXPECT_EQ(memcmp(md->args[2].value, REQ_ID, 32), 0);
}

/* has_data_length omitted but the initial chunk IS the whole calldata: allowed.
 */
TEST_F(SignedMetadataTest, V2AcceptsNoDataLengthWhenChunkComplete) {
  std::vector<uint8_t> blob = v2_base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  std::vector<uint8_t> data = v2_transfer_calldata();
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/false, 0);
  EXPECT_TRUE(signed_metadata_matches_tx(&msg));
}

/* Reject when the tx claims MORE calldata than the schema accounts for. */
TEST_F(SignedMetadataTest, V2RejectsExtraCalldataLength) {
  std::vector<uint8_t> blob = v2_base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  std::vector<uint8_t> data = v2_transfer_calldata();  // 68 bytes
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/true, 100);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

/* Reject a partial initial chunk (rest would stream later). */
TEST_F(SignedMetadataTest, V2RejectsPartialInitialChunk) {
  std::vector<uint8_t> blob = v2_base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  std::vector<uint8_t> data = v2_transfer_calldata();
  data.resize(40);  // selector + partial first word
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/true, 68);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

/* Reject an ABI address word with non-zero high bytes. */
TEST_F(SignedMetadataTest, V2RejectsDirtyAddressWord) {
  std::vector<uint8_t> blob = v2_base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  std::vector<uint8_t> data = v2_transfer_calldata();
  data[4] = 0x01;  // first (should-be-zero) byte of the address word
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/true, (uint32_t)data.size());
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

/* Wrong selector in calldata -> matches_tx fails before decode. */
TEST_F(SignedMetadataTest, V2RejectsSelectorMismatch) {
  std::vector<uint8_t> blob = v2_base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  std::vector<uint8_t> data = v2_transfer_calldata();
  memcpy(data.data(), SEL_APPROVE, 4);
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/true, (uint32_t)data.size());
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

/* An unsupported display format (dynamic types out of scope) -> MALFORMED. */
TEST_F(SignedMetadataTest, V2RejectsUnsupportedFormat) {
  V2Spec s = v2_base_spec();
  s.args[1] = V2Arg{"data", ARG_FORMAT_BYTES, 0, ""};
  std::vector<uint8_t> blob = sign_body(build_v2_body(s));
  ExpectMalformed(blob, TEST_KEY_ID);
}

/* Tampered v2 body must fail the signature check. */
TEST_F(SignedMetadataTest, V2RejectsTamperedBody) {
  std::vector<uint8_t> blob = v2_base_blob();
  blob[5] ^= 0xFF;  // flip a contract-address byte in the signed region
  ExpectMalformed(blob, TEST_KEY_ID);
}

/* Zero-arg v2 schema (selector-only call): valid, decodes nothing. */
TEST_F(SignedMetadataTest, V2ZeroArgsSelectorOnly) {
  V2Spec s = v2_base_spec();
  s.args.clear();
  s.method = "poke";
  std::vector<uint8_t> blob = sign_body(build_v2_body(s));
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  std::vector<uint8_t> data(SEL_TRANSFER, SEL_TRANSFER + 4);
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/true, 4);
  EXPECT_TRUE(signed_metadata_matches_tx(&msg));
  EXPECT_EQ(signed_metadata_get()->num_args, 0);
}

/* matches_tx() must be idempotent: a second call decodes to the same values
 * (regression for the TOKEN_AMOUNT prefix that used to grow on each call). */
TEST_F(SignedMetadataTest, V2MatchesTxIsIdempotent) {
  std::vector<uint8_t> blob = v2_base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  std::vector<uint8_t> data = v2_transfer_calldata();
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/true, (uint32_t)data.size());

  EXPECT_TRUE(signed_metadata_matches_tx(&msg));
  const SignedMetadata* md = signed_metadata_get();
  uint16_t len_addr = md->args[0].value_len, len_tok = md->args[1].value_len;

  EXPECT_TRUE(signed_metadata_matches_tx(&msg));  // second call
  EXPECT_EQ(md->args[0].value_len, len_addr);
  EXPECT_EQ(md->args[1].value_len, len_tok);
  EXPECT_EQ(md->args[1].value_len, 2 + 4 + 32);
  EXPECT_EQ(memcmp(md->args[0].value, RECIPIENT, 20), 0);
  EXPECT_EQ(memcmp(md->args[1].value + 6, AMOUNT32, 32), 0);
}

/* The v2 decode flag must reflect ONLY the latest matches_tx() call: a
 * successful decode followed by a mismatching tx must leave it false, so a
 * stale "decoded" proof can never survive into enforce. */
TEST_F(SignedMetadataTest, V2SchemaDecodedFlagNotStaleAfterMismatch) {
  std::vector<uint8_t> blob = v2_base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EXPECT_FALSE(signed_metadata_schema_decoded());  // not decoded yet

  EthereumSignTx ok;
  std::vector<uint8_t> data = v2_transfer_calldata();
  make_v2_msg(&ok, CONTRACT_A, data, /*has_len=*/true, (uint32_t)data.size());
  ASSERT_TRUE(signed_metadata_matches_tx(&ok));
  EXPECT_TRUE(signed_metadata_schema_decoded());  // decoded this tx

  /* Now a tx that fails an EARLY binding (wrong contract) — before the decode
   * branch. The flag must be cleared, not left over from the match above. */
  EthereumSignTx bad;
  make_v2_msg(&bad, CONTRACT_B, data, /*has_len=*/true, (uint32_t)data.size());
  EXPECT_FALSE(signed_metadata_matches_tx(&bad));
  EXPECT_FALSE(signed_metadata_schema_decoded());
}

/* ---- v2 enforce truth table (pure, no I/O) ------------------------------ */
/* Signature: (relied, available, decoded, classification). */

TEST(SignedMetadataEnforceSchema, NotReliedAlwaysAllow) {
  EXPECT_TRUE(signed_metadata_enforce_schema_decision(false, true, true,
                                                      METADATA_VERIFIED));
  EXPECT_TRUE(signed_metadata_enforce_schema_decision(false, false, false,
                                                      METADATA_OPAQUE));
}

TEST(SignedMetadataEnforceSchema, ReliedVerifiedDecodedAllow) {
  EXPECT_TRUE(signed_metadata_enforce_schema_decision(true, true, true,
                                                      METADATA_VERIFIED));
}

TEST(SignedMetadataEnforceSchema, ReliedButNotDecodedFails) {
  /* The core hardening: relied + available + VERIFIED but decode never ran. */
  EXPECT_FALSE(signed_metadata_enforce_schema_decision(true, true, false,
                                                       METADATA_VERIFIED));
}

TEST(SignedMetadataEnforceSchema, ReliedButUnavailableOrUnverifiedFails) {
  EXPECT_FALSE(signed_metadata_enforce_schema_decision(true, false, true,
                                                       METADATA_VERIFIED));
  EXPECT_FALSE(signed_metadata_enforce_schema_decision(true, true, true,
                                                       METADATA_OPAQUE));
  EXPECT_FALSE(signed_metadata_enforce_schema_decision(true, true, true,
                                                       METADATA_MALFORMED));
}

// Generic attestation primitive (used by the Solana signed-token-definition
// path): a valid signature from a loaded signer verifies; tampering, an
// unloaded key_id, or a wrong signature length are all rejected.
TEST(SignedMetadataAttestation, VerifiesValidRejectsTampered) {
  signed_metadata_clear_signers();
  signed_metadata_store_signer(TEST_KEY_ID, EXPECTED_SLOT3_PUB, TEST_ALIAS,
                               nullptr, 0, 0, 0, false);

  const uint8_t data[] = "KeepKeySolanaTokenDef/1|mint|decimals|USDC";
  const size_t len = sizeof(data) - 1;
  uint8_t digest[32];
  sha256_Raw(data, len, digest);
  uint8_t sig[64];
  uint8_t pby;
  ASSERT_EQ(
      0, ecdsa_sign_digest(&secp256k1, TEST_PRIV, digest, sig, &pby, nullptr));

  EXPECT_TRUE(signed_metadata_verify_attestation(TEST_KEY_ID, data, len, sig,
                                                 sizeof(sig)));

  std::vector<uint8_t> bad(data, data + len);
  bad[0] ^= 0x01;
  EXPECT_FALSE(signed_metadata_verify_attestation(TEST_KEY_ID, bad.data(), len,
                                                  sig, sizeof(sig)));
  EXPECT_FALSE(signed_metadata_verify_attestation((uint8_t)(TEST_KEY_ID + 1),
                                                  data, len, sig, sizeof(sig)));
  EXPECT_FALSE(
      signed_metadata_verify_attestation(TEST_KEY_ID, data, len, sig, 63));

  signed_metadata_clear_signers();
}

// End-to-end test of the production Solana token-definition path: builds the
// exact domain-separated preimage solana_token_info_trusted() reconstructs,
// signs it, and checks acceptance + every rejection branch.
TEST(SolanaTokenDef, TrustedOnlyWithValidAttestation) {
  signed_metadata_clear_signers();
  signed_metadata_store_signer(TEST_KEY_ID, EXPECTED_SLOT3_PUB, TEST_ALIAS,
                               nullptr, 0, 0, 0, false);

  SolanaTokenInfo ti;
  memset(&ti, 0, sizeof(ti));
  ti.has_mint = true;
  ti.mint.size = 32;
  memset(ti.mint.bytes, 0xAB, 32);
  ti.has_symbol = true;
  strcpy(ti.symbol, "USDC");
  ti.has_decimals = true;
  ti.decimals = 6;
  ti.has_signer_key_id = true;
  ti.signer_key_id = TEST_KEY_ID;

  // Canonical preimage: tag || mint(32) || decimals(le32) || symbol.
  std::vector<uint8_t> pre;
  const char* tag = "KeepKeySolanaTokenDef/1";
  pre.insert(pre.end(), tag, tag + strlen(tag));
  pre.insert(pre.end(), ti.mint.bytes, ti.mint.bytes + 32);
  pre.push_back(6);
  pre.push_back(0);
  pre.push_back(0);
  pre.push_back(0);
  pre.insert(pre.end(), ti.symbol, ti.symbol + strlen(ti.symbol));

  uint8_t digest[32];
  sha256_Raw(pre.data(), pre.size(), digest);
  uint8_t sig[64];
  uint8_t pby;
  ASSERT_EQ(
      0, ecdsa_sign_digest(&secp256k1, TEST_PRIV, digest, sig, &pby, nullptr));
  ti.has_signature = true;
  ti.signature.size = 64;
  memcpy(ti.signature.bytes, sig, 64);

  EXPECT_TRUE(solana_token_info_trusted(&ti));

  // Attested-tuple disagreement: a different decimals no longer matches the
  // sig.
  ti.decimals = 9;
  EXPECT_FALSE(solana_token_info_trusted(&ti));
  ti.decimals = 6;
  EXPECT_TRUE(solana_token_info_trusted(&ti));

  // Corrupted signature.
  ti.signature.bytes[10] ^= 0x40;
  EXPECT_FALSE(solana_token_info_trusted(&ti));
  ti.signature.bytes[10] ^= 0x40;

  // Out-of-range signer slot (256 would narrow to slot 0 without the guard).
  ti.signer_key_id = 256;
  EXPECT_FALSE(solana_token_info_trusted(&ti));
  ti.signer_key_id = TEST_KEY_ID;

  // No attestation -> not trusted (the caller falls back to unsigned display).
  ti.has_signature = false;
  EXPECT_FALSE(solana_token_info_trusted(&ti));

  signed_metadata_clear_signers();
}

}  // namespace
