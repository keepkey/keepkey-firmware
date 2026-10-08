extern "C" {
#include "keepkey/board/canvas.h"
#include "keepkey/board/font.h"
#include "keepkey/board/layout.h"
#include "keepkey/firmware/eip712_stream.h"
#include "keepkey/firmware/eip712_stream.h"  // Public declarations stay guarded.
#include "keepkey/firmware/erc7730_format.h"
#include "messages-ethereum.pb.h"
#include "trezor/crypto/address.h"
#include "trezor/crypto/sha3.h"
}

#include "gtest/gtest.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>
#include "kkconfirm_driver.h"

extern "C" {
#include "keepkey/board/confirm_sm.h"
}

void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);
std::vector<std::string> kkconfirm_captured_titles(void);

namespace {

typedef EthereumTypedDataStructAck_EthereumFieldType Field;

Field mk(EthereumTypedDataStructAck_EthereumDataType t) {
  Field f;
  memset(&f, 0, sizeof(f));
  f.data_type = t;
  return f;
}

Field mkSized(EthereumTypedDataStructAck_EthereumDataType t, uint32_t size) {
  Field f = mk(t);
  f.has_size = true;
  f.size = size;
  return f;
}

std::string nameOf(const Field& f) {
  char out[EIP712_MAX_TYPE_NAME];
  if (!eip712_type_name(&f, out, sizeof(out))) return "<refused>";
  return std::string(out);
}

std::string hexOf(const uint8_t* b, size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) {
    s += d[b[i] >> 4];
    s += d[b[i] & 0xF];
  }
  return s;
}

}  // namespace

// ── encodeType spelling ─────────────────────────────────────────────
// These strings go into typeHash. A wrong character here is not a display
// bug, it is a signature over a different document.

TEST(Eip712Stream, TypeNameAtomics) {
  EXPECT_EQ(
      nameOf(mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32)),
      "uint256");
  EXPECT_EQ(
      nameOf(mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 1)),
      "uint8");
  EXPECT_EQ(nameOf(mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, 2)),
            "int16");
  EXPECT_EQ(
      nameOf(mkSized(EthereumTypedDataStructAck_EthereumDataType_BYTES, 32)),
      "bytes32");
  EXPECT_EQ(nameOf(mk(EthereumTypedDataStructAck_EthereumDataType_BYTES)),
            "bytes");
  EXPECT_EQ(nameOf(mk(EthereumTypedDataStructAck_EthereumDataType_STRING)),
            "string");
  EXPECT_EQ(nameOf(mk(EthereumTypedDataStructAck_EthereumDataType_BOOL)),
            "bool");
  EXPECT_EQ(nameOf(mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS)),
            "address");
}

TEST(Eip712Stream, TypeNameRejectsNonCanonicalWidths) {
  // uint0 and uint264 have no canonical spelling. Inventing one would hash a
  // type string no verifier reproduces.
  EXPECT_EQ(
      nameOf(mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 0)),
      "<refused>");
  EXPECT_EQ(
      nameOf(mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 33)),
      "<refused>");
  EXPECT_EQ(
      nameOf(mkSized(EthereumTypedDataStructAck_EthereumDataType_BYTES, 33)),
      "<refused>");
  // A width-less integer is not "uint256" -- EIP-712 requires the width be
  // written, and the bare form is what the old parser silently accepted.
  EXPECT_EQ(nameOf(mk(EthereumTypedDataStructAck_EthereumDataType_UINT)),
            "<refused>");
}

TEST(Eip712Stream, TypeNameArraysInWrittenOrder) {
  Field f = mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, 2);
  f.array_levels_count = 3;
  f.array_levels[0] = 2;
  f.array_levels[1] = 0;  // dynamic
  f.array_levels[2] = 4;
  EXPECT_EQ(nameOf(f), "int16[2][][4]");

  Field s = mk(EthereumTypedDataStructAck_EthereumDataType_STRUCT);
  s.has_struct_name = true;
  strcpy(s.struct_name, "Person");
  s.array_levels_count = 1;
  s.array_levels[0] = 0;
  EXPECT_EQ(nameOf(s), "Person[]");
}

TEST(Eip712Stream, TypeNameRejectsArrayCountPastWireCapacity) {
  Field f = mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, 2);
  f.array_levels_count = sizeof(f.array_levels) / sizeof(f.array_levels[0]) + 1;
  EXPECT_EQ(nameOf(f), "<refused>");
}

TEST(Eip712Stream, TypeNameStructNeedsAName) {
  EXPECT_EQ(nameOf(mk(EthereumTypedDataStructAck_EthereumDataType_STRUCT)),
            "<refused>");
}

// ── encodeData ──────────────────────────────────────────────────────

TEST(Eip712Stream, EncodeUintIsLeftPadded) {
  Field f = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  uint8_t v[32];
  memset(v, 0, sizeof(v));
  v[31] = 0x2a;  // 42
  uint8_t out[32];
  ASSERT_TRUE(eip712_encode_leaf(&f, v, 32, out));
  EXPECT_EQ(hexOf(out, 32),
            "000000000000000000000000000000000000000000000000000000000000002a");
}

TEST(Eip712Stream, EncodeUnlimitedApprovalSurvives) {
  // The old JSON path parsed integers with strtoll and refused anything above
  // 2^63-1 -- which is every unlimited ERC-20 approval there has ever been.
  // Raw bytes have no such ceiling.
  Field f = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  uint8_t v[32];
  memset(v, 0xFF, sizeof(v));
  uint8_t out[32];
  ASSERT_TRUE(eip712_encode_leaf(&f, v, 32, out));
  EXPECT_EQ(hexOf(out, 32), std::string(64, 'f'));
}

TEST(Eip712Stream, EncodeNegativeIntSignExtends) {
  Field f = mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, 2);
  uint8_t v[2] = {0xFF, 0xFE};  // -2 as int16
  uint8_t out[32];
  ASSERT_TRUE(eip712_encode_leaf(&f, v, 2, out));
  EXPECT_EQ(hexOf(out, 32),
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe");
}

TEST(Eip712Stream, EncodePositiveIntZeroExtends) {
  Field f = mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, 2);
  uint8_t v[2] = {0x00, 0x02};
  uint8_t out[32];
  ASSERT_TRUE(eip712_encode_leaf(&f, v, 2, out));
  EXPECT_EQ(hexOf(out, 32),
            "0000000000000000000000000000000000000000000000000000000000000002");
}

TEST(Eip712Stream, EncodeBytesNIsRightPadded) {
  Field f = mkSized(EthereumTypedDataStructAck_EthereumDataType_BYTES, 4);
  uint8_t v[4] = {0xde, 0xad, 0xbe, 0xef};
  uint8_t out[32];
  ASSERT_TRUE(eip712_encode_leaf(&f, v, 4, out));
  EXPECT_EQ(hexOf(out, 32),
            "deadbeef00000000000000000000000000000000000000000000000000000000");
}

TEST(Eip712Stream, EncodeDynamicBytesIsHashed) {
  // keccak256("") -- the canonical empty-input digest.
  Field f = mk(EthereumTypedDataStructAck_EthereumDataType_BYTES);
  uint8_t out[32];
  ASSERT_TRUE(eip712_encode_leaf(&f, (const uint8_t*)"", 0, out));
  EXPECT_EQ(hexOf(out, 32),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
}

TEST(Eip712Stream, EncodeStringIsHashed) {
  // keccak256("abc")
  Field f = mk(EthereumTypedDataStructAck_EthereumDataType_STRING);
  uint8_t out[32];
  ASSERT_TRUE(eip712_encode_leaf(&f, (const uint8_t*)"abc", 3, out));
  EXPECT_EQ(hexOf(out, 32),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
}

TEST(Eip712Stream, AccumulatesOnlyValidatedDomainBindingFacts) {
  EXPECT_LE(sizeof(Eip712DomainFacts), 168u);
  Eip712DomainFacts facts{};
  Field chain = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  uint8_t chain_id[32] = {0};
  chain_id[31] = 1;
  ASSERT_TRUE(eip712_domain_facts_observe(&facts, "chainId", &chain, chain_id,
                                          sizeof(chain_id)));
  EXPECT_TRUE(facts.has_chain_id);
  EXPECT_EQ(facts.chain_id, 1u);
  EXPECT_FALSE(eip712_domain_facts_observe(&facts, "chainId", &chain, chain_id,
                                           sizeof(chain_id)));

  Field address = mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS);
  uint8_t contract[20];
  for (size_t i = 0; i < sizeof(contract); i++) contract[i] = i;
  ASSERT_TRUE(eip712_domain_facts_observe(&facts, "verifyingContract", &address,
                                          contract, sizeof(contract)));
  EXPECT_TRUE(facts.has_verifying_contract);
  EXPECT_EQ(memcmp(facts.verifying_contract, contract, sizeof(contract)), 0);

  Field name = mk(EthereumTypedDataStructAck_EthereumDataType_STRING);
  EXPECT_TRUE(eip712_domain_facts_observe(
      &facts, "name", &name, reinterpret_cast<const uint8_t*>("App"), 3));
}

// Ethermint chains (Evmos, Injective, Canto, Kava, Cronos) declare a string
// verifyingContract and salt; other domains carry chainId 0 or a name that
// is not a string. Each member is still shown and hashed: the facts only
// mark the domain unbindable, so no ERC-7730 definition can bind to it.
TEST(Eip712Stream, UnrepresentableDomainMembersAreShownAndSignedNotBound) {
  typedef std::vector<uint8_t> Value;
  struct Case {
    const char* member;
    Field field;
    Value value;
  };
  Value too_large(32, 0);
  too_large[0] = 1;
  const std::vector<Case> cases = {
      {"chainId", mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32),
       too_large},
      {"chainId", mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32),
       Value(32, 0)},
      {"chainId", mk(EthereumTypedDataStructAck_EthereumDataType_STRING),
       Value{'1'}},
      {"verifyingContract",
       mkSized(EthereumTypedDataStructAck_EthereumDataType_BYTES, 20),
       Value(20, 0)},
      {"verifyingContract",
       mk(EthereumTypedDataStructAck_EthereumDataType_STRING),
       Value{'c', 'o', 's', 'm', 'o', 's'}},
      {"salt", mk(EthereumTypedDataStructAck_EthereumDataType_STRING),
       Value{'0'}},
      {"salt", mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32),
       Value(32, 0)},
      {"name", mk(EthereumTypedDataStructAck_EthereumDataType_BYTES),
       Value{'A'}},
      {"version", mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 8),
       Value(8, 1)},
  };
  for (const Case& c : cases) {
    SCOPED_TRACE(c.member);
    Eip712DomainFacts facts{};
    EXPECT_TRUE(eip712_domain_facts_observe(&facts, c.member, &c.field,
                                            c.value.data(), c.value.size()));
    EXPECT_NE(facts.domain_present & EIP712_DOMAIN_UNBINDABLE, 0);
    EXPECT_FALSE(facts.has_chain_id);
    EXPECT_FALSE(facts.has_verifying_contract);
    const Eip712DomainFacts none{};
    EXPECT_EQ(memcmp(facts.domain_hashes, none.domain_hashes,
                     sizeof(none.domain_hashes)),
              0);
    // Still one member: a second of the same name is refused.
    EXPECT_FALSE(eip712_domain_facts_observe(&facts, c.member, &c.field,
                                             c.value.data(), c.value.size()));
  }
}

// A duplicate member, whatever its type, and a value that does not match its
// declared type are still refused.
TEST(Eip712Stream, RejectsMalformedDomainMembers) {
  Eip712DomainFacts facts{};
  Field text = mk(EthereumTypedDataStructAck_EthereumDataType_STRING);
  ASSERT_TRUE(eip712_domain_facts_observe(
      &facts, "verifyingContract", &text,
      reinterpret_cast<const uint8_t*>("cosmos"), 6));
  Field address = mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS);
  uint8_t contract[20] = {0};
  EXPECT_FALSE(eip712_domain_facts_observe(&facts, "verifyingContract",
                                           &address, contract, 20));
  EXPECT_FALSE(facts.has_verifying_contract);
  Eip712DomainFacts fresh{};
  EXPECT_FALSE(eip712_domain_facts_observe(&fresh, "verifyingContract",
                                           &address, contract, 19));
  const uint8_t bad_utf8[] = {0xff};
  EXPECT_FALSE(eip712_domain_facts_observe(&fresh, "name", &text, bad_utf8, 1));
}

TEST(Eip712Stream, CertifiedWalkPausesBeforeMessageValuesUntilAccepted) {
  EthereumSignTypedData begin{};
  strcpy(begin.primary_type, "Mail");
  ASSERT_TRUE(eip712_stream_begin(&begin, true));

  EthereumTypedDataStructAck empty{};
  ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_STRUCT);
  ASSERT_STREQ(eip712_stream_next()->struct_name, "EIP712Domain");
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // discover domain
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // hash domain type
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // complete domain
  ASSERT_STREQ(eip712_stream_next()->struct_name, "Mail");
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // discover message
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // hash message type

  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DEFINITION);
  EXPECT_EQ(eip712_stream_waiting(), EIP712_IDLE);
  EXPECT_TRUE(eip712_stream_definition_accepted());
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_STRUCT);
  EXPECT_STREQ(eip712_stream_next()->struct_name, "Mail");
  EXPECT_FALSE(eip712_stream_definition_accepted());
  eip712_stream_abort();
}

TEST(Eip712Stream, RefusesSchemaChangesAfterDiscoveryAndHashing) {
  for (int repeat_phase : {1, 2}) {
    EthereumSignTypedData begin{};
    strcpy(begin.primary_type, "Mail");
    ASSERT_TRUE(eip712_stream_begin(&begin, false));
    EthereumTypedDataStructAck schema{};
    for (int i = 0; i < repeat_phase; i++)
      ASSERT_TRUE(eip712_stream_on_struct(&schema));
    schema.members_count = 1;
    strcpy(schema.members[0].name, "injected");
    schema.members[0].type =
        mk(EthereumTypedDataStructAck_EthereumDataType_BOOL);
    EXPECT_FALSE(eip712_stream_on_struct(&schema));
    EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_FAIL);
  }
}

TEST(Eip712Stream, EnforcesSignedDomainNameAndAbsenceConstraints) {
  EthereumSignTypedData begin{};
  strcpy(begin.primary_type, "Mail");
  ASSERT_TRUE(eip712_stream_begin(&begin, true));
  EthereumTypedDataStructAck domain{};
  domain.members_count = 1;
  strcpy(domain.members[0].name, "name");
  domain.members[0].type =
      mk(EthereumTypedDataStructAck_EthereumDataType_STRING);
  for (int i = 0; i < 3; i++) ASSERT_TRUE(eip712_stream_on_struct(&domain));
  EthereumTypedDataValueAck value{};
  value.value.size = 3;
  memcpy(value.value.bytes, "App", 3);
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_TRUE(eip712_stream_on_value(&value));
  EXPECT_EQ(kkconfirm_drain(), 0);
  EthereumTypedDataStructAck empty{};
  for (int i = 0; i < 2; i++) ASSERT_TRUE(eip712_stream_on_struct(&empty));
  ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_DEFINITION);
  EXPECT_TRUE(
      eip712_stream_domain_matches(1, 4, (const uint8_t*)"App", 3, false));
  EXPECT_FALSE(
      eip712_stream_domain_matches(1, 4, (const uint8_t*)"Other", 5, false));
  EXPECT_FALSE(eip712_stream_domain_matches(1, 0, nullptr, 0, true));
  EXPECT_TRUE(eip712_stream_domain_matches(2, 0, nullptr, 0, true));
  EXPECT_FALSE(
      eip712_stream_domain_matches(2, 4, (const uint8_t*)"1", 1, false));
  eip712_stream_abort();
  EXPECT_FALSE(
      eip712_stream_domain_matches(1, 4, (const uint8_t*)"App", 3, false));
}

TEST(Eip712Stream, CertifiedFieldReplayPreservesDomainAndSigningPath) {
  EthereumSignTypedData begin{};
  strcpy(begin.primary_type, "Mail");
  begin.address_n_count = 1;
  begin.address_n[0] = 0x8000002c;
  ASSERT_TRUE(eip712_stream_begin(&begin, true));
  EthereumTypedDataStructAck empty{};
  for (int i = 0; i < 3; i++) ASSERT_TRUE(eip712_stream_on_struct(&empty));
  EthereumTypedDataStructAck schema{};
  schema.members_count = 1;
  strcpy(schema.members[0].name, "amount");
  schema.members[0].type =
      mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  for (int i = 0; i < 2; i++) ASSERT_TRUE(eip712_stream_on_struct(&schema));
  ASSERT_TRUE(eip712_stream_resume_for_field());
  ASSERT_TRUE(eip712_stream_on_struct(&schema));
  EthereumTypedDataValueAck value{};
  value.value.size = 32;
  value.value.bytes[31] = 42;
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_TRUE(eip712_stream_on_value(&value));
  ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
  const auto first = *eip712_stream_next();
  EXPECT_EQ(kkconfirm_drain(), 0);
  ASSERT_TRUE(eip712_stream_resume_for_field());
  EXPECT_STREQ(eip712_stream_next()->struct_name, "Mail");
  for (int i = 0; i < 3; i++) ASSERT_TRUE(eip712_stream_on_struct(&schema));
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_TRUE(eip712_stream_on_value(&value));
  ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
  EXPECT_EQ(memcmp(first.domain_separator,
                   eip712_stream_next()->domain_separator, 32),
            0);
  EXPECT_EQ(memcmp(first.message_hash, eip712_stream_next()->message_hash, 32),
            0);
  EXPECT_EQ(eip712_stream_next()->address_n[0], begin.address_n[0]);
  EXPECT_EQ(kkconfirm_drain(), 0);
  eip712_stream_abort();
  EXPECT_FALSE(eip712_stream_resume_for_field());
}

TEST(Eip712Stream, EncodeAddressIsLeftPadded) {
  Field f = mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS);
  uint8_t v[20];
  memset(v, 0x11, sizeof(v));
  uint8_t out[32];
  ASSERT_TRUE(eip712_encode_leaf(&f, v, 20, out));
  EXPECT_EQ(hexOf(out, 32),
            "0000000000000000000000001111111111111111111111111111111111111111");
}

// ── validation ──────────────────────────────────────────────────────

TEST(Eip712Stream, ValidateBool) {
  Field f = mk(EthereumTypedDataStructAck_EthereumDataType_BOOL);
  uint8_t t = 1, z = 0, bad = 2;
  EXPECT_TRUE(eip712_validate_leaf(&f, &t, 1));
  EXPECT_TRUE(eip712_validate_leaf(&f, &z, 1));
  EXPECT_FALSE(eip712_validate_leaf(&f, &bad, 1));  // 2 is not a bool
  EXPECT_FALSE(eip712_validate_leaf(&f, &t, 2));    // wrong width
}

TEST(Eip712Stream, ValidateAddressIsExactlyTwentyBytes) {
  Field f = mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS);
  uint8_t v[21];
  memset(v, 0, sizeof(v));
  EXPECT_TRUE(eip712_validate_leaf(&f, v, 20));
  EXPECT_FALSE(eip712_validate_leaf(&f, v, 19));
  EXPECT_FALSE(eip712_validate_leaf(&f, v, 21));
}

TEST(Eip712Stream, ValidateIntegerWidthMustMatchDeclaration) {
  // A short value would left-pad into a different number than the host meant.
  Field f = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  uint8_t v[32];
  memset(v, 0, sizeof(v));
  EXPECT_TRUE(eip712_validate_leaf(&f, v, 32));
  EXPECT_FALSE(eip712_validate_leaf(&f, v, 31));
  EXPECT_FALSE(eip712_validate_leaf(&f, v, 1));
}

// Real documents carry control bytes (a Snapshot vote's reason with a line
// break). Any valid UTF-8 signs; the review shows each control byte as an
// escape, so an embedded NUL is drawn, never a terminator
// (StringControlBytesAreShownEscaped).
TEST(Eip712Stream, ValidateStringAcceptsControlBytes) {
  Field f = mk(EthereumTypedDataStructAck_EthereumDataType_STRING);
  EXPECT_TRUE(eip712_validate_leaf(&f, (const uint8_t*)"Send 1 USDC", 11));
  EXPECT_TRUE(eip712_validate_leaf(&f, (const uint8_t*)"a\0b", 3));
  EXPECT_TRUE(eip712_validate_leaf(&f, (const uint8_t*)"a\nb", 3));
  EXPECT_TRUE(eip712_validate_leaf(&f, (const uint8_t*)"\t\r\x7f\x1b", 4));
  const uint8_t c1_control[] = {0xC2, 0x85};  // U+0085, valid UTF-8
  EXPECT_TRUE(eip712_validate_leaf(&f, c1_control, 2));
}

TEST(Eip712Stream, ValidateStringRejectsMalformedUtf8) {
  Field f = mk(EthereumTypedDataStructAck_EthereumDataType_STRING);
  const uint8_t lone_continuation[] = {0x80};
  EXPECT_FALSE(eip712_validate_leaf(&f, lone_continuation, 1));
  const uint8_t truncated[] = {0xE2, 0x82};  // needs a third byte
  EXPECT_FALSE(eip712_validate_leaf(&f, truncated, 2));
  const uint8_t overlong[] = {0xC0, 0xAF};  // overlong '/'
  EXPECT_FALSE(eip712_validate_leaf(&f, overlong, 2));
  const uint8_t surrogate[] = {0xED, 0xA0, 0x80};
  EXPECT_FALSE(eip712_validate_leaf(&f, surrogate, 3));
  const uint8_t euro[] = {0xE2, 0x82, 0xAC};  // U+20AC, valid
  EXPECT_TRUE(eip712_validate_leaf(&f, euro, 3));
}

TEST(Eip712Stream, ValidateBytesNIsExact) {
  Field f = mkSized(EthereumTypedDataStructAck_EthereumDataType_BYTES, 4);
  uint8_t v[5] = {0};
  EXPECT_TRUE(eip712_validate_leaf(&f, v, 4));
  EXPECT_FALSE(eip712_validate_leaf(&f, v, 3));
  EXPECT_FALSE(eip712_validate_leaf(&f, v, 5));
}

// ── encodeType / typeHash ───────────────────────────────────────────
//
// Backed by a fixture lookup rather than a device, which is the whole point of
// taking the lookup as a callback: the type graph is testable without an
// emulator, and these are the vectors a compliant verifier must agree with.

namespace {

struct Fixture {
  std::map<std::string, EthereumTypedDataStructAck> defs;
};

const EthereumTypedDataStructAck* fixtureLookup(const char* name, void* ctx) {
  Fixture* f = static_cast<Fixture*>(ctx);
  auto it = f->defs.find(std::string(name));
  return it == f->defs.end() ? nullptr : &it->second;
}

void addMember(EthereumTypedDataStructAck& ack, const char* mname,
               const Field& type) {
  auto& m = ack.members[ack.members_count++];
  memset(&m, 0, sizeof(m));
  m.type = type;
  strcpy(m.name, mname);
}

Field structField(const char* sname) {
  Field f = mk(EthereumTypedDataStructAck_EthereumDataType_STRUCT);
  f.has_struct_name = true;
  strcpy(f.struct_name, sname);
  return f;
}

std::string typeHashHex(Fixture& f, const char* primary) {
  uint8_t out[32];
  if (!eip712_type_hash(primary, fixtureLookup, &f, out)) return "<refused>";
  return hexOf(out, 32);
}

// keccak256 of a literal, for building expectations in the test itself.
std::string keccakHex(const std::string& s) {
  uint8_t out[32];
  keccak_256(reinterpret_cast<const uint8_t*>(s.data()), s.size(), out);
  return hexOf(out, 32);
}

}  // namespace

TEST(Eip712Stream, ReviewIdentifiersAreCanonicalAndNeverTruncated) {
  EXPECT_TRUE(eip712_identifier_ok("PermitSingle"));
  EXPECT_TRUE(eip712_identifier_ok("sigDeadline"));
  EXPECT_TRUE(eip712_identifier_ok("_value$2"));

  EXPECT_FALSE(eip712_identifier_ok(""));
  EXPECT_FALSE(eip712_identifier_ok("2value"));
  EXPECT_FALSE(eip712_identifier_ok("line\nbreak"));
  EXPECT_FALSE(eip712_identifier_ok("amount%08x"));
  EXPECT_FALSE(eip712_identifier_ok("member-name"));
  EXPECT_FALSE(eip712_identifier_ok("identifier_that_would_be_truncated"));
  // ':' is a struct-name character only (Hyperliquid's user-signed actions).
  EXPECT_FALSE(eip712_identifier_ok("HyperliquidTransaction:UsdSend"));
}

TEST(Eip712Stream, StructTypeNamesAllowAColonAndFortySevenCharacters) {
  EXPECT_TRUE(eip712_type_identifier_ok("PermitSingle"));
  EXPECT_TRUE(eip712_type_identifier_ok("HyperliquidTransaction:UsdSend"));
  EXPECT_TRUE(
      eip712_type_identifier_ok("HyperliquidTransaction:ApproveBuilderFee"));
  const std::string longest(EIP712_MAX_STRUCT_NAME - 1, 'T');
  EXPECT_GE(longest.size(), 47u);
  EXPECT_TRUE(eip712_type_identifier_ok(longest.c_str()));
  EXPECT_FALSE(eip712_type_identifier_ok((longest + "T").c_str()));
  EXPECT_FALSE(eip712_type_identifier_ok(":UsdSend"));
  EXPECT_FALSE(eip712_type_identifier_ok("Hyperliquid Transaction"));
  EXPECT_FALSE(eip712_type_identifier_ok("Order(uint256 a)"));
  EXPECT_FALSE(eip712_type_identifier_ok(""));

  // encodeType spells the name byte for byte.
  Fixture f;
  auto& send = f.defs["HyperliquidTransaction:UsdSend"];
  memset(&send, 0, sizeof(send));
  addMember(send, "destination",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));
  addMember(send, "time",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 8));
  EXPECT_EQ(typeHashHex(f, "HyperliquidTransaction:UsdSend"),
            keccakHex("HyperliquidTransaction:UsdSend(string destination,"
                      "uint64 time)"));
}

TEST(Eip712Stream, TypeHashRejectsDuplicateMemberNames) {
  Fixture f;
  auto& permit = f.defs["Permit"];
  memset(&permit, 0, sizeof(permit));
  addMember(permit, "value",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
  addMember(permit, "value",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
  EXPECT_EQ(typeHashHex(f, "Permit"), "<refused>");
}

TEST(Eip712Stream, TypeHashMatchesTheSpecExample) {
  // The canonical EIP-712 example. Note Person sorts AFTER Mail's own segment
  // and is appended, not interleaved.
  Fixture f;
  auto& person = f.defs["Person"];
  memset(&person, 0, sizeof(person));
  addMember(person, "name",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));
  addMember(person, "wallet",
            mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS));

  auto& mail = f.defs["Mail"];
  memset(&mail, 0, sizeof(mail));
  addMember(mail, "from", structField("Person"));
  addMember(mail, "to", structField("Person"));
  addMember(mail, "contents",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));

  // The expectation is the PUBLISHED literal, not a keccak of a string written
  // in this test. That distinction is the whole point: an expectation this test
  // derives the same way the implementation does would agree with a shared
  // misreading of the spec and still go green.
  //
  // Source: assets/eip-712/Example.js in the ethereum/EIPs repository -- the
  // reference implementation EIP-712 itself links to. Its assertions publish
  // typeHash('Mail') verbatim. Independently republished by Example.sol in the
  // same directory, by MetaMask eth-sig-util's hashStruct snapshots for both
  // V3 and V4, and by Mrtenz/eip-712.
  EXPECT_EQ(typeHashHex(f, "Mail"),
            "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2");

  // And the string itself, so a failure says WHICH half diverged.
  EXPECT_EQ(typeHashHex(f, "Mail"),
            keccakHex("Mail(Person from,Person to,string contents)"
                      "Person(string name,address wallet)"));
}

TEST(Eip712Stream, ReferencedStructsAreSortedByName) {
  // THE CANARY. eip712.c appends referenced definitions in DISCOVERY order and
  // contains no sort call, so this document -- which names Zebra before Apple
  // -- is exactly the case it gets wrong. Two devices would disagree with each
  // other and both would look internally consistent.
  Fixture f;
  auto& zebra = f.defs["Zebra"];
  memset(&zebra, 0, sizeof(zebra));
  addMember(zebra, "stripes",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));

  auto& apple = f.defs["Apple"];
  memset(&apple, 0, sizeof(apple));
  addMember(apple, "colour",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));

  auto& m = f.defs["M"];
  memset(&m, 0, sizeof(m));
  addMember(m, "z", structField("Zebra"));  // referenced FIRST
  addMember(m, "a", structField("Apple"));  // referenced SECOND

  // Alphabetical, not discovery order: Apple before Zebra.
  EXPECT_EQ(typeHashHex(f, "M"), keccakHex("M(Zebra z,Apple a)"
                                           "Apple(string colour)"
                                           "Zebra(uint256 stripes)"));
}

TEST(Eip712Stream, SortIsNotMerelyReversedDiscoveryOrder) {
  // The Zebra/Apple canary above is WEAKER THAN IT LOOKS. Zebra is discovered
  // before Apple, so plain "reverse the discovery list" produces the same
  // order as a correct sort and a buggy implementation passes it.
  //
  // Discovering in ALPHABETICAL order separates them, because now reversal is
  // the one thing that gets it wrong:
  //   discovery  [Alpha, Bravo]
  //   reversed   [Bravo, Alpha]   <- wrong
  //   SORTED     [Alpha, Bravo]   <- correct
  //
  // The two canaries are complementary and neither is redundant: Zebra/Apple
  // catches "no sort at all", this one catches "reversed". Deleting either
  // leaves a wrong implementation that passes the other. The five-dependency
  // case in RefusesADocumentWiderThanTheClosure separates all three at once.
  Fixture f;
  const char* names[] = {"Alpha", "Bravo"};
  for (const char* n : names) {
    auto& d = f.defs[n];
    memset(&d, 0, sizeof(d));
    addMember(d, "v",
              mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
  }
  auto& m = f.defs["M"];
  memset(&m, 0, sizeof(m));
  addMember(m, "a", structField("Alpha"));
  addMember(m, "b", structField("Bravo"));

  EXPECT_EQ(typeHashHex(f, "M"), keccakHex("M(Alpha a,Bravo b)"
                                           "Alpha(uint256 v)"
                                           "Bravo(uint256 v)"));
}

TEST(Eip712Stream, RefusesADocumentWiderThanTheClosure) {
  // EIP712_MAX_STRUCTS bounds the closure INCLUDING the primary type, so the
  // real ceiling is that many distinct struct types in one document. A
  // UniswapX V3DutchOrder witness sits exactly at it; one more dependency
  // must be REFUSED rather than silently truncated, because a truncated
  // closure still produces a well-formed 32-byte typeHash -- one that no
  // verifier reproduces.
  // Discovered neither sorted nor reverse-sorted.
  const char* names[] = {"Delta", "Alpha", "Foxtrot", "Golf",
                         "Bravo", "Echo",  "Charlie"};
  static_assert(sizeof(names) / sizeof(names[0]) == EIP712_MAX_STRUCTS,
                "one dependency more than fits");
  for (size_t used = EIP712_MAX_STRUCTS - 1; used <= EIP712_MAX_STRUCTS;
       used++) {
    Fixture f;
    auto& m = f.defs["M"];
    memset(&m, 0, sizeof(m));
    std::string head = "M(", tail;
    std::vector<std::string> sorted;
    for (size_t i = 0; i < used; i++) {
      auto& d = f.defs[names[i]];
      memset(&d, 0, sizeof(d));
      addMember(d, "v",
                mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
      char member[2] = {(char)('a' + i), 0};
      addMember(m, member, structField(names[i]));
      head += std::string(i ? "," : "") + names[i] + " " + member;
      sorted.push_back(names[i]);
    }
    std::sort(sorted.begin(), sorted.end());
    for (const std::string& n : sorted) tail += n + "(uint256 v)";
    if (used < EIP712_MAX_STRUCTS) {
      EXPECT_EQ(typeHashHex(f, "M"), keccakHex(head + ")" + tail));
    } else {
      EXPECT_EQ(typeHashHex(f, "M"), "<refused>");
    }
  }
}

TEST(Eip712Stream, TransitivelyReferencedStructsAreCollectedAndSorted) {
  // A struct reached only THROUGH another dependency still belongs in the
  // closure, and still sorts among the rest rather than trailing the struct
  // that introduced it.
  Fixture f;
  auto& inner = f.defs["Aardvark"];
  memset(&inner, 0, sizeof(inner));
  addMember(inner, "n",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));

  auto& mid = f.defs["Zulu"];
  memset(&mid, 0, sizeof(mid));
  addMember(mid, "deep", structField("Aardvark"));  // only reachable via Zulu

  auto& m = f.defs["M"];
  memset(&m, 0, sizeof(m));
  addMember(m, "z", structField("Zulu"));

  EXPECT_EQ(typeHashHex(f, "M"), keccakHex("M(Zulu z)"
                                           "Aardvark(uint256 n)"
                                           "Zulu(Aardvark deep)"));
}

TEST(Eip712Stream, StructReachableOnlyAsAnArrayElementIsStillInTheClosure) {
  // Trezor fixed exactly this in 2.5.1. An array member still carries
  // data_type STRUCT with array_levels set, so the collector must look at
  // struct_name regardless of the dimensions.
  Fixture f;
  auto& person = f.defs["Person"];
  memset(&person, 0, sizeof(person));
  addMember(person, "wallet",
            mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS));

  auto& m = f.defs["Group"];
  memset(&m, 0, sizeof(m));
  Field arr = structField("Person");
  arr.array_levels_count = 1;
  arr.array_levels[0] = 0;  // Person[]
  addMember(m, "members", arr);

  EXPECT_EQ(typeHashHex(f, "Group"),
            keccakHex("Group(Person[] members)Person(address wallet)"));
}

TEST(Eip712Stream, Permit2PermitSingleTypeHash) {
  // The payload that started all of this. PermitSingle nests PermitDetails, so
  // any flat-structs-only implementation cannot sign a Uniswap approval.
  Fixture f;
  auto& details = f.defs["PermitDetails"];
  memset(&details, 0, sizeof(details));
  addMember(details, "token",
            mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS));
  addMember(details, "amount",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 20));
  addMember(details, "expiration",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 6));
  addMember(details, "nonce",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 6));

  auto& single = f.defs["PermitSingle"];
  memset(&single, 0, sizeof(single));
  addMember(single, "details", structField("PermitDetails"));
  addMember(single, "spender",
            mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS));
  addMember(single, "sigDeadline",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));

  EXPECT_EQ(typeHashHex(f, "PermitSingle"),
            keccakHex("PermitSingle(PermitDetails details,address spender,"
                      "uint256 sigDeadline)"
                      "PermitDetails(address token,uint160 amount,"
                      "uint48 expiration,uint48 nonce)"));
}

TEST(Eip712Stream, Eip2612PermitTypeHashMatchesUsdcsOwnContract) {
  // Circle publishes this constant in their deployed FiatTokenV2_2 source:
  //   contracts/v2/EIP2612.sol
  //   bytes32 public constant PERMIT_TYPEHASH =
  //       0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
  // OpenZeppelin's ERC20Permit computes the same value. A flat struct, so this
  // pins field order and the atomic spellings rather than the closure.
  Fixture f;
  auto& permit = f.defs["Permit"];
  memset(&permit, 0, sizeof(permit));
  addMember(permit, "owner",
            mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS));
  addMember(permit, "spender",
            mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS));
  addMember(permit, "value",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
  addMember(permit, "nonce",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
  addMember(permit, "deadline",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));

  EXPECT_EQ(typeHashHex(f, "Permit"),
            "6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9");
}

TEST(Eip712Stream, TypeHashRefusesAMissingStruct) {
  Fixture f;
  auto& m = f.defs["M"];
  memset(&m, 0, sizeof(m));
  addMember(m, "ghost", structField("NotSupplied"));
  EXPECT_EQ(typeHashHex(f, "M"), "<refused>");
}

TEST(Eip712Stream, TypeHashTerminatesOnACycle) {
  // EIP-712 leaves cyclical data undefined. The collector must not recurse
  // forever on a host that supplies one.
  Fixture f;
  auto& a = f.defs["A"];
  memset(&a, 0, sizeof(a));
  addMember(a, "b", structField("B"));
  auto& b = f.defs["B"];
  memset(&b, 0, sizeof(b));
  addMember(b, "a", structField("A"));

  // Terminates. The value is not the interesting part; not hanging is.
  std::string h = typeHashHex(f, "A");
  EXPECT_EQ(h, keccakHex("A(B b)B(A a)"));
}

// ── Review screens and signing policy ────────────────────────────────
namespace {

typedef EthereumTypedDataStructAck Struct;
typedef std::vector<uint8_t> Bytes;

Bytes word(uint8_t low) {
  Bytes b(32, 0);
  b[31] = low;
  return b;
}

// The host half of a value: whole up to EIP712_MAX_LEAF; longer, in chunks of
// that size, the first naming the total and each later one echoing the
// offset the device asked for. g_tamper, when set, may then alter the answer.
void (*g_tamper)(EthereumTypedDataValueAck* ack) = nullptr;
int g_first_chunks;  // answers that carried value_total_length
int g_later_chunks;  // answers that carried value_offset

EthereumTypedDataValueAck valueAck(const Bytes& v, const Eip712Next* next) {
  EthereumTypedDataValueAck ack{};
  size_t at = 0, n = v.size();
  if (next->has_value_offset) {
    at = std::min<size_t>(next->value_offset, v.size());
    n = std::min<size_t>(v.size() - at, EIP712_MAX_LEAF);
    ack.has_value_offset = true;
    ack.value_offset = next->value_offset;
    g_later_chunks++;
  } else if (v.size() > EIP712_MAX_LEAF) {
    n = EIP712_MAX_LEAF;
    ack.has_value_total_length = true;
    ack.value_total_length = (uint32_t)v.size();
    g_first_chunks++;
  }
  ack.value.size = (pb_size_t)n;
  if (n) memcpy(ack.value.bytes, v.data() + at, n);
  if (g_tamper) g_tamper(&ack);
  return ack;
}

// Drive the walk to its end, answering every request from `types` and
// `value(path)`, with `screens` accepted confirmations available. Returns how
// many were used; -1 means more screens were shown than were accepted. With
// `topup`, every value answer first queues that many more acceptances (and no
// rejection sentinel), for documents with thousands of screens; count those
// from the captured screens instead.
int walk(const char* primary, const std::map<std::string, Struct>& types,
         Bytes (*value)(const std::vector<uint32_t>&), int screens,
         bool certified = false, int topup = 0) {
  EthereumSignTypedData begin{};
  strcpy(begin.primary_type, primary);
  g_first_chunks = g_later_chunks = 0;
  if (!(topup ? kkconfirm_preload_no_sentinel(screens, 0)
              : kkconfirm_preload(screens, 0)))
    return -2;
  if (!eip712_stream_begin(&begin, certified))
    return screens - kkconfirm_drain() / 2;
  for (;;) {
    const Eip712Next* next = eip712_stream_next();
    if (next->kind == EIP712_REQ_STRUCT) {
      auto it = types.find(next->struct_name);
      Struct empty{};
      eip712_stream_on_struct(it == types.end() ? &empty : &it->second);
    } else if (next->kind == EIP712_REQ_VALUE) {
      std::vector<uint32_t> path(next->member_path,
                                 next->member_path + next->member_path_len);
      EthereumTypedDataValueAck ack = valueAck(value(path), next);
      if (topup && !kkconfirm_preload_no_sentinel(topup, 0)) return -2;
      eip712_stream_on_value(&ack);
    } else {
      break;
    }
  }
  // Two messages per screen; negative means the rejection sentinel was used.
  const int unused = kkconfirm_drain();
  return unused < 0 ? -1 : screens - unused / 2;
}

std::string decimal(Field f, const Bytes& v) {
  char out[82];
  if (!eip712_render_integer(&f, v.data(), v.size(), out, sizeof(out)))
    return "<refused>";
  return out;
}

}  // namespace

TEST(Eip712Stream, IntegersRenderInDecimalWithTheirSign) {
  Field u256 = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  Field i8 = mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, 1);
  Field i16 = mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, 2);
  Field i256 = mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, 32);
  Bytes thousand(32, 0);
  thousand[30] = 0x03;
  thousand[31] = 0xe8;
  EXPECT_EQ(decimal(u256, thousand), "1000");
  EXPECT_EQ(decimal(u256, Bytes(32, 0)), "0");
  EXPECT_EQ(decimal(u256, Bytes(32, 0xff)),
            "115792089237316195423570985008687907853269984665640564039457584"
            "007913129639935");
  EXPECT_EQ(decimal(i8, Bytes{0x80}), "-128");
  EXPECT_EQ(decimal(i8, Bytes{0x7f}), "127");
  EXPECT_EQ(decimal(i16, Bytes{0xff, 0xff}), "-1");
  Bytes min256(32, 0);
  min256[0] = 0x80;
  EXPECT_EQ(decimal(i256, min256),
            "-57896044618658097711785492504343953926634992332820282019728792"
            "003956564819968");
  // uint does not sign-extend a set top bit.
  Field u8 = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 1);
  EXPECT_EQ(decimal(u8, Bytes{0x80}), "128");
}

// A dynamic value longer than one screen body used to be refused by confirm()
// and reported to the host as a user cancel. It is now disclosed in numbered
// parts, each its own confirmation, and the document signs.
TEST(Eip712Stream, LongValuesAreDisclosedInPartsAndSign) {
  std::map<std::string, Struct> types;
  addMember(types["Blob"], "data",
            mk(EthereumTypedDataStructAck_EthereumDataType_BYTES));
  addMember(types["Blob"], "note",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));
  int used = walk(
      "Blob", types,
      [](const std::vector<uint32_t>& path) -> Bytes {
        if (path[1] == 0) return Bytes(EIP712_MAX_LEAF, 0xab);
        Bytes s;  // 300 x U+00E9, escaped to four characters per byte
        for (int i = 0; i < 300; i++) {
          s.push_back(0xc3);
          s.push_back(0xa9);
        }
        return s;
      },
      200);
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
  // 2,050 hex characters and 2,400 escaped ones cannot fit fewer than
  // seven and eight 351-character bodies.
  EXPECT_GE(used, 15);
  eip712_stream_abort();
}

// Owner decision 2026-10-07: unlimited permits sign, never refused. The value
// leaf's own screen reads UNLIMITED under a warning title; a finite value and
// a revoking DAI permit keep the ordinary screen.
TEST(Eip712Stream, UnlimitedPermitsSignWithAWarningOnTheirValue) {
  struct Case {
    const char* primary;
    const char* container;
    const char* member;
    Field type;
    Bytes unlimited;
    Bytes finite;
    const char* unlimited_body;
    const char* finite_body;
  };
  const Case cases[] = {
      {"Permit", "Permit", "value",
       mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32),
       Bytes(32, 0xff), word(1), "value\nuint256: UNLIMITED",
       "value\nuint256: 1"},
      {"Permit", "Permit", "allowed",
       mk(EthereumTypedDataStructAck_EthereumDataType_BOOL), Bytes{1}, Bytes{0},
       "allowed\nbool: UNLIMITED (allowed)", "allowed\nbool: false"},
      {"PermitSingle", "PermitDetails", "amount",
       mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 20),
       Bytes(20, 0xff),
       []() {
         Bytes b(20, 0);
         b[19] = 1;
         return b;
       }(),
       "details.amount\nuint160: UNLIMITED", "details.amount\nuint160: 1"},
      {"PermitTransferFrom", "TokenPermissions", "amount",
       mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32),
       Bytes(32, 0xff), word(7), "details.amount\nuint256: UNLIMITED",
       "details.amount\nuint256: 7"},
  };
  static const Case* current;
  static bool unlimited;
  for (const Case& c : cases) {
    SCOPED_TRACE(c.member);
    std::map<std::string, Struct> types;
    addMember(types[c.container], "token",
              mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS));
    addMember(types[c.container], c.member, c.type);
    if (strcmp(c.primary, c.container) != 0)
      addMember(types[c.primary], "details", structField(c.container));
    current = &c;
    for (bool u : {true, false}) {
      unlimited = u;
      kkconfirm_capture_start();
      int used = walk(
          c.primary, types,
          [](const std::vector<uint32_t>& path) -> Bytes {
            if (path.back() == 0) return Bytes(20, 0x11);
            return unlimited ? current->unlimited : current->finite;
          },
          5);
      const std::vector<std::string> bodies = kkconfirm_capture_finish();
      const std::vector<std::string> titles = kkconfirm_captured_titles();
      EXPECT_EQ(used, 2);  // the token screen, then the value screen
      EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
      ASSERT_EQ(bodies.size(), 2u);
      EXPECT_EQ(titles[0], "EIP-712 Message");
      EXPECT_EQ(titles[1], u ? "UNLIMITED approval" : "EIP-712 Message");
      EXPECT_EQ(bodies[1], u ? c.unlimited_body : c.finite_body);
      std::string title = titles[1];
      for (char& ch : title) ch = (char)toupper((unsigned char)ch);
      EXPECT_EQ(1u,
                calc_str_line(get_title_font(), title.c_str(), TITLE_WIDTH));
      eip712_stream_abort();
    }
  }
}

// Only the permit members named above get the warning: an all-ones amount in
// any other struct is an ordinary number.
TEST(Eip712Stream, AllOnesOutsideAPermitIsAnOrdinaryNumber) {
  std::map<std::string, Struct> types;
  addMember(types["Order"], "value",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
  kkconfirm_capture_start();
  int used = walk(
      "Order", types,
      [](const std::vector<uint32_t>&) -> Bytes { return Bytes(32, 0xff); }, 4);
  const std::vector<std::string> bodies = kkconfirm_capture_finish();
  EXPECT_GE(used, 1);
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
  std::string shown;
  for (const std::string& title : kkconfirm_captured_titles())
    EXPECT_EQ(0u, title.rfind("EIP-712 Message", 0)) << title;
  for (const std::string& body : bodies) shown += body;
  EXPECT_EQ(std::string::npos, shown.find("UNLIMITED"));
  EXPECT_NE(std::string::npos, shown.find("115792089237316195"));
  eip712_stream_abort();
}

// eth-sig-util/MetaMask v4 sign keccak(0x1901 || domainSeparator) when the
// primary type is EIP712Domain; walking a "message" would sign another digest.
TEST(Eip712Stream, DomainOnlyPrimaryTypeSignsTheDomainSeparatorAlone) {
  std::map<std::string, Struct> types;
  addMember(types["EIP712Domain"], "name",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));
  int used = walk(
      "EIP712Domain", types,
      [](const std::vector<uint32_t>&) -> Bytes {
        return Bytes{'A', 'p', 'p'};
      },
      3);
  EXPECT_EQ(used, 1);
  const Eip712Next* next = eip712_stream_next();
  ASSERT_EQ(next->kind, EIP712_REQ_DONE);
  EXPECT_TRUE(next->domain_only);
  EXPECT_STREQ(next->primary_type, "EIP712Domain");
  // hashStruct(EIP712Domain{name:"App"}) from its spec definition.
  uint8_t type_hash[32], name_hash[32], encoded[64], expected[32];
  keccak_256((const uint8_t*)"EIP712Domain(string name)", 25, type_hash);
  keccak_256((const uint8_t*)"App", 3, name_hash);
  memcpy(encoded, type_hash, 32);
  memcpy(encoded + 32, name_hash, 32);
  keccak_256(encoded, sizeof(encoded), expected);
  EXPECT_EQ(hexOf(next->domain_separator, 32), hexOf(expected, 32));
  eip712_stream_abort();

  EthereumSignTypedData begin{};
  strcpy(begin.primary_type, "EIP712Domain");
  EXPECT_FALSE(eip712_stream_begin(&begin, true));
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_FAIL);
}

TEST(Eip712Stream, EmptyMessageIsFlaggedForTheFinalScreen) {
  std::map<std::string, Struct> types;
  types["Nothing"];
  const int used = walk(
      "Nothing", types,
      [](const std::vector<uint32_t>&) -> Bytes { return {}; }, 2);
  EXPECT_EQ(used, 0);
  ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
  EXPECT_TRUE(eip712_stream_next()->message_empty);
  EXPECT_FALSE(eip712_stream_next()->domain_only);
  eip712_stream_abort();
}

// Seaport's OrderComponents has 11 members and holds arrays of 5- and
// 6-member structs, which the former 12-slot pool could never fit.
// The outermost array hashes its elements as they arrive, so an order's item
// count costs no pool slots: 11 + 6 slots for any length.
static uint16_t g_items;

TEST(Eip712Stream, SeaportShapedDocumentFitsThePool) {
  std::map<std::string, Struct> types;
  Field u256 = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  Field items = structField("ConsiderationItem");
  items.array_levels_count = 1;
  for (int i = 0; i < 10; i++) {
    char name[8];
    snprintf(name, sizeof(name), "f%d", i);
    addMember(types["OrderComponents"], name, u256);
  }
  addMember(types["OrderComponents"], "consideration", items);
  for (int i = 0; i < 6; i++) {
    char name[8];
    snprintf(name, sizeof(name), "g%d", i);
    addMember(types["ConsiderationItem"], name, u256);
  }
  for (uint16_t items : {3, 8, 32, 64}) {
    SCOPED_TRACE(items);
    g_items = items;
    int used = walk(
        "OrderComponents", types,
        [](const std::vector<uint32_t>& path) -> Bytes {
          if (path.size() == 2 && path[1] == 10)
            return Bytes{(uint8_t)(g_items >> 8), (uint8_t)g_items};
          return word(path.back());
        },
        10 + items * 6 + 2);
    EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
    EXPECT_EQ(used, 10 + items * 6);
    eip712_stream_abort();
  }
}

// Every nested struct and every array dimension is one frame. Six fit (the
// UniswapX V3 Dutch order witness.baseOutputs[i].curve.relativeAmounts
// shape); a seventh is refused before it is pushed.
TEST(Eip712Stream, NestsSixFramesDeepButNotSeven) {
  const char* chain[] = {"L1", "L2", "L3", "L4", "L5", "L6", "L7"};
  for (size_t frames : {6u, 7u}) {
    SCOPED_TRACE(frames);
    std::map<std::string, Struct> types;
    for (size_t i = 0; i + 1 < frames; i++)
      addMember(types[chain[i]], "next", structField(chain[i + 1]));
    addMember(types[chain[frames - 1]], "v",
              mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
    const int used = walk(
        "L1", types,
        [](const std::vector<uint32_t>&) -> Bytes { return word(9); }, 2);
    if (frames == 6) {
      EXPECT_EQ(used, 1);
      EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
    } else {
      EXPECT_EQ(used, 0);
      ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_FAIL);
      EXPECT_STREQ(eip712_stream_next()->error,
                   "EIP-712 document nests too deeply for this device");
    }
    eip712_stream_abort();
  }
}

// The open frames' member names share one EIP712_MAX_PATH buffer. Whatever
// path the review screen can show must fit it: an empty array whose path is
// the longest that renders fills the buffer exactly, and a leaf path of
// EIP712_MAX_PATH - 1 characters six frames deep signs. One character more
// is refused by the review screen, as before.
TEST(Eip712Stream, MemberNamesFitEveryPathTheReviewCanShow) {
  // P0.a.b.c.d holds an empty uint256[] e: five 31-character names.
  {
    std::map<std::string, Struct> types;
    std::string path;
    const char* chain[] = {"P0", "P1", "P2", "P3", "P4"};
    for (int i = 0; i < 5; i++) {
      const std::string name = std::string(1, (char)('a' + i)) +
                               std::string(30, (char)('a' + i));
      path += (i ? "." : "") + name;
      if (i < 4) {
        addMember(types[chain[i]], name.c_str(), structField(chain[i + 1]));
      } else {
        Field arr = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
        arr.array_levels_count = 1;
        arr.array_levels[0] = 0;
        addMember(types[chain[i]], name.c_str(), arr);
      }
    }
    ASSERT_EQ(path.size(), (size_t)EIP712_MAX_PATH - 1);
    kkconfirm_capture_start();
    walk("P0", types,
         [](const std::vector<uint32_t>&) -> Bytes { return Bytes{0, 0}; }, 4);
    // One screen, which the pager may show as several pages.
    std::string shown;
    for (const std::string& page : kkconfirm_capture_finish()) shown += page;
    EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
    EXPECT_EQ(shown, path + "\nuint256[]: 0 items");
    eip712_stream_abort();
  }
  // L1..L6, one member each; the six names add up to `total` characters.
  for (size_t total : {154u, 155u}) {
    SCOPED_TRACE(total);
    const char* chain[] = {"L1", "L2", "L3", "L4", "L5", "L6"};
    std::map<std::string, Struct> types;
    std::string path;
    for (size_t i = 0; i < 6; i++) {
      const size_t len = i == 5 ? total - 5 * 26 : 26;
      const std::string name = std::string(len, (char)('a' + i));
      path += (i ? "." : "") + name;
      if (i < 5) {
        addMember(types[chain[i]], name.c_str(), structField(chain[i + 1]));
      } else {
        addMember(types[chain[i]], name.c_str(),
                  mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
      }
    }
    kkconfirm_capture_start();
    const int used = walk(
        "L1", types,
        [](const std::vector<uint32_t>&) -> Bytes { return word(9); }, 4);
    std::string shown;
    for (const std::string& page : kkconfirm_capture_finish()) shown += page;
    if (path.size() < EIP712_MAX_PATH) {
      EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
      EXPECT_EQ(shown, path + "\nuint256: 9");
    } else {
      EXPECT_EQ(used, 0);
      ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_FAIL);
      EXPECT_STREQ(eip712_stream_next()->error,
                   "EIP-712 value cannot be displayed");
    }
    eip712_stream_abort();
  }
}

namespace {

Eip712ReqKind walkMatrix(const std::vector<uint32_t>& written_levels,
                         uint16_t rows, uint16_t cols) {
  EthereumTypedDataStructAck domain{};
  EthereumTypedDataStructAck matrix{};
  Field values = mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, 2);
  values.array_levels_count = written_levels.size();
  for (size_t i = 0; i < written_levels.size(); i++)
    values.array_levels[i] = written_levels[i];
  addMember(matrix, "values", values);

  EthereumSignTypedData begin{};
  strcpy(begin.primary_type, "Matrix");
  eip712_stream_begin(&begin, false);
  for (int step = 0; step < 100; step++) {
    const Eip712Next* next = eip712_stream_next();
    switch (next->kind) {
      case EIP712_REQ_STRUCT:
        eip712_stream_on_struct(
            strcmp(next->struct_name, "Matrix") == 0 ? &matrix : &domain);
        break;
      case EIP712_REQ_DEFINITION:
        eip712_stream_definition_accepted();
        break;
      case EIP712_REQ_VALUE: {
        EthereumTypedDataValueAck ack{};
        uint16_t v = next->member_path_len == 2   ? rows
                     : next->member_path_len == 3 ? cols
                                                  : 1;
        ack.value.size = 2;
        ack.value.bytes[0] = v >> 8;
        ack.value.bytes[1] = v & 0xff;
        if (!kkconfirm_preload(1, 0)) return EIP712_REQ_NONE;
        eip712_stream_on_value(&ack);
        kkconfirm_drain();
        break;
      }
      default: {
        Eip712ReqKind kind = next->kind;
        eip712_stream_abort();
        return kind;
      }
    }
  }
  eip712_stream_abort();
  return EIP712_REQ_NONE;
}

}  // namespace

TEST(Eip712Stream, FixedDimensionsAreCheckedOutermostFirst) {
  EXPECT_EQ(walkMatrix({2, 4}, 4, 2), EIP712_REQ_DONE);
  EXPECT_EQ(walkMatrix({2, 4}, 2, 2), EIP712_REQ_FAIL);
  EXPECT_EQ(walkMatrix({2, 4}, 4, 4), EIP712_REQ_FAIL);
}

// The outermost array streams, and so does an array of fixed-size leaves
// nested inside it (a UniswapX V3 curve's relativeAmounts). Any other nested
// array keeps one pool slot per element: Matrix takes one slot, leaving 23.
TEST(Eip712Stream, ArraysInsideAStreamedArrayStillUseThePool) {
  EXPECT_EQ(walkMatrix({0, 0}, 1, EIP712_MAX_SLOTS - 1), EIP712_REQ_DONE);
  EXPECT_EQ(walkMatrix({0, 0}, 1, EIP712_MAX_SLOTS), EIP712_REQ_DONE);
  EXPECT_EQ(walkMatrix({0, 0}, 1, 2 * EIP712_MAX_SLOTS), EIP712_REQ_DONE);
  EXPECT_EQ(walkMatrix({0, 0, 0}, 1, EIP712_MAX_SLOTS - 1), EIP712_REQ_DONE);
  EXPECT_EQ(walkMatrix({0, 0, 0}, 1, EIP712_MAX_SLOTS), EIP712_REQ_FAIL);
  EXPECT_EQ(walkMatrix({0}, 60, 0), EIP712_REQ_DONE);
}

TEST(Eip712Stream, InnerDimensionsAreCheckedToo) {
  EXPECT_EQ(walkMatrix({2, 0}, 3, 2), EIP712_REQ_DONE);
  EXPECT_EQ(walkMatrix({2, 0}, 3, 1), EIP712_REQ_FAIL);
  EXPECT_EQ(walkMatrix({0, 4}, 4, 3), EIP712_REQ_DONE);
  EXPECT_EQ(walkMatrix({0, 4}, 3, 3), EIP712_REQ_FAIL);
}

// Titles do not push the body down when they wrap, so every review title
// must fit one row even for the longest accepted primary type.
TEST(Eip712Stream, LeafTitlesFitOneRowForTheLongestPrimaryType) {
  const std::string primary(EIP712_MAX_STRUCT_NAME - 1, 'W');
  ASSERT_TRUE(eip712_type_identifier_ok(primary.c_str()));
  std::map<std::string, Struct> types;
  addMember(types["EIP712Domain"], "name",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));
  addMember(types[primary], "amount",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
  kkconfirm_capture_start();
  const int used = walk(
      primary.c_str(), types,
      [](const std::vector<uint32_t>& path) -> Bytes {
        return path[0] == 0 ? Bytes{'A', 'p', 'p'} : word(5);
      },
      2);
  kkconfirm_capture_finish();
  EXPECT_EQ(used, 2);
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
  EXPECT_STREQ(eip712_stream_next()->primary_type, primary.c_str());
  const std::vector<std::string> titles = kkconfirm_captured_titles();
  ASSERT_EQ(titles.size(), 2u);
  for (std::string title : titles) {
    for (char& c : title) c = (char)toupper((unsigned char)c);
    EXPECT_EQ(1u, calc_str_line(get_title_font(), title.c_str(), TITLE_WIDTH))
        << title;
  }
  eip712_stream_abort();
}

// An empty array has no element screens. Its path, declared type and zero
// length are reviewed instead, at every nesting level.
TEST(Eip712Stream, EmptyArraysAreReviewedWithPathAndType) {
  struct Case {
    const char* name;
    Field type;
    std::vector<uint16_t> lengths;  // answered in request order
    std::vector<std::string> screens;
  };
  Field addresses = mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS);
  addresses.array_levels_count = 1;
  Field words = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  words.array_levels_count = 1;
  Field grid = words;
  grid.array_levels_count = 2;
  Field items = structField("Item");
  items.array_levels_count = 1;
  const Case cases[] = {
      {"address[]", addresses, {0}, {"recipients\naddress[]: 0 items"}},
      {"uint256[]", words, {0}, {"recipients\nuint256[]: 0 items"}},
      {"outer", grid, {0}, {"recipients\nuint256[][]: 0 items"}},
      {"inner",
       grid,
       {2, 0, 0},
       {"recipients[0]\nuint256[]: 0 items",
        "recipients[1]\nuint256[]: 0 items"}},
      {"structs", items, {0}, {"recipients\nItem[]: 0 items"}},
  };
  static std::vector<uint16_t> lengths;
  for (const Case& c : cases) {
    SCOPED_TRACE(c.name);
    std::map<std::string, Struct> types;
    addMember(types["Msg"], "amount",
              mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
    addMember(types["Msg"], "recipients", c.type);
    addMember(types["Item"], "to",
              mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS));
    lengths = c.lengths;
    kkconfirm_capture_start();
    const int used = walk(
        "Msg", types,
        [](const std::vector<uint32_t>& path) -> Bytes {
          if (path.size() == 2 && path[1] == 0) return word(7);
          const uint16_t n = lengths.front();
          lengths.erase(lengths.begin());
          return Bytes{(uint8_t)(n >> 8), (uint8_t)n};
        },
        1 + (int)c.screens.size());
    const std::vector<std::string> bodies = kkconfirm_capture_finish();
    EXPECT_EQ(used, 1 + (int)c.screens.size());
    ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
    ASSERT_EQ(bodies.size(), 1 + c.screens.size());
    for (size_t i = 0; i < c.screens.size(); i++)
      EXPECT_EQ(bodies[1 + i], c.screens[i]);
    eip712_stream_abort();
  }
}

// A struct without members has no screen of its own: as a member, or as the
// element of an array whose length then goes unseen, it would be signed blind.
TEST(Eip712Stream, StructsWithoutMembersAreRefused) {
  Field single = structField("Z");
  Field many = structField("Z");
  many.array_levels_count = 1;
  for (const Field& pad : {single, many}) {
    std::map<std::string, Struct> types;
    addMember(types["Msg"], "contents",
              mk(EthereumTypedDataStructAck_EthereumDataType_STRING));
    addMember(types["Msg"], "pad", pad);
    types["Z"];  // declared, no members
    walk(
        "Msg", types,
        [](const std::vector<uint32_t>& path) -> Bytes {
          if (path.size() == 2 && path[1] == 0) return Bytes{'h', 'i'};
          return Bytes{0, 5};
        },
        8);
    EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_FAIL);
    eip712_stream_abort();
  }
}

TEST(Eip712Stream, RejectingAnEmptyArrayCancelsTheSignature) {
  std::map<std::string, Struct> types;
  Field recipients = mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS);
  recipients.array_levels_count = 1;
  addMember(types["Msg"], "recipients", recipients);
  const int used = walk(
      "Msg", types,
      [](const std::vector<uint32_t>&) -> Bytes { return Bytes{0, 0}; }, 0);
  EXPECT_EQ(used, -1);  // the rejection sentinel answered the empty array
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_CANCELLED);
  eip712_stream_abort();
}

// "uint256" is a legal struct name and spells exactly like the atomic type,
// so the replay check must bind the member's kind, not just its spelling. A
// host switching UINT to STRUCT after hashing would otherwise display nested
// fields and sign their digest as the integer the type hash declared.
TEST(Eip712Stream, ReplayBindsMemberKindNotOnlySpelling) {
  EthereumSignTypedData begin{};
  strcpy(begin.primary_type, "M");
  ASSERT_TRUE(eip712_stream_begin(&begin, false));
  EthereumTypedDataStructAck empty{};
  for (int i = 0; i < 3; i++) ASSERT_TRUE(eip712_stream_on_struct(&empty));
  ASSERT_STREQ(eip712_stream_next()->struct_name, "M");

  EthereumTypedDataStructAck as_uint{};
  addMember(as_uint, "amount",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
  EthereumTypedDataStructAck as_struct{};
  addMember(as_struct, "amount", structField("uint256"));
  ASSERT_EQ(nameOf(as_uint.members[0].type), nameOf(as_struct.members[0].type));

  ASSERT_TRUE(eip712_stream_on_struct(&as_uint));  // discover
  ASSERT_TRUE(eip712_stream_on_struct(&as_uint));  // hash M(uint256 amount)
  ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_STRUCT);
  EXPECT_FALSE(eip712_stream_on_struct(&as_struct));  // member walk
  ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_FAIL);
  EXPECT_STREQ(eip712_stream_next()->error,
               "EIP-712 schema changed during signing");
  eip712_stream_abort();
}

// Seaport BulkOrder and LooksRare BatchOrder sign 2^h orders at once; the
// device cannot review them, so the shape is refused before any message
// screen. A same-named type of another shape walks as usual.
TEST(Eip712Stream, BulkOrderTreesAreRefusedByShape) {
  struct Case {
    const char* primary;
    const char* order;
    size_t height;
    bool gated;
  };
  const Case cases[] = {
      {"BulkOrder", "OrderComponents", 1, true},
      {"BulkOrder", "OrderComponents", 3, true},
      {"BatchOrder", "Maker", 1, true},
      {"BatchOrder", "Maker", 3, true},
      {"BulkOrder", "Listing", 1, false},
      {"Orders", "OrderComponents", 1, false},
  };
  for (const Case& c : cases) {
    SCOPED_TRACE(std::string(c.primary) + " of " + c.order +
                 " h=" + std::to_string(c.height));
    std::map<std::string, Struct> types;
    Field tree = structField(c.order);
    tree.array_levels_count = c.height;
    for (size_t i = 0; i < c.height; i++) tree.array_levels[i] = 2;
    addMember(types[c.primary], "tree", tree);
    addMember(types[c.order], "price",
              mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
    const int used = walk(
        c.primary, types,
        [](const std::vector<uint32_t>& path) -> Bytes {
          if (path.size() <= 3) return Bytes{0, 2};
          return word(1);
        },
        8);
    if (c.gated) {
      EXPECT_EQ(used, 0);
      ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_FAIL);
      EXPECT_STREQ(eip712_stream_next()->error,
                   "Bulk order: sign listings individually");
    } else {
      EXPECT_EQ(used, 2);
      EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
    }
    eip712_stream_abort();
  }
}

// ── Real-world corpus ───────────────────────────────────────────────
// One document per protocol, from the type strings in each protocol's own
// source (eip712_corpus.json lists them). Every one must sign, and its domain
// separator and message hash must equal the values computed outside this
// firmware: a pure-Python encoder written from the spec, cross-checked by
// eth-sig-util and ethers (eip712_corpus_gen.py).
namespace {

struct CorpusMember {
  const char* name;
  const char* type;
};
struct CorpusStruct {
  const char* name;
  std::vector<CorpusMember> members;
};
struct CorpusValue {
  std::vector<uint32_t> path;
  const char* hex;
};
struct CorpusDoc {
  const char* id;
  const char* primary;
  std::vector<CorpusStruct> types;
  std::vector<CorpusValue> values;
  int leaves;
  const char* domain_separator;
  const char* message_hash;
};

const std::vector<CorpusDoc> kCorpus = {
#include "eip712_corpus.inc"
};

// "uint160", "bytes32", "Person[]", "OrderComponents[2][2]" as the host's
// FieldType: dimensions in written order.
Field corpusField(const std::string& spelled) {
  const size_t bracket = spelled.find('[');
  const std::string base = spelled.substr(0, bracket);
  Field f;
  unsigned bits = 0;
  if (sscanf(base.c_str(), "uint%u", &bits) == 1 &&
      "uint" + std::to_string(bits) == base) {
    f = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, bits / 8);
  } else if (sscanf(base.c_str(), "int%u", &bits) == 1 &&
             "int" + std::to_string(bits) == base) {
    f = mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, bits / 8);
  } else if (sscanf(base.c_str(), "bytes%u", &bits) == 1 &&
             "bytes" + std::to_string(bits) == base) {
    f = mkSized(EthereumTypedDataStructAck_EthereumDataType_BYTES, bits);
  } else if (base == "bytes") {
    f = mk(EthereumTypedDataStructAck_EthereumDataType_BYTES);
  } else if (base == "string") {
    f = mk(EthereumTypedDataStructAck_EthereumDataType_STRING);
  } else if (base == "bool") {
    f = mk(EthereumTypedDataStructAck_EthereumDataType_BOOL);
  } else if (base == "address") {
    f = mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS);
  } else {
    f = structField(base.c_str());
  }
  for (size_t at = bracket; at != std::string::npos;
       at = spelled.find('[', at + 1)) {
    f.array_levels[f.array_levels_count++] =
        (uint32_t)strtoul(spelled.c_str() + at + 1, nullptr, 10);
  }
  return f;
}

Bytes fromHex(const char* hex) {
  Bytes out;
  for (size_t i = 0; hex[i] && hex[i + 1]; i += 2) {
    out.push_back((uint8_t)std::stoi(std::string(hex + i, 2), nullptr, 16));
  }
  return out;
}

const CorpusDoc* g_doc;
bool g_missing_value;

// Read at the first message value, once the domain is hashed: whether the
// domain's facts can bind an ERC-7730 definition.
int g_bindable;

Bytes corpusValue(const std::vector<uint32_t>& path) {
  if (g_bindable < 0 && !path.empty() && path[0] == 1) {
    Eip712DomainFacts facts;
    g_bindable = eip712_stream_domain_facts(&facts);
    // An unbindable domain matches nothing, not even an absent member.
    if (!g_bindable) {
      const uint8_t chain[2] = {0x23, 0x29};  // 9001
      EXPECT_FALSE(eip712_stream_domain_matches(3, 7, chain, 2, false));
      EXPECT_FALSE(eip712_stream_domain_matches(4, 0, nullptr, 0, true));
      EXPECT_FALSE(eip712_stream_domain_matches(5, 0, nullptr, 0, true));
    }
  }
  for (const CorpusValue& v : g_doc->values) {
    if (v.path == path) return fromHex(v.hex);
  }
  g_missing_value = true;
  return Bytes{};
}

}  // namespace

TEST(Eip712Stream, RealWorldCorpusSignsWithIndependentDigests) {
  EXPECT_GE(kCorpus.size(), 61u);
  // Max approvals sign, with the warning on the value's own screen.
  const std::map<std::string, std::string> unlimited = {
      {"permit2-PermitSingle-unlimited", "details.amount\nuint160: UNLIMITED"},
      {"eip2612-Permit-unlimited", "value\nuint256: UNLIMITED"},
      {"dai-Permit-allowed", "allowed\nbool: UNLIMITED (allowed)"},
      {"safe-SafeTx-approve-unlimited",
       "Allow 0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45 to spend ALL your "
       "USDC"},
      // A real MultiSend: approve(max) inside, then a CoW swap order.
      {"safe-SafeTx-multisend-approve-unlimited",
       "Allow 0xC92E8bdf79f0507f65a392b0ab4667716BFE0110 to spend ALL your "
       "WETH"},
  };
  const std::set<std::string> unbindable = {"evmos-MsgSend",
                                            "injective-MsgSend-v2"};
  size_t warned_docs = 0;
  for (const CorpusDoc& doc : kCorpus) {
    SCOPED_TRACE(doc.id);
    std::map<std::string, Struct> types;
    for (const CorpusStruct& s : doc.types) {
      Struct& ack = types[s.name];
      for (const CorpusMember& m : s.members)
        addMember(ack, m.name, corpusField(m.type));
    }
    g_doc = &doc;
    g_missing_value = false;
    g_bindable = -1;
    // A long value is reviewed in parts, so allow several screens per leaf,
    // and one per eight bytes of a value long enough to be chunked.
    size_t value_bytes = 0;
    for (const CorpusValue& v : doc.values) value_bytes += strlen(v.hex) / 2;
    kkconfirm_capture_start();
    const int used = walk(doc.primary, types, corpusValue,
                          4 * doc.leaves + 8 + (int)(value_bytes / 8));
    const std::vector<std::string> bodies = kkconfirm_capture_finish();
    const std::vector<std::string> titles = kkconfirm_captured_titles();
    std::vector<std::string> warned;
    for (size_t i = 0; i < titles.size(); i++)
      if (titles[i] == "UNLIMITED approval") warned.push_back(bodies[i]);
    // Real Safe batches (operation 1 to MultiSend, inner calls 0) read clean.
    EXPECT_EQ(std::count(titles.begin(), titles.end(), "Delegatecall"), 0);
    EXPECT_EQ(std::count(titles.begin(), titles.end(), "Delegatecall in batch"),
              0);
    EXPECT_EQ(std::count(titles.begin(), titles.end(), "Batch not checked"), 0);
    const auto expect = unlimited.find(doc.id);
    if (expect == unlimited.end()) {
      EXPECT_TRUE(warned.empty());
    } else {
      warned_docs++;
      EXPECT_EQ(warned, std::vector<std::string>{expect->second});
    }
    const Eip712Next* next = eip712_stream_next();
    EXPECT_FALSE(g_missing_value);
    // Ethermint domains (string verifyingContract and salt) sign, unbound.
    EXPECT_EQ(g_bindable, unbindable.count(doc.id) ? 0 : 1);
    if (next->kind != EIP712_REQ_DONE) {
      ADD_FAILURE() << "refused: "
                    << (next->kind == EIP712_REQ_FAIL && next->error
                            ? next->error
                            : "(no error)");
      eip712_stream_abort();
      continue;
    }
    EXPECT_GE(used, doc.leaves);
    // Values over one ValueAck (Safe MultiSend data, a Snapshot body) were
    // sent in chunks.
    size_t widest = 0;
    for (const CorpusValue& v : doc.values)
      widest = std::max(widest, strlen(v.hex) / 2);
    EXPECT_EQ(g_first_chunks > 0, widest > EIP712_MAX_LEAF);
    EXPECT_FALSE(next->message_empty);
    EXPECT_STREQ(next->primary_type, doc.primary);
    EXPECT_EQ(hexOf(next->domain_separator, 32), doc.domain_separator);
    EXPECT_EQ(hexOf(next->message_hash, 32), doc.message_hash);
    eip712_stream_abort();
  }
  EXPECT_EQ(warned_docs, unlimited.size());
}

// ── One screen per string ───────────────────────────────────────────
// The body renderer drops a space where it wraps a line and the pager drops
// one at a page start, so a string leaf that keeps a space literally can draw
// the same pixels as the string without it, while the two hash differently.
namespace {

std::string g_note;

// Title plus the canvas the real layout draws, for every captured screen.
std::vector<std::string> pixels(const std::vector<std::string>& titles,
                                const std::vector<std::string>& bodies) {
  std::vector<std::string> out;
  for (size_t i = 0; i < bodies.size(); i++) {
    layout_has_icon(false);
    layout_standard_notification(titles[i].c_str(), bodies[i].c_str(),
                                 NOTIFICATION_REQUEST_NO_ANIMATION);
    const Canvas* canvas = layout_get_canvas();
    out.push_back(titles[i] + '\0' +
                  std::string((const char*)canvas->buffer,
                              (size_t)canvas->width * canvas->height));
  }
  return out;
}

// Every screen a document with one string member `note` draws.
std::vector<std::string> noteScreens(const std::string& note) {
  std::map<std::string, Struct> types;
  addMember(types["EIP712Domain"], "name",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));
  addMember(types["Msg"], "note",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));
  g_note = note;
  kkconfirm_capture_start();
  const int used = walk(
      "Msg", types,
      [](const std::vector<uint32_t>& path) -> Bytes {
        if (path[0] == 0) return Bytes{'A', 'p', 'p'};
        return Bytes(g_note.begin(), g_note.end());
      },
      40);
  const std::vector<std::string> bodies = kkconfirm_capture_finish();
  EXPECT_GT(used, 0);
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
  eip712_stream_abort();
  return pixels(kkconfirm_captured_titles(), bodies);
}

// The screens confirm() draws for `body` as given, and its page bodies.
std::vector<std::string> rawScreens(const std::string& body,
                                    std::vector<std::string>* pages) {
  kkconfirm_capture_start();
  EXPECT_TRUE(kkconfirm_preload(10, 0));
  EXPECT_TRUE(
      confirm(ButtonRequestType_ButtonRequest_Other, "T", "%s", body.c_str()));
  kkconfirm_drain();
  *pages = kkconfirm_capture_finish();
  return pixels(kkconfirm_captured_titles(), *pages);
}

}  // namespace

TEST(Eip712Stream, StringsDifferingByOneSpaceNeverShareAScreen) {
  const std::string tail = "payTo0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
  const std::string prefix = "note\nstring: ";
  bool wrap_covered = false, page_covered = false;
  // A row holds 37 'X': k = 37 puts the space at the first page break and
  // k = 74 at a line wrap inside the second page. Each window brackets one.
  for (size_t k : {35, 36, 37, 38, 39, 72, 73, 74, 75, 76}) {
    SCOPED_TRACE(k);
    const std::string spaced = std::string(k, 'X') + " " + tail;
    const std::string joined = std::string(k, 'X') + tail;

    // Coverage: shown verbatim, which k put the space where it is dropped?
    std::vector<std::string> pages, unused;
    if (rawScreens(prefix + spaced, &pages) ==
        rawScreens(prefix + joined, &unused)) {
      const std::string raw = prefix + spaced;
      const size_t space = prefix.size() + k;
      size_t pos = 0;
      bool at_page_edge = false;
      for (size_t i = 0; i < pages.size(); i++) {
        while (raw[pos] == ' ') at_page_edge |= pos++ == space;
        pos += pages[i].size();
        at_page_edge |= i + 1 < pages.size() && pos - 1 == space;
      }
      (at_page_edge ? page_covered : wrap_covered) = true;
    }

    EXPECT_TRUE(noteScreens(spaced) != noteScreens(joined));
  }
  // The sweep reached both kinds of dropped space.
  EXPECT_TRUE(wrap_covered);
  EXPECT_TRUE(page_covered);
}

// A control byte draws as an escape, and a backslash is escaped too, so the
// newline and the four literal characters "\x0a" never share a screen.
TEST(Eip712Stream, StringControlBytesAreShownEscaped) {
  const std::string newline = std::string("a\nb\tc") + '\0' + "d";
  const std::string literal = "a\\x0ab\\x09c\\x00d";
  std::map<std::string, Struct> types;
  addMember(types["EIP712Domain"], "name",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));
  addMember(types["Msg"], "note",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));
  std::vector<std::string> bodies;
  for (const std::string* note : {&newline, &literal}) {
    g_note = *note;
    kkconfirm_capture_start();
    walk(
        "Msg", types,
        [](const std::vector<uint32_t>& path) -> Bytes {
          if (path[0] == 0) return Bytes{'A', 'p', 'p'};
          return Bytes(g_note.begin(), g_note.end());
        },
        40);
    EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
    eip712_stream_abort();
    const std::vector<std::string> shown = kkconfirm_capture_finish();
    ASSERT_GE(shown.size(), 2u);
    bodies.push_back(shown[1]);
  }
  EXPECT_EQ(bodies[0], "note\nstring: a\\x0ab\\x09c\\x00d");
  EXPECT_EQ(bodies[1], "note\nstring: a\\\\x0ab\\\\x09c\\\\x00d");
  EXPECT_TRUE(noteScreens(newline) != noteScreens(literal));
}

// approve(spender, amount) inside a `bytes` leaf (a Safe transaction's data)
// gets the top-level policy: 2^256-1 signs only after the UNLIMITED warning,
// and a dirty spender word is refused.
namespace {

Bytes g_approve;
bool g_data_first;
int g_operation;
const char* g_to;
std::vector<std::string> g_safe_members;

Bytes approveCall(uint8_t spender_high, uint8_t amount_fill) {
  Bytes b = {0x09, 0x5e, 0xa7, 0xb3};
  b.insert(b.end(), 12, 0);
  b[15] = spender_high;
  for (int i = 0; i < 20; i++) b.push_back((uint8_t)(0x10 + i));
  b.insert(b.end(), 32, amount_fill);
  return b;
}

enum ToPlace { TO_FIRST, TO_LAST, TO_ABSENT };

// The domain's chainId, then SafeTx {to, value, data} (or data first), and
// `operation` last (or first) when it is not negative. `to` (USDC unless
// given) moves to the end, or is left out, by `to_place`.
Eip712ReqKind walkSafeTx(const Bytes& data, bool data_first, int screens,
                         std::vector<std::string>* titles,
                         std::vector<std::string>* bodies, int operation = -1,
                         bool operation_first = false, const char* to = nullptr,
                         ToPlace to_place = TO_FIRST) {
  std::map<std::string, Struct> types;
  addMember(types["EIP712Domain"], "chainId",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
  g_safe_members = {"to", "value"};
  g_safe_members.insert(
      data_first ? g_safe_members.begin() : g_safe_members.end(), "data");
  if (operation >= 0)
    g_safe_members.insert(
        operation_first ? g_safe_members.begin() : g_safe_members.end(),
        "operation");
  if (to_place != TO_FIRST) {
    g_safe_members.erase(
        std::find(g_safe_members.begin(), g_safe_members.end(), "to"));
    if (to_place == TO_LAST) g_safe_members.push_back("to");
  }
  g_to = to ? to : "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";  // USDC
  for (const std::string& name : g_safe_members) {
    if (name == "to")
      addMember(types["SafeTx"], name.c_str(),
                mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS));
    else if (name == "data")
      addMember(types["SafeTx"], name.c_str(),
                mk(EthereumTypedDataStructAck_EthereumDataType_BYTES));
    else
      addMember(types["SafeTx"], name.c_str(),
                mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT,
                        name == "operation" ? 1 : 32));
  }
  g_approve = data;
  g_data_first = data_first;
  g_operation = operation;
  kkconfirm_capture_start();
  walk(
      "SafeTx", types,
      [](const std::vector<uint32_t>& path) -> Bytes {
        if (path[0] == 0) return word(1);
        const std::string& name = g_safe_members[path[1]];
        if (name == "data") return g_approve;
        if (name == "to") return fromHex(g_to);
        if (name == "operation") return Bytes{(uint8_t)g_operation};
        return word(0);
      },
      screens);
  *bodies = kkconfirm_capture_finish();
  *titles = kkconfirm_captured_titles();
  const Eip712ReqKind kind = eip712_stream_next()->kind;
  eip712_stream_abort();
  return kind;
}

}  // namespace

TEST(Eip712Stream, EmbeddedUnlimitedApproveSignsAfterTheWarning) {
  std::vector<std::string> titles, bodies;
  char expected[128];

  // `to` already reviewed: the token is named.
  EXPECT_EQ(walkSafeTx(approveCall(0, 0xff), false, 20, &titles, &bodies),
            EIP712_REQ_DONE);
  std::vector<std::string> warned;
  for (size_t i = 0; i < titles.size(); i++)
    if (titles[i] == "UNLIMITED approval") warned.push_back(bodies[i]);
  ASSERT_EQ(warned.size(), 1u);
  EXPECT_NE(warned[0].find("to spend ALL your USDC"), std::string::npos);
  char checksummed[41];
  const Bytes call = approveCall(0, 0xff);
  ethereum_address_checksum(call.data() + 16, checksummed, false, 1);
  snprintf(expected, sizeof(expected), "Allow 0x%s to spend ALL your USDC",
           checksummed);
  EXPECT_EQ(warned[0], expected);

  // `data` before `to`: the token is pointed at, not guessed.
  EXPECT_EQ(walkSafeTx(approveCall(0, 0xff), true, 20, &titles, &bodies),
            EIP712_REQ_DONE);
  snprintf(expected, sizeof(expected),
           "Allow 0x%s to spend ALL your tokens of the contract in 'to'",
           checksummed);
  EXPECT_EQ(std::count(bodies.begin(), bodies.end(), std::string(expected)), 1);

  // A finite approve keeps the ordinary screen.
  EXPECT_EQ(walkSafeTx(approveCall(0, 0x01), false, 20, &titles, &bodies),
            EIP712_REQ_DONE);
  EXPECT_EQ(std::count(titles.begin(), titles.end(), "UNLIMITED approval"), 0);

  // Declining the warning signs nothing: only the domain and `to`, `value`
  // screens are accepted.
  EXPECT_EQ(walkSafeTx(approveCall(0, 0xff), false, 3, &titles, &bodies),
            EIP712_REQ_CANCELLED);

  // A dirty spender word is refused before any screen of it.
  EXPECT_EQ(walkSafeTx(approveCall(0x01, 0xff), false, 20, &titles, &bodies),
            EIP712_REQ_FAIL);
  EXPECT_EQ(std::count(titles.begin(), titles.end(), "UNLIMITED approval"), 0);
}

namespace {

// A SafeTx {x, data, to} reached after another SafeTx's `to` was recorded in
// a slot the new frame now reuses: R{A a; B b} (A{SafeTx s}, B{p, q, SafeTx
// s}), or R{SafeTx[] a; B b} (B{p, SafeTx s}). Every x is USDC's address.
Eip712ReqKind walkReusedSafeTxSlot(bool array_variant,
                                   std::vector<std::string>* bodies,
                                   std::vector<std::string>* titles) {
  std::map<std::string, Struct> types;
  Field u256 = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  addMember(types["EIP712Domain"], "chainId", u256);
  addMember(types["SafeTx"], "x", u256);
  addMember(types["SafeTx"], "data",
            mk(EthereumTypedDataStructAck_EthereumDataType_BYTES));
  addMember(types["SafeTx"], "to",
            mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS));
  if (array_variant) {
    Field txs = structField("SafeTx");
    txs.array_levels_count = 1;
    addMember(types["R"], "a", txs);
  } else {
    addMember(types["R"], "a", structField("A"));
    addMember(types["A"], "s", structField("SafeTx"));
  }
  addMember(types["R"], "b", structField("B"));
  addMember(types["B"], "p", u256);
  if (!array_variant) addMember(types["B"], "q", u256);
  addMember(types["B"], "s", structField("SafeTx"));
  kkconfirm_capture_start();
  walk(
      "R", types,
      [](const std::vector<uint32_t>& path) -> Bytes {
        if (path[0] == 0) return word(1);
        if (path.size() == 2) return Bytes{0, 1};  // a's length
        if (path.size() == 3) return word(0);      // p, q
        switch (path.back()) {
          case 0: {  // x
            Bytes x(12, 0);
            Bytes usdc = fromHex("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
            x.insert(x.end(), usdc.begin(), usdc.end());
            return x;
          }
          case 1:
            return approveCall(0, 0xff);
          default:
            return Bytes(20, 0x11);
        }
      },
      40);
  *bodies = kkconfirm_capture_finish();
  *titles = kkconfirm_captured_titles();
  const Eip712ReqKind kind = eip712_stream_next()->kind;
  eip712_stream_abort();
  return kind;
}

}  // namespace

// The recorded SafeTx.to belongs to the frame that read it. A later SafeTx
// whose `data` comes before its own `to` points at 'to', never at a value of
// its own (x) that happens to sit in the dead frame's slot.
TEST(Eip712Stream, EmbeddedApproveNeverNamesAnotherFramesTo) {
  for (bool array_variant : {false, true}) {
    SCOPED_TRACE(array_variant);
    std::vector<std::string> titles, bodies;
    EXPECT_EQ(walkReusedSafeTxSlot(array_variant, &bodies, &titles),
              EIP712_REQ_DONE);
    std::vector<std::string> warned;
    for (size_t i = 0; i < titles.size(); i++)
      if (titles[i] == "UNLIMITED approval") warned.push_back(bodies[i]);
    ASSERT_EQ(warned.size(), 2u);
    for (const std::string& body : warned) {
      EXPECT_EQ(body.find("USDC"), std::string::npos) << body;
      EXPECT_NE(body.find("of the contract in 'to'"), std::string::npos)
          << body;
    }
  }
}

// A streamed array's length is uint16 on the wire. Past 255 elements the
// walk still completes, every index is shown as itself, and the digest is the
// one an independent keccak computes (sponge.py, keccak of
// EIP712Domain(uint256 chainId) with chainId 1, and Msg(uint256[] v) with
// v[i] = i for i < 300).
TEST(Eip712Stream, StreamedArraysPastTwoHundredFiftyFiveElementsComplete) {
  std::map<std::string, Struct> types;
  Field u256 = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  addMember(types["EIP712Domain"], "chainId", u256);
  Field values = u256;
  values.array_levels_count = 1;
  addMember(types["Msg"], "v", values);
  kkconfirm_capture_start();
  const int used = walk(
      "Msg", types,
      [](const std::vector<uint32_t>& path) -> Bytes {
        if (path[0] == 0) return word(1);
        if (path.size() == 2) return Bytes{300 >> 8, 300 & 0xff};
        Bytes w(32, 0);
        w[30] = (uint8_t)(path[2] >> 8);
        w[31] = (uint8_t)path[2];
        return w;
      },
      302);
  const std::vector<std::string> bodies = kkconfirm_capture_finish();
  ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
  EXPECT_EQ(used, 301);
  EXPECT_EQ(hexOf(eip712_stream_next()->domain_separator, 32),
            "2d9145f2f941cb14d4c738374c6ebde69c75a737e93da5905ee040bab57e46a8");
  EXPECT_EQ(hexOf(eip712_stream_next()->message_hash, 32),
            "89f049ac78541e85b598bdf522d566bcf14f5d3441fb671742f5403aae9b5609");
  eip712_stream_abort();
  ASSERT_EQ(bodies.size(), 301u);
  EXPECT_EQ(bodies[1 + 255], "v[255]\nuint256: 255");
  EXPECT_EQ(bodies[1 + 256], "v[256]\nuint256: 256");
  EXPECT_EQ(bodies[1 + 299], "v[299]\nuint256: 299");
}

// ── Values longer than one ValueAck ─────────────────────────────────
// A `bytes` or `string` leaf over EIP712_MAX_LEAF arrives in chunks, each
// hashed and shown as it comes, under a part counter for the whole value.
namespace {

Bytes g_long;

// Msg {bytes data | string data; uint256 n} under EIP712Domain(uint256
// chainId), or with the long value as the domain's `name` when `in_domain`.
std::map<std::string, Struct> longTypes(bool text, bool in_domain = false) {
  std::map<std::string, Struct> types;
  Field u256 = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  Field data = mk(text ? EthereumTypedDataStructAck_EthereumDataType_STRING
                       : EthereumTypedDataStructAck_EthereumDataType_BYTES);
  addMember(types["EIP712Domain"], in_domain ? "name" : "chainId",
            in_domain ? data : u256);
  addMember(types["Msg"], "data", data);
  addMember(types["Msg"], "n", u256);
  return types;
}

Bytes longMessageValue(const std::vector<uint32_t>& path) {
  if (path[0] == 0) return word(1);
  return path[1] == 0 ? g_long : word(7);
}

Bytes longDomainValue(const std::vector<uint32_t>& path) {
  return path[0] == 0 ? g_long : word(7);
}

struct LongRun {
  Eip712ReqKind kind;
  std::string error;
  std::string message_hash;
  std::vector<std::string> titles, bodies;
};

LongRun signLong(const Bytes& v, bool text, int topup = 0,
                 bool in_domain = false) {
  g_long = v;
  kkconfirm_capture_start();
  walk("Msg", longTypes(text, in_domain),
       in_domain ? longDomainValue : longMessageValue, topup ? 64 : 400, false,
       topup);
  LongRun r;
  r.bodies = kkconfirm_capture_finish();
  r.titles = kkconfirm_captured_titles();
  const Eip712Next* next = eip712_stream_next();
  r.kind = next->kind;
  if (next->kind == EIP712_REQ_FAIL && next->error) r.error = next->error;
  if (next->kind == EIP712_REQ_DONE) r.message_hash = hexOf(next->message_hash, 32);
  eip712_stream_abort();
  return r;
}

// hashStruct(Msg), straight from the specification.
std::string expectedLongHash(const Bytes& v, bool text) {
  const std::string type =
      text ? "Msg(string data,uint256 n)" : "Msg(bytes data,uint256 n)";
  Bytes enc(64);
  keccak_256(reinterpret_cast<const uint8_t*>(type.data()), type.size(),
             enc.data());
  keccak_256(v.data(), v.size(), enc.data() + 32);
  const Bytes n = word(7);
  enc.insert(enc.end(), n.begin(), n.end());
  uint8_t out[32];
  keccak_256(enc.data(), enc.size(), out);
  return hexOf(out, 32);
}

// The `data` parts, which must count 1..N in order with one N, joined. A
// part longer than the display is paged by confirm(); its later pages follow
// it, up to the next part or the `n` leaf. Nothing here has a space, which
// the pager may drop at a page edge.
std::string joinParts(const LongRun& r, const std::string& type,
                      unsigned* parts) {
  std::string joined;
  unsigned next = 1, total = 0;
  bool in_part = false;
  *parts = 0;
  for (const std::string& body : r.bodies) {
    if (body.compare(0, 6, "data (") != 0) {
      in_part = in_part && body.compare(0, 2, "n\n") != 0;
      if (in_part) joined += body;
      continue;
    }
    unsigned i = 0, n = 0;
    int used = 0;
    if (sscanf(body.c_str(), "data (%u/%u)\n%n", &i, &n, &used) != 2 ||
        used == 0 || i != next++ || (total && n != total))
      return "<misnumbered: " + body.substr(0, 40) + ">";
    total = n;
    const std::string label = type + ": ";
    if (body.compare(used, label.size(), label) != 0) return "<unlabelled>";
    joined += body.substr(used + label.size());
    in_part = true;
  }
  if (next - 1 != total) return "<missing parts>";
  *parts = total;
  return joined;
}

std::string hexText(const Bytes& v) {
  return "0x" + hexOf(v.data(), v.size());
}

std::string escapedText(const Bytes& v) {
  std::string out(4 * v.size() + 1, '\0');
  EXPECT_TRUE(erc7730_format_text(v.data(), v.size(), &out[0], out.size()));
  out.resize(strlen(out.c_str()));
  return out;
}

Bytes letters(size_t n) {
  Bytes v(n);
  for (size_t i = 0; i < n; i++) v[i] = (uint8_t)('a' + i % 26);
  return v;
}

}  // namespace

// 1024 bytes still go in one ValueAck; past that the host chunks. The
// digest is the specification's, every byte is shown once and in order, and
// the counter names the whole value's part count from its first screen.
TEST(Eip712Stream, ChunkedValuesSignAtEveryBoundaryLength) {
  for (bool text : {false, true}) {
    for (size_t len : {1024u, 1025u, 2048u, 3000u}) {
      SCOPED_TRACE(std::string(text ? "string " : "bytes ") +
                   std::to_string(len));
      Bytes v = letters(len);
      if (!text) v[len - 1] = 0xfe;
      const LongRun r = signLong(v, text);
      ASSERT_EQ(r.kind, EIP712_REQ_DONE) << r.error;
      EXPECT_EQ(r.message_hash, expectedLongHash(v, text));
      const size_t chunks = (len + EIP712_MAX_LEAF - 1) / EIP712_MAX_LEAF;
      EXPECT_EQ(g_first_chunks, len > EIP712_MAX_LEAF ? 1 : 0);
      // A string is read twice: counted, then shown from offset 0.
      EXPECT_EQ(g_later_chunks,
                len > EIP712_MAX_LEAF ? (int)(text ? 2 * chunks - 1
                                                   : chunks - 1)
                                      : 0);
      unsigned parts = 0;
      EXPECT_EQ(joinParts(r, text ? "string" : "bytes", &parts),
                text ? escapedText(v) : hexText(v));
      EXPECT_GT(parts, 1u);
    }
  }
}

// Exactly EIP712_MAX_VALUE signs; one byte more is refused before any of it
// is shown.
TEST(Eip712Stream, ChunkedValuesSignAtTheCapAndNotPastIt) {
  for (bool text : {false, true}) {
    SCOPED_TRACE(text ? "string" : "bytes");
    Bytes v = letters(EIP712_MAX_VALUE);
    LongRun r = signLong(v, text, 64);
    ASSERT_EQ(r.kind, EIP712_REQ_DONE) << r.error;
    EXPECT_EQ(r.message_hash, expectedLongHash(v, text));
    unsigned parts = 0;
    EXPECT_EQ(joinParts(r, text ? "string" : "bytes", &parts),
              text ? escapedText(v) : hexText(v));
    EXPECT_GT(parts, 3000u);

    v.push_back('z');
    r = signLong(v, text, 64);
    EXPECT_EQ(r.kind, EIP712_REQ_FAIL);
    EXPECT_EQ(r.error, "EIP-712 value too long for this device");
    EXPECT_EQ(r.bodies.size(), 1u);  // the domain's chainId only
    EXPECT_EQ(eip712_stream_waiting(), EIP712_IDLE);
  }
}

// UTF-8 is checked across chunk boundaries, and a string is checked whole
// before its first screen: a bad byte at 2,000 is refused unseen.
TEST(Eip712Stream, ChunkedStringsCheckUtf8AcrossChunks) {
  // U+20AC split 1/2 across the first boundary signs and shows escaped.
  Bytes euro = letters(EIP712_MAX_LEAF - 1);
  for (uint8_t b : {0xe2, 0x82, 0xac}) euro.push_back(b);
  Bytes tail = letters(500);
  euro.insert(euro.end(), tail.begin(), tail.end());
  LongRun r = signLong(euro, true);
  ASSERT_EQ(r.kind, EIP712_REQ_DONE) << r.error;
  EXPECT_EQ(r.message_hash, expectedLongHash(euro, true));
  unsigned parts = 0;
  const std::string shown = joinParts(r, "string", &parts);
  EXPECT_NE(shown.find("\\xe2\\x82\\xac"), std::string::npos);

  struct Bad {
    const char* what;
    Bytes v;
  };
  std::vector<Bad> bad;
  Bytes broken = letters(EIP712_MAX_LEAF - 1);  // continuation is not one
  for (uint8_t b : {0xe2, 0x82, 0x58}) broken.push_back(b);  // 'X'
  bad.push_back({"split sequence broken", broken});
  Bytes truncated = letters(1500);  // ends inside a sequence
  truncated.push_back(0xe2);
  truncated.push_back(0x82);
  bad.push_back({"value ends mid-sequence", truncated});
  Bytes deep = letters(3000);
  deep[2000] = 0xff;
  bad.push_back({"bad byte at 2000", deep});
  Bytes overlong = letters(EIP712_MAX_LEAF - 1);  // "/" as two bytes
  overlong.push_back(0xc0);
  overlong.push_back(0xaf);
  overlong.push_back('a');
  bad.push_back({"overlong across the boundary", overlong});
  for (const Bad& b : bad) {
    SCOPED_TRACE(b.what);
    r = signLong(b.v, true);
    EXPECT_EQ(r.kind, EIP712_REQ_FAIL);
    EXPECT_EQ(r.error, "EIP-712 value does not match its declared type");
    EXPECT_EQ(r.bodies.size(), 1u);  // nothing of the string was shown
  }
}

namespace {

int g_tamper_mode;

void tamperChunk(EthereumTypedDataValueAck* ack) {
  const bool first = ack->has_value_total_length;
  const bool later = ack->has_value_offset;
  switch (g_tamper_mode) {
    case 0:  // a later chunk names the wrong offset
      if (later) ack->value_offset += 1;
      break;
    case 1:  // a later chunk does not name its offset
      if (later) ack->has_value_offset = false;
      break;
    case 2:  // a later chunk names a total again
      if (later) {
        ack->has_value_total_length = true;
        ack->value_total_length = 3000;
      }
      break;
    case 3:  // a later chunk runs past the total
      if (later) ack->value.size = EIP712_MAX_LEAF;
      break;
    case 4:  // a chunk short of a full one before the last
      if (later) ack->value.size -= 24;
      break;
    case 5:  // the first chunk is short
      if (first) ack->value.size = 1000;
      break;
    case 6:  // a total that fits one ValueAck
      if (first) ack->value_total_length = EIP712_MAX_LEAF;
      break;
    case 7:  // the first answer names an offset
      if (first) {
        ack->has_value_offset = true;
        ack->value_offset = 0;
      }
      break;
    case 8:  // the first chunk again, in place of the second
      if (later && ack->value_offset == EIP712_MAX_LEAF) {
        ack->value_offset = 0;
      }
      break;
    case 9:  // the string differs on its second reading
      if (later && ack->value_offset == 0) ack->value.bytes[5] ^= 1;
      break;
  }
}

}  // namespace

// Chunks come exactly as asked: offset echoed, full size until the last, no
// byte past the total. Anything else is refused and the session wiped.
TEST(Eip712Stream, ChunkedValuesRefuseMisframedChunks) {
  struct Case {
    int mode;
    size_t len;
    bool text;
    const char* error;
  };
  const Case cases[] = {
      {0, 3000, false, "EIP-712 value chunk out of order"},
      {1, 3000, false, "EIP-712 value chunk out of order"},
      {2, 3000, false, "EIP-712 value chunk out of order"},
      {3, 1500, false, "EIP-712 value chunk has the wrong length"},
      {4, 3000, false, "EIP-712 value chunk has the wrong length"},
      {5, 3000, false, "EIP-712 value chunk has the wrong length"},
      {6, 3000, false, "EIP-712 value chunk has the wrong length"},
      {7, 3000, false, "EIP-712 value chunk out of order"},
      {8, 3000, true, "EIP-712 value chunk out of order"},
      {9, 3000, true, "EIP-712 value changed while it was shown"},
  };
  g_tamper = tamperChunk;
  for (const Case& c : cases) {
    SCOPED_TRACE(c.mode);
    g_tamper_mode = c.mode;
    const LongRun r = signLong(letters(c.len), c.text);
    EXPECT_EQ(r.kind, EIP712_REQ_FAIL);
    EXPECT_EQ(r.error, c.error);
    EXPECT_EQ(eip712_stream_waiting(), EIP712_IDLE);
  }
  g_tamper = nullptr;
}

namespace {

// Chunk the answer to whatever is asked next, though it is no long value.
void chunkEverything(EthereumTypedDataValueAck* ack) {
  if (ack->has_value_total_length || ack->has_value_offset) return;
  ack->has_value_total_length = true;
  ack->value_total_length = 3000;
}

}  // namespace

// Only a message's dynamic `bytes` or `string` may be chunked: not a fixed
// width, not an array length, not a domain member, and never past the cap.
TEST(Eip712Stream, OnlyDynamicMessageValuesAreChunked) {
  std::map<std::string, Struct> types;
  Field u256 = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  addMember(types["EIP712Domain"], "chainId", u256);
  Field list = u256;
  list.array_levels_count = 1;
  addMember(types["Msg"], "n", u256);
  addMember(types["Msg"], "list", list);
  g_tamper = chunkEverything;
  walk("Msg", types,
       [](const std::vector<uint32_t>& path) -> Bytes {
         return path.size() == 2 && path[1] == 1 ? Bytes{0, 1} : word(1);
       },
       10);
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_FAIL);
  // The domain's chainId is the first answer, refused as a fixed width.
  EXPECT_STREQ(eip712_stream_next()->error, "EIP-712 value cannot be chunked");
  g_tamper = nullptr;

  // An array length, chunked.
  types["EIP712Domain"] = Struct{};
  addMember(types["EIP712Domain"], "chainId", u256);
  types["Msg"] = Struct{};
  addMember(types["Msg"], "list", list);
  g_tamper = [](EthereumTypedDataValueAck* ack) {
    if (ack->value.size == 2) chunkEverything(ack);
  };
  walk("Msg", types,
       [](const std::vector<uint32_t>& path) -> Bytes {
         return path[0] == 1 && path.size() == 2 ? Bytes{0, 1} : word(1);
       },
       10);
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_FAIL);
  EXPECT_STREQ(eip712_stream_next()->error,
               "EIP-712 array length must be two bytes");
  g_tamper = nullptr;
  eip712_stream_abort();

  // A domain string over 1 KB.
  const LongRun r = signLong(letters(2000), true, 0, true);
  EXPECT_EQ(r.kind, EIP712_REQ_FAIL);
  EXPECT_EQ(r.error, "EIP-712 domain value too long");
  EXPECT_TRUE(r.bodies.empty());
}

namespace {

bool g_abort_mid_value;

void abortAtSecondChunk(EthereumTypedDataValueAck* ack) {
  // The FSM wipes the walk on a host Cancel, Initialize or a PIN clear.
  if (g_abort_mid_value && ack->has_value_offset) {
    eip712_stream_abort();
    g_abort_mid_value = false;
  }
}

}  // namespace

// A walk ended mid-value (host abort, or the user declining a part) leaves
// nothing behind: the next chunk is refused and the next document signs with
// its own digest.
TEST(Eip712Stream, ChunkedValueAbortWipesTheSession) {
  const Bytes v = letters(3000);
  g_tamper = abortAtSecondChunk;
  g_abort_mid_value = true;
  LongRun r = signLong(v, false);
  g_tamper = nullptr;
  EXPECT_EQ(r.kind, EIP712_REQ_FAIL);
  EXPECT_EQ(r.error, "Unexpected EIP-712 value");
  EXPECT_EQ(eip712_stream_waiting(), EIP712_IDLE);

  // Declined on the second part: cancelled, nothing pending.
  g_long = v;
  kkconfirm_capture_start();
  walk("Msg", longTypes(false), longMessageValue, 2);
  kkconfirm_capture_finish();
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_CANCELLED);
  EXPECT_EQ(eip712_stream_waiting(), EIP712_IDLE);

  r = signLong(v, false);
  ASSERT_EQ(r.kind, EIP712_REQ_DONE) << r.error;
  EXPECT_EQ(r.message_hash, expectedLongHash(v, false));
}

// An approve() at the head of a chunked `data` is read from the first chunk:
// its UNLIMITED warning comes before any screen of the bytes, and a dirty
// spender word is refused before any.
TEST(Eip712Stream, ChunkedEmbeddedApproveWarnsBeforeTheBytes) {
  Bytes call = approveCall(0, 0xff);
  call.resize(3000, 0x5a);
  for (bool data_first : {false, true}) {
    SCOPED_TRACE(data_first);
    std::vector<std::string> titles, bodies;
    EXPECT_EQ(walkSafeTx(call, data_first, 200, &titles, &bodies),
              EIP712_REQ_DONE);
    size_t warning = titles.size(), first_data = titles.size();
    for (size_t i = 0; i < titles.size(); i++) {
      if (titles[i] == "UNLIMITED approval" && warning == titles.size())
        warning = i;
      if (bodies[i].compare(0, 6, "data (") == 0 && first_data == titles.size())
        first_data = i;
    }
    EXPECT_EQ(std::count(titles.begin(), titles.end(), "UNLIMITED approval"),
              1);
    ASSERT_LT(first_data, titles.size());
    EXPECT_LT(warning, first_data);
    EXPECT_EQ(bodies[first_data].compare(0, 8, "data (1/"), 0);
    // The rest of the bytes were read and shown too.
    EXPECT_EQ(g_first_chunks, 1);
    EXPECT_EQ(g_later_chunks, 2);
  }

  Bytes dirty = approveCall(0x01, 0xff);
  dirty.resize(3000, 0x5a);
  std::vector<std::string> titles, bodies;
  EXPECT_EQ(walkSafeTx(dirty, false, 200, &titles, &bodies), EIP712_REQ_FAIL);
  for (const std::string& body : bodies)
    EXPECT_NE(body.compare(0, 4, "data"), 0) << body;
}

// ── Approves inside a MultiSend ─────────────────────────────────────
// SafeTx.data = multiSend(bytes transactions), each call packed as
// operation | to | value | dataLength | data. An approve(spender, 2^256-1)
// among them gets the top-level policy: the UNLIMITED warning, naming the
// spender and the inner `to` as the token, before the bytes that follow it.
namespace {

const char* const kDai = "6b175474e89094c44da98b954eedeac495271d0f";
const char* const kUsdc = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

Bytes be32(uint32_t v) {
  Bytes w(32, 0);
  for (int i = 0; i < 4; i++) w[31 - i] = (uint8_t)(v >> (8 * i));
  return w;
}

void append(Bytes* out, const Bytes& more) {
  out->insert(out->end(), more.begin(), more.end());
}

// `op`, `to`, value 0, then `data` under its own length (or `len`).
Bytes packedCall(const char* to, const Bytes& data, int64_t len = -1,
                 uint8_t op = 0) {
  Bytes b = {op};
  append(&b, fromHex(to));
  append(&b, Bytes(32, 0));
  append(&b, be32(len < 0 ? (uint32_t)data.size() : (uint32_t)len));
  append(&b, data);
  return b;
}

// multiSend(packed), ABI-encoded and padded; `length` overrides the length
// word.
Bytes multiSendCall(const Bytes& packed, int64_t length = -1) {
  Bytes b = {0x8d, 0x80, 0xff, 0x0a};
  append(&b, be32(0x20));
  append(&b, be32(length < 0 ? (uint32_t)packed.size() : (uint32_t)length));
  append(&b, packed);
  b.resize(4 + 32 * ((b.size() - 4 + 31) / 32), 0);
  return b;
}

// A router call of `n` bytes that is no approve.
Bytes swapCall(size_t n) {
  Bytes b = {0x41, 0x4b, 0xf3, 0x89};  // exactInputSingle
  for (size_t i = 4; i < n; i++) b.push_back((uint8_t)(i * 7));
  return b;
}

std::string allowText(const Bytes& call, const char* token) {
  char checksummed[41];
  ethereum_address_checksum(call.data() + 16, checksummed, false, 1);
  return std::string("Allow 0x") + checksummed + " to spend ALL your " + token;
}

struct MsRun {
  Eip712ReqKind kind;
  std::string error;
  std::vector<std::string> titles, bodies;
  std::vector<size_t> warned;          // indexes of the UNLIMITED screens
  std::vector<size_t> delegated;       // "Delegatecall in batch" screens
  std::vector<size_t> safe_delegated;  // the SafeTx's "Delegatecall"
  std::vector<size_t> unchecked;       // "Batch not checked" screens
  size_t first_data = SIZE_MAX, last_data = SIZE_MAX;
};

MsRun signMultiSend(const Bytes& data, int screens = 400, int operation = -1,
                    bool operation_first = false, const char* to = nullptr,
                    ToPlace to_place = TO_FIRST) {
  MsRun r;
  r.kind = walkSafeTx(data, false, screens, &r.titles, &r.bodies, operation,
                      operation_first, to, to_place);
  // The abort that ends walkSafeTx() leaves the last request in place.
  if (r.kind == EIP712_REQ_FAIL && eip712_stream_next()->error)
    r.error = eip712_stream_next()->error;
  for (size_t i = 0; i < r.titles.size(); i++) {
    if (r.titles[i] == "UNLIMITED approval") r.warned.push_back(i);
    if (r.titles[i] == "Delegatecall in batch") r.delegated.push_back(i);
    if (r.titles[i] == "Delegatecall") r.safe_delegated.push_back(i);
    if (r.titles[i] == "Batch not checked") r.unchecked.push_back(i);
    if (r.bodies[i].compare(0, 5, "data\n") == 0 ||
        r.bodies[i].compare(0, 6, "data (") == 0) {
      if (r.first_data == SIZE_MAX) r.first_data = i;
      r.last_data = i;
    }
  }
  return r;
}

}  // namespace

TEST(Eip712Stream, MultiSendUnlimitedApproveWarnsBeforeTheBytes) {
  const Bytes approve = approveCall(0, 0xff);
  Bytes packed = packedCall(kDai, approve);
  append(&packed, packedCall(kUsdc, swapCall(260)));
  const Bytes data = multiSendCall(packed);
  ASSERT_LE(data.size(), (size_t)EIP712_MAX_LEAF);
  const MsRun r = signMultiSend(data);
  ASSERT_EQ(r.kind, EIP712_REQ_DONE);
  ASSERT_EQ(r.warned.size(), 1u);
  // The inner `to` is the token, not SafeTx.to (USDC).
  EXPECT_EQ(r.bodies[r.warned[0]], allowText(approve, "DAI"));
  ASSERT_NE(r.first_data, SIZE_MAX);
  EXPECT_LT(r.warned[0], r.first_data);
}

TEST(Eip712Stream, MultiSendChunkedApproveWarnsBeforeTheBytes) {
  const Bytes approve = approveCall(0, 0xff);
  Bytes packed = packedCall(kDai, approve);
  append(&packed, packedCall(kUsdc, swapCall(2000)));
  const Bytes data = multiSendCall(packed);
  const MsRun r = signMultiSend(data);
  ASSERT_EQ(r.kind, EIP712_REQ_DONE);
  EXPECT_EQ(g_first_chunks, 1);
  EXPECT_EQ(g_later_chunks, 2);
  ASSERT_EQ(r.warned.size(), 1u);
  EXPECT_EQ(r.bodies[r.warned[0]], allowText(approve, "DAI"));
  EXPECT_LT(r.warned[0], r.first_data);
  EXPECT_EQ(r.bodies[r.first_data].compare(0, 8, "data (1/"), 0);
}

// An approve whose 68 bytes straddle the first chunk boundary is warned
// about once its last byte arrives: after the first chunk's parts, before
// the second's.
TEST(Eip712Stream, MultiSendApproveSplitAcrossChunksWarnsWhenComplete) {
  const Bytes approve = approveCall(0, 0xff);
  // 68 header bytes + 85 + filler + 85 puts the approve's data at 1000.
  const size_t filler = 1000 - 68 - 85 - 85;
  Bytes packed = packedCall(kUsdc, swapCall(filler));
  append(&packed, packedCall(kDai, approve));
  append(&packed, packedCall(kUsdc, swapCall(600)));
  const Bytes data = multiSendCall(packed);
  ASSERT_EQ(Bytes(data.begin() + 1000, data.begin() + 1068), approve);
  const MsRun r = signMultiSend(data);
  ASSERT_EQ(r.kind, EIP712_REQ_DONE);
  ASSERT_EQ(r.warned.size(), 1u);
  EXPECT_EQ(r.bodies[r.warned[0]], allowText(approve, "DAI"));
  // The first chunk's parts came first; the second chunk's follow.
  EXPECT_GT(r.warned[0], r.first_data);
  EXPECT_LT(r.warned[0], r.last_data);
  // Every part before the warning is from the first 1024 bytes: the hex
  // shown so far ends exactly at the boundary.
  std::string before;
  for (size_t i = r.first_data; i < r.warned[0]; i++) {
    const size_t colon = r.bodies[i].find("bytes: ");
    before += colon == std::string::npos ? r.bodies[i]
                                         : r.bodies[i].substr(colon + 7);
  }
  EXPECT_EQ(before, "0x" + hexOf(data.data(), EIP712_MAX_LEAF));
}

TEST(Eip712Stream, MultiSendTwoUnlimitedApprovesWarnTwice) {
  const Bytes first = approveCall(0, 0xff);
  Bytes second = approveCall(0, 0xff);
  second[16] = 0x77;  // another spender
  Bytes packed = packedCall(kDai, first);
  append(&packed, packedCall(kUsdc, second));
  append(&packed, packedCall(kUsdc, swapCall(100)));
  for (bool chunked : {false, true}) {
    SCOPED_TRACE(chunked);
    Bytes all = packed;
    if (chunked) append(&all, packedCall(kUsdc, swapCall(1500)));
    const MsRun r = signMultiSend(multiSendCall(all));
    ASSERT_EQ(r.kind, EIP712_REQ_DONE);
    ASSERT_EQ(r.warned.size(), 2u);
    EXPECT_EQ(r.bodies[r.warned[0]], allowText(first, "DAI"));
    EXPECT_EQ(r.bodies[r.warned[1]], allowText(second, "USDC"));
  }
}

TEST(Eip712Stream, MultiSendUnlimitedIncreaseAllowanceWarns) {
  Bytes increase = approveCall(0, 0xff);
  const uint8_t selector[4] = {0x39, 0x50, 0x93, 0x51};
  std::copy(selector, selector + 4, increase.begin());
  const MsRun r = signMultiSend(multiSendCall(packedCall(kDai, increase)));
  ASSERT_EQ(r.kind, EIP712_REQ_DONE);
  ASSERT_EQ(r.warned.size(), 1u);
  EXPECT_EQ(r.bodies[r.warned[0]], allowText(increase, "DAI"));
}

TEST(Eip712Stream, MultiSendFiniteApproveHasNoWarning) {
  Bytes packed = packedCall(kDai, approveCall(0, 0x01));
  append(&packed, packedCall(kUsdc, swapCall(1500)));
  Bytes almost = approveCall(0, 0xff);
  almost[67] = 0xfe;
  append(&packed, packedCall(kDai, almost));
  const MsRun r = signMultiSend(multiSendCall(packed));
  ASSERT_EQ(r.kind, EIP712_REQ_DONE);
  EXPECT_TRUE(r.warned.empty());
}

TEST(Eip712Stream, MultiSendDirtySpenderIsRefused) {
  for (bool chunked : {false, true}) {
    SCOPED_TRACE(chunked);
    Bytes packed = packedCall(kDai, approveCall(0x01, 0x01));
    if (chunked) {
      packed = packedCall(kUsdc, swapCall(1500));
      append(&packed, packedCall(kDai, approveCall(0x01, 0xff)));
    }
    const MsRun r = signMultiSend(multiSendCall(packed));
    EXPECT_EQ(r.kind, EIP712_REQ_FAIL);
    EXPECT_EQ(r.error, "Malformed ERC20 approval");
    EXPECT_TRUE(r.warned.empty());
    // Whole, it is refused before any screen of the bytes.
    if (!chunked) EXPECT_EQ(r.first_data, SIZE_MAX);
  }
}

TEST(Eip712Stream, MultiSendDecliningTheWarningSignsNothing) {
  for (bool chunked : {false, true}) {
    SCOPED_TRACE(chunked);
    Bytes packed = packedCall(kDai, approveCall(0, 0xff));
    if (chunked) append(&packed, packedCall(kUsdc, swapCall(1500)));
    // Four screens accepted (the domain, `to` in two pages, `value`); the
    // warning is the next, declined, and the walk ends with no byte of
    // `data` shown.
    const MsRun r = signMultiSend(multiSendCall(packed), 4);
    EXPECT_EQ(r.kind, EIP712_REQ_CANCELLED);
    ASSERT_EQ(r.warned.size(), 1u);
    EXPECT_EQ(r.warned[0], r.titles.size() - 1);
    EXPECT_EQ(r.bodies[r.warned[0] - 1].compare(0, 6, "value\n"), 0);
    EXPECT_EQ(r.first_data, SIZE_MAX);
    EXPECT_EQ(eip712_stream_waiting(), EIP712_IDLE);
  }
}

// Only the canonical packing is read. Anything else is still shown in full
// and signs, after "Batch not checked" where the scan stops; a batch that
// ends exactly at a call's end reads clean, whatever follows `length`.
TEST(Eip712Stream, MultiSendMalformedPackingIsNotChecked) {
  const Bytes approve = approveCall(0, 0xff);
  struct Case {
    const char* what;
    Bytes data;
    bool unchecked;
  };
  std::vector<Case> cases;
  Bytes packed = packedCall(kDai, approve);
  cases.push_back({"dataLength past length",
                   multiSendCall(packedCall(kDai, approve, 5000)), true});
  cases.push_back({"dataLength over 32 bits",
                   [&] {
                     Bytes b = multiSendCall(packed);
                     b[4 + 64 + 53] = 0x01;  // the dataLength word's top byte
                     return b;
                   }(),
                   true});
  cases.push_back(
      {"length cuts the amount", multiSendCall(packed, 85 + 67), true});
  // The approve lies past `length`: MultiSend never reaches it.
  Bytes past = packedCall(kUsdc, swapCall(10));
  const size_t first = past.size();
  append(&past, packed);
  cases.push_back({"approve past length", multiSendCall(past, first), false});
  cases.push_back({"header cut short", multiSendCall(packed, 40), true});
  cases.push_back({"length longer than the value",
                   multiSendCall(packedCall(kUsdc, swapCall(10)), 900), true});
  cases.push_back({"length over 32 bits",
                   [&] {
                     Bytes b = multiSendCall(packed);
                     b[4 + 32] = 0x01;
                     return b;
                   }(),
                   true});
  cases.push_back(
      {"operation 2", multiSendCall(packedCall(kDai, approve, -1, 2)), true});
  cases.push_back({"selector and offset only",
                   [] {
                     Bytes b = {0x8d, 0x80, 0xff, 0x0a};
                     append(&b, be32(0x20));
                     return b;
                   }(),
                   true});
  cases.push_back({"selector only", Bytes{0x8d, 0x80, 0xff, 0x0a}, true});
  cases.push_back({"empty", multiSendCall(Bytes{}), false});
  cases.push_back({"chunked, cut mid-call",
                   [&] {
                     Bytes p = packedCall(kUsdc, swapCall(1500));
                     return multiSendCall(p, 1200);
                   }(),
                   true});
  cases.push_back({"chunked, value ends first",
                   [&] {
                     Bytes b = multiSendCall(packedCall(kUsdc, swapCall(1500)));
                     b.resize(1300);
                     return b;
                   }(),
                   true});
  for (const Case& c : cases) {
    SCOPED_TRACE(c.what);
    const MsRun r = signMultiSend(c.data);
    ASSERT_EQ(r.kind, EIP712_REQ_DONE);
    EXPECT_TRUE(r.warned.empty());
    ASSERT_EQ(r.unchecked.size(), c.unchecked ? 1u : 0u);
    ASSERT_NE(r.first_data, SIZE_MAX);
    if (c.unchecked) {
      EXPECT_EQ(r.bodies[r.unchecked[0]],
                "KeepKey could not read this batch's calls; approvals inside "
                "it are not shown.");
      // Before the last of the bytes: before all of them unless the value
      // ran out first.
      EXPECT_LT(r.unchecked[0], r.last_data);
      if (strcmp(c.what, "chunked, value ends first") != 0)
        EXPECT_LT(r.unchecked[0], r.first_data);
    }
  }
}

// An offset word other than 0x20 moves where a decoder reads `transactions`
// from, past the scan: like any batch it cannot read, it is shown in full and
// signs after "Batch not checked", never refused.
TEST(Eip712Stream, MultiSendNonCanonicalOffsetIsNotChecked) {
  for (bool chunked : {false, true}) {
    SCOPED_TRACE(chunked);
    Bytes packed = packedCall(kDai, approveCall(0, 0xff));
    if (chunked) append(&packed, packedCall(kUsdc, swapCall(1500)));
    Bytes data = multiSendCall(packed);
    data[4 + 31] = 0x40;
    const MsRun r = signMultiSend(data);
    ASSERT_EQ(r.kind, EIP712_REQ_DONE);
    EXPECT_TRUE(r.warned.empty());
    ASSERT_EQ(r.unchecked.size(), 1u);
    ASSERT_NE(r.first_data, SIZE_MAX);
    EXPECT_LT(r.unchecked[0], r.first_data);
  }
}

// ── Delegatecalls and batches the scan cannot read ──────────────────
// A delegatecall runs code the device does not read with the Safe's
// authority, so it can hide any approval: an inner one is warned about
// before its data, and so is a SafeTx delegatecall unless its data is a
// batch read clean to its end. The payloads are the review's (ms_sim.py).
namespace {

const char* const kWeth = "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
const char* const kMultiSend = "a238cbeb142c10ef7ad8442c6d1f9e89e07e7761";

Bytes attackerApprove() {
  Bytes b = {0x09, 0x5e, 0xa7, 0xb3};
  b.insert(b.end(), 12, 0);
  b.insert(b.end(), 20, 0x11);
  b.insert(b.end(), 32, 0xff);
  return b;
}

// Attack A: a delegatecall to MultiSend whose data is another multiSend.
Bytes nestedMultiSend(size_t filler) {
  Bytes inner = packedCall(kWeth, attackerApprove());
  if (filler) append(&inner, packedCall(kUsdc, swapCall(filler)));
  return multiSendCall(
      packedCall(kMultiSend, multiSendCall(inner), -1, /*op=*/1));
}

// Attack B: MultiSend v1.0.0's ABI words: operation, to, value, the data's
// offset and length, then the data padded.
Bytes legacyMultiSend(const Bytes& data) {
  Bytes call = be32(0);
  Bytes to = fromHex(kWeth);
  call.insert(call.end(), 12, 0);
  append(&call, to);
  append(&call, be32(0));
  append(&call, be32(0x80));
  append(&call, be32((uint32_t)data.size()));
  append(&call, data);
  call.resize(32 * ((call.size() + 31) / 32), 0);
  return multiSendCall(call);
}

std::string delegateText(const char* who, const char* target) {
  char checksummed[41];
  ethereum_address_checksum(fromHex(target).data(), checksummed, false, 1);
  return std::string(who) + " gives 0x" + checksummed +
         " your Safe's full authority. Not checked.";
}

}  // namespace

TEST(Eip712Stream, MultiSendNestedDelegatecallWarns) {
  for (size_t filler : {0, 1500}) {
    for (int operation : {-1, 1}) {
      SCOPED_TRACE(filler);
      SCOPED_TRACE(operation);
      const Bytes data = nestedMultiSend(filler);
      EXPECT_EQ(data.size() > EIP712_MAX_LEAF, filler != 0);
      const MsRun r = signMultiSend(data, 400, operation);
      ASSERT_EQ(r.kind, EIP712_REQ_DONE);
      ASSERT_EQ(r.delegated.size(), 1u);
      EXPECT_EQ(r.bodies[r.delegated[0]], delegateText("Call #1", kMultiSend));
      EXPECT_LT(r.delegated[0], r.first_data);
      // The SafeTx's own delegatecall is warned about too: its batch holds
      // one. No `operation`, no SafeTx delegatecall.
      ASSERT_EQ(r.safe_delegated.size(), operation == 1 ? 1u : 0u);
      if (operation == 1)
        EXPECT_EQ(r.bodies[r.safe_delegated[0]], delegateText("SafeTx", kUsdc));
    }
  }
}

TEST(Eip712Stream, MultiSendLegacyLayoutIsNotChecked) {
  for (size_t filler : {0, 1500}) {
    SCOPED_TRACE(filler);
    Bytes inner = attackerApprove();
    if (filler) append(&inner, swapCall(filler));
    const Bytes data = legacyMultiSend(inner);
    const MsRun r = signMultiSend(data, 400, 1);
    ASSERT_EQ(r.kind, EIP712_REQ_DONE);
    ASSERT_EQ(r.unchecked.size(), 1u);
    EXPECT_LT(r.unchecked[0], r.first_data);
    ASSERT_EQ(r.safe_delegated.size(), 1u);
    EXPECT_GT(r.safe_delegated[0], r.last_data);
  }
}

// Safe's MultiSend and MultiSendCallOnly, every address variant of 1.1.1,
// 1.3.0, 1.4.1 and 1.5.0 in safe-global/safe-deployments 7b1fb6d6
// (src/assets/v1.x.x/multi_send*.json).
const char* const kSafeMultiSends[] = {
    "8D29bE29923b68abfDD21e541b9374737B49cdAD",  // 1.1.1
    "A238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761",  // 1.3.0 canonical
    "998739BFdAAdde7C933B942a68053933098f9EDa",  // 1.3.0 eip155
    "0dFcccB95225ffB03c6FBB2559B530C2B7C8A912",  // 1.3.0 zksync
    "40A2aCCbd92BCA938b02010E17A5b8929b49130D",  // 1.3.0 CallOnly canonical
    "A1dabEF33b3B82c7814B6D82A79e50F4AC44102B",  // 1.3.0 CallOnly eip155
    "f220D3b4DFb23C4ade8C88E526C1353AbAcbC38F",  // 1.3.0 CallOnly zksync
    "38869bf66a61cF6bDB996A6aE40D5853Fd43B526",  // 1.4.1 canonical
    "309D0B190FeCCa8e1D5D8309a16F7e3CB133E885",  // 1.4.1 zksync
    "9641d764fc13c8B624c04430C7356C1C7C8102e2",  // 1.4.1 CallOnly canonical
    "0408EF011960d02349d50286D20531229BCef773",  // 1.4.1 CallOnly zksync
    "218543288004CD07832472D464648173c77D7eB7",  // 1.5.0
    "A83c336B20401Af773B6219BA5027174338D1836",  // 1.5.0 CallOnly
};

const char* const kAttacker = "1111111111111111111111111111111111111111";

TEST(Eip712Stream, SafeTxDelegatecallWarnsUnlessACleanBatch) {
  Bytes clean = packedCall(kDai, approveCall(0, 0x01));
  append(&clean, packedCall(kUsdc, swapCall(100)));
  struct Case {
    const char* what;
    Bytes data;
    int operation;
    bool warns;
  };
  // SafeTx.to is USDC, no MultiSend: every delegatecall is warned about.
  const std::vector<Case> cases = {
      {"plain call", swapCall(100), 1, true},
      {"plain call, chunked", swapCall(1500), 1, true},
      {"plain call, operation 0", swapCall(100), 0, false},
      {"empty data", Bytes{}, 1, true},
      {"clean batch", multiSendCall(clean), 1, true},
      {"clean batch, operation 0", multiSendCall(clean), 0, false},
      {"empty batch", multiSendCall(Bytes{}), 1, true},
  };
  for (const Case& c : cases) {
    for (bool operation_first : {false, true}) {
      for (ToPlace place : {TO_FIRST, TO_LAST}) {
        SCOPED_TRACE(c.what);
        SCOPED_TRACE(operation_first);
        SCOPED_TRACE(place);
        const MsRun r = signMultiSend(c.data, 400, c.operation, operation_first,
                                      nullptr, place);
        ASSERT_EQ(r.kind, EIP712_REQ_DONE);
        EXPECT_TRUE(r.unchecked.empty());
        EXPECT_TRUE(r.delegated.empty());
        ASSERT_EQ(r.safe_delegated.size(), c.warns ? 1u : 0u);
        if (!c.warns) continue;
        EXPECT_EQ(r.bodies[r.safe_delegated[0]], delegateText("SafeTx", kUsdc));
        // Decided when the last of `to`, `operation` and `data` is read:
        // after the bytes, or before the last of them.
        if (c.data.empty()) continue;
        if (operation_first && place == TO_FIRST)
          EXPECT_LT(r.safe_delegated[0], r.last_data);
        else
          EXPECT_GT(r.safe_delegated[0], r.last_data);
      }
    }
  }

  // The same clean batch to a Safe MultiSend keeps its screens, in any
  // member order.
  for (const char* multisend : kSafeMultiSends) {
    for (bool operation_first : {false, true}) {
      for (ToPlace place : {TO_FIRST, TO_LAST}) {
        SCOPED_TRACE(multisend);
        SCOPED_TRACE(operation_first);
        SCOPED_TRACE(place);
        const MsRun r = signMultiSend(multiSendCall(clean), 400, 1,
                                      operation_first, multisend, place);
        ASSERT_EQ(r.kind, EIP712_REQ_DONE);
        EXPECT_TRUE(r.unchecked.empty());
        EXPECT_TRUE(r.delegated.empty());
        EXPECT_TRUE(r.safe_delegated.empty());
      }
    }
  }
}

// A delegatecall to any contract runs it as the Safe: a clean (or empty)
// multiSend in `data` says nothing about what `to` does with it.
TEST(Eip712Stream, SafeTxDelegatecallToAnAttackerWithACleanBatchWarns) {
  const Bytes harmless = multiSendCall(packedCall(kUsdc, swapCall(100)));
  for (const Bytes& data : {multiSendCall(Bytes{}), harmless}) {
    for (bool operation_first : {false, true}) {
      for (ToPlace place : {TO_FIRST, TO_LAST}) {
        SCOPED_TRACE(data.size());
        SCOPED_TRACE(operation_first);
        SCOPED_TRACE(place);
        const MsRun r =
            signMultiSend(data, 400, 1, operation_first, kAttacker, place);
        ASSERT_EQ(r.kind, EIP712_REQ_DONE);
        EXPECT_TRUE(r.unchecked.empty());
        EXPECT_TRUE(r.delegated.empty());
        ASSERT_EQ(r.safe_delegated.size(), 1u);
        EXPECT_EQ(r.bodies[r.safe_delegated[0]],
                  delegateText("SafeTx", kAttacker));
      }
    }
  }
  // Declining it signs nothing.
  const MsRun all = signMultiSend(harmless, 400, 1, false, kAttacker);
  ASSERT_EQ(all.safe_delegated.size(), 1u);
  const MsRun r =
      signMultiSend(harmless, (int)all.safe_delegated[0], 1, false, kAttacker);
  EXPECT_EQ(r.kind, EIP712_REQ_CANCELLED);
  EXPECT_EQ(r.titles.size(), all.safe_delegated[0] + 1);
}

// No `to` in the SafeTx: nothing names the code, so the delegatecall is
// warned about when the SafeTx ends.
TEST(Eip712Stream, SafeTxDelegatecallWithoutToWarns) {
  Bytes clean = packedCall(kUsdc, swapCall(100));
  for (bool operation_first : {false, true}) {
    SCOPED_TRACE(operation_first);
    const MsRun r = signMultiSend(multiSendCall(clean), 400, 1, operation_first,
                                  nullptr, TO_ABSENT);
    ASSERT_EQ(r.kind, EIP712_REQ_DONE);
    ASSERT_EQ(r.safe_delegated.size(), 1u);
    EXPECT_EQ(r.bodies[r.safe_delegated[0]],
              "SafeTx gives the contract in 'to' your Safe's full authority. "
              "Not checked.");
    EXPECT_GT(r.safe_delegated[0], r.last_data);
    const MsRun none = signMultiSend(multiSendCall(clean), 400, 0,
                                     operation_first, nullptr, TO_ABSENT);
    EXPECT_TRUE(none.safe_delegated.empty());
  }
}

TEST(Eip712Stream, DecliningADelegatecallWarningSignsNothing) {
  for (const char* title :
       {"Delegatecall", "Delegatecall in batch", "Batch not checked"}) {
    SCOPED_TRACE(title);
    const Bytes data = strcmp(title, "Delegatecall") == 0 ? swapCall(100)
                       : strcmp(title, "Batch not checked") == 0
                           ? legacyMultiSend(attackerApprove())
                           : nestedMultiSend(0);
    const MsRun all = signMultiSend(data, 400, 1);
    ASSERT_EQ(all.kind, EIP712_REQ_DONE);
    const auto at = std::find(all.titles.begin(), all.titles.end(), title);
    ASSERT_NE(at, all.titles.end());
    const int before = (int)(at - all.titles.begin());
    const MsRun r = signMultiSend(data, before, 1);
    EXPECT_EQ(r.kind, EIP712_REQ_CANCELLED);
    EXPECT_EQ(r.titles.size(), (size_t)before + 1);
    EXPECT_EQ(r.titles.back(), title);
    EXPECT_EQ(eip712_stream_waiting(), EIP712_IDLE);
  }
}
