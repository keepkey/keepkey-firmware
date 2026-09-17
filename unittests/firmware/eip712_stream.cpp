extern "C" {
#include "keepkey/firmware/eip712_stream.h"
#include "messages-ethereum.pb.h"
#include "sha3.h"
}

#include "gtest/gtest.h"

#include <cstring>
#include <map>
#include <string>

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
  EXPECT_LE(sizeof(Eip712DomainFacts), 64u);
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

TEST(Eip712Stream, RejectsUnrepresentableOrMalformedDomainBindings) {
  Eip712DomainFacts facts{};
  Field chain = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  uint8_t too_large[32] = {0};
  too_large[0] = 1;
  EXPECT_FALSE(eip712_domain_facts_observe(&facts, "chainId", &chain, too_large,
                                           sizeof(too_large)));
  uint8_t zero[32] = {0};
  EXPECT_FALSE(eip712_domain_facts_observe(&facts, "chainId", &chain, zero,
                                           sizeof(zero)));
  Field bytes = mkSized(EthereumTypedDataStructAck_EthereumDataType_BYTES, 20);
  uint8_t contract[20] = {0};
  EXPECT_FALSE(eip712_domain_facts_observe(&facts, "verifyingContract", &bytes,
                                           contract, sizeof(contract)));
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
  uint8_t domain_hash[32];
  uint8_t type_hash[32];
  EXPECT_TRUE(eip712_stream_container_hash(5, domain_hash));
  EXPECT_TRUE(eip712_stream_container_hash(6, type_hash));
  EXPECT_NE(memcmp(domain_hash, type_hash, sizeof(domain_hash)), 0);
  EXPECT_FALSE(eip712_stream_container_hash(4, type_hash));
  EXPECT_TRUE(eip712_stream_definition_accepted());
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_STRUCT);
  EXPECT_STREQ(eip712_stream_next()->struct_name, "Mail");
  EXPECT_FALSE(eip712_stream_definition_accepted());
  eip712_stream_abort();
}

TEST(Eip712Stream, CertifiedDocumentCanBeRehashedForBoundedDisplayReplay) {
  EthereumSignTypedData begin{};
  strcpy(begin.primary_type, "Mail");
  ASSERT_TRUE(eip712_stream_begin(&begin, true));

  EthereumTypedDataStructAck empty{};
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // discover domain
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // hash domain type
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // finish domain
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // discover message
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // hash message type
  ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_DEFINITION);
  ASSERT_TRUE(eip712_stream_definition_accepted());
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // finish message
  ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
  uint8_t first_domain[32];
  uint8_t first_message[32];
  memcpy(first_domain, eip712_stream_next()->domain_separator, 32);
  memcpy(first_message, eip712_stream_next()->message_hash, 32);

  ASSERT_TRUE(eip712_stream_replay());
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_STRUCT);
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // discover domain
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // hash domain type
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // finish domain
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // discover message
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // hash message type
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // finish message
  ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
  EXPECT_EQ(memcmp(first_domain, eip712_stream_next()->domain_separator, 32),
            0);
  EXPECT_EQ(memcmp(first_message, eip712_stream_next()->message_hash, 32), 0);
  eip712_stream_abort();
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

TEST(Eip712Stream, ValidateStringRejectsControlBytes) {
  Field f = mk(EthereumTypedDataStructAck_EthereumDataType_STRING);
  EXPECT_TRUE(eip712_validate_leaf(&f, (const uint8_t*)"Send 1 USDC", 11));
  // An embedded NUL is how bytes past the terminator get signed but never
  // drawn -- the exact defect class 7.14.2 closed for message signing.
  EXPECT_FALSE(eip712_validate_leaf(&f, (const uint8_t*)"a\0b", 3));
  EXPECT_FALSE(eip712_validate_leaf(&f, (const uint8_t*)"a\nb", 3));
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
  // leaves a wrong implementation that passes the other. A single three-
  // dependency case would separate all three hypotheses at once, but the
  // closure holds EIP712_MAX_STRUCTS names INCLUDING the primary type, so
  // three dependencies do not fit -- see RefusesADocumentWiderThanTheClosure.
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
  // real ceiling is that many distinct struct types in one document. Seaport's
  // OrderComponents sits exactly at it (itself plus OfferItem plus
  // ConsiderationItem); one more dependency must be REFUSED rather than
  // silently truncated, because a truncated closure still produces a
  // well-formed 32-byte typeHash -- one that no verifier reproduces.
  Fixture f;
  const char* names[] = {"Alpha", "Bravo", "Charlie"};
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
  addMember(m, "c", structField("Charlie"));

  // M + three dependencies exceeds EIP712_MAX_STRUCTS.
  EXPECT_EQ(typeHashHex(f, "M"), "<refused>");
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
