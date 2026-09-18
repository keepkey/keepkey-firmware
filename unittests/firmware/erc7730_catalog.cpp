extern "C" {
#include "keepkey/firmware/erc7730_catalog.h"
#include "sha2.h"
}

#include "gtest/gtest.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace {

void append32(std::vector<uint8_t>& out, uint32_t value) {
  out.push_back((uint8_t)(value >> 24));
  out.push_back((uint8_t)(value >> 16));
  out.push_back((uint8_t)(value >> 8));
  out.push_back((uint8_t)value);
}

void append16(std::vector<uint8_t>& out, uint16_t value) {
  out.push_back((uint8_t)(value >> 8));
  out.push_back((uint8_t)value);
}

void section(std::vector<uint8_t>& out, uint8_t type,
             const std::vector<uint8_t>& payload = {}) {
  out.push_back(type);
  append32(out, (uint32_t)payload.size());
  out.insert(out.end(), payload.begin(), payload.end());
}

std::vector<uint8_t> emptyTable() { return {0, 0}; }

std::vector<uint8_t> resources() {
  std::vector<uint8_t> r;
  const uint16_t counts[8] = {1, 2, 0, 0, 0, 0, 2, 1};
  for (uint16_t count : counts) append16(r, count);
  r.insert(r.end(), {2, 0, 0, 0});  // ABI depth and runtime maxima
  append16(r, 4);                   // maximum string length
  return r;
}

std::vector<uint8_t> minimalProgram() {
  std::vector<uint8_t> p(ERC7730_PROGRAM_HEADER_SIZE, 0);
  memcpy(p.data(), "C773", 4);
  p[4] = 1;
  p[5] = 2;
  p[6] = 0;
  p[7] = ERC7730_DEFINITION_CALLDATA;
  p[17] = 1;  // chain id 1
  p[18] = 0x11;
  p[38] = 0xaa;
  p[39] = 0xbb;
  p[40] = 0xcc;
  p[41] = 0xdd;
  p[70] = 1;   // source JSON hash
  p[102] = 2;  // compiler identity hash
  p[134] = 3;  // token/network set hash
  p[169] = 7;  // provider id
  p[173] = 8;  // issuance epoch
  p[177] = 3;  // revocation epoch
  p[178] = 7;
  section(p, 1, {0, 1, 0, 4, 'T', 'e', 's', 't'});  // string table
  std::vector<uint8_t> abi;
  append16(abi, 2);
  abi.insert(abi.end(), {8, 0, 0, 0, 1, 0, 1, 0, 0});  // tuple -> node 1
  abi.insert(abi.end(), {1, 1, 0, 0, 0, 0, 0, 0, 0});  // uint256
  section(p, 2, abi);
  section(p, 3, emptyTable());  // paths
  section(p, 6, emptyTable());  // formatters
  section(p, 7,
          {0, 2, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 10, 0, 0xff, 0xff, 0xff,
           0xff, 0xff, 0xff});  // intent, end
  std::vector<uint8_t> binding = {0, 1, 1, 0, 28};
  binding.insert(binding.end(), {0, 0, 0, 0, 0, 0, 0, 1});
  binding.push_back(0x11);
  binding.resize(binding.size() + 19, 0);
  section(p, 8, binding);      // exact chain/address deployment
  section(p, 9, resources());  // resource declaration
  return p;
}

std::vector<uint8_t> programWithStrings(
    const std::vector<std::vector<uint8_t>>& strings) {
  auto p = minimalProgram();
  std::vector<uint8_t> payload;
  append16(payload, (uint16_t)strings.size());
  size_t longest = 0;
  for (const auto& value : strings) {
    append16(payload, (uint16_t)value.size());
    payload.insert(payload.end(), value.begin(), value.end());
    longest = std::max(longest, value.size());
  }
  std::vector<uint8_t> replacement;
  section(replacement, 1, payload);
  const size_t old_length =
      5u + (((uint32_t)p[ERC7730_PROGRAM_HEADER_SIZE + 1] << 24) |
            ((uint32_t)p[ERC7730_PROGRAM_HEADER_SIZE + 2] << 16) |
            ((uint32_t)p[ERC7730_PROGRAM_HEADER_SIZE + 3] << 8) |
            p[ERC7730_PROGRAM_HEADER_SIZE + 4]);
  p.erase(p.begin() + ERC7730_PROGRAM_HEADER_SIZE,
          p.begin() + ERC7730_PROGRAM_HEADER_SIZE + old_length);
  p.insert(p.begin() + ERC7730_PROGRAM_HEADER_SIZE, replacement.begin(),
           replacement.end());
  const size_t resource = p.size() - 22;
  p[resource] = (uint8_t)(strings.size() >> 8);
  p[resource + 1] = (uint8_t)strings.size();
  p[p.size() - 2] = (uint8_t)(longest >> 8);
  p[p.size() - 1] = (uint8_t)longest;
  return p;
}

size_t sectionOffset(const std::vector<uint8_t>& p, uint8_t wanted) {
  size_t offset = ERC7730_PROGRAM_HEADER_SIZE;
  while (offset + 5 <= p.size()) {
    if (p[offset] == wanted) return offset;
    const uint32_t length = ((uint32_t)p[offset + 1] << 24) |
                            ((uint32_t)p[offset + 2] << 16) |
                            ((uint32_t)p[offset + 3] << 8) | p[offset + 4];
    offset += 5 + length;
  }
  return p.size();
}

std::vector<uint8_t> programWithTable(uint8_t type,
                                      const std::vector<uint8_t>& entries,
                                      uint16_t count) {
  auto p = minimalProgram();
  std::vector<uint8_t> payload;
  append16(payload, count);
  payload.insert(payload.end(), entries.begin(), entries.end());
  std::vector<uint8_t> encoded;
  section(encoded, type, payload);
  size_t insert_at = ERC7730_PROGRAM_HEADER_SIZE;
  while (insert_at < p.size() && p[insert_at] < type) {
    const uint32_t length = ((uint32_t)p[insert_at + 1] << 24) |
                            ((uint32_t)p[insert_at + 2] << 16) |
                            ((uint32_t)p[insert_at + 3] << 8) |
                            p[insert_at + 4];
    insert_at += 5 + length;
  }
  p.insert(p.begin() + insert_at, encoded.begin(), encoded.end());
  p[178]++;
  const size_t resource = sectionOffset(p, 9) + 5;
  p[resource + (type - 1) * 2] = (uint8_t)(count >> 8);
  p[resource + (type - 1) * 2 + 1] = (uint8_t)count;
  return p;
}

std::vector<uint8_t> replaceTable(std::vector<uint8_t> p, uint8_t type,
                                  const std::vector<uint8_t>& entries,
                                  uint16_t count) {
  std::vector<uint8_t> payload;
  append16(payload, count);
  payload.insert(payload.end(), entries.begin(), entries.end());
  std::vector<uint8_t> encoded;
  section(encoded, type, payload);
  const size_t old = sectionOffset(p, type);
  const uint32_t old_payload = ((uint32_t)p[old + 1] << 24) |
                               ((uint32_t)p[old + 2] << 16) |
                               ((uint32_t)p[old + 3] << 8) | p[old + 4];
  p.erase(p.begin() + old, p.begin() + old + 5 + old_payload);
  p.insert(p.begin() + old, encoded.begin(), encoded.end());
  const size_t resource = sectionOffset(p, 9) + 5;
  p[resource + (type - 1) * 2] = (uint8_t)(count >> 8);
  p[resource + (type - 1) * 2 + 1] = (uint8_t)count;
  return p;
}

std::vector<uint8_t> programWithPaths(const std::vector<uint8_t>& entries,
                                      uint16_t count) {
  auto p = minimalProgram();
  std::vector<uint8_t> payload;
  append16(payload, count);
  payload.insert(payload.end(), entries.begin(), entries.end());
  std::vector<uint8_t> replacement;
  section(replacement, 3, payload);
  const size_t old = sectionOffset(p, 3);
  p.erase(p.begin() + old, p.begin() + old + 7);
  p.insert(p.begin() + old, replacement.begin(), replacement.end());
  const size_t resource = sectionOffset(p, 9) + 5;
  p[resource + 4] = (uint8_t)(count >> 8);
  p[resource + 5] = (uint8_t)count;
  return p;
}

std::vector<uint8_t> envelope(const std::vector<uint8_t>& program) {
  std::vector<uint8_t> e = {'K', '7', '7', '3', 1, 1};
  append32(e, (uint32_t)program.size());
  e.insert(e.end(), program.begin(), program.end());
  e.push_back(0);  // empty proof: leaf is the catalog root
  e.push_back(0);
  e.push_back(CLEARSIGN_CERT_LEN);
  e.resize(e.size() + CLEARSIGN_CERT_LEN + 64, 0);
  e.push_back(0);
  return e;
}

std::vector<uint8_t> digest(const std::vector<uint8_t>& data) {
  std::vector<uint8_t> out(32);
  sha256_Raw(data.data(), data.size(), out.data());
  return out;
}

Erc7730CatalogResult feedAll(const std::vector<uint8_t>& e, size_t chunk_size) {
  auto id = digest(e);
  Erc7730CatalogVerifier verifier;
  Erc7730CatalogIdentity identity = {};
  erc7730_catalog_begin(&verifier, id.data(), (uint32_t)e.size());
  Erc7730CatalogResult result = ERC7730_CATALOG_MORE;
  for (size_t offset = 0; offset < e.size(); offset += chunk_size) {
    const size_t length = std::min(chunk_size, e.size() - offset);
    result = erc7730_catalog_feed(&verifier, (uint32_t)offset,
                                  e.data() + offset, length, &identity);
    if (result != ERC7730_CATALOG_MORE && offset + length != e.size()) break;
  }
  erc7730_catalog_abort(&verifier);
  return result;
}

}  // namespace

TEST(Erc7730Catalog, VerifierStateIsSmallerThanOneTransportChunk) {
  EXPECT_LE(sizeof(Erc7730CatalogVerifier),
            (size_t)ERC7730_TRANSPORT_CHUNK_MAX);
}

TEST(Erc7730Catalog, CanonicalEnvelopeReachesAuthenticationInAnyChunking) {
  auto e = envelope(minimalProgram());
  EXPECT_EQ(feedAll(e, e.size()), ERC7730_CATALOG_UNTRUSTED);
  EXPECT_EQ(feedAll(e, 1), ERC7730_CATALOG_UNTRUSTED);
  EXPECT_EQ(feedAll(e, 37), ERC7730_CATALOG_UNTRUSTED);
}

TEST(Erc7730Catalog, RejectsOutOfOrderAndDuplicateChunks) {
  auto e = envelope(minimalProgram());
  auto id = digest(e);
  Erc7730CatalogVerifier verifier;
  Erc7730CatalogIdentity identity = {};
  erc7730_catalog_begin(&verifier, id.data(), (uint32_t)e.size());
  EXPECT_EQ(erc7730_catalog_feed(&verifier, 1, e.data(), 10, &identity),
            ERC7730_CATALOG_BAD_SEQUENCE);

  erc7730_catalog_begin(&verifier, id.data(), (uint32_t)e.size());
  ASSERT_EQ(erc7730_catalog_feed(&verifier, 0, e.data(), 10, &identity),
            ERC7730_CATALOG_MORE);
  EXPECT_EQ(erc7730_catalog_feed(&verifier, 0, e.data(), 10, &identity),
            ERC7730_CATALOG_BAD_SEQUENCE);
}

TEST(Erc7730Catalog, RejectsDefinitionIdMismatch) {
  auto e = envelope(minimalProgram());
  auto id = digest(e);
  id[0] ^= 1;
  Erc7730CatalogVerifier verifier;
  Erc7730CatalogIdentity identity = {};
  erc7730_catalog_begin(&verifier, id.data(), (uint32_t)e.size());
  EXPECT_EQ(erc7730_catalog_feed(&verifier, 0, e.data(), e.size(), &identity),
            ERC7730_CATALOG_UNTRUSTED);
}

TEST(Erc7730Catalog, RejectsNonCanonicalProgramHeaderAndSections) {
  auto p = minimalProgram();
  p[8] = 1;  // unknown required flag
  EXPECT_EQ(feedAll(envelope(p), 31), ERC7730_CATALOG_BAD_PROGRAM);

  p = minimalProgram();
  p[178] = 8;
  p.push_back(9);  // duplicate/out-of-order section
  append32(p, 0);
  EXPECT_EQ(feedAll(envelope(p), 31), ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, RejectsMalformedOrAliasedAbiGraphsWhileStreaming) {
  auto p = minimalProgram();
  const size_t kFirstNode = sectionOffset(p, 2) + 5 + 2;
  const size_t kSecondNode = kFirstNode + 9;
  p[kSecondNode + 2] = 1;  // uint257 is not a legal Solidity integer width
  EXPECT_EQ(feedAll(envelope(p), 1), ERC7730_CATALOG_BAD_PROGRAM);

  p = minimalProgram();
  p[kFirstNode + 4] = 2;  // tuple child begins beyond the two-node table
  EXPECT_EQ(feedAll(envelope(p), 19), ERC7730_CATALOG_BAD_PROGRAM);

  p = minimalProgram();
  p[kSecondNode] = 8;      // tuple
  p[kSecondNode + 4] = 1;  // backwards/self edge
  p[kSecondNode + 6] = 1;
  EXPECT_EQ(feedAll(envelope(p), 43), ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, AcceptsCanonicalEmptyRootTupleForArgumentlessCall) {
  auto p = replaceTable(minimalProgram(), 2,
                        {8, 0, 0, 0, 0, 0, 0, 0, 0}, 1);
  p[p.size() - 6] = 1;  // exact ABI depth for the empty root tuple
  EXPECT_EQ(feedAll(envelope(p), 1), ERC7730_CATALOG_UNTRUSTED);
}

TEST(Erc7730Catalog, RecomputesSignedResourceDeclaration) {
  auto p = minimalProgram();
  p[p.size() - 22] = 1;  // claims 256 strings instead of zero
  EXPECT_EQ(feedAll(envelope(p), 29), ERC7730_CATALOG_BAD_PROGRAM);

  p = minimalProgram();
  p[p.size() - 6] = 3;  // claims ABI depth three; graph depth is two
  EXPECT_EQ(feedAll(envelope(p), 29), ERC7730_CATALOG_BAD_PROGRAM);

  p = minimalProgram();
  p[p.size() - 3] = 5;  // embedded recursion above the firmware limit
  EXPECT_EQ(feedAll(envelope(p), 29), ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, ValidatesCanonicalUtf8StringTableIncrementally) {
  auto p = programWithStrings({{'A'}, {'B'}, {0xe2, 0x82, 0xac}});
  EXPECT_EQ(feedAll(envelope(p), 1), ERC7730_CATALOG_UNTRUSTED);

  p = programWithStrings({{'A'}, {'A'}});
  EXPECT_EQ(feedAll(envelope(p), 17), ERC7730_CATALOG_BAD_PROGRAM);

  p = programWithStrings({{'B'}, {'A'}});
  EXPECT_EQ(feedAll(envelope(p), 17), ERC7730_CATALOG_BAD_PROGRAM);

  p = programWithStrings({{0xc0, 0x80}});  // overlong NUL
  EXPECT_EQ(feedAll(envelope(p), 17), ERC7730_CATALOG_BAD_PROGRAM);

  p = programWithStrings({{'A', 0x0a, 'B'}});  // display control character
  EXPECT_EQ(feedAll(envelope(p), 17), ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, ValidatesTypedPathsSlicesAndFullArraySteps) {
  std::vector<uint8_t> entries = {
      1, 2, 0xff, 0xff,                          // structured, two steps
      1, 0, 0,    0,    0,                       // index 0
      3, 1, 0xff, 0xff, 0xff, 0xec,              // slice [-20:]
      2, 0, 0,    2,                             // @.to
      1, 2, 0xff, 0xff, 1,    0,    0, 0, 1, 2,  // field 1 then all elements
  };
  auto p = programWithPaths(entries, 3);
  EXPECT_EQ(feedAll(envelope(p), 1), ERC7730_CATALOG_UNTRUSTED);

  entries = {1, 2, 0xff, 0xff, 3, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0};
  p = programWithPaths(entries, 1);  // slice is not final
  EXPECT_EQ(feedAll(envelope(p), 23), ERC7730_CATALOG_BAD_PROGRAM);

  entries = {1, 2, 0xff, 0xff, 2, 2};
  p = programWithPaths(entries, 1);  // nested full-array selectors
  EXPECT_EQ(feedAll(envelope(p), 1), ERC7730_CATALOG_UNTRUSTED);

  entries = {2, 1, 0, 2, 1, 0, 0, 0, 0};
  p = programWithPaths(entries, 1);  // container paths have no steps
  EXPECT_EQ(feedAll(envelope(p), 23), ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, ValidatesCanonicalLiteralsAndConditions) {
  std::vector<uint8_t> literals = {
      1, 0, 1, 1,                    // uint 1
      3, 0, 1, 0xaa,                 // bytes aa
      9, 0, 6, 0,    2, 0, 0, 0, 1,  // set {literal 0, literal 1}
  };
  auto p = programWithTable(4, literals, 3);
  EXPECT_EQ(feedAll(envelope(p), 1), ERC7730_CATALOG_UNTRUSTED);

  literals = {1, 0, 2, 0, 1};  // non-minimal unsigned integer
  p = programWithTable(4, literals, 1);
  EXPECT_EQ(feedAll(envelope(p), 13), ERC7730_CATALOG_BAD_PROGRAM);

  literals = {9, 0, 4, 0, 1, 0, 1, 1, 0, 1, 7};
  p = programWithTable(4, literals, 2);  // set 0 refers forward to literal 1
  EXPECT_EQ(feedAll(envelope(p), 13), ERC7730_CATALOG_BAD_PROGRAM);

  std::vector<uint8_t> conditions = {1, 0xff, 0xff, 0xff, 0xff, 0, 0, 0};
  p = programWithTable(5, conditions, 1);
  EXPECT_EQ(feedAll(envelope(p), 1), ERC7730_CATALOG_UNTRUSTED);

  conditions[7] = 1;
  p = programWithTable(5, conditions, 1);
  EXPECT_EQ(feedAll(envelope(p), 13), ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, ValidatesFormatterOperandsAndDisplayProgram) {
  const std::vector<uint8_t> path = {1, 1, 0xff, 0xff, 1, 0, 0, 0, 0};
  auto p = programWithPaths(path, 1);
  // raw(value=path 0)
  const std::vector<uint8_t> formatter = {1, 0, 1, 1, 1, 0, 0};
  p = replaceTable(p, 6, formatter, 1);
  const std::vector<uint8_t> display = {
      1,  0, 0,    0,    0xff, 0xff, 0xff, 0xff,  // intent
      4,  0, 0,    0,    0,    0,    0xff, 0xff,  // field
      10, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // end
  };
  p = replaceTable(p, 7, display, 3);
  EXPECT_EQ(feedAll(envelope(p), 1), ERC7730_CATALOG_UNTRUSTED);

  // tokenAmount without a token operand is canonical and displays the
  // device-decoded integer as an unknown-token fallback.
  const std::vector<uint8_t> unknown_token = {3, 0, 1, 1, 1, 0, 0};
  p = programWithPaths(path, 1);
  p = replaceTable(p, 6, unknown_token, 1);
  p = replaceTable(p, 7, display, 3);
  EXPECT_EQ(feedAll(envelope(p), 1), ERC7730_CATALOG_UNTRUSTED);

  auto bad_formatter = formatter;
  bad_formatter[4] = 3;
  bad_formatter[6] = 1;  // value operand claims a missing string index
  p = programWithPaths(path, 1);
  p = replaceTable(p, 6, bad_formatter, 1);
  EXPECT_EQ(feedAll(envelope(p), 31), ERC7730_CATALOG_BAD_PROGRAM);

  p = programWithPaths(path, 1);
  p = replaceTable(p, 6, formatter, 1);
  auto bad_display = display;
  bad_display[18] = 1;  // end instruction has a non-absent operand
  p = replaceTable(p, 7, bad_display, 3);
  EXPECT_EQ(feedAll(envelope(p), 31), ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, ValidatesNestedGroupControlFlowAndRejectsBadReturns) {
  auto p = minimalProgram();
  const std::vector<uint8_t> display = {
      1,  0, 0,    0,    0xff, 0xff, 0xff, 0xff,  // intent
      5,  0, 0xff, 0xff, 0xff, 0xff, 0,    4,     // outer begin -> pc 4
      5,  0, 0xff, 0xff, 0xff, 0xff, 0,    3,     // inner begin -> pc 3
      6,  0, 0,    2,    0xff, 0xff, 0xff, 0xff,  // inner end -> pc 2
      6,  0, 0,    1,    0xff, 0xff, 0xff, 0xff,  // outer end -> pc 1
      10, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // end
  };
  p = replaceTable(p, 7, display, 6);
  p[sectionOffset(p, 9) + 5 + 18] = 2;
  EXPECT_EQ(feedAll(envelope(p), 17), ERC7730_CATALOG_UNTRUSTED);

  auto malformed = display;
  malformed[3 * 8 + 3] = 1;  // inner end returns to the outer begin
  p = replaceTable(minimalProgram(), 7, malformed, 6);
  p[sectionOffset(p, 9) + 5 + 18] = 2;
  EXPECT_EQ(feedAll(envelope(p), 17), ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, BindsSignedDeploymentsExactly) {
  auto p = minimalProgram();
  const size_t binding = sectionOffset(p, 8) + 5;
  // count(2), record header(3), chain(8), then address.
  p[binding + 2 + 3 + 8] = 0x22;
  EXPECT_EQ(feedAll(envelope(p), 37), ERC7730_CATALOG_BAD_PROGRAM);

  p = minimalProgram();
  const size_t first = sectionOffset(p, 8) + 5 + 2;
  std::vector<uint8_t> record(p.begin() + first, p.begin() + first + 31);
  std::vector<uint8_t> records = record;
  records.insert(records.end(), record.begin(), record.end());
  p = replaceTable(p, 8, records, 2);
  EXPECT_EQ(feedAll(envelope(p), 37), ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, RejectsOversizedAndTruncatedEnvelopes) {
  uint8_t id[32] = {0};
  Erc7730CatalogVerifier verifier;
  Erc7730CatalogIdentity identity = {};
  erc7730_catalog_begin(&verifier, id, UINT32_MAX);
  const uint8_t byte = 0;
  EXPECT_EQ(erc7730_catalog_feed(&verifier, 0, &byte, 1, &identity),
            ERC7730_CATALOG_BAD_SEQUENCE);

  auto e = envelope(minimalProgram());
  e.pop_back();
  EXPECT_EQ(feedAll(e, 64), ERC7730_CATALOG_BAD_ENVELOPE);
}

TEST(Erc7730Catalog, PreloadSlotFailsClosedAndCanRestartAtOffsetZero) {
  auto e = envelope(minimalProgram());
  auto id = digest(e);
  uint32_t next = 99;
  bool complete = true;
  erc7730_catalog_clear_preload();

  ASSERT_EQ(erc7730_catalog_preload_chunk(id.data(), 0, (uint32_t)e.size(),
                                          e.data(), 23, &next, &complete),
            ERC7730_CATALOG_MORE);
  EXPECT_EQ(next, 23u);
  EXPECT_FALSE(complete);

  EXPECT_EQ(erc7730_catalog_preload_chunk(id.data(), 24, (uint32_t)e.size(),
                                          e.data() + 23, 10, &next, &complete),
            ERC7730_CATALOG_BAD_SEQUENCE);
  Erc7730CatalogIdentity identity = {};
  EXPECT_FALSE(erc7730_catalog_preloaded(&identity));

  EXPECT_EQ(erc7730_catalog_preload_chunk(id.data(), 0, (uint32_t)e.size(),
                                          e.data(), e.size(), &next, &complete),
            ERC7730_CATALOG_UNTRUSTED);
  EXPECT_FALSE(erc7730_catalog_preloaded(&identity));
}

TEST(Erc7730Catalog, CalldataIdentityMatchesExactLookupTuple) {
  Erc7730CatalogIdentity identity{};
  identity.kind = ERC7730_DEFINITION_CALLDATA;
  identity.chain_id = 1;
  for (size_t i = 0; i < sizeof(identity.contract_address); ++i) {
    identity.contract_address[i] = static_cast<uint8_t>(i + 1);
  }
  identity.selector_or_type_hash[0] = 0xa9;
  identity.selector_or_type_hash[1] = 0x05;
  identity.selector_or_type_hash[2] = 0x9c;
  identity.selector_or_type_hash[3] = 0xbb;
  const uint8_t selector[4] = {0xa9, 0x05, 0x9c, 0xbb};

  EXPECT_TRUE(erc7730_catalog_matches_calldata(
      &identity, 1, identity.contract_address, selector));

  Erc7730CatalogIdentity changed = identity;
  changed.kind = ERC7730_DEFINITION_EIP712;
  EXPECT_FALSE(erc7730_catalog_matches_calldata(
      &changed, 1, identity.contract_address, selector));
  changed = identity;
  changed.selector_or_type_hash[31] = 1;
  EXPECT_FALSE(erc7730_catalog_matches_calldata(
      &changed, 1, identity.contract_address, selector));

  uint8_t other_address[20];
  memcpy(other_address, identity.contract_address, sizeof(other_address));
  other_address[19] ^= 1;
  EXPECT_FALSE(
      erc7730_catalog_matches_calldata(&identity, 1, other_address, selector));
  EXPECT_FALSE(erc7730_catalog_matches_calldata(
      &identity, 10, identity.contract_address, selector));
}

TEST(Erc7730Catalog, Eip712IdentityMatchesOnlyDeviceProvenFacts) {
  Erc7730CatalogIdentity identity{};
  identity.kind = ERC7730_DEFINITION_EIP712;
  identity.chain_id = 1;
  memset(identity.contract_address, 0x11, sizeof(identity.contract_address));
  memset(identity.selector_or_type_hash, 0x22,
         sizeof(identity.selector_or_type_hash));

  uint8_t contract[20];
  uint8_t type_hash[32];
  memset(contract, 0x11, sizeof(contract));
  memset(type_hash, 0x22, sizeof(type_hash));
  EXPECT_TRUE(
      erc7730_catalog_matches_eip712(&identity, 1, contract, true, type_hash));
  EXPECT_FALSE(
      erc7730_catalog_matches_eip712(&identity, 2, contract, true, type_hash));
  EXPECT_FALSE(
      erc7730_catalog_matches_eip712(&identity, 1, contract, false, type_hash));
  contract[0] ^= 1;
  EXPECT_FALSE(
      erc7730_catalog_matches_eip712(&identity, 1, contract, true, type_hash));
  contract[0] ^= 1;
  type_hash[0] ^= 1;
  EXPECT_FALSE(
      erc7730_catalog_matches_eip712(&identity, 1, contract, true, type_hash));

  memset(identity.contract_address, 0, sizeof(identity.contract_address));
  type_hash[0] ^= 1;
  EXPECT_TRUE(
      erc7730_catalog_matches_eip712(&identity, 1, nullptr, false, type_hash));
  identity.kind = ERC7730_DEFINITION_CALLDATA;
  EXPECT_FALSE(
      erc7730_catalog_matches_eip712(&identity, 1, nullptr, false, type_hash));
}

TEST(Erc7730Catalog, ExtractsProgramOnlyFromEnvelopeReplayChunks) {
  Erc7730CatalogIdentity identity{};
  identity.program_length = ERC7730_PROGRAM_HEADER_SIZE;
  std::vector<uint8_t> bytes(256);
  for (size_t i = 0; i < bytes.size(); ++i) bytes[i] = (uint8_t)i;
  uint32_t offset = 99;
  const uint8_t* data = reinterpret_cast<const uint8_t*>(1);
  size_t length = 99;

  ASSERT_TRUE(erc7730_catalog_program_chunk(&identity, 0, bytes.data(), 12,
                                            &offset, &data, &length));
  EXPECT_EQ(offset, 0u);
  ASSERT_EQ(length, 2u);
  EXPECT_EQ(data, bytes.data() + 10);

  ASSERT_TRUE(erc7730_catalog_program_chunk(
      &identity, 12, bytes.data(), bytes.size(), &offset, &data, &length));
  EXPECT_EQ(offset, 2u);
  ASSERT_EQ(length, ERC7730_PROGRAM_HEADER_SIZE - 2u);
  EXPECT_EQ(data, bytes.data());

  ASSERT_TRUE(
      erc7730_catalog_program_chunk(&identity, 10 + ERC7730_PROGRAM_HEADER_SIZE,
                                    bytes.data(), 1, &offset, &data, &length));
  EXPECT_EQ(length, 0u);
  EXPECT_EQ(data, nullptr);

  EXPECT_FALSE(erc7730_catalog_program_chunk(
      &identity, UINT32_MAX, bytes.data(), 2, &offset, &data, &length));
}

TEST(Erc7730Catalog, ReplayIsContiguousAndFailsClosedBeforeAuthentication) {
  const auto program = minimalProgram();
  const auto signed_envelope = envelope(program);
  const auto id = digest(signed_envelope);
  Erc7730CatalogIdentity expected{};
  memcpy(expected.definition_id, id.data(), id.size());
  expected.program_length = (uint32_t)program.size();
  expected.envelope_length = (uint32_t)signed_envelope.size();
  Erc7730CatalogReplay replay;
  erc7730_catalog_replay_begin(&replay, &expected);
  EXPECT_LE(sizeof(replay), 1024u);

  Erc7730CatalogIdentity accepted{};
  uint32_t program_offset = 99;
  const uint8_t* program_data = reinterpret_cast<const uint8_t*>(1);
  size_t program_length = 99;
  ASSERT_EQ(erc7730_catalog_replay_feed(
                &replay, id.data(), 0, (uint32_t)signed_envelope.size(),
                signed_envelope.data(), 11, &program_offset, &program_data,
                &program_length, &accepted),
            ERC7730_CATALOG_MORE);
  EXPECT_EQ(program_offset, 0u);
  ASSERT_EQ(program_length, 1u);
  EXPECT_EQ(*program_data, program[0]);

  EXPECT_EQ(erc7730_catalog_replay_feed(
                &replay, id.data(), 12, (uint32_t)signed_envelope.size(),
                signed_envelope.data() + 11, 1, &program_offset, &program_data,
                &program_length, &accepted),
            ERC7730_CATALOG_BAD_SEQUENCE);
  EXPECT_EQ(program_length, 0u);
  EXPECT_EQ(program_data, nullptr);

  erc7730_catalog_replay_begin(&replay, &expected);
  EXPECT_EQ(erc7730_catalog_replay_feed(
                &replay, id.data(), 0, (uint32_t)signed_envelope.size(),
                signed_envelope.data(), signed_envelope.size(), &program_offset,
                &program_data, &program_length, &accepted),
            ERC7730_CATALOG_UNTRUSTED);
  EXPECT_EQ(program_length, 0u);
  EXPECT_EQ(program_data, nullptr);
}
