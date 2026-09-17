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
  section(p, 1);  // string table
  std::vector<uint8_t> abi;
  append16(abi, 2);
  abi.insert(abi.end(), {8, 0, 0, 0, 1, 0, 1, 0, 0});  // tuple -> node 1
  abi.insert(abi.end(), {1, 1, 0, 0, 0, 0, 0, 0, 0});  // uint256
  section(p, 2, abi);
  section(p, 3);  // paths
  section(p, 6);  // formatters
  section(p, 7);  // display instructions
  section(p, 8);  // deployment constraints
  section(p, 9);  // resource declaration
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
  constexpr size_t kFirstNode = ERC7730_PROGRAM_HEADER_SIZE + 5 + 5 + 2;
  constexpr size_t kSecondNode = kFirstNode + 9;

  auto p = minimalProgram();
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
