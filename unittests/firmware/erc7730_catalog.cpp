extern "C" {
#include "keepkey/firmware/erc7730_capabilities.h"
#include "keepkey/firmware/erc7730_catalog.h"
#include "keepkey/firmware/erc7730_program.h"
#include "keepkey/firmware/storage.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"
void setup(void);
}

#include "gtest/gtest.h"

#include <algorithm>
#include <cstring>
#include <string>
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

std::vector<uint8_t> programWithTableFrom(std::vector<uint8_t> p, uint8_t type,
                                          const std::vector<uint8_t>& entries,
                                          uint16_t count) {
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

std::vector<uint8_t> programWithTable(uint8_t type,
                                      const std::vector<uint8_t>& entries,
                                      uint16_t count) {
  return programWithTableFrom(minimalProgram(), type, entries, count);
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

// Replace the ABI with `nodes` (9 bytes each) and declare its depth.
std::vector<uint8_t> withAbi(std::vector<uint8_t> p,
                             const std::vector<uint8_t>& nodes, uint8_t depth) {
  std::vector<uint8_t> payload;
  append16(payload, (uint16_t)(nodes.size() / 9));
  payload.insert(payload.end(), nodes.begin(), nodes.end());
  std::vector<uint8_t> encoded;
  section(encoded, 2, payload);
  const size_t old = sectionOffset(p, 2);
  const uint32_t old_payload = ((uint32_t)p[old + 1] << 24) |
                               ((uint32_t)p[old + 2] << 16) |
                               ((uint32_t)p[old + 3] << 8) | p[old + 4];
  p.erase(p.begin() + old, p.begin() + old + 5 + old_payload);
  p.insert(p.begin() + old, encoded.begin(), encoded.end());
  const size_t resource = sectionOffset(p, 9) + 5;
  p[resource + 2] = (uint8_t)((nodes.size() / 9) >> 8);
  p[resource + 3] = (uint8_t)(nodes.size() / 9);
  p[resource + 16] = depth;
  return p;
}

// One raw field reading path 0: the executable shape of this firmware.
std::vector<uint8_t> rawFieldProgram(const std::vector<uint8_t>& path) {
  auto p = programWithPaths(path, 1);
  p = replaceTable(p, 6, {1, 0, 1, 1, 1, 0, 0}, 1);
  return replaceTable(p, 7,
                      {
                          1,  0, 0,    0,    0xff, 0xff, 0xff, 0xff,  // intent
                          4,  0, 0,    0,    0,    0,    0xff, 0xff,  // field
                          10, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // end
                      },
                      3);
}

std::vector<uint8_t> envelope(const std::vector<uint8_t>& program) {
  std::vector<uint8_t> e = {'K', '7', '7', '3', 1, 1};
  append32(e, (uint32_t)program.size());
  e.insert(e.end(), program.begin(), program.end());
  e.push_back(0);  // empty proof: leaf is the catalog root
  e.push_back(0);
  e.push_back(ERC7730_DELEGATE_RECORD_LEN);
  e.resize(e.size() + ERC7730_DELEGATE_RECORD_LEN + 64, 0);
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

TEST(Erc7730Catalog, EmptyRootTupleReachesAuthentication) {
  auto p = replaceTable(minimalProgram(), 2, {8, 0, 0, 0, 0, 0, 0, 0, 0}, 1);
  p[sectionOffset(p, 9) + 5 + 16] = 1;
  EXPECT_EQ(feedAll(envelope(p), 1), ERC7730_CATALOG_UNTRUSTED);
  p[sectionOffset(p, 2) + 5 + 2 + 4] = 1;
  EXPECT_EQ(feedAll(envelope(p), 17), ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, LoaderRetainsEveryDomainConstraintAcrossChunkBoundaries) {
  auto p = replaceTable(minimalProgram(), 8,
                        {2, 0, 4, 1, 1, 0, 7, 2, 0, 4, 2, 2, 0xff, 0xff}, 2);
  for (size_t chunk : {1u, 7u, 1024u}) {
    Erc7730ProgramLoader loader{};
    erc7730_program_loader_begin(&loader, p.size());
    for (size_t offset = 0; offset < p.size(); offset += chunk) {
      ASSERT_TRUE(
          erc7730_program_loader_feed(&loader, offset, p.data() + offset,
                                      std::min(chunk, p.size() - offset)));
    }
    Erc7730AbiProgram abi{};
    ASSERT_TRUE(erc7730_program_loader_complete(&loader, &abi));
    EXPECT_EQ(loader.domain.operations[0], 1);
    EXPECT_EQ(loader.domain.literals[0], 7);
    EXPECT_EQ(loader.domain.operations[1], 2);
    EXPECT_EQ(loader.domain.literals[1], UINT16_MAX);
  }
}

namespace {

const uint8_t kPurpose[] = "KEEPKEY:ERC7730:CATALOG\0";

struct SignedFixture {
  uint8_t key[32];
  uint8_t pubkey[33];
};

void loadRuntimeSigner(SignedFixture* fixture, const char* alias) {
  if (storage_getLocation() == FLASH_INVALID) {
    setup();
    storage_init();
  }
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
  signed_metadata_clear_signers();
  memset(fixture->key, 0, sizeof(fixture->key));
  fixture->key[31] = 1;
  ecdsa_get_public_key33(&secp256k1, fixture->key, fixture->pubkey);
  ASSERT_TRUE(signed_metadata_store_signer(3, fixture->pubkey, alias, nullptr,
                                           0, 0, 0, false));
}

// Sorted-pair node per erc7730-compiled-format.md, computed independently of
// the verifier: SHA256(0x01 || min(a, b) || max(a, b)).
std::vector<uint8_t> merkleParent(const std::vector<uint8_t>& a,
                                  const std::vector<uint8_t>& b) {
  std::vector<uint8_t> input{1};
  const bool a_first =
      std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
  const auto& first = a_first ? a : b;
  const auto& second = a_first ? b : a;
  input.insert(input.end(), first.begin(), first.end());
  input.insert(input.end(), second.begin(), second.end());
  return digest(input);
}

// Builds K773 || program || proof || certificate || signature || recovery,
// signing SHA256(purpose || root) with the fixture key.
std::vector<uint8_t> signedEnvelope(
    const SignedFixture& fixture, const std::vector<uint8_t>& program,
    const std::vector<std::vector<uint8_t>>& proof = {},
    const std::vector<uint8_t>& purpose =
        std::vector<uint8_t>(kPurpose, kPurpose + sizeof(kPurpose) - 1)) {
  std::vector<uint8_t> e = {'K', '7', '7', '3', 1, 1};
  append32(e, (uint32_t)program.size());
  e.insert(e.end(), program.begin(), program.end());
  e.push_back((uint8_t)proof.size());
  std::vector<uint8_t> leaf{0};
  leaf.insert(leaf.end(), program.begin(), program.end());
  auto root = digest(leaf);
  for (const auto& sibling : proof) {
    e.insert(e.end(), sibling.begin(), sibling.end());
    root = merkleParent(root, sibling);
  }
  append16(e, ERC7730_DELEGATE_RECORD_LEN);
  const size_t cert = e.size();
  e.resize(e.size() + ERC7730_DELEGATE_RECORD_LEN + 64 + 1, 0);
  e[cert] = 1;
  e[cert + ERC7730_DELEGATE_OFF_SCOPE + 3] = 1;  // chain id 1
  memcpy(e.data() + cert + ERC7730_DELEGATE_OFF_ALIAS, "Host alias", 10);
  memcpy(e.data() + cert + ERC7730_DELEGATE_OFF_PUBKEY, fixture.pubkey, 33);
  std::vector<uint8_t> attestation(purpose);
  attestation.insert(attestation.end(), root.begin(), root.end());
  auto hash = digest(attestation);
  uint8_t recovery = 0;
  EXPECT_EQ(ecdsa_sign_digest(&secp256k1, fixture.key, hash.data(),
                              e.data() + cert + ERC7730_DELEGATE_RECORD_LEN,
                              &recovery, nullptr),
            0);
  e.back() = recovery;
  return e;
}

size_t certOffset(const std::vector<uint8_t>& program, size_t proof_count) {
  return 10 + program.size() + 1 + 32 * proof_count + 2;
}

Erc7730CatalogResult feedIdentity(const std::vector<uint8_t>& e,
                                  Erc7730CatalogIdentity* identity) {
  auto id = digest(e);
  Erc7730CatalogVerifier verifier;
  erc7730_catalog_begin(&verifier, id.data(), (uint32_t)e.size());
  Erc7730CatalogResult result = ERC7730_CATALOG_MORE;
  for (size_t offset = 0; offset < e.size() && result == ERC7730_CATALOG_MORE;
       offset += 29) {
    result =
        erc7730_catalog_feed(&verifier, (uint32_t)offset, e.data() + offset,
                             std::min<size_t>(29, e.size() - offset), identity);
  }
  erc7730_catalog_abort(&verifier);
  return result;
}

}  // namespace

// The envelope signature covers the purpose tag and the Merkle root, which
// commits to the whole program (header included). The certificate record is
// NOT signed: its pubkey must name a user-loaded runtime signer and verify the
// signature, and its scope must equal the signed header's chain id, but its
// other bytes carry no authority (see erc7730_catalog.h).
TEST(Erc7730Catalog, SignatureAuthenticatesProgramUnderLoadedDelegateKey) {
  SignedFixture fixture;
  loadRuntimeSigner(&fixture, "Approved signer");
  auto program = minimalProgram();
  auto e = signedEnvelope(fixture, program);
  const size_t cert = certOffset(program, 0);
  Erc7730CatalogIdentity identity{};
  ASSERT_EQ(feedIdentity(e, &identity), ERC7730_CATALOG_COMPLETE);
  // The alias shown is the one the user approved, never the record's.
  EXPECT_STREQ(identity.delegate_alias, "Approved signer");

  auto changed = e;
  changed[10 + 173]++;  // Signed issuance epoch, still structurally valid.
  EXPECT_EQ(feedAll(changed, 31), ERC7730_CATALOG_UNTRUSTED);
  changed = e;
  changed[cert + ERC7730_DELEGATE_OFF_PUBKEY] ^= 1;
  EXPECT_EQ(feedAll(changed, 31), ERC7730_CATALOG_UNTRUSTED);
  // Scope is a consistency check against the signed header, not a signed
  // field: any value other than the header chain id is refused.
  changed = e;
  changed[cert + ERC7730_DELEGATE_OFF_SCOPE + 3] = 2;
  EXPECT_EQ(feedAll(changed, 31), ERC7730_CATALOG_UNTRUSTED);
  changed = e;
  changed[cert + ERC7730_DELEGATE_OFF_VERSION] = 2;
  EXPECT_EQ(feedAll(changed, 31), ERC7730_CATALOG_UNTRUSTED);

  // Unsigned record bytes are ignored: changing them changes nothing the
  // device shows or relies on.
  for (size_t offset : {size_t{1}, size_t{6}, size_t{9}, size_t{75},
                        size_t{ERC7730_DELEGATE_RECORD_LEN - 1}}) {
    changed = e;
    changed[cert + offset] ^= 0x5a;
    Erc7730CatalogIdentity other{};
    ASSERT_EQ(feedIdentity(changed, &other), ERC7730_CATALOG_COMPLETE)
        << offset;
    EXPECT_STREQ(other.delegate_alias, "Approved signer");
    EXPECT_STREQ(other.delegate_fingerprint, identity.delegate_fingerprint);
  }
  changed = e;
  memcpy(changed.data() + cert + ERC7730_DELEGATE_OFF_ALIAS, "Other name", 10);
  Erc7730CatalogIdentity other{};
  ASSERT_EQ(feedIdentity(changed, &other), ERC7730_CATALOG_COMPLETE);
  EXPECT_STREQ(other.delegate_alias, "Approved signer");

  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
  EXPECT_EQ(feedAll(e, 31), ERC7730_CATALOG_UNTRUSTED);
  signed_metadata_clear_signers();
}

TEST(Erc7730Catalog, RejectsWrongPurposeRecoveryCertLengthAndClearedSigner) {
  SignedFixture fixture;
  loadRuntimeSigner(&fixture, "Approved signer");
  auto program = minimalProgram();
  auto e = signedEnvelope(fixture, program);
  ASSERT_EQ(feedAll(e, 64), ERC7730_CATALOG_COMPLETE);

  const char legacy[] = "KEEPKEY:ERC7730:CATALOG";  // missing the NUL byte
  EXPECT_EQ(feedAll(signedEnvelope(fixture, program, {},
                                   std::vector<uint8_t>(
                                       legacy, legacy + sizeof(legacy) - 1)),
                    64),
            ERC7730_CATALOG_UNTRUSTED);
  const char other[] = "KEEPKEY:ERC7730:CATALOH\0";
  EXPECT_EQ(feedAll(signedEnvelope(
                        fixture, program, {},
                        std::vector<uint8_t>(other, other + sizeof(other) - 1)),
                    64),
            ERC7730_CATALOG_UNTRUSTED);

  auto changed = e;
  changed.back() = 2;
  EXPECT_EQ(feedAll(changed, 64), ERC7730_CATALOG_UNTRUSTED);
  changed.back() = 0xff;
  EXPECT_EQ(feedAll(changed, 64), ERC7730_CATALOG_UNTRUSTED);

  const size_t cert_length = certOffset(program, 0) - 2;
  changed = e;
  changed[cert_length + 1] = ERC7730_DELEGATE_RECORD_LEN - 1;
  EXPECT_EQ(feedAll(changed, 64), ERC7730_CATALOG_BAD_ENVELOPE);
  changed = e;
  changed[cert_length + 1] = ERC7730_DELEGATE_RECORD_LEN + 1;
  EXPECT_EQ(feedAll(changed, 64), ERC7730_CATALOG_BAD_ENVELOPE);

  // A different key loaded under the same alias does not verify.
  uint8_t other_key[32] = {0};
  other_key[31] = 2;
  uint8_t other_pubkey[33];
  ecdsa_get_public_key33(&secp256k1, other_key, other_pubkey);
  signed_metadata_clear_signers();
  ASSERT_TRUE(signed_metadata_store_signer(3, other_pubkey, "Approved signer",
                                           nullptr, 0, 0, 0, false));
  EXPECT_EQ(feedAll(e, 64), ERC7730_CATALOG_UNTRUSTED);

  // The same key reloaded under another alias verifies and shows the new one.
  signed_metadata_clear_signers();
  ASSERT_TRUE(signed_metadata_store_signer(1, fixture.pubkey, "Renamed signer",
                                           nullptr, 0, 0, 0, false));
  Erc7730CatalogIdentity identity{};
  ASSERT_EQ(feedIdentity(e, &identity), ERC7730_CATALOG_COMPLETE);
  EXPECT_STREQ(identity.delegate_alias, "Renamed signer");

  // Replaying an accepted envelope after the signers are cleared fails.
  signed_metadata_clear_signers();
  EXPECT_EQ(feedAll(e, 64), ERC7730_CATALOG_UNTRUSTED);
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
}

TEST(Erc7730Catalog, AuthenticatesMerkleProofPathsUpToDepthLimit) {
  SignedFixture fixture;
  loadRuntimeSigner(&fixture, "Approved signer");
  auto program = minimalProgram();
  std::vector<std::vector<uint8_t>> proof;
  for (size_t i = 0; i < ERC7730_CATALOG_MAX_PROOF_DEPTH; i++) {
    // Alternate siblings above and below the running node so both orderings
    // of the sorted pair are exercised.
    proof.push_back(std::vector<uint8_t>(32, i % 2 ? 0x00 : 0xff));
    proof.back()[31] = (uint8_t)i;
  }
  for (size_t depth : {size_t{1}, size_t{2}, size_t{7},
                       size_t{ERC7730_CATALOG_MAX_PROOF_DEPTH}}) {
    std::vector<std::vector<uint8_t>> path(proof.begin(),
                                           proof.begin() + depth);
    auto e = signedEnvelope(fixture, program, path);
    EXPECT_EQ(feedAll(e, 1), ERC7730_CATALOG_COMPLETE) << depth;
    EXPECT_EQ(feedAll(e, 1024), ERC7730_CATALOG_COMPLETE) << depth;
    // Tamper with one sibling byte: the root, and so the signature, changes.
    auto tampered = e;
    tampered[10 + program.size() + 1 + 32 * (depth - 1) + 5] ^= 1;
    EXPECT_EQ(feedAll(tampered, 31), ERC7730_CATALOG_UNTRUSTED) << depth;
    // Dropping the proof leaves a signature over a different root.
    if (depth == 1) {
      auto unproven = signedEnvelope(fixture, program, path);
      unproven.erase(unproven.begin() + 10 + program.size() + 1,
                     unproven.begin() + 10 + program.size() + 1 + 32);
      unproven[10 + program.size()] = 0;
      EXPECT_EQ(feedAll(unproven, 31), ERC7730_CATALOG_UNTRUSTED);
    }
  }
  proof.push_back(std::vector<uint8_t>(32, 0x42));
  auto too_deep = signedEnvelope(fixture, program, proof);
  EXPECT_EQ(feedAll(too_deep, 64), ERC7730_CATALOG_BAD_ENVELOPE);
  signed_metadata_clear_signers();
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
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

  p = programWithStrings({{'A', 0, 'B'}});  // no hidden suffix on a C string
  EXPECT_EQ(feedAll(envelope(p), 1), ERC7730_CATALOG_BAD_PROGRAM);
  EXPECT_EQ(feedAll(envelope(p), 17), ERC7730_CATALOG_BAD_PROGRAM);

  p = programWithStrings({{'A', 0x0a, 'B'}});  // display control character
  EXPECT_EQ(feedAll(envelope(p), 17), ERC7730_CATALOG_BAD_PROGRAM);
  p = programWithStrings({{'A', 0x7f}});  // DEL
  EXPECT_EQ(feedAll(envelope(p), 17), ERC7730_CATALOG_BAD_PROGRAM);
  p = programWithStrings({{0xf4, 0x90, 0x80, 0x80}});  // above U+10FFFF
  EXPECT_EQ(feedAll(envelope(p), 17), ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, ValidatesTypedPathsSlicesAndFullArraySteps) {
  // index 0 reaches the uint256 leaf: executable.
  auto p = programWithPaths({1, 1, 0xff, 0xff, 1, 0, 0, 0, 0}, 1);
  EXPECT_EQ(feedAll(envelope(p), 1), ERC7730_CATALOG_UNTRUSTED);

  // Slices, whole-array steps, container and literal sources are not in the
  // capability table: the runtime cannot capture them, so preload refuses.
  // @.from, @.to, @.value and a literal are executable value sources.
  for (const auto& entries : std::vector<std::vector<uint8_t>>{
           {2, 0, 0, 1}, {2, 0, 0, 2}, {2, 0, 0, 3}, {3, 0, 0, 0}}) {
    p = programWithPaths(entries, 1);
    EXPECT_EQ(feedAll(envelope(p), 23), ERC7730_CATALOG_UNTRUSTED);
  }

  // Slices, whole-array steps, the other containers and out-of-table literal
  // indices are not executed, so preload refuses them.
  const std::vector<std::vector<uint8_t>> refused = {
      {1, 2, 0xff, 0xff, 1, 0, 0, 0, 0, 3, 1, 0xff, 0xff, 0xff, 0xec},
      {1, 1, 0xff, 0xff, 2},
      {2, 0, 0, 4},
      {3, 0, 0, 64},
      {1, 2, 0xff, 0xff, 3, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0},
      {1, 2, 0xff, 0xff, 2, 2},
      {2, 1, 0, 2, 1, 0, 0, 0, 0},
  };
  for (const auto& entries : refused) {
    p = programWithPaths(entries, 1);
    EXPECT_EQ(feedAll(envelope(p), 23), ERC7730_CATALOG_BAD_PROGRAM);
  }
}

// Calldata and typed-data captures refuse ERC7730_ABI_MAX_DEPTH or more path
// steps, so the preload verifier must too: a longer signed path would pass
// preload and then fail after the user had approved earlier screens.
TEST(Erc7730Catalog, PathStepLimitMatchesExecutionCaptures) {
  // Seven nested tuples above a uint256: depth eight, the ABI maximum, and a
  // seven-step path to the leaf, the capture maximum.
  std::vector<uint8_t> nodes;
  for (uint8_t i = 0; i < ERC7730_ABI_MAX_DEPTH - 1u; i++)
    nodes.insert(nodes.end(), {8, 0, 0, 0, (uint8_t)(i + 1), 0, 1, 0, 0});
  nodes.insert(nodes.end(), {1, 1, 0, 0, 0, 0, 0, 0, 0});
  for (uint8_t steps : {(uint8_t)(ERC7730_ABI_MAX_DEPTH - 1u),
                        (uint8_t)ERC7730_ABI_MAX_DEPTH}) {
    std::vector<uint8_t> entries = {1, steps, 0xff, 0xff};
    for (uint8_t i = 0; i < steps; i++)
      entries.insert(entries.end(), {1, 0, 0, 0, 0});
    const auto p =
        withAbi(programWithPaths(entries, 1), nodes, ERC7730_ABI_MAX_DEPTH);
    EXPECT_EQ(feedAll(envelope(p), 23), steps < ERC7730_ABI_MAX_DEPTH
                                            ? ERC7730_CATALOG_UNTRUSTED
                                            : ERC7730_CATALOG_BAD_PROGRAM)
        << (int)steps;
  }
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

  // The runtime executes only condition opcode 3, "optional", and always
  // shows the field; every opcode that could hide a field is refused.
  p = programWithTable(5, {}, 0);
  EXPECT_EQ(feedAll(envelope(p), 1), ERC7730_CATALOG_UNTRUSTED);
  p = programWithTable(5, {3, 0xff, 0xff, 0xff, 0xff, 0, 0, 0}, 1);
  EXPECT_EQ(feedAll(envelope(p), 1), ERC7730_CATALOG_UNTRUSTED);
  for (uint8_t opcode : {1, 2}) {
    p = programWithTable(5, {opcode, 0xff, 0xff, 0xff, 0xff, 0, 0, 0}, 1);
    EXPECT_EQ(feedAll(envelope(p), 1), ERC7730_CATALOG_BAD_PROGRAM)
        << (int)opcode;
  }
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

  // No deployment record may name the zero address, so a zero header
  // contract can never describe a transaction, not even one sent to 0x0.
  memset(identity.contract_address, 0, sizeof(identity.contract_address));
  EXPECT_FALSE(erc7730_catalog_matches_calldata(
      &identity, 1, identity.contract_address, selector));
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

  // A zero ("domain-wide") header contract still needs a verifyingContract;
  // the replay loader then requires it to be a signed deployment.
  memset(identity.contract_address, 0, sizeof(identity.contract_address));
  type_hash[0] ^= 1;
  EXPECT_FALSE(
      erc7730_catalog_matches_eip712(&identity, 1, nullptr, false, type_hash));
  EXPECT_FALSE(
      erc7730_catalog_matches_eip712(&identity, 1, contract, false, type_hash));
  EXPECT_TRUE(
      erc7730_catalog_matches_eip712(&identity, 1, contract, true, type_hash));
  identity.kind = ERC7730_DEFINITION_CALLDATA;
  EXPECT_FALSE(
      erc7730_catalog_matches_eip712(&identity, 1, contract, true, type_hash));
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

namespace {

bool loadProgram(const std::vector<uint8_t>& p, uint64_t chain_id,
                 const uint8_t* contract) {
  Erc7730ProgramLoader loader{};
  erc7730_program_loader_begin(&loader, p.size());
  if (contract &&
      !erc7730_program_loader_require_deployment(&loader, chain_id, contract))
    return false;
  for (size_t offset = 0; offset < p.size(); offset += 13) {
    if (!erc7730_program_loader_feed(&loader, offset, p.data() + offset,
                                     std::min<size_t>(13, p.size() - offset)))
      return false;
  }
  Erc7730AbiProgram abi{};
  return erc7730_program_loader_complete(&loader, &abi);
}

std::vector<uint8_t> deployment(uint8_t chain, uint8_t address_byte) {
  std::vector<uint8_t> record = {1, 0, 28, 0, 0, 0, 0, 0, 0, 0, chain};
  record.resize(record.size() + 20, address_byte);
  return record;
}

}  // namespace

TEST(Erc7730Catalog, TypedDataMustUseListedSignedDeployment) {
  // Two deployments, sorted by payload: chain 1 at 0x11.., chain 1 at 0x22..
  auto p = minimalProgram();
  std::vector<uint8_t> records = deployment(1, 0x11);
  auto second = deployment(1, 0x22);
  records.insert(records.end(), second.begin(), second.end());
  p = replaceTable(p, 8, records, 2);
  p[18] = 0;  // zero ("domain-wide") header contract
  EXPECT_EQ(feedAll(envelope(p), 7), ERC7730_CATALOG_UNTRUSTED);

  uint8_t listed[20];
  memset(listed, 0x22, sizeof(listed));
  EXPECT_TRUE(loadProgram(p, 1, listed));
  memset(listed, 0x11, sizeof(listed));
  EXPECT_TRUE(loadProgram(p, 1, listed));

  uint8_t unlisted[20];
  memset(unlisted, 0x22, sizeof(unlisted));
  unlisted[19] = 0x23;
  EXPECT_FALSE(loadProgram(p, 1, unlisted));
  memset(unlisted, 0x33, sizeof(unlisted));
  EXPECT_FALSE(loadProgram(p, 1, unlisted));
  // Listed address, but on a chain no deployment names.
  EXPECT_FALSE(loadProgram(p, 2, listed));
  // Calldata replay does not ask for a deployment and is unaffected.
  EXPECT_TRUE(loadProgram(p, 0, nullptr));

  // The requirement must precede the first program byte.
  Erc7730ProgramLoader loader{};
  erc7730_program_loader_begin(&loader, p.size());
  ASSERT_TRUE(erc7730_program_loader_feed(&loader, 0, p.data(), 1));
  EXPECT_FALSE(erc7730_program_loader_require_deployment(&loader, 1, listed));
  EXPECT_TRUE(loader.failed);
}

TEST(Erc7730Catalog, IssuanceEpochFloorIsEnforced) {
  auto p = minimalProgram();
  p[170] = p[171] = p[172] = 0;
  p[173] = 0;
  p[174] = p[175] = p[176] = p[177] = 0;
  p[170] = (uint8_t)(ERC7730_MIN_ISSUANCE_EPOCH >> 24);
  p[171] = (uint8_t)(ERC7730_MIN_ISSUANCE_EPOCH >> 16);
  p[172] = (uint8_t)(ERC7730_MIN_ISSUANCE_EPOCH >> 8);
  p[173] = (uint8_t)ERC7730_MIN_ISSUANCE_EPOCH;
  EXPECT_EQ(feedAll(envelope(p), 31), ERC7730_CATALOG_UNTRUSTED);
  if (ERC7730_MIN_ISSUANCE_EPOCH != 0) {
    const uint32_t below = ERC7730_MIN_ISSUANCE_EPOCH - 1u;
    p[170] = (uint8_t)(below >> 24);
    p[171] = (uint8_t)(below >> 16);
    p[172] = (uint8_t)(below >> 8);
    p[173] = (uint8_t)below;
    EXPECT_EQ(feedAll(envelope(p), 31), ERC7730_CATALOG_BAD_PROGRAM);
  }
  // Issuance below the signed revocation epoch is refused.
  p = minimalProgram();
  p[173] = 2;
  EXPECT_EQ(feedAll(envelope(p), 31), ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, VerifierEnforcesReplayReaderDisplayLimit) {
  auto displayProgram = [](uint16_t count) {
    std::vector<uint8_t> display = {1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff};
    for (uint16_t i = 0; i + 2u < count; i++)
      display.insert(display.end(), {4, 0, 0, 0, 0, 0, 0xff, 0xff});
    display.insert(display.end(), {10, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
    return replaceTable(rawFieldProgram({1, 1, 0xff, 0xff, 1, 0, 0, 0, 0}), 7,
                        display, count);
  };
  auto reads = [](const std::vector<uint8_t>& p, uint16_t count) {
    Erc7730ProgramDisplay display{};
    const size_t payload = 2u + 8u * count;
    erc7730_program_display_begin(&display, payload, 0);
    return erc7730_program_display_feed(
        &display, 0, p.data() + sectionOffset(p, 7) + 5, payload);
  };
  auto p = displayProgram(ERC7730_PROGRAM_MAX_DISPLAY_INSTRUCTIONS);
  EXPECT_EQ(feedAll(envelope(p), 97), ERC7730_CATALOG_UNTRUSTED);
  EXPECT_TRUE(reads(p, ERC7730_PROGRAM_MAX_DISPLAY_INSTRUCTIONS));
  p = displayProgram(ERC7730_PROGRAM_MAX_DISPLAY_INSTRUCTIONS + 1);
  EXPECT_FALSE(reads(p, ERC7730_PROGRAM_MAX_DISPLAY_INSTRUCTIONS + 1));
  EXPECT_EQ(feedAll(envelope(p), 97), ERC7730_CATALOG_BAD_PROGRAM);

  // An executable definition with no display instruction cannot replay.
  p = replaceTable(minimalProgram(), 7, {}, 0);
  EXPECT_EQ(feedAll(envelope(p), 31), ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, VerifierEnforcesReplayReaderLiteralLengths) {
  auto reads = [](const std::vector<uint8_t>& p) {
    const size_t section = sectionOffset(p, 4);
    const uint32_t length = ((uint32_t)p[section + 1] << 24) |
                            ((uint32_t)p[section + 2] << 16) |
                            ((uint32_t)p[section + 3] << 8) | p[section + 4];
    Erc7730ProgramLiteral literal{};
    erc7730_program_literal_begin(&literal, length, 0);
    return erc7730_program_literal_feed(&literal, 0, p.data() + section + 5,
                                        length);
  };
  std::vector<uint8_t> literal = {3, 0x01, 0x02};
  literal.resize(3 + ERC7730_LITERAL_MAX_LENGTH, 0xaa);
  auto p = programWithTable(4, literal, 1);
  EXPECT_TRUE(reads(p));
  EXPECT_EQ(feedAll(envelope(p), 61), ERC7730_CATALOG_UNTRUSTED);

  literal = {3, 0x01, 0x03};
  literal.resize(3 + ERC7730_LITERAL_MAX_LENGTH + 1, 0xaa);
  p = programWithTable(4, literal, 1);
  EXPECT_FALSE(reads(p));
  EXPECT_EQ(feedAll(envelope(p), 61), ERC7730_CATALOG_BAD_PROGRAM);

  // An empty bytes literal (e.g. a "0x" salt) is not a replayable literal.
  literal = {3, 0, 0};
  p = programWithTable(4, literal, 1);
  EXPECT_FALSE(reads(p));
  EXPECT_EQ(feedAll(envelope(p), 5), ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, VerifierRejectsDuplicateDomainFieldLikeLoader) {
  auto base = programWithTable(4, {1, 0, 1, 7}, 1);  // literal 0 = uint 7
  base[18] = 0;  // zero header contract; the deployment below is 0x11..11
  const auto deployed = deployment(1, 0x11);
  auto withConstraints = [&](const std::vector<uint8_t>& constraints,
                             uint16_t count) {
    std::vector<uint8_t> records = deployed;
    records.insert(records.end(), constraints.begin(), constraints.end());
    return replaceTable(base, 8, records, (uint16_t)(count + 1u));
  };
  // name == literal 0, version absent: distinct fields.
  auto p = withConstraints({2, 0, 4, 1, 1, 0, 0, 2, 0, 4, 2, 2, 0xff, 0xff}, 2);
  EXPECT_EQ(feedAll(envelope(p), 11), ERC7730_CATALOG_UNTRUSTED);
  EXPECT_TRUE(loadProgram(p, 0, nullptr));

  // name == literal 0 and name absent: contradictory duplicate field.
  p = withConstraints({2, 0, 4, 1, 1, 0, 0, 2, 0, 4, 1, 2, 0xff, 0xff}, 2);
  EXPECT_FALSE(loadProgram(p, 0, nullptr));
  EXPECT_EQ(feedAll(envelope(p), 11), ERC7730_CATALOG_BAD_PROGRAM);
}

// The preload verifier and the runtime consult one capability table, so
// every shape the runtime cannot execute is refused before the first screen.
// Each refusal below is paired with the runtime predicate that would have
// refused it mid-review.
TEST(Erc7730Catalog, PreloadRefusesDisplayInstructionsTheRuntimeCannotRun) {
  const std::vector<uint8_t> path = {1, 1, 0xff, 0xff, 1, 0, 0, 0, 0};
  EXPECT_EQ(feedAll(envelope(rawFieldProgram(path)), 7),
            ERC7730_CATALOG_UNTRUSTED);
  const Erc7730DisplayInstruction runnable[] = {
      {1, 0, 0, UINT16_MAX, UINT16_MAX},
      {4, 0, 0, 0, UINT16_MAX},
      {10, 0, UINT16_MAX, UINT16_MAX, UINT16_MAX},
  };
  EXPECT_TRUE(erc7730_cap_display(&runnable[0], 0));
  EXPECT_TRUE(erc7730_cap_display(&runnable[1], 1));
  EXPECT_TRUE(erc7730_cap_display(&runnable[2], 2));

  struct Case {
    std::vector<uint8_t> display;
    uint16_t count;
    Erc7730DisplayInstruction refused;
    uint16_t pc;
  };
  // Interpolated intent: text (2) and value (3) parts directly after the
  // intent run; once a field has started they are refused.
  const std::vector<uint8_t> interpolated = {
      1,  0, 0,    0,    0xff, 0xff, 0xff, 0xff,  // intent
      2,  0, 0,    0,    0xff, 0xff, 0xff, 0xff,  // "Test"
      3,  0, 0,    0,    0xff, 0xff, 0xff, 0xff,  // formatter 0
      4,  0, 0,    0,    0,    0,    0xff, 0xff,  // field
      10, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  EXPECT_EQ(
      feedAll(envelope(replaceTable(rawFieldProgram(path), 7, interpolated, 5)),
              7),
      ERC7730_CATALOG_UNTRUSTED);
  const Case cases[] = {
      // an intent part after a field
      {{1,    0,    0,  0,    0xff, 0xff, 0xff, 0xff, 4,    0,    0,
        0,    0,    0,  0xff, 0xff, 2,    0,    0,    0,    0xff, 0xff,
        0xff, 0xff, 10, 0,    0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
       4,
       {2, 0, 0, UINT16_MAX, 0},
       2},
      {{1,    0,    0,  0,    0xff, 0xff, 0xff, 0xff, 4,    0,    0,
        0,    0,    0,  0xff, 0xff, 3,    0,    0,    0,    0xff, 0xff,
        0xff, 0xff, 10, 0,    0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
       4,
       {3, 0, 0, 0, UINT16_MAX},
       2},
      // a group end that names no group
      {{1,    0,    0,    0,    0xff, 0xff, 0xff, 0xff, 6,    0,    0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 10,   0,    0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
       3,
       {6, 0, UINT16_MAX, UINT16_MAX, UINT16_MAX},
       1},
      // opcode 9
      {{1, 0, 0,    0,    0xff, 0xff, 0xff, 0xff, 9,    0,    0xff, 0xff,
        0, 0, 0xff, 0xff, 10,   0,    0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
       3,
       {9, 0, UINT16_MAX, 0, UINT16_MAX},
       1},
      // a second intent
      {{1,    0,    0,    0,    0xff, 0xff, 0xff, 0xff, 1,    0,    0,    0,
        0xff, 0xff, 0xff, 0xff, 10,   0,    0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
       3,
       {1, 0, 0, UINT16_MAX, UINT16_MAX},
       1},
      // a field before the intent
      {{4, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff},
       2,
       {4, 0, 0, 0, UINT16_MAX},
       0},
      // an end with no intent
      {{10, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
       1,
       {10, 0, UINT16_MAX, UINT16_MAX, UINT16_MAX},
       0},
  };
  for (const auto& c : cases) {
    const auto p = replaceTable(rawFieldProgram(path), 7, c.display, c.count);
    EXPECT_EQ(feedAll(envelope(p), 7), ERC7730_CATALOG_BAD_PROGRAM)
        << (int)c.refused.opcode << "@" << c.pc;
    EXPECT_FALSE(erc7730_cap_display(&c.refused, c.pc))
        << (int)c.refused.opcode << "@" << c.pc;
  }
  // A field may carry an "optional" condition, which only ever shows it.
  const Erc7730DisplayInstruction conditional = {4, 0, 0, 0, 0};
  EXPECT_TRUE(erc7730_cap_display(&conditional, 1));
  // A plain group around the field is executable.
  const std::vector<uint8_t> group = {
      1,  0, 0,    0,    0xff, 0xff, 0xff, 0xff,  //
      5,  0, 0xff, 0xff, 0xff, 0xff, 0,    3,     //
      4,  0, 0,    0,    0,    0,    0xff, 0xff,  //
      6,  0, 0,    1,    0xff, 0xff, 0xff, 0xff,  //
      10, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  auto grouped = replaceTable(rawFieldProgram(path), 7, group, 5);
  grouped[sectionOffset(grouped, 9) + 5 + 18] = 1;  // declared display depth
  EXPECT_EQ(feedAll(envelope(grouped), 7), ERC7730_CATALOG_UNTRUSTED);
}

TEST(Erc7730Catalog, PreloadRefusesFormatterKindsTheRuntimeCannotRun) {
  const std::vector<uint8_t> path = {1, 1, 0xff, 0xff, 1, 0, 0, 0, 0};
  Erc7730Formatter formatter = {};
  formatter.argument_count = 1;
  formatter.arguments[0] = {1, 1, 0};
  formatter.kind = 1;
  EXPECT_TRUE(erc7730_cap_formatter(&formatter));
  for (uint8_t kind = 2; kind <= 14; kind++) {
    // A lone uint256 value runs as amount, date (a timestamp) or duration.
    // tokenAmount, nftName, unit and enum lack a required argument,
    // addressName needs an address, and kinds 9 and 11-14 never run.
    const bool runs = kind == 2 || kind == 5 || kind == 6;
    auto p =
        replaceTable(rawFieldProgram(path), 6, {kind, 0, 1, 1, 1, 0, 0}, 1);
    EXPECT_EQ(feedAll(envelope(p), 7),
              runs ? ERC7730_CATALOG_UNTRUSTED : ERC7730_CATALOG_BAD_PROGRAM)
        << (int)kind;
    formatter.kind = kind;
    EXPECT_EQ(erc7730_cap_formatter(&formatter), runs || kind == 10)
        << (int)kind;
  }
  // raw with a second, signer-supplied operand is not raw.
  formatter.kind = 1;
  formatter.argument_count = 2;
  formatter.arguments[1] = {9, 3, 0};
  EXPECT_FALSE(erc7730_cap_formatter(&formatter));
  formatter.argument_count = 0;
  EXPECT_FALSE(erc7730_cap_formatter(&formatter));
}

TEST(Erc7730Catalog, PreloadWalksEveryPathAgainstTheAbi) {
  // (uint256 a, uint256[3] b, address[] c, (bool) d)
  const std::vector<uint8_t> nodes = {
      8, 0, 0, 0, 1, 0, 4, 0,    0,     // 0 root
      1, 1, 0, 0, 0, 0, 0, 0,    0,     // 1 a
      9, 0, 0, 0, 5, 0, 1, 0,    3,     // 2 b: uint256[3]
      9, 0, 0, 0, 6, 0, 1, 0xff, 0xff,  // 3 c: address[]
      8, 0, 0, 0, 7, 0, 1, 0,    0,     // 4 d: (bool)
      1, 1, 0, 0, 0, 0, 0, 0,    0,     // 5 b[i]
      3, 0, 0, 0, 0, 0, 0, 0,    0,     // 6 c[i]
      4, 0, 0, 0, 0, 0, 0, 0,    0,     // 7 d.0
  };
  auto step = [](int32_t index) {
    return std::vector<uint8_t>{
        1, (uint8_t)((uint32_t)index >> 24), (uint8_t)((uint32_t)index >> 16),
        (uint8_t)((uint32_t)index >> 8), (uint8_t)index};
  };
  struct Case {
    std::vector<int32_t> steps;
    bool executable;
  };
  const Case cases[] = {
      {{0}, true},        {{4}, false},    {{-1}, false},    {{0, 0}, false},
      {{1}, false},       {{1, 2}, true},  {{1, 3}, false},  {{1, -3}, true},
      {{1, -4}, false},   {{2, 63}, true}, {{2, 64}, false}, {{2, -64}, true},
      {{2, -65}, false},  {{3}, false},    {{3, 0}, true},   {{3, 1}, false},
      {{3, 0, 0}, false},
  };
  for (const auto& c : cases) {
    std::vector<uint8_t> path = {1, (uint8_t)c.steps.size(), 0xff, 0xff};
    for (int32_t index : c.steps) {
      const auto encoded = step(index);
      path.insert(path.end(), encoded.begin(), encoded.end());
    }
    const auto p = withAbi(rawFieldProgram(path), nodes, 3);
    EXPECT_EQ(feedAll(envelope(p), 5), c.executable
                                           ? ERC7730_CATALOG_UNTRUSTED
                                           : ERC7730_CATALOG_BAD_PROGRAM)
        << c.steps.size() << ":" << c.steps[0];
  }

  // The argumentless root has no member to read.
  const auto p = withAbi(rawFieldProgram({1, 1, 0xff, 0xff, 1, 0, 0, 0, 0}),
                         {8, 0, 0, 0, 0, 0, 0, 0, 0}, 1);
  EXPECT_EQ(feedAll(envelope(p), 5), ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, RuntimePathPredicateMatchesTheTable) {
  Erc7730Path path = {};
  path.source = 1;
  path.step_count = 1;
  path.steps[0].opcode = 1;
  EXPECT_TRUE(erc7730_cap_path(&path));
  path.steps[0].opcode = 2;
  EXPECT_TRUE(erc7730_cap_path(&path));
  path.steps[0].opcode = 3;
  EXPECT_FALSE(erc7730_cap_path(&path));
  path.steps[0].opcode = 1;
  path.step_count = ERC7730_ABI_MAX_DEPTH;
  EXPECT_FALSE(erc7730_cap_path(&path));
  path.step_count = 0;
  EXPECT_FALSE(erc7730_cap_path(&path));
  path.step_count = 1;
  path.source = 3;
  EXPECT_FALSE(erc7730_cap_path(&path));
}

namespace {

// f(address token, uint256 amount) with value paths 0 = token, 1 = amount,
// 2 = literal 0 and 3 = @.to, plus `literals` and one formatter.
std::vector<uint8_t> tokenProgram(const std::vector<uint8_t>& formatter,
                                  const std::vector<uint8_t>& literals = {},
                                  uint16_t literal_count = 0) {
  const std::vector<uint8_t> paths = {
      1, 1, 0xff, 0xff, 1, 0, 0, 0, 0,  // token
      1, 1, 0xff, 0xff, 1, 0, 0, 0, 1,  // amount
      3, 0, 0,    0,                    // literal 0
      2, 0, 0,    2,                    // @.to
  };
  auto p = withAbi(rawFieldProgram({1, 1, 0xff, 0xff, 1, 0, 0, 0, 0}),
                   {8, 0, 0, 0, 1, 0, 2, 0, 0,   // (address, uint256)
                    3, 0, 0, 0, 0, 0, 0, 0, 0,   //
                    1, 1, 0, 0, 0, 0, 0, 0, 0},  //
                   2);
  p = replaceTable(p, 3, paths, 4);
  if (literal_count) p = programWithTableFrom(p, 4, literals, literal_count);
  return replaceTable(p, 6, formatter, 1);
}

}  // namespace

// Arguments of tokenAmount and addressName, from container and literal
// values. Every
// argument is type-checked at preload against the class the runtime needs, so
// a mistyped program is refused before the first screen. Each refusal below
// has an accepted neighbour differing only in the offending byte.
TEST(Erc7730Catalog, PreloadTypeChecksTokenAmountArguments) {
  auto result = [](const std::vector<uint8_t>& formatter,
                   const std::vector<uint8_t>& literals = {},
                   uint16_t count = 0) {
    return feedAll(envelope(tokenProgram(formatter, literals, count)), 11);
  };
  // value = amount, token = token argument
  EXPECT_EQ(result({3, 0, 2, 1, 1, 0, 1, 2, 1, 0, 0}),
            ERC7730_CATALOG_UNTRUSTED);
  EXPECT_EQ(result({3, 0, 2, 1, 1, 0, 0, 2, 1, 0, 1}),
            ERC7730_CATALOG_BAD_PROGRAM);  // swapped types
  EXPECT_EQ(result({3, 0, 1, 1, 1, 0, 1}),
            ERC7730_CATALOG_BAD_PROGRAM);  // no token
  // token = @.to
  EXPECT_EQ(result({3, 0, 2, 1, 1, 0, 1, 2, 1, 0, 3}),
            ERC7730_CATALOG_UNTRUSTED);
  // token = literal address; a literal integer is not a token
  const std::vector<uint8_t> address(20, 0x11);
  std::vector<uint8_t> address_literal = {5, 0, 20};
  address_literal.insert(address_literal.end(), address.begin(), address.end());
  EXPECT_EQ(result({3, 0, 2, 1, 1, 0, 1, 2, 1, 0, 2}, address_literal, 1),
            ERC7730_CATALOG_UNTRUSTED);
  EXPECT_EQ(result({3, 0, 2, 1, 1, 0, 1, 2, 1, 0, 2}, {1, 0, 1, 7}, 1),
            ERC7730_CATALOG_BAD_PROGRAM);

  // threshold (role 7) is a literal integer; message (role 8) a string
  auto literals = address_literal;
  literals.insert(literals.end(), {1, 0, 1, 9});  // literal 1 = 9
  EXPECT_EQ(result({3, 0, 4, 1, 1, 0, 1, 2, 1, 0, 0, 7, 2, 0, 1, 8, 3, 0, 0},
                   literals, 2),
            ERC7730_CATALOG_UNTRUSTED);
  EXPECT_EQ(result({3, 0, 4, 1, 1, 0, 1, 2, 1, 0, 0, 7, 2, 0, 0, 8, 3, 0, 0},
                   literals, 2),
            ERC7730_CATALOG_BAD_PROGRAM);  // threshold is an address

  // native aliases (role 22): a set of at most ERC7730_CAP_ALIAS_SET_MAX
  auto aliasSet = [&](uint16_t members) {
    std::vector<uint8_t> out;
    for (uint16_t i = 0; i < members; i++)
      out.insert(out.end(), address_literal.begin(), address_literal.end());
    out.insert(out.end(),
               {9, 0, (uint8_t)(2 + 2 * members), 0, (uint8_t)members});
    for (uint16_t i = 0; i < members; i++)
      out.insert(out.end(), {0, (uint8_t)i});
    return out;
  };
  for (uint16_t members : {(uint16_t)ERC7730_CAP_ALIAS_SET_MAX,
                           (uint16_t)(ERC7730_CAP_ALIAS_SET_MAX + 1)}) {
    EXPECT_EQ(
        result({3, 0, 3, 1, 1, 0, 1, 2, 1, 0, 0, 22, 2, 0, (uint8_t)members},
               aliasSet(members), (uint16_t)(members + 1)),
        members <= ERC7730_CAP_ALIAS_SET_MAX ? ERC7730_CATALOG_UNTRUSTED
                                             : ERC7730_CATALOG_BAD_PROGRAM)
        << members;
  }
}

TEST(Erc7730Catalog, PreloadTypeChecksAddressNameAndRawLiterals) {
  EXPECT_EQ(feedAll(envelope(tokenProgram({10, 0, 1, 1, 1, 0, 0})), 9),
            ERC7730_CATALOG_UNTRUSTED);
  EXPECT_EQ(feedAll(envelope(tokenProgram({10, 0, 1, 1, 1, 0, 1})), 9),
            ERC7730_CATALOG_BAD_PROGRAM);  // a uint is not an address
  EXPECT_EQ(feedAll(envelope(tokenProgram({10, 0, 1, 1, 1, 0, 3})), 9),
            ERC7730_CATALOG_UNTRUSTED);  // @.to

  // raw of a signed constant string (literal kind 4 -> string 0)
  EXPECT_EQ(
      feedAll(envelope(tokenProgram({1, 0, 1, 1, 1, 0, 2}, {4, 0, 2, 0, 0}, 1)),
              9),
      ERC7730_CATALOG_UNTRUSTED);
  EXPECT_EQ(
      feedAll(envelope(tokenProgram({1, 0, 1, 1, 1, 0, 2}, {3, 0, 1, 0xaa}, 1)),
              9),
      ERC7730_CATALOG_BAD_PROGRAM);  // raw bytes literals are not executed
}

TEST(Erc7730Catalog, ContainersAreCalldataOnly) {
  const std::vector<uint8_t> two_paths = {
      1, 1, 0xff, 0xff, 1, 0, 0, 0, 0,  // token
      1, 1, 0xff, 0xff, 1, 0, 0, 0, 1,  // amount
  };
  auto with_container = two_paths;
  with_container.insert(with_container.end(), {2, 0, 0, 2});  // @.to
  for (uint8_t kind : {(uint8_t)ERC7730_DEFINITION_CALLDATA,
                       (uint8_t)ERC7730_DEFINITION_EIP712}) {
    auto control =
        replaceTable(tokenProgram({10, 0, 1, 1, 1, 0, 0}), 3, two_paths, 2);
    auto p = replaceTable(tokenProgram({10, 0, 1, 1, 1, 0, 0}), 3,
                          with_container, 3);
    control[7] = p[7] = kind;
    EXPECT_EQ(feedAll(envelope(control), 9), ERC7730_CATALOG_UNTRUSTED)
        << (int)kind;
    EXPECT_EQ(feedAll(envelope(p), 9), kind == ERC7730_DEFINITION_CALLDATA
                                           ? ERC7730_CATALOG_UNTRUSTED
                                           : ERC7730_CATALOG_BAD_PROGRAM)
        << (int)kind;
  }
}

TEST(Erc7730Catalog, DisplayReaderCountsTheInterpolatedIntentRun) {
  // intent, text, value, text, field, value-after-field, end
  const std::vector<uint8_t> display = {
      0,  7,                                      //
      1,  0, 0,    0,    0xff, 0xff, 0xff, 0xff,  //
      2,  0, 0,    0,    0xff, 0xff, 0xff, 0xff,  //
      3,  0, 0,    0,    0xff, 0xff, 0xff, 0xff,  //
      2,  0, 0,    1,    0xff, 0xff, 0xff, 0xff,  //
      4,  0, 0,    0,    0,    0,    0xff, 0xff,  //
      3,  0, 0,    0,    0xff, 0xff, 0xff, 0xff,  //
      10, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  Erc7730ProgramDisplay reader{};
  erc7730_program_display_begin(&reader, display.size(), 2);
  ASSERT_TRUE(
      erc7730_program_display_feed(&reader, 0, display.data(), display.size()));
  EXPECT_EQ(reader.intent_parts, 3);
}

namespace {

// Replace the string table of `p` (entries must already be sorted).
std::vector<uint8_t> withStrings(std::vector<uint8_t> p,
                                 const std::vector<std::string>& strings) {
  std::vector<uint8_t> payload;
  append16(payload, (uint16_t)strings.size());
  size_t longest = 0;
  for (const auto& value : strings) {
    append16(payload, (uint16_t)value.size());
    payload.insert(payload.end(), value.begin(), value.end());
    longest = std::max(longest, value.size());
  }
  std::vector<uint8_t> encoded;
  section(encoded, 1, payload);
  const size_t old = sectionOffset(p, 1);
  const uint32_t old_payload = ((uint32_t)p[old + 1] << 24) |
                               ((uint32_t)p[old + 2] << 16) |
                               ((uint32_t)p[old + 3] << 8) | p[old + 4];
  p.erase(p.begin() + old, p.begin() + old + 5 + old_payload);
  p.insert(p.begin() + old, encoded.begin(), encoded.end());
  const size_t resource = sectionOffset(p, 9) + 5;
  p[resource] = (uint8_t)(strings.size() >> 8);
  p[resource + 1] = (uint8_t)strings.size();
  p[resource + 20] = (uint8_t)(longest >> 8);
  p[resource + 21] = (uint8_t)longest;
  return p;
}

Erc7730CatalogResult phaseC(const std::vector<uint8_t>& formatter,
                            const std::vector<uint8_t>& literals = {},
                            uint16_t literal_count = 0) {
  // strings: 0 "Test", 1 "blockheight", 2 "kg", 3 "timestamp" (sorted)
  auto p = withStrings(tokenProgram(formatter, literals, literal_count),
                       {"Test", "blockheight", "kg", "timestamp"});
  return feedAll(envelope(p), 13);
}

}  // namespace

// Every argument of amount, nftName, date, duration, unit and enum
// is type-checked at preload, including the values the runtime interprets:
// a date encoding must be "timestamp" or "blockheight", unit decimals must
// fit a byte, and an enum map is bounded.
TEST(Erc7730Catalog, PreloadTypeChecksPhaseCArguments) {
  // amount: an integer; the fixture's @.to (path 3) is an address.
  EXPECT_EQ(phaseC({2, 0, 1, 1, 1, 0, 1}), ERC7730_CATALOG_UNTRUSTED);
  EXPECT_EQ(phaseC({2, 0, 1, 1, 1, 0, 3}), ERC7730_CATALOG_BAD_PROGRAM);
  // nftName: token id, collection address
  EXPECT_EQ(phaseC({4, 0, 2, 1, 1, 0, 1, 3, 1, 0, 0}),
            ERC7730_CATALOG_UNTRUSTED);
  EXPECT_EQ(phaseC({4, 0, 2, 1, 1, 0, 1, 3, 1, 0, 1}),
            ERC7730_CATALOG_BAD_PROGRAM);
  // date: the encoding names a date encoding
  EXPECT_EQ(phaseC({5, 0, 2, 1, 1, 0, 1, 9, 3, 0, 3}),
            ERC7730_CATALOG_UNTRUSTED);
  EXPECT_EQ(phaseC({5, 0, 2, 1, 1, 0, 1, 9, 3, 0, 1}),
            ERC7730_CATALOG_UNTRUSTED);
  EXPECT_EQ(phaseC({5, 0, 2, 1, 1, 0, 1, 9, 3, 0, 2}),
            ERC7730_CATALOG_BAD_PROGRAM);  // "kg"
  // unit: decimals (one byte), base, prefix flag
  const std::vector<uint8_t> unit = {7, 0, 4, 1, 1, 0, 1, 4, 2, 0,
                                     0, 5, 3, 0, 2, 6, 2, 0, 1};
  EXPECT_EQ(phaseC(unit, {1, 0, 1, 18, 6, 0, 1, 1}, 2),
            ERC7730_CATALOG_UNTRUSTED);
  EXPECT_EQ(phaseC(unit, {1, 0, 2, 1, 0, 6, 0, 1, 1}, 2),
            ERC7730_CATALOG_BAD_PROGRAM);  // 256 decimals
  // enum: a map of at most ERC7730_CAP_ENUM_MAX entries
  auto enumMap = [](uint16_t entries) {
    std::vector<uint8_t> out;
    for (uint16_t i = 0; i < entries; i++)
      out.insert(out.end(), {1, 0, 1, (uint8_t)(i + 1)});
    out.insert(out.end(),
               {8, 0, (uint8_t)(2 + 4 * entries), 0, (uint8_t)entries});
    for (uint16_t i = 0; i < entries; i++)
      out.insert(out.end(), {0, (uint8_t)i, 0, 0});
    return out;
  };
  for (uint16_t entries :
       {(uint16_t)ERC7730_CAP_ENUM_MAX, (uint16_t)(ERC7730_CAP_ENUM_MAX + 1)}) {
    EXPECT_EQ(phaseC({8, 0, 2, 1, 1, 0, 1, 10, 2, 0, (uint8_t)entries},
                     enumMap(entries), (uint16_t)(entries + 1)),
              entries <= ERC7730_CAP_ENUM_MAX ? ERC7730_CATALOG_UNTRUSTED
                                              : ERC7730_CATALOG_BAD_PROGRAM)
        << entries;
  }
}

namespace {

// f(address[] a, address[] b); paths 0 = a.[] and 1 = b.[]; formatters
// 0 = addressName(a.[]) and 1 = addressName(b.[]); then `display`.
std::vector<uint8_t> iterationProgram(const std::vector<uint8_t>& display,
                                      uint16_t count, uint8_t depth) {
  auto p = withAbi(rawFieldProgram({1, 1, 0xff, 0xff, 1, 0, 0, 0, 0}),
                   {8, 0, 0, 0, 1, 0, 2, 0,    0,     // root
                    9, 0, 0, 0, 3, 0, 1, 0xff, 0xff,  // a: address[]
                    9, 0, 0, 0, 4, 0, 1, 0xff, 0xff,  // b: address[]
                    3, 0, 0, 0, 0, 0, 0, 0,    0,     //
                    3, 0, 0, 0, 0, 0, 0, 0,    0},    //
                   3);
  p = replaceTable(p, 3, {1, 2, 0xff, 0xff, 1, 0, 0, 0, 0, 2,   // a.[]
                          1, 2, 0xff, 0xff, 1, 0, 0, 0, 1, 2},  // b.[]
                   2);
  p = replaceTable(p, 6, {10, 0, 1, 1, 1, 0, 0, 10, 0, 1, 1, 1, 0, 1}, 2);
  p = replaceTable(p, 7, display, count);
  p[sectionOffset(p, 9) + 5 + 17] = 64;  // declares iteration
  p[sectionOffset(p, 9) + 5 + 18] = depth;
  return p;
}

const uint8_t kIntent[] = {1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff};
const uint8_t kEnd[] = {10, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

std::vector<uint8_t> displays(
    std::initializer_list<std::vector<uint8_t>> body) {
  std::vector<uint8_t> out(kIntent, kIntent + 8);
  for (const auto& instruction : body)
    out.insert(out.end(), instruction.begin(), instruction.end());
  out.insert(out.end(), kEnd, kEnd + 8);
  return out;
}

// Opening a frame (the second display instruction) must leave the path
// classes in signature[] untouched.
void expectFrameKeepsPathClasses(const std::vector<uint8_t>& program) {
  const auto signed_envelope = envelope(program);
  const auto id = digest(signed_envelope);
  Erc7730CatalogVerifier verifier;
  Erc7730CatalogIdentity identity = {};
  erc7730_catalog_begin(&verifier, id.data(), signed_envelope.size());
  const size_t before_begin = 10u + sectionOffset(program, 7) + 5u + 2u + 8u;
  ASSERT_EQ(erc7730_catalog_feed(&verifier, 0, signed_envelope.data(),
                                 before_begin, &identity),
            ERC7730_CATALOG_MORE);
  uint8_t classes[5];
  memcpy(classes, verifier.signature, sizeof(classes));
  ASSERT_EQ(
      erc7730_catalog_feed(&verifier, before_begin,
                           signed_envelope.data() + before_begin, 8, &identity),
      ERC7730_CATALOG_MORE);
  EXPECT_EQ(memcmp(classes, verifier.signature, sizeof(classes)), 0);
  erc7730_catalog_abort(&verifier);
}

}  // namespace

// An iteration walks one array, reached through tuples only, in a
// calldata definition; every field inside reads that array, and a field that
// iterates appears only inside an iteration.
TEST(Erc7730Catalog, PreloadChecksIterationAgainstTheArrayItWalks) {
  const std::vector<uint8_t> begin_a = {7, 0, 0, 0, 0xff, 0xff, 0, 3};
  const std::vector<uint8_t> field_a = {4, 0, 0, 0, 0, 0, 0xff, 0xff};
  const std::vector<uint8_t> field_b = {4, 0, 0, 0, 0, 1, 0xff, 0xff};
  const std::vector<uint8_t> end = {8, 0, 0, 1, 0xff, 0xff, 0xff, 0xff};
  auto p = iterationProgram(displays({begin_a, field_a, end}), 5, 1);
  EXPECT_EQ(feedAll(envelope(p), 11), ERC7730_CATALOG_UNTRUSTED);
  // Typed data never iterates.
  p[7] = ERC7730_DEFINITION_EIP712;
  EXPECT_EQ(feedAll(envelope(p), 11), ERC7730_CATALOG_BAD_PROGRAM);
  // A field inside that reads another array.
  p = iterationProgram(displays({begin_a, field_b, end}), 5, 1);
  EXPECT_EQ(feedAll(envelope(p), 11), ERC7730_CATALOG_BAD_PROGRAM);
  // A scalar value inside an iteration cannot be repeated for every item.
  const std::vector<uint8_t> scalar_field = {4, 0, 0, 0, 0, 2, 0xff, 0xff};
  p = iterationProgram(displays({begin_a, scalar_field, end}), 5, 1);
  p = replaceTable(p, 3, {1,    2,    0xff, 0xff, 1, 0, 0, 0, 0, 2, 1, 2,
                          0xff, 0xff, 1,    0,    0, 0, 1, 2, 2, 0, 0, 2},
                   3);
  p = replaceTable(
      p, 6, {10, 0, 1, 1, 1, 0, 0, 10, 0, 1, 1, 1, 0, 1, 10, 0, 1, 1, 1, 0, 2},
      3);
  EXPECT_EQ(feedAll(envelope(p), 11), ERC7730_CATALOG_BAD_PROGRAM);
  // An iterating field outside any iteration.
  p = iterationProgram(displays({field_a}), 3, 0);
  EXPECT_EQ(feedAll(envelope(p), 11), ERC7730_CATALOG_BAD_PROGRAM);
  // An iteration inside an iteration.
  p = iterationProgram(displays({{7, 0, 0, 0, 0xff, 0xff, 0, 5},
                                 {7, 0, 0, 1, 0xff, 0xff, 0, 4},
                                 field_b,
                                 {8, 0, 0, 2, 0xff, 0xff, 0xff, 0xff},
                                 {8, 0, 0, 1, 0xff, 0xff, 0xff, 0xff}}),
                       7, 2);
  EXPECT_EQ(feedAll(envelope(p), 11), ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, DisplayFramesPreservePathClasses) {
  const std::vector<uint8_t> begin_a = {7, 0, 0, 0, 0xff, 0xff, 0, 3};
  const std::vector<uint8_t> field_a = {4, 0, 0, 0, 0, 0, 0xff, 0xff};
  const std::vector<uint8_t> end = {8, 0, 0, 1, 0xff, 0xff, 0xff, 0xff};
  expectFrameKeepsPathClasses(
      iterationProgram(displays({begin_a, field_a, end}), 5, 1));
}

TEST(Erc7730Catalog, IterationPathsReachTheirArrayThroughTuplesOnly) {
  // (address[] x)[2] items: items.[1].x.[] indexes an array before iterating.
  const std::vector<uint8_t> nodes = {
      8, 0, 0, 0, 1, 0, 1, 0,    0,     // root
      9, 0, 0, 0, 2, 0, 1, 0,    2,     // items: (..)[2]
      8, 0, 0, 0, 3, 0, 1, 0,    0,     // (address[] x)
      9, 0, 0, 0, 4, 0, 1, 0xff, 0xff,  // x
      3, 0, 0, 0, 0, 0, 0, 0,    0};    // address
  auto indexed = withAbi(programWithPaths({1, 4, 0xff, 0xff, 1, 0, 0, 0, 0, 1,
                                           0, 0, 0,    1,    1, 0, 0, 0, 0, 2},
                                          1),
                         nodes, 5);
  EXPECT_EQ(feedAll(envelope(indexed), 11), ERC7730_CATALOG_BAD_PROGRAM);
  // items.[].x.[0]: iterating the outer array, then indexing, is fine.
  auto outer = withAbi(programWithPaths({1, 4, 0xff, 0xff, 1, 0, 0, 0, 0, 2,
                                         1, 0, 0,    0,    0, 1, 0, 0, 0, 0},
                                        1),
                       nodes, 5);
  EXPECT_EQ(feedAll(envelope(outer), 11), ERC7730_CATALOG_UNTRUSTED);
}

// Shapes that would fail mid-review, or take a fact from the wrong source,
// are decided at preload. Each refusal sits next to its accepted neighbour.
TEST(Erc7730Catalog, OnlyARawFieldShowsASignerConstant) {
  // A formatter shows a value the device decodes. amount(literal) of one or
  // two bytes is refused; amount(the uint256 argument) and raw(literal) run.
  for (const auto& literal : std::vector<std::vector<uint8_t>>{
           {1, 0, 1, 0x05}, {1, 0, 2, 0x03, 0xe8}}) {
    EXPECT_EQ(
        feedAll(envelope(tokenProgram({2, 0, 1, 1, 1, 0, 2}, literal, 1)), 9),
        ERC7730_CATALOG_BAD_PROGRAM)
        << literal.size();
    EXPECT_EQ(
        feedAll(envelope(tokenProgram({1, 0, 1, 1, 1, 0, 2}, literal, 1)), 9),
        ERC7730_CATALOG_UNTRUSTED)
        << literal.size();
  }
  EXPECT_EQ(feedAll(envelope(tokenProgram({2, 0, 1, 1, 1, 0, 1})), 9),
            ERC7730_CATALOG_UNTRUSTED);
}

TEST(Erc7730Catalog, AnEnumMapsADecodedValueNeverAConstant) {
  // literal 0 = 1 (the constant, also the map's key); literal 1 = a
  // one-entry map. Path 2 is literal 0, path 1 the uint256 argument.
  const std::vector<uint8_t> literals = {1, 0, 1, 1,  //
                                         8, 0, 6, 0, 1, 0, 0, 0, 0};
  EXPECT_EQ(feedAll(envelope(tokenProgram({8, 0, 2, 1, 1, 0, 1, 10, 2, 0, 1},
                                          literals, 2)),
                    11),
            ERC7730_CATALOG_UNTRUSTED);
  EXPECT_EQ(feedAll(envelope(tokenProgram({8, 0, 2, 1, 1, 0, 2, 10, 2, 0, 1},
                                          literals, 2)),
                    11),
            ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, SignerTextAndDecimalsFitTheScreenAtPreload) {
  const std::string fits(ERC7730_CAP_SIGNER_TEXT_MAX, 'L');
  const std::string long_text(ERC7730_CAP_SIGNER_TEXT_MAX + 1u, 'L');
  // A field label (string 0 of rawFieldProgram's display).
  const std::vector<uint8_t> path = {1, 1, 0xff, 0xff, 1, 0, 0, 0, 0};
  EXPECT_EQ(feedAll(envelope(withStrings(rawFieldProgram(path), {fits})), 9),
            ERC7730_CATALOG_UNTRUSTED);
  EXPECT_EQ(
      feedAll(envelope(withStrings(rawFieldProgram(path), {long_text})), 9),
      ERC7730_CATALOG_BAD_PROGRAM);
  // unit decimals 77 runs; 78 is refused.
  const std::vector<uint8_t> unit = {7, 0, 4, 1, 1, 0, 1, 4, 2, 0,
                                     0, 5, 3, 0, 2, 6, 2, 0, 1};
  EXPECT_EQ(phaseC(unit, {1, 0, 1, 77, 6, 0, 1, 1}, 2),
            ERC7730_CATALOG_UNTRUSTED);
  EXPECT_EQ(phaseC(unit, {1, 0, 1, 78, 6, 0, 1, 1}, 2),
            ERC7730_CATALOG_BAD_PROGRAM);
  // Signer text inside a value's screen: a unit base, a threshold message
  // and an enum label. String 2 is the text under test; strings sort, and
  // "k..." falls between "blockheight" and "timestamp".
  const std::string fits_k(ERC7730_CAP_SIGNER_TEXT_MAX, 'k');
  const std::string long_k(ERC7730_CAP_SIGNER_TEXT_MAX + 1u, 'k');
  auto signerText = [](const std::vector<uint8_t>& formatter,
                       const std::vector<uint8_t>& literals, uint16_t count,
                       const std::string& text) {
    return feedAll(
        envelope(withStrings(tokenProgram(formatter, literals, count),
                             {"Test", "blockheight", text, "timestamp"})),
        13);
  };
  const std::vector<uint8_t> threshold = {3, 0, 4, 1, 1, 0, 1, 2, 1, 0,
                                          0, 7, 2, 0, 0, 8, 3, 0, 2};
  const std::vector<uint8_t> enumeration = {8, 0, 2, 1, 1, 0, 1, 10, 2, 0, 1};
  const std::vector<uint8_t> label_map = {1, 0, 1, 1,  //
                                          8, 0, 6, 0, 1, 0, 0, 0, 2};
  for (const auto& text : {fits_k, long_k}) {
    const auto expected = text.size() <= ERC7730_CAP_SIGNER_TEXT_MAX
                              ? ERC7730_CATALOG_UNTRUSTED
                              : ERC7730_CATALOG_BAD_PROGRAM;
    EXPECT_EQ(signerText(unit, {1, 0, 1, 18, 6, 0, 1, 1}, 2, text), expected)
        << "unit base " << text.size();
    EXPECT_EQ(signerText(threshold, {1, 0, 1, 5}, 1, text), expected)
        << "threshold message " << text.size();
    EXPECT_EQ(signerText(enumeration, label_map, 2, text), expected)
        << "enum label " << text.size();
  }
}

namespace {

// f(address to, bytes data): paths 0 = to, 1 = data, 2 = literal 0, 3 = @.to.
std::vector<uint8_t> embeddedProgram(const std::vector<uint8_t>& formatter,
                                     const std::vector<uint8_t>& display = {},
                                     uint16_t display_count = 0) {
  auto p = withAbi(rawFieldProgram({1, 1, 0xff, 0xff, 1, 0, 0, 0, 0}),
                   {8, 0, 0, 0, 1, 0, 2, 0, 0,   // (address, bytes)
                    3, 0, 0, 0, 0, 0, 0, 0, 0,   //
                    6, 0, 0, 0, 0, 0, 0, 0, 0},  //
                   2);
  p = replaceTable(p, 3, {1, 1, 0xff, 0xff, 1, 0, 0, 0, 0,  // to
                          1, 1, 0xff, 0xff, 1, 0, 0, 0, 1,  // data
                          3, 0, 0,    0,                    // literal 0
                          2, 0, 0,    2},                   // @.to
                   4);
  std::vector<uint8_t> address = {5, 0, 20};
  address.resize(23, 0x22);
  p = programWithTableFrom(p, 4, address, 1);
  p = replaceTable(p, 6, formatter, 1);
  if (display_count) p = replaceTable(p, 7, display, display_count);
  return p;
}

}  // namespace

TEST(Erc7730Catalog, EmbeddedCallsTakeTheirCalleeFromCalldata) {
  EXPECT_EQ(
      feedAll(envelope(embeddedProgram({13, 0, 2, 1, 1, 0, 1, 15, 1, 0, 0})),
              9),
      ERC7730_CATALOG_UNTRUSTED);
  EXPECT_EQ(
      feedAll(envelope(embeddedProgram({13, 0, 2, 1, 1, 0, 1, 15, 1, 0, 3})),
              9),
      ERC7730_CATALOG_UNTRUSTED);  // @.to
  EXPECT_EQ(
      feedAll(envelope(embeddedProgram({13, 0, 2, 1, 1, 0, 1, 15, 1, 0, 2})),
              9),
      ERC7730_CATALOG_BAD_PROGRAM);  // a signer constant
  // Nor its authority (role 18, literal 0 is an address). The value (role
  // 17) is checked the same way; the fixture has no numeric literal path.
  EXPECT_EQ(feedAll(envelope(embeddedProgram(
                        {13, 0, 3, 1, 1, 0, 1, 15, 1, 0, 0, 18, 1, 0, 0})),
                    9),
            ERC7730_CATALOG_UNTRUSTED);  // authority from calldata
  EXPECT_EQ(feedAll(envelope(embeddedProgram(
                        {13, 0, 3, 1, 1, 0, 1, 15, 1, 0, 0, 18, 1, 0, 2})),
                    9),
            ERC7730_CATALOG_BAD_PROGRAM);  // a signer constant
  // Typed data never runs embedded calls.
  auto typed = embeddedProgram({13, 0, 2, 1, 1, 0, 1, 15, 1, 0, 0});
  auto typed_paths = replaceTable(
      typed, 3,
      {1, 1, 0xff, 0xff, 1, 0, 0, 0, 0, 1, 1, 0xff, 0xff, 1, 0, 0, 0, 1}, 2);
  typed_paths[7] = ERC7730_DEFINITION_EIP712;
  EXPECT_EQ(feedAll(envelope(typed_paths), 9), ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, AnEmbeddedCallIsNeverAnIntentPart) {
  const std::vector<uint8_t> formatter = {13, 0, 2, 1, 1, 0, 1, 15, 1, 0, 0};
  const std::vector<uint8_t> as_field = {
      1,  0, 0,    0,    0xff, 0xff, 0xff, 0xff,  //
      4,  0, 0,    0,    0,    0,    0xff, 0xff,  //
      10, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  EXPECT_EQ(feedAll(envelope(embeddedProgram(formatter, as_field, 3)), 9),
            ERC7730_CATALOG_UNTRUSTED);
  const std::vector<uint8_t> as_intent = {
      1,  0, 0,    0,    0xff, 0xff, 0xff, 0xff,  //
      3,  0, 0,    0,    0xff, 0xff, 0xff, 0xff,  //
      4,  0, 0,    0,    0,    0,    0xff, 0xff,  //
      10, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  EXPECT_EQ(feedAll(envelope(embeddedProgram(formatter, as_intent, 4)), 9),
            ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, ASignerConstantIsNeverAnIntentValue) {
  // "Intent value i of n" names a value the device decoded. raw(literal 0,
  // a signed address) may be a field but not an intent value; raw(to), read
  // from calldata, may be both.
  const std::vector<uint8_t> as_intent = {
      1,  0, 0,    0,    0xff, 0xff, 0xff, 0xff,  //
      3,  0, 0,    0,    0xff, 0xff, 0xff, 0xff,  //
      4,  0, 0,    0,    0,    0,    0xff, 0xff,  //
      10, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  EXPECT_EQ(
      feedAll(envelope(embeddedProgram({1, 0, 1, 1, 1, 0, 0}, as_intent, 4)),
              9),
      ERC7730_CATALOG_UNTRUSTED);
  EXPECT_EQ(
      feedAll(envelope(embeddedProgram({1, 0, 1, 1, 1, 0, 2}, as_intent, 4)),
              9),
      ERC7730_CATALOG_BAD_PROGRAM);
  const std::vector<uint8_t> as_field = {
      1,  0, 0,    0,    0xff, 0xff, 0xff, 0xff,  //
      4,  0, 0,    0,    0,    0,    0xff, 0xff,  //
      10, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  EXPECT_EQ(
      feedAll(envelope(embeddedProgram({1, 0, 1, 1, 1, 0, 2}, as_field, 3)), 9),
      ERC7730_CATALOG_UNTRUSTED);
}

TEST(Erc7730Catalog, GroupFramesPreservePathClasses) {
  const std::vector<uint8_t> group = {
      1,    0,    0,    0,    0xff, 0xff, 0xff, 0xff, 5,    0,
      0xff, 0xff, 0xff, 0xff, 0,    3,    4,    0,    0,    0,
      0,    0,    0xff, 0xff, 6,    0,    0,    1,    0xff, 0xff,
      0xff, 0xff, 10,   0,    0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  auto program = replaceTable(
      rawFieldProgram({1, 1, 0xff, 0xff, 1, 0, 0, 0, 0}), 7, group, 5);
  program[sectionOffset(program, 9) + 5 + 18] = 1;
  expectFrameKeepsPathClasses(program);
}
