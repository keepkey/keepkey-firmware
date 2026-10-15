extern "C" {
#include "keepkey/firmware/clearsign_root.h"
#include "keepkey/firmware/erc7730_capabilities.h"
#include "keepkey/firmware/erc7730_catalog.h"
#include "keepkey/firmware/erc7730_program.h"
#include "keepkey/board/memory.h"
#include "keepkey/firmware/erc7730_workflow.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/erc7730_workflow.h"
#include "keepkey/board/memory.h"
#include "messages-ethereum.pb.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"
void setup(void);
}

#include "clearsign_test_cert.h"
#include "gtest/gtest.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

bool kkconfirm_preload(int, int);
int kkconfirm_drain(void);
void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);
bool kkconfirm_readResponse(uint16_t, const pb_field_t*, void*);

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
class Erc7730SigningHandlers : public ::testing::Test {
 protected:
  std::vector<uint8_t> flash = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  uint8_t* previous;
  void SetUp() override {
    ASSERT_TRUE(kkconfirm_preload(0, 0));
    ASSERT_EQ(0, kkconfirm_drain());
    previous = emulator_flash_base;
    emulator_flash_base = flash.data();
    storage_init();
    LoadDevice load = {};
    load.has_mnemonic = true;
    strcpy(load.mnemonic, "all all all all all all all all all all all all");
    storage_loadDevice(&load);
    ASSERT_TRUE(storage_isInitialized());
    fsm_test_clearLastFailure();
  }
  void TearDown() override {
    fsm_abort_workflows();
    erc7730_catalog_clear_preload();
    signed_metadata_clear_signers();
    kkconfirm_drain();
    storage_wipe();
    storage_reset();
    emulator_flash_base = previous;
  }
  void prepare(const uint8_t selector[4], EthereumSignTx* tx) {
    SignedFixture signer;
    loadRuntimeSigner(&signer, "Allowance regression signer");
    auto program = minimalProgram();
    memcpy(program.data() + 38, selector, 4);
    const auto envelope = signedEnvelope(signer, program);
    const auto id = digest(envelope);
    uint32_t next = 0;
    bool complete = false;
    ASSERT_EQ(ERC7730_CATALOG_COMPLETE,
              erc7730_catalog_preload_chunk(id.data(), 0, envelope.size(),
                                            envelope.data(), envelope.size(),
                                            &next, &complete));
    ASSERT_TRUE(complete);
    Erc7730CatalogIdentity identity = {};
    ASSERT_TRUE(erc7730_catalog_preloaded(&identity));
    *tx = {};
    tx->has_chain_id = tx->has_to = tx->has_data_length =
        tx->has_data_initial_chunk = true;
    tx->chain_id = 1;
    tx->to.size = 20;
    tx->to.bytes[0] = 0x11;
    tx->data_length = 68;
    tx->data_initial_chunk.size = 4;
    memcpy(tx->data_initial_chunk.bytes, selector, 4);
    ASSERT_TRUE(erc7730_catalog_matches_calldata(&identity, tx->chain_id,
                                                 tx->to.bytes, selector));
  }
};

TEST_F(Erc7730SigningHandlers,
       CertifiedAllowancesFailBeforeDefinitionReplayOrConsent) {
  const uint8_t selectors[][4] = {
      {0x09, 0x5e, 0xa7, 0xb3},   // approve
      {0x39, 0x50, 0x93, 0x51}};  // increaseAllowance
  for (const auto& selector : selectors) {
    EthereumSignTx tx;
    prepare(selector, &tx);
    ASSERT_FALSE(HasFatalFailure());
    ASSERT_TRUE(kkconfirm_preload(0, 0));
    fsm_test_clearLastFailure();
    kkconfirm_capture_start();
    fsm_msgEthereumSignTx(&tx);
    EXPECT_TRUE(kkconfirm_capture_finish().empty());
    EXPECT_EQ(FailureType_Failure_SyntaxError, fsm_test_lastFailureCode());
    EXPECT_STREQ("ERC-7730 approval not supported",
                 fsm_test_lastFailureMessage());
    EXPECT_FALSE(erc7730_workflow_active(erc7730_workflow_state()));
    Erc7730CatalogIdentity identity = {};
    EXPECT_FALSE(erc7730_catalog_preloaded(&identity));
    Failure refusal = {};
    ASSERT_TRUE(kkconfirm_readResponse(MessageType_MessageType_Failure,
                                       Failure_fields, &refusal));
    EXPECT_EQ(FailureType_Failure_SyntaxError, refusal.code);
    EXPECT_STREQ("ERC-7730 approval not supported", refusal.message);
    EthereumTxRequest signature = {};
    EXPECT_FALSE(
        kkconfirm_readResponse(MessageType_MessageType_EthereumTxRequest,
                               EthereumTxRequest_fields, &signature));
    EXPECT_EQ(0, kkconfirm_drain());
  }
}

TEST_F(Erc7730SigningHandlers,
       CertifiedNonAllowanceControlStartsDefinitionReplay) {
  const uint8_t selector[4] = {0xaa, 0xbb, 0xcc, 0xdd};
  EthereumSignTx tx;
  prepare(selector, &tx);
  ASSERT_FALSE(HasFatalFailure());
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  kkconfirm_capture_start();
  fsm_msgEthereumSignTx(&tx);
  EXPECT_TRUE(kkconfirm_capture_finish().empty());
  EXPECT_EQ(0, fsm_test_lastFailureCode());
  EXPECT_EQ(ERC7730_WORKFLOW_REPLAY, erc7730_workflow_state()->phase);
  EthereumClearSignDefinitionRequest request = {};
  EXPECT_TRUE(kkconfirm_readResponse(
      MessageType_MessageType_EthereumClearSignDefinitionRequest,
      EthereumClearSignDefinitionRequest_fields, &request));
  EXPECT_EQ(0, kkconfirm_drain());
}

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

TEST(Erc7730Catalog, RuntimeSignedDefinitionIsRuntimeTier) {
  SignedFixture fixture;
  loadRuntimeSigner(&fixture, "Approved signer");
  Erc7730CatalogIdentity identity{};
  ASSERT_EQ(feedIdentity(signedEnvelope(fixture, minimalProgram()), &identity),
            ERC7730_CATALOG_COMPLETE);
  EXPECT_EQ(identity.tier, (uint8_t)METADATA_TIER_RUNTIME);
  signed_metadata_clear_signers();
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
}

namespace {

// The compiled-in root's private key exists only on the root KeepKey, so the
// certified fixtures are signed here under a test root that the emulator-only
// hook substitutes for it (clearsign_root_set_test_root).
struct CertifiedFixture {
  uint8_t root_key[32];
  uint8_t root_pubkey[33];
  SignedFixture delegate;
};

// Restores the compiled-in root however the test ends.
struct TestRoot {
  explicit TestRoot(const uint8_t* pubkey) {
    clearsign_root_set_test_root(pubkey);
  }
  ~TestRoot() { clearsign_root_set_test_root(nullptr); }
};

void makeCertifiedFixture(CertifiedFixture* fixture) {
  if (storage_getLocation() == FLASH_INVALID) {
    setup();
    storage_init();
  }
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
  signed_metadata_clear_signers();  // no runtime signer is loaded
  memset(fixture, 0, sizeof(*fixture));
  fixture->root_key[31] = 0x52;
  fixture->delegate.key[31] = 0x44;
  ecdsa_get_public_key33(&secp256k1, fixture->root_key, fixture->root_pubkey);
  ecdsa_get_public_key33(&secp256k1, fixture->delegate.key,
                         fixture->delegate.pubkey);
}

// The delegate signs the catalog root exactly as on the runtime tier; the
// record carries its root certificate.
std::vector<uint8_t> certifiedEnvelope(
    const CertifiedFixture& fixture, const std::vector<uint8_t>& program,
    const std::vector<uint8_t>& cert,
    const std::vector<uint8_t>& purpose =
        std::vector<uint8_t>(kPurpose, kPurpose + sizeof(kPurpose) - 1)) {
  auto e = signedEnvelope(fixture.delegate, program, {}, purpose);
  std::copy(cert.begin(), cert.end(), e.begin() + certOffset(program, 0));
  return e;
}

}  // namespace

TEST(Erc7730Catalog, RootCertifiedDefinitionVerifiesWithoutRuntimeSigner) {
  CertifiedFixture fixture;
  makeCertifiedFixture(&fixture);
  TestRoot root(fixture.root_pubkey);
  auto program = minimalProgram();
  auto e = certifiedEnvelope(
      fixture, program, rootCert(fixture.root_key, fixture.delegate.pubkey));
  Erc7730CatalogIdentity identity{};
  ASSERT_EQ(feedIdentity(e, &identity), ERC7730_CATALOG_COMPLETE);
  EXPECT_EQ(identity.tier, (uint8_t)METADATA_TIER_KEEPKEY);
  // The alias shown is the one the root signed.
  EXPECT_STREQ(identity.delegate_alias, "KeepKey Test");
  char fingerprint[METADATA_FINGERPRINT_LEN];
  signed_metadata_pubkey_fingerprint(fixture.delegate.pubkey, fingerprint);
  EXPECT_STREQ(identity.delegate_fingerprint, fingerprint);
  EXPECT_EQ(feedAll(e, 1), ERC7730_CATALOG_COMPLETE);

  // D-007: a certified definition verifies without AdvancedMode.
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
  Erc7730CatalogIdentity off{};
  ASSERT_EQ(feedIdentity(e, &off), ERC7730_CATALOG_COMPLETE);
  EXPECT_EQ(off.tier, (uint8_t)METADATA_TIER_KEEPKEY);
  EXPECT_STREQ(off.delegate_alias, "KeepKey Test");
}

TEST(Erc7730Catalog, RootCertificateDefectsAreRefused) {
  CertifiedFixture fixture;
  makeCertifiedFixture(&fixture);
  TestRoot root(fixture.root_pubkey);
  const uint8_t* delegate = fixture.delegate.pubkey;
  auto program = minimalProgram();
  const char other[] = "KEEPKEY:ERC7730:CATALOH\0";
  const std::vector<std::vector<uint8_t>> refused = {
      // Signed by a key that is not the root.
      certifiedEnvelope(fixture, program,
                        rootCert(fixture.delegate.key, delegate)),
      // Delegate signature under another purpose.
      certifiedEnvelope(fixture, program, rootCert(fixture.root_key, delegate),
                        std::vector<uint8_t>(other, other + sizeof(other) - 1)),
      // Scope is not the definition's chain id.
      certifiedEnvelope(fixture, program,
                        rootCert(fixture.root_key, delegate,
                                 CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, 2)),
      // No MAY_SUPPRESS_RAW.
      certifiedEnvelope(fixture, program,
                        rootCert(fixture.root_key, delegate, 0)),
      // Expired: not_after at the firmware's floor.
      certifiedEnvelope(
          fixture, program,
          rootCert(fixture.root_key, delegate, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW,
                   1, KK_CLEARSIGN_MIN_EXPIRY)),
      // Alias with a control byte.
      certifiedEnvelope(
          fixture, program,
          rootCert(fixture.root_key, delegate, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW,
                   1, KK_CLEARSIGN_MIN_EXPIRY + 1, "KeepKey\nTest")),
  };
  // With no runtime signer loaded there is nothing to fall back to, with
  // AdvancedMode on or off.
  for (bool advanced : {true, false}) {
    ASSERT_TRUE(storage_setPolicy("AdvancedMode", advanced));
    for (size_t i = 0; i < refused.size(); i++)
      EXPECT_EQ(feedAll(refused[i], 64), ERC7730_CATALOG_UNTRUSTED)
          << i << " advanced=" << advanced;
  }
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));

  // The same defect with the delegate loaded as a runtime signer falls back
  // to the runtime tier, under the alias the user approved.
  ASSERT_TRUE(signed_metadata_store_signer(3, delegate, "Approved signer",
                                           nullptr, 0, 0, 0, false));
  Erc7730CatalogIdentity identity{};
  ASSERT_EQ(feedIdentity(refused[0], &identity), ERC7730_CATALOG_COMPLETE);
  EXPECT_EQ(identity.tier, (uint8_t)METADATA_TIER_RUNTIME);
  EXPECT_STREQ(identity.delegate_alias, "Approved signer");
  // The runtime fallback is never reached without AdvancedMode.
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
  EXPECT_EQ(feedAll(refused[0], 64), ERC7730_CATALOG_UNTRUSTED);
  signed_metadata_clear_signers();
}

TEST(Erc7730Catalog, ChainIdAboveUint32IsRefusedNotTruncated) {
  CertifiedFixture fixture;
  makeCertifiedFixture(&fixture);
  TestRoot root(fixture.root_pubkey);
  // Chain id 2^32 + 1 truncates to the certificate's scope 1. It is refused
  // with the header, before any signature is checked, on either tier.
  auto program = minimalProgram();
  program[13] = 1;
  program[sectionOffset(program, 8) + 5 + 5 + 3] = 1;  // deployment chain id
  auto e = certifiedEnvelope(
      fixture, program, rootCert(fixture.root_key, fixture.delegate.pubkey));
  EXPECT_EQ(feedAll(e, 64), ERC7730_CATALOG_BAD_PROGRAM);
  ASSERT_TRUE(signed_metadata_store_signer(
      3, fixture.delegate.pubkey, "Approved signer", nullptr, 0, 0, 0, false));
  EXPECT_EQ(feedAll(signedEnvelope(fixture.delegate, program), 64),
            ERC7730_CATALOG_BAD_PROGRAM);
  signed_metadata_clear_signers();
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
}

TEST(Erc7730Catalog, SolanaScopeCertificateNeverCertifiesEvmChain501) {
  CertifiedFixture fixture;
  makeCertifiedFixture(&fixture);
  TestRoot root(fixture.root_pubkey);
  // EVM chain id 501 (header and deployment) under a root-signed scope-501
  // certificate, which the root issued for Solana.
  auto program = minimalProgram();
  const size_t deployment = sectionOffset(program, 8) + 5 + 5;
  program[16] = program[deployment + 6] = 0x01;
  program[17] = program[deployment + 7] = 0xf5;
  auto e = certifiedEnvelope(
      fixture, program,
      rootCert(fixture.root_key, fixture.delegate.pubkey,
               CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, CLEARSIGN_SCOPE_SOLANA));
  EXPECT_EQ(feedAll(e, 64), ERC7730_CATALOG_UNTRUSTED);
  // The same envelope is well formed: a runtime signer the user loaded
  // verifies it, on the AdvancedMode-gated runtime tier only.
  ASSERT_TRUE(signed_metadata_store_signer(
      3, fixture.delegate.pubkey, "Approved signer", nullptr, 0, 0, 0, false));
  Erc7730CatalogIdentity identity{};
  ASSERT_EQ(feedIdentity(e, &identity), ERC7730_CATALOG_COMPLETE);
  EXPECT_EQ(identity.tier, (uint8_t)METADATA_TIER_RUNTIME);
  signed_metadata_clear_signers();
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

// The declared id must be the envelope's own hash. The envelope here is
// validly signed, so the id comparison is the only thing that can refuse it.
TEST(Erc7730Catalog, RejectsDefinitionIdMismatch) {
  SignedFixture fixture;
  loadRuntimeSigner(&fixture, "Approved signer");
  const auto e = signedEnvelope(fixture, minimalProgram());
  for (bool wrong : {false, true}) {
    auto id = digest(e);
    if (wrong) id[0] ^= 1;
    Erc7730CatalogVerifier verifier;
    Erc7730CatalogIdentity identity = {};
    erc7730_catalog_begin(&verifier, id.data(), (uint32_t)e.size());
    EXPECT_EQ(erc7730_catalog_feed(&verifier, 0, e.data(), e.size(), &identity),
              wrong ? ERC7730_CATALOG_UNTRUSTED : ERC7730_CATALOG_COMPLETE);
    erc7730_catalog_abort(&verifier);
  }
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

  // root -> tuple -> uint256, each child after its parent: accepted.
  p = withAbi(minimalProgram(),
              {8, 0, 0, 0, 1, 0, 1, 0, 0,   // root -> node 1
               8, 0, 0, 0, 2, 0, 1, 0, 0,   // tuple -> node 2
               1, 1, 0, 0, 0, 0, 0, 0, 0},  // uint256
              3);
  EXPECT_EQ(feedAll(envelope(p), 43), ERC7730_CATALOG_UNTRUSTED);

  // The same tree with the child before its parent. Every node still has
  // exactly one parent, so only the forward-edge rule refuses it.
  p = withAbi(minimalProgram(),
              {8, 0, 0, 0, 2, 0, 1, 0, 0,   // root -> node 2
               1, 1, 0, 0, 0, 0, 0, 0, 0,   // uint256
               8, 0, 0, 0, 1, 0, 1, 0, 0},  // tuple -> node 1: backwards
              3);
  EXPECT_EQ(feedAll(envelope(p), 43), ERC7730_CATALOG_BAD_PROGRAM);

  // A tuple that is its own only parent.
  p = withAbi(minimalProgram(),
              {8, 0, 0, 0, 1, 0, 1, 0, 0,   // root -> node 1
               1, 1, 0, 0, 0, 0, 0, 0, 0,   // uint256
               8, 0, 0, 0, 2, 0, 1, 0, 0},  // tuple -> itself
              2);
  EXPECT_EQ(feedAll(envelope(p), 43), ERC7730_CATALOG_BAD_PROGRAM);

  // Two parents share a child: the edges all point forward, so only the
  // one-parent rule refuses it.
  p = withAbi(minimalProgram(),
              {8, 0, 0, 0, 1, 0, 2, 0, 0,   // root -> nodes 1 and 2
               8, 0, 0, 0, 2, 0, 1, 0, 0,   // tuple -> node 2 again
               1, 1, 0, 0, 0, 0, 0, 0, 0},  // uint256
              3);
  EXPECT_EQ(feedAll(envelope(p), 43), ERC7730_CATALOG_BAD_PROGRAM);
}

TEST(Erc7730Catalog, RecomputesSignedResourceDeclaration) {
  auto p = minimalProgram();
  p[p.size() - 22] = 1;  // claims 257 strings instead of one
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

  // @.from, @.to, @.value and a literal are executable value sources.
  for (const auto& entries : std::vector<std::vector<uint8_t>>{
           {2, 0, 0, 1}, {2, 0, 0, 2}, {2, 0, 0, 3}, {3, 0, 0, 0}}) {
    p = programWithPaths(entries, 1);
    EXPECT_EQ(feedAll(envelope(p), 23), ERC7730_CATALOG_UNTRUSTED);
  }

  // Slices, a whole-array step on the root tuple, the other containers, a
  // container with a step and an out-of-range literal index are refused.
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

// The verifier's path step limit does not cut into the paths an ABI admits:
// the deepest one, ERC7730_ABI_MAX_DEPTH - 1 steps, passes preload. One step
// more is refused, but that does not show the limit itself: ABI depth is
// capped at ERC7730_ABI_MAX_DEPTH and each step descends one level, so the
// walk has no node left for that step and refuses the path on its own.
TEST(Erc7730Catalog, PathStepLimitAdmitsTheDeepestAbiPath) {
  // Seven nested tuples above a uint256: depth eight, the ABI maximum, and a
  // seven-step path to the leaf.
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

  // The same operand with its source left a path: index 1 of one path. Only
  // the index bound can refuse this one.
  bad_formatter = formatter;
  bad_formatter[6] = 1;
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
// Each refusal below is paired with the runtime check that would have refused
// it mid-review.
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
  // An intent part after a field. The capability predicate sees one
  // instruction at a time and accepts it; the runtime refuses it because its
  // index lies beyond the intent run the replay reader counted.
  for (uint8_t opcode : {2, 3}) {
    const std::vector<uint8_t> late = {
        1,      0, 0,    0,    0xff, 0xff, 0xff, 0xff,  // intent
        4,      0, 0,    0,    0,    0,    0xff, 0xff,  // field
        opcode, 0, 0,    0,    0xff, 0xff, 0xff, 0xff,  // part
        10,     0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const auto p = replaceTable(rawFieldProgram(path), 7, late, 4);
    EXPECT_EQ(feedAll(envelope(p), 7), ERC7730_CATALOG_BAD_PROGRAM)
        << (int)opcode;
    const Erc7730DisplayInstruction part = {opcode, 0, 0, UINT16_MAX,
                                            UINT16_MAX};
    EXPECT_TRUE(erc7730_cap_display(&part, 2)) << (int)opcode;
    Erc7730ProgramDisplay reader{};
    const size_t payload = 2u + late.size();
    erc7730_program_display_begin(&reader, payload, 2);
    ASSERT_TRUE(erc7730_program_display_feed(
        &reader, 0, p.data() + sectionOffset(p, 7) + 5, payload));
    EXPECT_LT(reader.intent_parts, 2) << (int)opcode;
  }
  const Case cases[] = {
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
  // A table that does not end in an end instruction. The runtime leaves the
  // review only at an end, so it would step past the last instruction, where
  // the replay reader has nothing to select.
  const std::vector<std::vector<uint8_t>> unterminated = {
      {1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff},  // intent
      {1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff,   // intent
       4, 0, 0, 0, 0,    0,    0xff, 0xff},  // field
  };
  for (const auto& display : unterminated) {
    const uint16_t count = (uint16_t)(display.size() / 8u);
    const auto p = replaceTable(rawFieldProgram(path), 7, display, count);
    EXPECT_EQ(feedAll(envelope(p), 7), ERC7730_CATALOG_BAD_PROGRAM) << count;
    Erc7730ProgramDisplay reader{};
    const size_t payload = 2u + display.size();
    erc7730_program_display_begin(&reader, payload, count);
    EXPECT_FALSE(erc7730_program_display_feed(
        &reader, 0, p.data() + sectionOffset(p, 7) + 5, payload))
        << count;
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
  // Every step is an index, so only the step count tells these two apart.
  for (uint8_t i = 0; i < ERC7730_ABI_MAX_DEPTH; i++) path.steps[i].opcode = 1;
  path.step_count = ERC7730_ABI_MAX_DEPTH - 1u;
  EXPECT_TRUE(erc7730_cap_path(&path));
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
  // literal 0 = 256 (the constant, also the map's key); literal 1 = a
  // one-entry map. Path 2 is literal 0, path 1 the uint256 argument. Two
  // bytes give the constant the class of a decoded uint256, so only the
  // signer-constant rule tells the two programs apart.
  const std::vector<uint8_t> literals = {1, 0, 2, 1, 0,  //
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

// D-007 through the FSM: what a host sees for a definition on each tier, with
// AdvancedMode on and off. The device signs only after every screen is
// accepted; the run reads the signature frame the host would receive.
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);
void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);
bool kkconfirm_readResponse(uint16_t expected, const pb_field_t* fields,
                            void* result);

namespace {

constexpr int kScreenBudget = 12;

struct ScopedWallet {
  std::vector<uint8_t> bytes = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  uint8_t* previous = emulator_flash_base;
  ScopedWallet() {
    emulator_flash_base = bytes.data();
    storage_init();
    storage_setMnemonic("all all all all all all all all all all all all");
  }
  ~ScopedWallet() {
    fsm_abort_workflows();
    erc7730_catalog_clear_preload();
    signed_metadata_clear_signers();
    storage_reset();
    emulator_flash_base = previous;
  }
};

struct SignRun {
  FailureType code = (FailureType)0;
  std::string message;
  int screens = 0;
  bool signature = false;
  std::vector<std::string> bodies;
};

std::vector<uint8_t> word(uint8_t low) {
  std::vector<uint8_t> w(32, 0);
  w[31] = low;
  return w;
}

// Preloads `e`, then signs a call of minimalProgram()'s selector with
// `args` on `chain`. `tamper_signing_pass` changes one byte the host sends on
// the final, signing pass.
SignRun signWithDefinition(const std::vector<uint8_t>& e,
                           const std::vector<uint8_t>& args, uint64_t chain = 1,
                           bool tamper_signing_pass = false) {
  SignRun run;
  fsm_test_clearLastFailure();
  EXPECT_TRUE(kkconfirm_preload(kScreenBudget, 0));
  kkconfirm_capture_start();
  const auto id = digest(e);

  for (size_t offset = 0; offset < e.size();) {
    EthereumClearSignDefinition chunk{};
    chunk.definition_id.size = 32;
    memcpy(chunk.definition_id.bytes, id.data(), 32);
    chunk.offset = (uint32_t)offset;
    chunk.total_length = (uint32_t)e.size();
    chunk.data.size = (pb_size_t)std::min<size_t>(ERC7730_TRANSPORT_CHUNK_MAX,
                                                  e.size() - offset);
    memcpy(chunk.data.bytes, e.data() + offset, chunk.data.size);
    fsm_msgEthereumClearSignDefinition(&chunk);
    if (fsm_test_lastFailureCode() != 0) break;
    offset += chunk.data.size;
  }

  if (fsm_test_lastFailureCode() == 0) {
    EthereumSignTx tx{};
    const uint32_t path[5] = {0x8000002c, 0x8000003c, 0x80000000, 0, 0};
    memcpy(tx.address_n, path, sizeof(path));
    tx.address_n_count = 5;
    tx.has_chain_id = true;
    tx.chain_id = chain;
    tx.has_nonce = tx.has_gas_price = tx.has_gas_limit = true;
    tx.nonce.size = tx.gas_price.size = tx.gas_limit.size = 1;
    tx.nonce.bytes[0] = 0;
    tx.gas_price.bytes[0] = 1;
    tx.gas_limit.bytes[0] = 0x80;
    tx.has_to = true;
    tx.to.size = 20;
    tx.to.bytes[0] = 0x11;
    tx.has_data_length = tx.has_data_initial_chunk = true;
    tx.data_length = 4 + (uint32_t)args.size();
    tx.data_initial_chunk.size = 4;
    memcpy(tx.data_initial_chunk.bytes, "\xaa\xbb\xcc\xdd", 4);
    fsm_msgEthereumSignTx(&tx);
  }

  Erc7730Workflow* workflow = erc7730_workflow_state();
  for (int guard = 0; guard < 256 && fsm_test_lastFailureCode() == 0; guard++) {
    uint8_t id_wanted[32];
    uint32_t offset = 0, total = 0;
    size_t remaining = 0;
    if (erc7730_workflow_waiting(workflow, id_wanted, &offset, &total)) {
      EthereumClearSignDefinitionChunk chunk{};
      chunk.definition_id.size = 32;
      memcpy(chunk.definition_id.bytes, id_wanted, 32);
      chunk.offset = offset;
      chunk.total_length = total;
      chunk.data.size = (pb_size_t)std::min<size_t>(ERC7730_TRANSPORT_CHUNK_MAX,
                                                    total - offset);
      memcpy(chunk.data.bytes, e.data() + offset, chunk.data.size);
      fsm_msgEthereumClearSignDefinitionChunk(&chunk);
    } else if (erc7730_workflow_calldata_waiting(workflow, &remaining)) {
      const size_t at = workflow->outer_received;
      EthereumTxAck ack{};
      ack.has_data_chunk = true;
      ack.data_chunk.size = (pb_size_t)std::min<size_t>(remaining, 1024);
      memcpy(ack.data_chunk.bytes, args.data() + at, ack.data_chunk.size);
      if (tamper_signing_pass && workflow->signing_pass)
        ack.data_chunk.bytes[ack.data_chunk.size - 1] ^= 1;
      fsm_msgEthereumTxAck(&ack);
    } else {
      break;
    }
  }

  run.code = fsm_test_lastFailureCode();
  run.message = fsm_test_lastFailureMessage();
  run.bodies = kkconfirm_capture_finish();
  run.screens = kScreenBudget - kkconfirm_drain() / 2;
  if (run.code == 0) {
    for (int i = 0; i < 64 && !run.signature; i++) {
      EthereumTxRequest response{};
      if (!kkconfirm_readResponse(MessageType_MessageType_EthereumTxRequest,
                                  EthereumTxRequest_fields, &response))
        break;
      run.signature = response.has_signature_r && response.has_signature_s;
    }
  }
  fsm_abort_workflows();
  erc7730_catalog_clear_preload();
  return run;
}

bool shows(const SignRun& run, const char* text) {
  for (const auto& body : run.bodies)
    if (body.find(text) != std::string::npos) return true;
  return false;
}

}  // namespace

TEST(Erc7730Certified, SignsWithoutAdvancedModeAndShowsItsScreens) {
  CertifiedFixture fixture;
  makeCertifiedFixture(&fixture);
  TestRoot root(fixture.root_pubkey);
  ScopedWallet wallet;
  auto e =
      certifiedEnvelope(fixture, minimalProgram(),
                        rootCert(fixture.root_key, fixture.delegate.pubkey));
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
  const SignRun run = signWithDefinition(e, word(42));
  EXPECT_EQ(run.code, (FailureType)0) << run.message;
  EXPECT_TRUE(run.signature);
  // Provenance, the program's intent, then the device's own amount and fee
  // screens. No raw-data review.
  EXPECT_TRUE(shows(run, "KeepKey Test (")) << run.screens;
  EXPECT_TRUE(shows(run, "describes this transaction."));
  EXPECT_TRUE(shows(run, "Test"));
  EXPECT_FALSE(shows(run, "NOT verified by KeepKey"));
  EXPECT_TRUE(shows(run, "Send message to 0x1100"));
  EXPECT_EQ(run.screens, 4);
  EXPECT_EQ(run.bodies.size(), 4u);

  // AdvancedMode on changes nothing for a certified definition.
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
  const SignRun advanced = signWithDefinition(e, word(42));
  EXPECT_EQ(advanced.code, (FailureType)0) << advanced.message;
  EXPECT_TRUE(advanced.signature);
  EXPECT_EQ(advanced.bodies, run.bodies);
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
}

TEST(Erc7730Certified, RuntimeSignerStaysOnTheAdvancedModePath) {
  CertifiedFixture fixture;
  makeCertifiedFixture(&fixture);
  ScopedWallet wallet;
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
  ASSERT_TRUE(signed_metadata_store_signer(
      3, fixture.delegate.pubkey, "Approved signer", nullptr, 0, 0, 0, false));
  auto e = signedEnvelope(fixture.delegate, minimalProgram());

  // AdvancedMode on: the 7.15 review, raw-data review included.
  const SignRun on = signWithDefinition(e, word(42));
  EXPECT_EQ(on.code, (FailureType)0) << on.message;
  EXPECT_TRUE(on.signature);
  EXPECT_TRUE(shows(on, "NOT verified by KeepKey"));
  // Signer, warning, intent, amount, fee and the calldata's Keccak-256.
  EXPECT_EQ(on.screens, 6);
  ASSERT_EQ(on.bodies.size(), 6u);
  EXPECT_EQ(on.bodies.back().size(), 64u);

  // AdvancedMode off: refused, naming AdvancedMode, before any screen.
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
  const SignRun off = signWithDefinition(e, word(42));
  EXPECT_EQ(off.code, FailureType_Failure_Other);
  EXPECT_EQ(off.message, "AdvancedMode required for ERC-7730");
  EXPECT_EQ(off.screens, 0);
  EXPECT_FALSE(off.signature);
}

TEST(Erc7730Certified, UnverifiedCertificatesStayOnTheAdvancedModePath) {
  CertifiedFixture fixture;
  makeCertifiedFixture(&fixture);
  TestRoot root(fixture.root_pubkey);
  ScopedWallet wallet;
  const uint8_t* delegate = fixture.delegate.pubkey;
  auto program = minimalProgram();
  const std::vector<std::vector<uint8_t>> refused = {
      // Not signed by the root.
      certifiedEnvelope(fixture, program,
                        rootCert(fixture.delegate.key, delegate)),
      // Expired.
      certifiedEnvelope(
          fixture, program,
          rootCert(fixture.root_key, delegate, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW,
                   1, KK_CLEARSIGN_MIN_EXPIRY)),
      // Scoped to another chain.
      certifiedEnvelope(fixture, program,
                        rootCert(fixture.root_key, delegate,
                                 CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, 2)),
      // No MAY_SUPPRESS_RAW.
      certifiedEnvelope(fixture, program,
                        rootCert(fixture.root_key, delegate, 0)),
  };
  for (size_t i = 0; i < refused.size(); i++) {
    // Without AdvancedMode: the 7.15 refusal, which names AdvancedMode.
    ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
    const SignRun off = signWithDefinition(refused[i], word(42));
    EXPECT_EQ(off.code, FailureType_Failure_Other) << i;
    EXPECT_EQ(off.message, "AdvancedMode required for ERC-7730") << i;
    EXPECT_EQ(off.screens, 0) << i;
    EXPECT_FALSE(off.signature) << i;
    // With AdvancedMode: the definition is refused as before.
    ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
    const SignRun on = signWithDefinition(refused[i], word(42));
    EXPECT_EQ(on.message, "Invalid certified ERC-7730 definition") << i;
    EXPECT_FALSE(on.signature) << i;
  }
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
}

TEST(Erc7730Certified, CertifiedDefinitionStillBindsChainAndCalldata) {
  CertifiedFixture fixture;
  makeCertifiedFixture(&fixture);
  TestRoot root(fixture.root_pubkey);
  ScopedWallet wallet;
  auto e =
      certifiedEnvelope(fixture, minimalProgram(),
                        rootCert(fixture.root_key, fixture.delegate.pubkey));
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));

  // Another chain than the definition's.
  const SignRun chain = signWithDefinition(e, word(42), 2);
  EXPECT_EQ(chain.message, "ERC-7730 definition does not match transaction");
  EXPECT_EQ(chain.screens, 0);
  EXPECT_FALSE(chain.signature);

  // Calldata the program's ABI does not describe (a trailing word).
  auto extra = word(42);
  const auto more = word(7);
  extra.insert(extra.end(), more.begin(), more.end());
  const SignRun calldata = signWithDefinition(e, extra);
  EXPECT_EQ(calldata.message, "ERC-7730 calldata does not match definition");
  EXPECT_EQ(calldata.screens, 0);
  EXPECT_FALSE(calldata.signature);

  // Bytes changed on the signing pass after the review.
  const SignRun swapped = signWithDefinition(e, word(42), 1, true);
  EXPECT_EQ(swapped.message, "ERC-7730 calldata does not match definition");
  EXPECT_FALSE(swapped.signature);
}
