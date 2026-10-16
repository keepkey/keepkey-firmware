#include "gtest/gtest.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include "keepkey/board/memory.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/usb.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/storage.h"
#include "pb_decode.h"
#include "pb_encode.h"
#include "trezor/crypto/aes/aes.h"
#include "trezor/crypto/bip32.h"
#include "trezor/crypto/ed25519-donna/ed25519.h"
}

#include "test_board.h"
bool kkconfirm_preload(int nYes, int nNo);
bool kkconfirm_preload_no_sentinel(int nYes, int nNo);
bool kkconfirm_sendCancel(void);
int kkconfirm_drain(void);
bool kkconfirm_readResponse(uint16_t expected, const pb_field_t* fields,
                            void* result);

namespace {
constexpr char kMnemonic[] =
    "alcohol woman abuse must during monitor noble actual mixed trade anger "
    "aisle";

std::string hex(const uint8_t* bytes, size_t size) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  for (size_t i = 0; i < size; ++i) {
    result += digits[bytes[i] >> 4];
    result += digits[bytes[i] & 15];
  }
  return result;
}

void receive(MessageType id, const pb_field_t* fields, const void* msg) {
  uint8_t encoded[1024] = {};
  auto stream = pb_ostream_from_buffer(encoded, sizeof(encoded));
  ASSERT_TRUE(pb_encode(&stream, fields, msg));
  const size_t size = stream.bytes_written;
  uint8_t frame[64] = {'?', '#', '#', static_cast<uint8_t>(id >> 8),
                       static_cast<uint8_t>(id)};
  frame[5] = size >> 24;
  frame[6] = size >> 16;
  frame[7] = size >> 8;
  frame[8] = size;
  size_t sent = std::min(size, sizeof(frame) - 9);
  std::memcpy(frame + 9, encoded, sent);
  usb_test_receive(frame, sizeof(frame));
  while (sent < size) {
    std::memset(frame + 1, 0, sizeof(frame) - 1);
    const size_t take = std::min(size - sent, sizeof(frame) - 1);
    std::memcpy(frame + 1, encoded + sent, take);
    usb_test_receive(frame, sizeof(frame));
    sent += take;
  }
}

void response(MessageType expected, const pb_field_t* fields, void* result) {
  ASSERT_TRUE(kkconfirm_readResponse(expected, fields, result));
}

class CryptoCleanup : public ::testing::Test {
 protected:
  std::vector<uint8_t> flash = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  uint8_t* previous_flash = nullptr;

  void SetUp() override {
    kk_test_board_init();
    fsm_init();
    setup_abort();
    previous_flash = emulator_flash_base;
    emulator_flash_base = flash.data();
    storage_init();
    LoadDevice load = {};
    load.has_mnemonic = true;
    std::strcpy(load.mnemonic, kMnemonic);
    storage_loadDevice(&load);
    storage_commit();
  }

  void TearDown() override {
    fsm_abort_workflows();
    storage_reset();
    emulator_flash_base = previous_flash;
  }

  SignIdentity identity(const char* protocol, const char* curve,
                        uint32_t index = 0) {
    SignIdentity request = {};
    request.has_identity = true;
    request.identity.has_proto = request.identity.has_user = true;
    request.identity.has_host = request.identity.has_index = true;
    std::strcpy(request.identity.proto, protocol);
    std::strcpy(request.identity.user, "satoshi");
    std::strcpy(request.identity.host, "bitcoin.org");
    request.identity.index = index;
    request.has_ecdsa_curve_name = true;
    std::strcpy(request.ecdsa_curve_name, curve);
    const uint8_t challenge[32] = {
        0xcd, 0x85, 0x52, 0x56, 0x9d, 0x6e, 0x45, 0x09, 0x26, 0x6e, 0xf1,
        0x37, 0x58, 0x4d, 0x1e, 0x62, 0xc7, 0x57, 0x9b, 0x5b, 0x8e, 0xd6,
        0x9b, 0xba, 0xfa, 0x4b, 0x86, 0x4c, 0x65, 0x21, 0xe7, 0xc2};
    request.has_challenge_hidden = request.has_challenge_visual = true;
    request.challenge_hidden.size = sizeof(challenge);
    std::memcpy(request.challenge_hidden.bytes, challenge, sizeof(challenge));
    std::strcpy(request.challenge_visual, "2015-03-23 17:39:22");
    return request;
  }

  // Each secret workspace in SignIdentity is wiped by FSM_SCRUB on the paths
  // that use it: the 32-byte identity fingerprint, the 20-byte derivation
  // path and the 64-byte generic-protocol digest. The derived node is checked
  // separately through fsm_test_derivedNodeIsZero(). Counts are exact, so a
  // removed or duplicated wipe on any path is caught.
  static void ExpectWorkspaceWipes(size_t fingerprint, size_t path,
                                   size_t digest, size_t node) {
    EXPECT_EQ(fingerprint, fsm_test_scrubCount(32));
    EXPECT_EQ(path, fsm_test_scrubCount(20));
    EXPECT_EQ(digest, fsm_test_scrubCount(64));
    EXPECT_EQ(node, fsm_test_scrubCount(sizeof(HDNode)));
  }

  // CipherKeyValue: the HMAC-derived key material (256 + 4 bytes), the AES
  // context of the direction used (one per call), and the derived node.
  static void ExpectCipherWipes(size_t key_material, size_t ctx, size_t node) {
    size_t observed = fsm_test_scrubCount(sizeof(aes_encrypt_ctx));
    if (sizeof(aes_decrypt_ctx) != sizeof(aes_encrypt_ctx))
      observed += fsm_test_scrubCount(sizeof(aes_decrypt_ctx));
    EXPECT_EQ(key_material, fsm_test_scrubCount(256 + 4));
    EXPECT_EQ(ctx, observed);
    EXPECT_EQ(node, fsm_test_scrubCount(sizeof(HDNode)));
  }

  void sign(SignIdentity* request, bool wire) {
    fsm_test_clearLastFailure();
    fsm_test_clearScrubs();
    if (wire) {
      receive(MessageType_MessageType_SignIdentity, SignIdentity_fields,
              request);
    } else {
      fsm_msgSignIdentity(request);
    }
    EXPECT_TRUE(fsm_test_derivedNodeIsZero());
  }

  CipherKeyValue cipher(bool encrypt) {
    CipherKeyValue request = {};
    request.address_n_count = 3;
    request.address_n[1] = 1;
    request.address_n[2] = 2;
    request.has_key = request.has_value = request.has_encrypt = true;
    std::strcpy(request.key, "test");
    request.has_ask_on_encrypt = request.has_ask_on_decrypt = true;
    request.ask_on_encrypt = request.ask_on_decrypt = true;
    request.encrypt = encrypt;
    request.value.size = 16;
    if (encrypt) {
      std::memcpy(request.value.bytes, "testing message!", 16);
    } else {
      const uint8_t ciphertext[16] = {0x67, 0x6f, 0xaf, 0x8f, 0x13, 0x27,
                                      0x2a, 0xf6, 0x01, 0x77, 0x6b, 0xc3,
                                      0x1b, 0xc1, 0x4e, 0x8f};
      std::memcpy(request.value.bytes, ciphertext, sizeof(ciphertext));
    }
    return request;
  }

  void cipher(CipherKeyValue* request, bool wire) {
    fsm_test_clearLastFailure();
    fsm_test_clearScrubs();
    if (wire) {
      receive(MessageType_MessageType_CipherKeyValue, CipherKeyValue_fields,
              request);
    } else {
      fsm_msgCipherKeyValue(request);
    }
    EXPECT_TRUE(fsm_test_derivedNodeIsZero());
  }
};
}  // namespace

// Independent compatibility oracles from the pinned trezor-firmware
// tests/device_tests/test_msg_signidentity.py (MNEMONIC12). Each vector runs
// through both the handler and the USB receive path. The direct call proves
// handler cleanup without relying on the dispatcher's later blanket scrub.
TEST_F(CryptoCleanup,
       IdentitySuccessScrubsEverySigningBranchAndPreservesVectors) {
  struct Vector {
    const char *protocol, *curve, *pubkey, *signature;
    uint32_t index;
  };
  const Vector vectors[] = {
      {"https", "secp256k1",
       "023a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f45",
       "20f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb417"
       "70bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba02",
       0},
      {"ssh", "nist256p1",
       "0373f21a3da3d0e96fc2189f81dd826658c3d76b2d55bd1da349bc6c3573b13ae4",
       "005122cebabb852cdd32103b602662afa88e54c0c0c1b38d7099c64dcd49efe908"
       "288114e66ed2d8c82f23a70b769a4db723173ec53840c08aafb840d3f09a18d3",
       47},
      {"ssh", "ed25519",
       "000fac2a491e0f5b871dc48288a4cae551bac5cb0ed19df0764d6e721ec5fade18",
       "00f05e5085e666429de397c70a081932654369619c0bd2a6579ea6c1ef2af112ef"
       "79998d6c862a16b932d44b1ac1b83c8cbcd0fbda228274fde9e0d0ca6e9cb709",
       47},
      {"gpg", "ed25519",
       "00d18cdf4dbdbb50ef1fdba1ae0539451f3354a366d6a35313712ab82f16d4cd9e",
       "00f47f1a09a2875b971811ebbece19c3004c3ecbe84e65666dc8c36cc2fc002544"
       "af8a3f545375ebe53d73b41c700df2f9020256c31bb774a7eb03ed9819226407",
       0},
      {"signify", "ed25519",
       "0038c0f42c0e47b233e837763098f029fd01009b74fdf4b0d60db114fb0f4f8b17",
       nullptr, 0},
  };
  for (const auto& v : vectors) {
    for (bool wire : {false, true}) {
      SCOPED_TRACE(std::string(v.protocol) + "/" + v.curve +
                   (wire ? "/wire" : "/handler"));
      auto request = identity(v.protocol, v.curve, v.index);
      const bool https = std::strcmp(v.protocol, "https") == 0;
      if (https) {
        request.identity.has_path = true;
        std::strcpy(request.identity.path, "/login");
      }
      const bool generic = std::strcmp(v.protocol, "ssh") != 0 &&
                           std::strcmp(v.protocol, "gpg") != 0;
      // Screens: Identity Key, [Identity Path when a path is sent], the
      // identity summary, then (generic only) a separate Visual Challenge, and
      // finally the signed hidden challenge. SSH/GPG sign only the hidden
      // challenge, so they skip the Visual Challenge screen.
      const int screens = 2 + (https ? 1 : 0) + (generic ? 1 : 0) + 1;
      ASSERT_TRUE(kkconfirm_preload(screens, 0));
      sign(&request, wire);
      EXPECT_EQ(0, kkconfirm_drain());
      ExpectWorkspaceWipes(1, 1, generic ? 1 : 0, 1);
      SignedIdentity result = {};
      response(MessageType_MessageType_SignedIdentity, SignedIdentity_fields,
               &result);
      ASSERT_TRUE(result.has_signature);
      EXPECT_EQ(v.pubkey, hex(result.public_key.bytes, result.public_key.size));
      if (v.signature) {
        EXPECT_EQ(v.signature,
                  hex(result.signature.bytes, result.signature.size));
      } else {
        // KeepKey has SSH/GPG special cases; other protocol names follow the
        // generic Bitcoin envelope, including "signify". Its upstream Trezor
        // special-case signature is not this firmware's compatibility oracle.
        // This independent hashlib vector is SHA256d(0x18 || Bitcoin header ||
        // 0x40 || SHA256(hidden) || SHA256(visual)), using the fixed input
        // above.
        const uint8_t digest[32] = {
            0x0f, 0x50, 0x51, 0x4d, 0x57, 0x86, 0xa6, 0xe9, 0x38, 0xf9, 0xfb,
            0x1c, 0x5c, 0x76, 0xc3, 0xcc, 0xd2, 0xaf, 0x39, 0xaa, 0x6f, 0xf3,
            0xb8, 0x85, 0xa9, 0x3f, 0xef, 0xa7, 0x77, 0x88, 0xaa, 0x04};
        ASSERT_EQ(65u, result.signature.size);
        EXPECT_EQ(31, result.signature.bytes[0]);
        EXPECT_EQ(0, ed25519_sign_open(digest, sizeof(digest),
                                       result.public_key.bytes + 1,
                                       result.signature.bytes + 1));
      }
      EXPECT_EQ(https, result.has_address);
      if (https)
        EXPECT_STREQ("17F17smBTX9VTZA9Mj8LM5QGYNZnmziCjL", result.address);
    }
  }
}

TEST_F(CryptoCleanup, GpgExactDigestWithoutVisualChallengeSignsAndScrubs) {
  for (bool wire : {false, true}) {
    auto request = identity("gpg", "secp256k1");
    request.has_challenge_visual = false;
    request.challenge_visual[0] = '\0';
    // Identity Key, identity summary, then the signed GPG digest screen (the
    // hidden challenge is reviewed even though there is no visual challenge).
    ASSERT_TRUE(kkconfirm_preload(3, 0));
    sign(&request, wire);
    EXPECT_EQ(0, kkconfirm_drain());
    ExpectWorkspaceWipes(1, 1, 0, 1);
    SignedIdentity result = {};
    response(MessageType_MessageType_SignedIdentity, SignedIdentity_fields,
             &result);
    EXPECT_TRUE(result.has_signature);
    EXPECT_EQ(65u, result.signature.size);
    EXPECT_TRUE(result.has_public_key);
    EXPECT_EQ(33u, result.public_key.size);
  }
}

TEST_F(CryptoCleanup, IdentitySigningFailureScrubsBeforeReturningFailure) {
  for (bool wire : {false, true}) {
    for (size_t length : {size_t(0), size_t(31), size_t(33)}) {
      auto request = identity("gpg", "secp256k1");
      request.challenge_hidden.size = length;
      ASSERT_TRUE(kkconfirm_preload(3, 0));
      sign(&request, wire);
      EXPECT_EQ(0, kkconfirm_drain());
      ExpectWorkspaceWipes(1, 1, 0, 1);
      Failure result = {};
      response(MessageType_MessageType_Failure, Failure_fields, &result);
      EXPECT_EQ(FailureType_Failure_Other, result.code);
      EXPECT_STREQ("Error signing identity", result.message);
    }
  }
}

TEST_F(CryptoCleanup, IdentityDerivationFailureClearsPriorScratch) {
  LoadDevice load = {};
  load.has_node = true;
  load.node.has_private_key = true;
  load.node.private_key.size = load.node.chain_code.size = 32;
  load.node.private_key.bytes[31] = 1;
  storage_loadDevice(&load);
  for (bool wire : {false, true}) {
    auto request = identity("ssh", "nist256p1");
    fsm_test_seedDerivedNode();
    ASSERT_TRUE(kkconfirm_preload(3, 0));
    sign(&request, wire);
    EXPECT_EQ(0, kkconfirm_drain());
    // Derivation failed, but the fingerprint and path were already built.
    ExpectWorkspaceWipes(1, 1, 0, 0);
    EXPECT_EQ(FailureType_Failure_NotInitialized, fsm_test_lastFailureCode());
  }
}

TEST_F(CryptoCleanup, IdentityCancellationProducesNoSignatureOrRetainedKey) {
  for (bool wire : {false, true}) {
    auto request = identity("ssh", "ed25519", 47);
    ASSERT_TRUE(kkconfirm_preload(0, 1));
    sign(&request, wire);
    EXPECT_EQ(0, kkconfirm_drain());
    // Cancelled before any path or digest existed; only the fingerprint.
    ExpectWorkspaceWipes(1, 0, 0, 0);
    EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
    Failure result = {};
    response(MessageType_MessageType_Failure, Failure_fields, &result);
    EXPECT_STREQ("Sign identity cancelled", result.message);
  }
}

TEST_F(CryptoCleanup, CipherSuccessScrubsAndPreservesEncryptDecryptVectors) {
  for (bool wire : {false, true}) {
    for (bool encrypt : {true, false}) {
      auto request = cipher(encrypt);
      ASSERT_TRUE(kkconfirm_preload(1, 0));
      cipher(&request, wire);
      EXPECT_EQ(0, kkconfirm_drain());
      ExpectCipherWipes(1, 1, 1);
      CipheredKeyValue result = {};
      response(MessageType_MessageType_CipheredKeyValue,
               CipheredKeyValue_fields, &result);
      ASSERT_TRUE(result.has_value);
      ASSERT_EQ(16u, result.value.size);
      if (encrypt) {
        EXPECT_EQ("676faf8f13272af601776bc31bc14e8f",
                  hex(result.value.bytes, result.value.size));
      } else {
        EXPECT_EQ(0, std::memcmp(result.value.bytes, "testing message!", 16));
      }
    }
  }
}

TEST_F(CryptoCleanup, CipherCancellationScrubsAlreadyDerivedKey) {
  for (bool wire : {false, true}) {
    for (bool encrypt : {true, false}) {
      auto request = cipher(encrypt);
      ASSERT_TRUE(kkconfirm_preload(0, 1));
      cipher(&request, wire);
      EXPECT_EQ(0, kkconfirm_drain());
      // Cancelled after derivation: only the node existed.
      ExpectCipherWipes(0, 0, 1);
      EXPECT_EQ(FailureType_Failure_ActionCancelled,
                fsm_test_lastFailureCode());
    }
  }
}

// A confirmed request whose PIN prompt is then cancelled has already built the
// identity fingerprint, the seed of the derivation path. It must be wiped
// although no key was ever derived.
TEST_F(CryptoCleanup, IdentityPinCancellationWipesFingerprintBeforeReturning) {
  storage_setPin("1234");
  session_clear(/*clear_pin=*/true);
  for (bool wire : {false, true}) {
    auto request = identity("ssh", "ed25519", 47);
    // The PIN wait rejects a foreign acknowledgement (Block 02), so the usual
    // trailing ButtonAck sentinel must not reach it; the Cancel ends the flow.
    ASSERT_TRUE(kkconfirm_preload_no_sentinel(3, 0));
    ASSERT_TRUE(kkconfirm_sendCancel());
    sign(&request, wire);
    ExpectWorkspaceWipes(1, 0, 0, 0);
    EXPECT_EQ(FailureType_Failure_PinCancelled, fsm_test_lastFailureCode());
    session_clear(/*clear_pin=*/true);
  }
}
