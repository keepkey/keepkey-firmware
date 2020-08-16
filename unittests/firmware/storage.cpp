extern "C" {
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/policy.h"
#include "keepkey/board/keepkey_board.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/aes/aes.h"
#include "types.pb.h"
#include "storage.h"
}

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include <cstring>
#include <string>

using ::testing::ElementsAreArray;

TEST(Storage, ReadMeta) {
    Metadata dst;
    const char src[] = "M1M2u1u2u3u4u5u6S1S2S3S4S5S6S7S8S9SASBSC";

    storage_readMeta(&dst, src, sizeof(src));

    ASSERT_TRUE(memcmp(dst.magic, "M1M2", 4) == 0);
    ASSERT_TRUE(memcmp(dst.uuid, "u1u2u3u4u5u6", 12) == 0);
    ASSERT_TRUE(memcmp(dst.uuid_str, "S1S2S3S4S5S6S7S8S9SASBSC", 24) == 0);

    for (size_t i = 0; i < sizeof(src); i++) {
        ASSERT_EQ(src[i], ((char *)&dst)[i]) << "i: " << i;
    }
}

TEST(Storage, WriteMeta) {
    Metadata src;
    memcpy(&src.magic[0], "M1M", sizeof(src.magic));
    memcpy(&src.uuid[0], "u1u2u3u4u5u", sizeof(src.uuid));
    memcpy(&src.uuid_str[0], "S1S2S3S4S5S6S7S8S9SASBS\0", sizeof(src.uuid_str));

    char dst[41];
    memset(dst, 0, sizeof(dst));

    storage_writeMeta(&dst[0], sizeof(dst), &src);

    ASSERT_TRUE(memcmp(dst, "M1M\0u1u2u3u4u5u\0S1S2S3S4S5S6S7S8S9SASBS\0", sizeof(dst)) == 0);
}

TEST(Storage, ReadPolicyV1) {
    PolicyType dst;
    const char src[] = "\x01N1N2N3N4N5N6N7N\x01\x01";

    storage_readPolicyV1(&dst, src, sizeof(src));

    ASSERT_EQ(dst.has_policy_name, true);
    ASSERT_TRUE(memcmp(dst.policy_name, "N1N2N3N4N5N6N7N8N", 15) == 0);
    ASSERT_EQ(dst.has_enabled, true);
    ASSERT_EQ(dst.enabled, true);
}

TEST(Storage, WritePolicyV1) {
    PolicyType src;
    src.has_policy_name = true;
    memcpy(&src.policy_name[0], "0123456789ABCD", 15);
    src.has_enabled = true;
    src.enabled = true;

    char dst[18];
    memset(dst, 0, sizeof(dst));

    storage_writePolicyV1(&dst[0], sizeof(dst), &src);

    ASSERT_TRUE(memcmp(dst, "\x01""0123456789ABCD\0\x01\x01", sizeof(dst)) == 0);
}

TEST(Storage, ReadStorageV1) {
    const char src[559] =
        /*   0 */ "\x0a\x00\x00\x00" // version
        /*   4 */ "\x01"             // has_node
                  "\x00\x00\x00"     // reserved
        /*   8 */ "\x03\x00\x00\x00" // depth
        /*  12 */ "\x2a\x00\x00\x00" // fingerprint
        /*  16 */ "\x11\x00\x00\x00" // child_num
        /*  20 */ "\x20\x00\x00\x00" // chain_code.size
        /*  24 */ "\x58\x4d\x52\x58\x4d\x52\x58\x4d\x52\x58\x4d\x52\x58\x4d\x52\x58" // chain_code.bytes
                  "\x4d\x52\x58\x4d\x52\x58\x4d\x52\x58\x4d\x52\x58\x4d\x52\x58\x00" // chain_code.bytes
        /*  56 */ "\x01"             // has_private_key
                  "\x00\x00\x00"     // reserved
        /*  60 */ "\x20\x00\x00\x00" // private_key.size
        /*  64 */ "\x46\x4f\x58\x59\x4b\x50\x4b\x59\x46\x4f\x58\x59\x4b\x50\x4b\x59" // private_key.bytes
                  "\x46\x4f\x58\x59\x4b\x50\x4b\x59\x46\x4f\x58\x59\x4b\x50\x4b\x00" // private_key.bytes
        /*  96 */ "\x01"             // has_public_key
                  "\x00\x00\x00"     // reserved
        /* 100 */ "\x21\x00\x00\x00" // public_key.size
        /* 104 */ "\x57\x68\x6f\x20\x69\x73\x20\x53\x61\x74\x6f\x73\x68\x69\x20\x4e" // public_key.bytes
                  "\x61\x6b\x6f\x6d\x6f\x74\x6f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f" // public_key.bytes
        /* 136 */ "\x00"             // public_key.bytes
        /* 137 */ "\x00\x00\x00"     // reserved
        /* 140 */ "\x01"             // has_mnemonic
        /* 141 */ "\x7a\x6f\x6f\x20\x7a\x6f\x6f\x20\x7a\x6f\x6f\x20\x7a\x6f\x6f\x20" // mnemonic
                  "\x7a\x6f\x6f\x20\x7a\x6f\x6f\x20\x7a\x6f\x6f\x20\x7a\x6f\x6f\x20" // mnemonic
                  "\x7a\x6f\x6f\x20\x7a\x6f\x6f\x20\x7a\x6f\x6f\x20\x77\x72\x6f\x6e" // menmonic
                  "\x67\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
                  "\x00"             // mnemonic
        /* 382 */ "\x00"             // reserved
        /* 383 */ "\x00"             // passphrase_protection
        /* 384 */ "\x01"             // has_pin_failed_attempts
                  "\x00\x00\x00"     // reserved
        /* 388 */ "\x2a\x00\x00\x00" // pin_failed_attempts
        /* 392 */ "\x01"             // has_pin
        /* 393 */ "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x00" // pin
        /* 403 */ "\x01"             // has_language
        /* 404 */ "\x65\x73\x70\x65\x72\x61\x6e\x74\x6f\x00\x00\x00\x00\x00\x00\x00" // language
                  "\x00"             // language
        /* 421 */ "\x01"             // has_label
        /* 422 */ "\x4d\x65\x6e\x6f\x73\x4d\x61\x72\x78\x4d\x61\x69\x73\x4d\x69\x73" // label
                  "\x65\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // label
                  "\x00"             // label
        /* 455 */ "\x01"             // reserved
        /* 456 */ "\x00"             // imported
        /* 457 */ "\x00\x00\x00"     // reserved
        /* 460 */ "\x01\x00\x00\x00" // policies_count
        /* 464 */ "\x01"             // policies[0].has_policy_name
        /* 465 */ "\x53\x68\x61\x70\x65\x53\x68\x69\x66\x74\x00\x00\x00\x00\x00" // policies[0].policy_name
        /* 481 */ "\x01"             // policies[0].has_enabled
        /* 482 */ "\x01"             // policies[0].enabled
        /* 483 */ "\x00"             // reserved
        /* 484 */ "\x2a\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34" // cache
                  "\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30" // cache
                  "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36" // cache
                  "\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32" // cache
                  "\x00\x73\x65\x63\x70\x32\x35\x36\x6b\x31\x00";                    // cache

    Storage dst;
    memset(&dst, 0xCC, sizeof(dst));

    SessionState session;
    memset(&session, 0, sizeof(session));

    storage_readStorageV1(&session, &dst, &src[0], sizeof(src));

    // Check that the secret area of storage remains cleared.
    EXPECT_EQ(dst.sec.node.depth, 0);

    // Decrypt upgraded storage.
    uint8_t wrapping_key[64];
    storage_deriveWrappingKey("123456789", wrapping_key, dst.pub.sca_hardened, dst.pub.random_salt, ""); // strongest pin evar
    storage_unwrapStorageKey(wrapping_key, dst.pub.wrapped_storage_key, session.storageKey);
    storage_secMigrate(&session, &dst, /*encrypt=*/false);

    // Check that the secret area was correctly unencrypted.
    EXPECT_EQ(dst.version, 10);
    EXPECT_TRUE(dst.pub.has_node);
    EXPECT_EQ(dst.sec.node.depth, 3);
    EXPECT_EQ(dst.sec.node.fingerprint, 42);
    EXPECT_EQ(dst.sec.node.child_num, 17);
    EXPECT_EQ(dst.sec.node.chain_code.size, 32);
    EXPECT_TRUE(memcmp(dst.sec.node.chain_code.bytes, "XMRXMRXMRXMRXMRXMRXMRXMRXMRXMRX\0", 32) == 0);
    EXPECT_EQ(dst.sec.node.has_private_key, true);
    EXPECT_EQ(dst.sec.node.public_key.size, 33);
    EXPECT_TRUE(memcmp(dst.sec.node.public_key.bytes, "Who is Satoshi Nakomoto?????????\0", 32) == 0);
    EXPECT_EQ(dst.pub.has_mnemonic, true);

    // Check the load path on storage_secMigrate()
    char encrypted_sec[sizeof(dst.encrypted_sec)];
    memcpy(encrypted_sec, dst.encrypted_sec, sizeof(encrypted_sec));
    memzero(dst.encrypted_sec, sizeof(encrypted_sec));
    storage_secMigrate(&session, &dst, /*encrypt=*/true);
    EXPECT_THAT(dst.encrypted_sec, ElementsAreArray(encrypted_sec));
}

TEST(Storage, WriteCacheV1) {
    Cache src;
    src.root_seed_cache_status = 42;
    memcpy(&src.root_seed_cache[0], "012345678901234567890123456789012345678901234567890123456789012", sizeof(src.root_seed_cache));
    memcpy(&src.root_ecdsa_curve_type[0], "secp256k1", 10);

    char dst[75];
    memset(dst, 0xCC, sizeof(dst));

    storage_writeCacheV1(&dst[0], sizeof(dst), &src);

    const char expected[76] = "\x2a\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x00\x73\x65\x63\x70\x32\x35\x36\x6b\x31";

    for (int i = 0; i < sizeof(dst); i++) {
        ASSERT_EQ(dst[i], expected[i]) << "i: " << i;
        ASSERT_EQ(dst[i], ((const char *)&src)[i]) << "i: " << i;
    }
}

TEST(Storage, ReadCacheV1) {
    const char src[76] = "\x2a\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x00\x73\x65\x63\x70\x32\x35\x36\x6b\x31";

    Cache dst;

    storage_readCacheV1(&dst, &src[0], sizeof(src));

    ASSERT_EQ(dst.root_seed_cache_status, 42);
    for (int i = 0; i < 64; i++) {
        ASSERT_EQ(dst.root_seed_cache[i], "012345678901234567890123456789012345678901234567890123456789012"[i]) << "i: " << i;
    }
    ASSERT_TRUE(memcmp(dst.root_ecdsa_curve_type, "secp256k1", 10) == 0);

    for (int i = 0; i < sizeof(src) - 1; ++i) {
        ASSERT_EQ(src[i], ((char *)&dst)[i]) << "i: " << i;
    }
}

TEST(Storage, DumpNode) {
    HDNodeType dst;
    HDNode src;
    src.depth = 42;
    src.child_num = 11;
    src.chain_code[0] = 1;
    src.chain_code[1] = 2;
    src.chain_code[3] = 3;
    src.chain_code[4] = 4;
    src.private_key[0] = 5;
    src.private_key[1] = 6;
    src.private_key[2] = 7;
    src.public_key[0] = 74;

    memset(&dst, 0, sizeof(dst));
    storage_dumpNode(&dst, &src);

#if !DEBUG_LINK
    EXPECT_EQ(dst.depth, 0);
    EXPECT_EQ(dst.fingerprint, 0);
    EXPECT_EQ(dst.child_num, 0);
    EXPECT_EQ(dst.chain_code.size, 0);
    EXPECT_EQ(dst.chain_code.bytes[0], 0);
    EXPECT_EQ(dst.has_private_key, 0);
    EXPECT_EQ(dst.private_key.size, 0);
    EXPECT_EQ(dst.private_key.bytes[0], 0);
    EXPECT_EQ(dst.has_public_key, 0);
    EXPECT_EQ(dst.public_key.size, 0);
    EXPECT_EQ(dst.public_key.bytes[0], 0);
#else
    EXPECT_EQ(dst.depth, src.depth);
    EXPECT_EQ(dst.child_num, src.child_num);
    EXPECT_EQ(dst.chain_code.size, 32);
    EXPECT_THAT(dst.chain_code.bytes, ElementsAreArray(src.chain_code));
    EXPECT_EQ(dst.has_private_key, true);
    EXPECT_EQ(dst.private_key.size, 32);
    EXPECT_THAT(dst.private_key.bytes, ElementsAreArray(src.private_key));
    EXPECT_EQ(dst.public_key.size, 33);
    EXPECT_THAT(dst.public_key.bytes, ElementsAreArray(src.public_key));
#endif
}

static void check_policyIsSame(const PolicyType *lhs, const PolicyType *rhs) {
    EXPECT_EQ(lhs->has_policy_name, rhs->has_policy_name);

    if (lhs->has_policy_name) {
        EXPECT_EQ(std::string(lhs->policy_name), std::string(rhs->policy_name));
    }

    EXPECT_EQ(lhs->has_enabled, rhs->has_enabled);
    EXPECT_EQ(lhs->enabled, rhs->enabled);
}

TEST(Storage, ResetPolicies) {
    Storage storage;
    memset(&storage, 0xCC, sizeof(storage));

    storage_resetPolicies(&storage);

    EXPECT_EQ(storage.pub.policies_count, POLICY_COUNT);

    for (int i = 0; i < POLICY_COUNT; ++i) {
        check_policyIsSame(&storage.pub.policies[i], &policies[i]);
    }
}

TEST(Storage, SetPolicy) {
    Storage storage;
    memset(&storage, 0xCC, sizeof(storage));

    storage_resetPolicies(&storage);

    EXPECT_EQ(storage.pub.policies_count, POLICY_COUNT);

    for (int i = 0; i < POLICY_COUNT; ++i) {
        check_policyIsSame(&storage.pub.policies[i], &policies[i]);
    }

    storage_setPolicy_impl(storage.pub.policies, "ShapeShift", true);
    EXPECT_EQ(storage.pub.policies[0].enabled, true);

    storage_setPolicy_impl(storage.pub.policies, "AdvancedMode", false);
    EXPECT_EQ(storage.pub.policies[3].enabled, false);

    storage_setPolicy_impl(storage.pub.policies, "ShapeShift", false);
    EXPECT_EQ(storage.pub.policies[0].enabled, false);

    storage_setPolicy_impl(storage.pub.policies, "AdvancedMode", true);
    EXPECT_EQ(storage.pub.policies[3].enabled, true);
}

TEST(Storage, ResetCache) {
    Cache src;
    memset(&src, 0xCC, sizeof(src));

    storage_resetCache(&src);

    char dst[sizeof(src)];
    memset(&dst[0], 0, sizeof(dst));

    EXPECT_EQ(memcmp(&src, &dst, sizeof(Cache)), 0);
}

TEST(Storage, StorageUpgrade_Normal) {
    const char flash[] =
        // Meta
        "\x73\x74\x6f\x72\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

        // Storage
        "\x08\x00\x00\x00" // version
        "\x01"             // has_node
        "\x00\x00\x00"     // reserved
        "\x03\x00\x00\x00" // depth
        "\x2a\x00\x00\x00" // fingerprint
        "\x11\x00\x00\x00" // child_num
        "\x20\x00\x00\x00" // chain_code.size
        "\x58\x4d\x52\x58\x4d\x52\x58\x4d\x52\x58\x4d\x52\x58\x4d\x52\x58" // chain_code.bytes
        "\x4d\x52\x58\x4d\x52\x58\x4d\x52\x58\x4d\x52\x58\x4d\x52\x58\x00" // chain_code.bytes
        "\x01"             // has_private_key
        "\x00\x00\x00"     // reserved
        "\x20\x00\x00\x00" // private_key.size
        "\x46\x4f\x58\x59\x4b\x50\x4b\x59\x46\x4f\x58\x59\x4b\x50\x4b\x59" // private_key.bytes
        "\x46\x4f\x58\x59\x4b\x50\x4b\x59\x46\x4f\x58\x59\x4b\x50\x4b\x00" // private_key.bytes
        "\x01"             // has_public_key
        "\x00\x00\x00"     // reserved
        "\x21\x00\x00\x00" // public_key.size
        "\x57\x68\x6f\x20\x69\x73\x20\x53\x61\x74\x6f\x73\x68\x69\x20\x4e" // public_key.bytes
        "\x61\x6b\x6f\x6d\x6f\x74\x6f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f" // public_key.bytes
        "\x00"             // public_key.bytes
        "\x00\x00\x00"     // reserved
        "\x01"             // has_mnemonic
        "\x7a\x6f\x6f\x20\x7a\x6f\x6f\x20\x7a\x6f\x6f\x20\x7a\x6f\x6f\x20" // mnemonic
        "\x7a\x6f\x6f\x20\x7a\x6f\x6f\x20\x7a\x6f\x6f\x20\x7a\x6f\x6f\x20" // mnemonic
        "\x7a\x6f\x6f\x20\x7a\x6f\x6f\x20\x7a\x6f\x6f\x20\x77\x72\x6f\x6e" // menmonic
        "\x67\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // mnemonic
        "\x00"             // mnemonic
        "\x01"             // reserved
        "\x00"             // passphrase_protection
        "\x01"             // has_pin_failed_attempts
        "\x00\x00\x00"     // reserved
        "\x2a\x00\x00\x00" // pin_failed_attempts
        "\x01"             // has_pin
        "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x00" // pin
        "\x01"             // has_language
        "\x65\x73\x70\x65\x72\x61\x6e\x74\x6f\x00\x00\x00\x00\x00\x00\x00" // language
        "\x00"             // language
        "\x01"             // has_label
        "\x4d\x65\x6e\x6f\x73\x4d\x61\x72\x78\x4d\x61\x69\x73\x4d\x69\x73" // label
        "\x65\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // label
        "\x00"             // label
        "\x01"             // has_imported
        "\x00"             // imported
        "\x00\x00\x00"     // reserved
        "\x01\x00\x00\x00" // policies_count
        "\x01"             // policies[0].has_policy_name
        "\x53\x68\x61\x70\x65\x53\x68\x69\x66\x74\x00\x00\x00\x00\x00" // policies[0].policy_name
        "\x01"             // policies[0].has_enabled
        "\x01"             // policies[0].enabled

        // Cache
        "\x2a\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34"
        "\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
        "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36"
        "\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32"
        "\x00\x73\x65\x63\x70\x32\x35\x36\x6b\x31\x00\x00";

    SessionState session;
    memset(&session, 0, sizeof(session));

    ConfigFlash shadow;
    ASSERT_EQ(storage_fromFlash(&session, &shadow, flash), SUS_Updated);

    // Decrypt upgraded storage.
    uint8_t wrapping_key[64];
    storage_deriveWrappingKey("123456789", wrapping_key, shadow.storage.pub.sca_hardened, shadow.storage.pub.random_salt, ""); // strongest pin evar
    storage_unwrapStorageKey(wrapping_key, shadow.storage.pub.wrapped_storage_key,
                             session.storageKey);

    storage_secMigrate(&session, &shadow.storage, /*encrypt=*/false);

    ConfigFlash shadow2;
    memcpy(&shadow2, &shadow, sizeof(shadow2));
    memzero(&shadow2.storage.encrypted_sec, sizeof(shadow2.storage.encrypted_sec));
    ASSERT_TRUE(shadow.storage.has_sec);
    shadow2.storage.has_sec = shadow.storage.has_sec;

    storage_secMigrate(&session, &shadow2.storage, /*encrypt=*/true);

    EXPECT_TRUE(memcmp(&shadow.storage.encrypted_sec,
                       &shadow2.storage.encrypted_sec,
                       sizeof(shadow.storage.encrypted_sec)) == 0);

    EXPECT_EQ(shadow.storage.version, STORAGE_VERSION);
    EXPECT_EQ(shadow.storage.sec.node.depth, 3);
    EXPECT_EQ(memcmp(shadow.meta.magic, "stor", 4), 0);
    EXPECT_EQ(std::string(shadow.storage.pub.policies[0].policy_name), "ShapeShift");
    EXPECT_EQ(shadow.storage.pub.policies[0].enabled, true);
    EXPECT_EQ(std::string(shadow.storage.pub.policies[1].policy_name), "Pin Caching");
    EXPECT_EQ(shadow.storage.pub.policies[1].enabled, true);
}

TEST(Storage, StorageRoundTrip) {
    ConfigFlash start;
    memset(&start, 0xAB, sizeof(start));
    memcpy(start.meta.magic, "stor", 4);
    start.storage.version = STORAGE_VERSION;
    start.storage.sec.node.fingerprint = 42;
    start.storage.pub.has_pin = true;
    start.storage.pub.has_language = true;
    start.storage.pub.has_label = true;
    start.storage.pub.has_auto_lock_delay_ms = true;
    start.storage.pub.imported = true;
    start.storage.pub.passphrase_protection = true;
    start.storage.pub.no_backup = false;
    start.storage.pub.has_node = false;
    start.storage.pub.has_mnemonic = true;
    start.storage.pub.has_u2froot = false;
    start.storage.pub.u2froot.has_public_key = false;
    start.storage.pub.u2froot.has_private_key = true;
    start.storage.pub.sca_hardened = false;
    start.storage.has_sec = true;
    start.storage.sec.pin[0] = '\0';
    start.storage.sec.cache.root_seed_cache_status = 0xEC;
    start.storage.sec.node.has_public_key = true;
    start.storage.sec.node.has_private_key = true;

    SessionState session;
    memset(&session, 0, sizeof(session));

    uint8_t wrapping_key[64];
    storage_deriveWrappingKey("", wrapping_key, start.storage.pub.sca_hardened, start.storage.pub.random_salt, "");
    storage_unwrapStorageKey(wrapping_key, start.storage.pub.wrapped_storage_key, session.storageKey);

    storage_secMigrate(&session, &start.storage, /*encrypt=*/true);

    std::vector<uint8_t> flash(1024);

    storage_writeV11((char*)&flash[0], flash.size(), &start);

#if 0
    printf("        ");
    for (int i = 0; i < flash.size(); i++) {
        if (i == 44 || i == 508)
            printf("STORAGE_VERSION,");
        else
            printf("0x%02hhx,", flash[i]);
        if (i % 16 == 15)
            printf("\n        ");
        else
            printf(" ");
    }
    printf("\n");
#endif

    const uint8_t expected_flash[] = {
        0x73, 0x74, 0x6f, 0x72, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x00, 0x00, 0x00, STORAGE_VERSION, 0x00, 0x00, 0x00,
        0xff, 0x42, 0x00, 0x00, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x20, 0x00, 0x00, 0x00, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x01, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0x68, 0x9a, 0xf4, 0xaa, 0x5f, 0x36, 0xb1, 0x9c, 0x8c, 0x5a, 0xfb, 0xaa, 0x6e, 0xc3,
        0xd9, 0xfb, 0x6c, 0xee, 0x31, 0xed, 0xf2, 0xb3, 0x08, 0x53, 0x19, 0x8b, 0x20, 0xf1, 0x15, 0x02,
        0x73, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, STORAGE_VERSION, 0x00, 0x00, 0x00,
        0xe4, 0x8d, 0xfe, 0xcf, 0xd0, 0x54, 0x71, 0x50, 0xcb, 0x12, 0x84, 0xfa, 0x5f, 0xbf, 0xcb, 0x09,
        0xca, 0x00, 0xf1, 0x37, 0xe4, 0x8f, 0x5e, 0xf9, 0x81, 0x57, 0x26, 0xb6, 0x7b, 0x8e, 0x03, 0x44,
        0x9a, 0x2a, 0x7c, 0xf4, 0x3c, 0x79, 0x87, 0x5d, 0x26, 0xae, 0x9b, 0x4b, 0xb4, 0xd2, 0xc4, 0x67,
        0x97, 0xe7, 0x6b, 0x6c, 0x4c, 0xbe, 0x68, 0x19, 0x4c, 0x28, 0xf0, 0x5d, 0xef, 0xe8, 0x36, 0x20,
        0x0e, 0x4e, 0x0d, 0x5a, 0x9a, 0xc6, 0x09, 0x37, 0x38, 0xcb, 0x70, 0xb1, 0x90, 0x9d, 0xe7, 0x2c,
        0x4b, 0x32, 0x91, 0x41, 0x1d, 0xda, 0x38, 0x8c, 0xc7, 0x7b, 0x24, 0xc2, 0x5f, 0x40, 0xae, 0xfb,
        0xf8, 0xe7, 0xcd, 0x9e, 0xb5, 0x85, 0x29, 0xdb, 0xa3, 0x70, 0xc3, 0x1b, 0x56, 0xf2, 0x03, 0xfb,
        0xf8, 0xbe, 0xf6, 0x0d, 0x08, 0x00, 0xb4, 0xf8, 0x3b, 0x28, 0xdc, 0x9e, 0x56, 0xf4, 0x86, 0x0f,
        0x86, 0xbb, 0x54, 0xb6, 0x0e, 0x03, 0x78, 0x98, 0x53, 0xeb, 0xbc, 0xe7, 0xb4, 0x5f, 0xd6, 0x3a,
        0x7a, 0xc3, 0xfd, 0x7a, 0x1e, 0xe5, 0x8b, 0x55, 0x03, 0x3d, 0x32, 0x9a, 0x9c, 0x1b, 0x58, 0xdd,
        0xca, 0x23, 0x8d, 0x3b, 0x52, 0x71, 0x7c, 0x66, 0x2f, 0x83, 0xaa, 0xc8, 0xc9, 0xb3, 0xcc, 0xb3,
        0x82, 0x88, 0xac, 0x65, 0x1c, 0xf2, 0xe9, 0x0e, 0x94, 0xff, 0xeb, 0xfb, 0xbe, 0x71, 0x3f, 0x53,
        0x79, 0x73, 0x49, 0x9c, 0x25, 0xe5, 0xf1, 0xe4, 0xf6, 0xcf, 0x29, 0x80, 0x17, 0x6f, 0x1e, 0x94,
        0xf3, 0x79, 0x7f, 0xb0, 0x31, 0x75, 0xeb, 0xf6, 0xd3, 0x11, 0xf3, 0xb1, 0xea, 0xbe, 0x7d, 0x7c,
        0x39, 0xd9, 0x59, 0x7a, 0x30, 0x76, 0xce, 0xc5, 0x20, 0x63, 0xc2, 0x42, 0x95, 0xa5, 0xbc, 0xf3,
        0xe6, 0x39, 0x13, 0xd6, 0xea, 0x7a, 0xf5, 0xf3, 0x68, 0xed, 0x34, 0x63, 0x76, 0xf9, 0xf6, 0x28,
        0x9e, 0x5a, 0x79, 0x76, 0xa7, 0xbd, 0x67, 0x7f, 0xcc, 0xbc, 0xeb, 0x8d, 0x70, 0xbf, 0x4b, 0xaf,
        0xe9, 0x60, 0xb2, 0x90, 0x7d, 0xed, 0x98, 0x6e, 0x35, 0x64, 0x64, 0xdc, 0xf9, 0x79, 0xcc, 0x2c,
        0xfb, 0x94, 0x25, 0xbe, 0xb3, 0xc0, 0x12, 0xc2, 0x5e, 0xb0, 0x8e, 0x5c, 0x4a, 0x92, 0x2a, 0x71,
        0x87, 0xc1, 0x21, 0x6a, 0xb3, 0xed, 0x87, 0x7c, 0xfa, 0xff, 0xc0, 0xcd, 0x6c, 0xd4, 0xf7, 0x54,
        0xe9, 0x54, 0xdc, 0xa7, 0xb3, 0x8a, 0xa5, 0x0a, 0xd4, 0x02, 0xe1, 0xdf, 0x4c, 0xdf, 0x6c, 0xeb,
        0x97, 0xd3, 0x97, 0x29, 0x68, 0xde, 0x50, 0x2f, 0x7c, 0xeb, 0xc4, 0x1a, 0x40, 0x7f, 0x69, 0x4f,
        0xb5, 0x4f, 0x81, 0x64, 0x30, 0x49, 0xd7, 0x01, 0x7a, 0xd7, 0x55, 0x19, 0xb6, 0x33, 0xde, 0x0d,
        0x13, 0x75, 0xf7, 0x57, 0xd3, 0x81, 0xb8, 0xdd, 0x8c, 0x67, 0x73, 0xe0, 0x76, 0xb6, 0x44, 0x9f,
        0x6a, 0x33, 0x7b, 0x60, 0x60, 0x0b, 0xef, 0x23, 0x8b, 0x9d, 0x8c, 0x17, 0x1b, 0x02, 0xef, 0xf5,
        0x10, 0xcf, 0x5a, 0x8e, 0x3b, 0x00, 0x12, 0xb0, 0x45, 0x8e, 0x12, 0x57, 0x81, 0x5f, 0xfb, 0xfd,
        0x04, 0xff, 0xbc, 0xf4, 0x4c, 0xbf, 0xb5, 0x06, 0x10, 0xc1, 0xd8, 0x5e, 0x80, 0x17, 0x06, 0xda,
        0x37, 0x11, 0xba, 0x77, 0x61, 0xe5, 0xd6, 0x4a, 0x0d, 0xd8, 0x6f, 0xd1, 0xd4, 0x57, 0xba, 0xe6,
        0x8f, 0xd8, 0x7a, 0xfa, 0x4f, 0x35, 0x12, 0xdb, 0xbb, 0x34, 0xdf, 0x3f, 0x24, 0x30, 0x95, 0x42,
        0xe9, 0xc4, 0x71, 0xed, 0x0b, 0x4a, 0x9a, 0x61, 0xfa, 0x79, 0xc6, 0x5d, 0x1b, 0x0d, 0x34, 0x61,
        0x5f, 0x45, 0xc9, 0xa1, 0x01, 0xdf, 0x19, 0x3e, 0x7f, 0x3e, 0xb7, 0x2f, 0x0f, 0xdc, 0x26, 0x45,
        0xa2, 0xa0, 0xaa, 0xf9, 0xe1, 0x2b, 0x6b, 0x23, 0x19, 0xb7, 0x03, 0xd0, 0xa1, 0xb9, 0x88, 0x11,
    };

    EXPECT_TRUE(memcmp(&flash[0], expected_flash, sizeof(expected_flash)) == 0);

    ConfigFlash end;
    memset(&end, 0xCC, sizeof(end));
    EXPECT_EQ(storage_fromFlash(&session, &end, (char*)&flash[0]), SUS_Valid);

    storage_secMigrate(&session, &end.storage, /*encrypt=*/false);

    EXPECT_EQ(end.storage.version, STORAGE_VERSION);

    EXPECT_EQ(end.storage.sec.cache.root_seed_cache_status,
              start.storage.sec.cache.root_seed_cache_status);
}

TEST(Storage, NoopSecMigrate) {
    SessionState session;
    Storage storage;
    memset(storage.encrypted_sec, 0xAB, sizeof(storage.encrypted_sec));
    storage.has_sec = false;

    // Check that we don't blow away the encrypted_sec, if there weren't any
    // plaintext secrets.
    storage_secMigrate(&session, &storage, /*encrypt=*/true);
    for (int i = 0; i < sizeof(storage.encrypted_sec); i++) {
        ASSERT_EQ(storage.encrypted_sec[i], 0xAB);
    }
}

TEST(Storage, UpgradePolicies) {
    Storage src;
    src.pub.policies_count = 1;
    src.pub.policies[0].has_policy_name = true;
    memcpy(&src.pub.policies[0].policy_name[0], "ShapeShift", 11);
    src.pub.policies[0].has_enabled = true;
    src.pub.policies[0].enabled = true;

    storage_upgradePolicies(&src);

    EXPECT_EQ(src.pub.policies[0].has_policy_name, true);
    EXPECT_EQ(std::string(src.pub.policies[0].policy_name), "ShapeShift");
    EXPECT_EQ(src.pub.policies[0].has_enabled, true);
    EXPECT_EQ(src.pub.policies[0].enabled, true);

    EXPECT_EQ(src.pub.policies[1].has_policy_name, true);
    EXPECT_EQ(std::string(src.pub.policies[1].policy_name), "Pin Caching");
    EXPECT_EQ(src.pub.policies[1].has_enabled, true);
    EXPECT_EQ(src.pub.policies[1].enabled, true);
}

TEST(Storage, IsPinCorrect) {
    bool sca_hardened = true;

    uint8_t wrapping_key[64];
    uint8_t random_salt[32];
    memset(random_salt, 0, sizeof(random_salt));
    storage_deriveWrappingKey("1234", wrapping_key, sca_hardened, random_salt, "");

    const uint8_t storage_key[64] = "Quick blue fox";
    uint8_t wrapped_key[64];
    storage_wrapStorageKey(wrapping_key, storage_key, wrapped_key);

    uint8_t fingerprint[32];
    storage_keyFingerprint(storage_key, fingerprint);

    uint8_t key_out[64];
    EXPECT_TRUE(storage_isPinCorrect_impl("1234", wrapped_key, fingerprint, &sca_hardened, key_out, random_salt));

    EXPECT_TRUE(memcmp(key_out, storage_key, 64) == 0);
}

TEST(Storage, Vuln1996) {
    ConfigFlash config;
    SessionState session;
    uint8_t wrapping_key[64], wrapped_key1[64], wrapping_key_upin[64], storage_key[64], random_salt[32];

    struct {
        const char *pin;
    } vec[] = {
        { "" },
        { "1234" },
        { "000000000" },
    };

    for (const auto &v : vec) {
        memset(&session, 0, sizeof(session));
        memset(&config, 0, sizeof(config));
        memset(random_salt, 0, sizeof(random_salt));
        storage_reset_impl(&session, &config);
    
        storage_setPin_impl(&session, &config.storage, v.pin);

        ASSERT_TRUE(PIN_GOOD == storage_isPinCorrect_impl(v.pin,
            config.storage.pub.wrapped_storage_key,
            config.storage.pub.storage_key_fingerprint,
            &config.storage.pub.sca_hardened,
            storage_key,
            random_salt));
        ASSERT_TRUE(config.storage.pub.sca_hardened == true);
        memcpy(wrapped_key1, config.storage.pub.wrapped_storage_key, sizeof(wrapped_key1));

        // wrapped_key1 should be wrapped with aes128-pinstretch

        // Check storage wrapping update by generating parameters consistent with aes256-pinnostretch

        // first obtain the storage key generated above 
        storage_deriveWrappingKey(v.pin, wrapping_key, config.storage.pub.sca_hardened, random_salt, "");
        storage_unwrapStorageKey(wrapping_key, config.storage.pub.wrapped_storage_key, storage_key);

        // now derive a wrapping key from unstretched pin and wrap the storage key with it
        storage_deriveWrappingKey(v.pin, wrapping_key_upin, false, random_salt, "");
        uint8_t iv[64];
        memcpy(iv, wrapping_key_upin, sizeof(iv));
        aes_encrypt_ctx ctx;
        aes_encrypt_key256(wrapping_key_upin, &ctx);
        aes_cbc_encrypt(storage_key, config.storage.pub.wrapped_storage_key, 64, iv + 32, &ctx);
        config.storage.pub.sca_hardened = false;    // indicate this is an unhardened wrap key
    
        // wrapped_key1 is aes128-pinstretch.  Config version is wrapped aes256-pinnostretch 
        // for test. 

        // This check ensures that test conditions are correct.
        ASSERT_TRUE(memcmp(wrapped_key1, config.storage.pub.wrapped_storage_key, sizeof(wrapped_key1)) != 0);

        // now check that aes256-nopinstretch turns into aes128-pinstretched wrapping key
        ASSERT_TRUE(storage_isPinCorrect_impl(v.pin,
            config.storage.pub.wrapped_storage_key,
            config.storage.pub.storage_key_fingerprint,
            &config.storage.pub.sca_hardened,
            storage_key,
            random_salt));
        ASSERT_TRUE(memcmp(wrapped_key1, config.storage.pub.wrapped_storage_key, sizeof(wrapped_key1)) == 0);
        ASSERT_TRUE(config.storage.pub.sca_hardened == true);
    }
}

TEST(Storage, Reset) {
    ConfigFlash config;
    SessionState session;
    memset(&session, 0, sizeof(session));

    storage_reset_impl(&session, &config);

    ASSERT_TRUE(storage_isPinCorrect_impl("",
        config.storage.pub.wrapped_storage_key,
        config.storage.pub.storage_key_fingerprint,
        &config.storage.pub.sca_hardened,
        session.storageKey,
        config.storage.pub.random_salt));

    uint8_t old_storage_key[64];
    memcpy(old_storage_key, session.storageKey, sizeof(old_storage_key));
    storage_setPin_impl(&session, &config.storage, "1234");

    ASSERT_TRUE(memcmp(session.storageKey, old_storage_key, 64) != 0)
        << "RNG broken?";

    uint8_t new_storage_key[64];
    ASSERT_TRUE(storage_isPinCorrect_impl("1234",
        config.storage.pub.wrapped_storage_key,
        config.storage.pub.storage_key_fingerprint,
        &config.storage.pub.sca_hardened,
        new_storage_key,
        config.storage.pub.random_salt));

    ASSERT_TRUE(memcmp(session.storageKey, new_storage_key, 64) == 0);
}
