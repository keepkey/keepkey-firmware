extern "C" {
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/policy.h"
#include "keepkey/board/keepkey_board.h"
#include "trezor/crypto/memzero.h"
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

    for (int i = 0; i < sizeof(src); i++) {
        ASSERT_EQ(src[i], ((char *)&dst)[i]) << "i: " << i;
    }
}

TEST(Storage, WriteMeta) {
    const Metadata src = {
        .magic = "M1M",
        .uuid = "u1u2u3u4u5u",
        .uuid_str = "S1S2S3S4S5S6S7S8S9SASBS",
    };

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
    const PolicyType src = {
        .has_policy_name = true,
        .policy_name = "0123456789ABCD",
        .has_enabled = true,
        .enabled = true,
    };

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
    storage_deriveWrappingKey("123456789", wrapping_key); // strongest pin evar
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
    const Cache src = {
        .root_seed_cache_status = 42,
        .root_seed_cache = "012345678901234567890123456789012345678901234567890123456789012",
        .root_ecdsa_curve_type = "secp256k1",
    };

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
    HDNode src = {
      .depth = 42,
      .child_num = 11,
      .chain_code = { 1, 2, 3, 4 },
      .private_key = { 5, 6, 7 },
      .public_key = { 74 },
    };

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

    storage_setPolicy_impl(storage.pub.policies, "Pin Caching", false);
    EXPECT_EQ(storage.pub.policies[1].enabled, false);

    storage_setPolicy_impl(storage.pub.policies, "ShapeShift", false);
    EXPECT_EQ(storage.pub.policies[0].enabled, false);

    storage_setPolicy_impl(storage.pub.policies, "Pin Caching", true);
    EXPECT_EQ(storage.pub.policies[1].enabled, true);
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
    storage_deriveWrappingKey("123456789", wrapping_key); // strongest pin evar
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
    EXPECT_EQ(shadow.storage.pub.policies[1].enabled, false);
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
    start.storage.has_sec = true;
    start.storage.sec.pin[0] = '\0';
    start.storage.sec.cache.root_seed_cache_status = 0xEC;
    start.storage.sec.node.has_public_key = true;
    start.storage.sec.node.has_private_key = true;

    SessionState session;
    memset(&session, 0, sizeof(session));

    uint8_t wrapping_key[64];
    storage_deriveWrappingKey("", wrapping_key);
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
        0x7f, 0x42, 0x00, 0x00, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
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
        0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, STORAGE_VERSION, 0x00, 0x00, 0x00,
        0x94, 0x61, 0x3e, 0xe6, 0x6f, 0x79, 0xe8, 0x29, 0xba, 0x49, 0x41, 0xeb, 0x80, 0x8e, 0x4c, 0x2a,
        0x4a, 0x2b, 0x37, 0x08, 0xf5, 0x95, 0x61, 0x89, 0x57, 0xef, 0x98, 0xa1, 0x45, 0x19, 0x78, 0xe7,
        0x57, 0x58, 0xfa, 0x53, 0x1a, 0x10, 0x9a, 0x8b, 0xa4, 0x30, 0xcb, 0xd2, 0x41, 0x94, 0xeb, 0x23,
        0x74, 0xed, 0xb5, 0x5c, 0xce, 0xc9, 0xa4, 0x82, 0x86, 0xed, 0x27, 0x4c, 0x17, 0xe2, 0xd0, 0x51,
        0x57, 0x6e, 0xe5, 0x2e, 0xc3, 0x02, 0xa0, 0x08, 0xdc, 0x4f, 0x51, 0xcd, 0xee, 0x24, 0x84, 0xe4,
        0xc2, 0xb7, 0xed, 0x60, 0xf4, 0x2d, 0xf9, 0x7b, 0x9f, 0x04, 0x8d, 0x0b, 0xc5, 0x69, 0xbd, 0xc4,
        0x9a, 0x87, 0x2a, 0xdd, 0xfc, 0xa9, 0x13, 0xac, 0x93, 0x96, 0xb0, 0xb7, 0x6f, 0x18, 0x57, 0xab,
        0x76, 0x94, 0xaa, 0xe2, 0x82, 0x42, 0xaa, 0x84, 0x74, 0xfb, 0x77, 0x7a, 0x68, 0x6e, 0xd9, 0xcf,
        0x97, 0x55, 0x4d, 0xd3, 0xa3, 0x29, 0xf4, 0xc7, 0x75, 0xee, 0x36, 0x67, 0xc6, 0x97, 0x4a, 0x6e,
        0xf7, 0x4e, 0xab, 0xdb, 0x43, 0xcb, 0x50, 0xac, 0x8c, 0x75, 0xef, 0x7a, 0x30, 0x45, 0x11, 0x65,
        0xa2, 0x61, 0x34, 0x3c, 0x7d, 0x0c, 0x91, 0xee, 0xb3, 0x99, 0x86, 0xc3, 0x06, 0x7b, 0x82, 0xef,
        0xc5, 0xe4, 0x03, 0x3d, 0xf2, 0xc0, 0x03, 0xfe, 0xea, 0x54, 0x7b, 0x7e, 0x8c, 0x01, 0x26, 0x7c,
        0x94, 0x20, 0x99, 0x50, 0xcb, 0xd2, 0x2d, 0xaf, 0x74, 0x92, 0x23, 0x2c, 0xa6, 0xf7, 0x0a, 0x5f,
        0x37, 0x80, 0x03, 0x57, 0xb1, 0x1b, 0x25, 0x95, 0x42, 0x63, 0x7e, 0xf2, 0x76, 0xf5, 0x90, 0xb2,
        0x3f, 0x68, 0x61, 0xab, 0xf4, 0xfb, 0x44, 0x99, 0x44, 0x4d, 0x66, 0x9f, 0x01, 0xd7, 0xab, 0x67,
        0x93, 0x5c, 0x72, 0x94, 0xed, 0x85, 0x25, 0x26, 0xd9, 0xf6, 0xe4, 0x8a, 0x76, 0x8a, 0x1f, 0x24,
        0xad, 0x94, 0x40, 0xdf, 0xec, 0x88, 0x20, 0x6c, 0x05, 0xce, 0xdf, 0x5d, 0x8d, 0xf5, 0xa6, 0xfc,
        0x86, 0x8e, 0xe8, 0x36, 0x8e, 0xd5, 0xe2, 0xbb, 0xe6, 0x3d, 0x6b, 0x5b, 0xe8, 0xcd, 0x11, 0x94,
        0x8d, 0x3f, 0x25, 0xeb, 0xd9, 0x7d, 0x0f, 0xc4, 0xcc, 0xad, 0xe1, 0x91, 0xc4, 0xa7, 0x2e, 0xdd,
        0x11, 0xf5, 0xc7, 0x71, 0xa8, 0xd1, 0xfa, 0x35, 0x69, 0xcc, 0x98, 0x8e, 0xf8, 0x86, 0xfb, 0x8e,
        0xbb, 0x39, 0xf0, 0xf9, 0xc3, 0xda, 0x94, 0x09, 0xf2, 0xc7, 0xd6, 0xa9, 0xf7, 0x40, 0xbe, 0x69,
        0x74, 0xc9, 0xc6, 0xe0, 0xa6, 0x7a, 0x30, 0x4f, 0xa6, 0xe7, 0x13, 0x5e, 0x3a, 0xf1, 0x78, 0xb9,
        0x5c, 0x3b, 0x5d, 0x9f, 0xc0, 0x8d, 0xe9, 0x39, 0xe8, 0xf0, 0x83, 0x73, 0xf5, 0x83, 0xe9, 0xbb,
        0x36, 0x6b, 0xea, 0x8f, 0xd6, 0x4f, 0xab, 0xe6, 0xa0, 0xf1, 0x78, 0x12, 0x90, 0xef, 0x77, 0xf9,
        0x9f, 0xa1, 0x87, 0x29, 0xce, 0xa7, 0xa0, 0x1b, 0x0c, 0xd6, 0xcb, 0x06, 0x34, 0xe2, 0x11, 0xf3,
        0xb7, 0xbc, 0xb6, 0x91, 0x80, 0xf4, 0xed, 0x46, 0x7a, 0x36, 0x4b, 0x45, 0x50, 0xd0, 0x65, 0x2f,
        0x7a, 0x38, 0x52, 0xcb, 0x0e, 0x64, 0x79, 0x76, 0x9c, 0x41, 0x36, 0xcc, 0xc4, 0x11, 0x85, 0xb3,
        0x7d, 0x0f, 0xea, 0x95, 0x22, 0x95, 0x08, 0x3e, 0xbe, 0xc5, 0xed, 0x00, 0x6f, 0xca, 0x51, 0x37,
        0x34, 0x07, 0x33, 0xa2, 0xbb, 0x91, 0x51, 0x60, 0x8c, 0x5c, 0x0f, 0xd7, 0x05, 0x5b, 0x3a, 0x61,
        0x30, 0xef, 0xa3, 0x0c, 0xa9, 0x15, 0xd9, 0x37, 0x6a, 0xa7, 0x57, 0xeb, 0xc3, 0xb1, 0x5a, 0x82,
        0xdf, 0xd6, 0x67, 0x46, 0x9c, 0xdc, 0xaa, 0x51, 0x1b, 0x43, 0xc2, 0xf3, 0x8a, 0xfd, 0x7b, 0xba,
        0x59, 0x08, 0x70, 0x8a, 0x71, 0x9f, 0x18, 0x50, 0x87, 0x6a, 0x16, 0x1f, 0x14, 0xbd, 0xfe, 0x19,
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
    Storage src = {
        .pub = {
            .policies_count = 1,
            .policies = {{
                .has_policy_name = true,
                .policy_name = "ShapeShift",
                .has_enabled = true,
                .enabled = true,
            }},
        },
    };

    storage_upgradePolicies(&src);

    EXPECT_EQ(src.pub.policies[0].has_policy_name, true);
    EXPECT_EQ(std::string(src.pub.policies[0].policy_name), "ShapeShift");
    EXPECT_EQ(src.pub.policies[0].has_enabled, true);
    EXPECT_EQ(src.pub.policies[0].enabled, true);

    EXPECT_EQ(src.pub.policies[1].has_policy_name, true);
    EXPECT_EQ(std::string(src.pub.policies[1].policy_name), "Pin Caching");
    EXPECT_EQ(src.pub.policies[1].has_enabled, true);
    EXPECT_EQ(src.pub.policies[1].enabled, false);
}

TEST(Storage, IsPinCorrect) {

    uint8_t wrapping_key[64];
    storage_deriveWrappingKey("1234", wrapping_key);

    const uint8_t storage_key[64] = "Quick blue fox";
    uint8_t wrapped_key[64];
    storage_wrapStorageKey(wrapping_key, storage_key, wrapped_key);

    uint8_t fingerprint[32];
    storage_keyFingerprint(storage_key, fingerprint);

    uint8_t key_out[64];
    EXPECT_TRUE(storage_isPinCorrect_impl("1234", wrapped_key, fingerprint, key_out));

    EXPECT_TRUE(memcmp(key_out, storage_key, 64) == 0);
}

TEST(Storage, Pin) {
    storage_setPin("");
    ASSERT_TRUE(storage_isPinCorrect(""));

    storage_setPin("1234");
    ASSERT_TRUE(storage_isPinCorrect("1234"));
    ASSERT_FALSE(storage_isPinCorrect(""));
    ASSERT_FALSE(storage_isPinCorrect("9876"));

    storage_setPin("987654321");
    ASSERT_FALSE(storage_isPinCorrect(""));
    ASSERT_TRUE(storage_isPinCorrect("987654321"));

    storage_setPin("");
    ASSERT_TRUE(storage_isPinCorrect(""));
}

TEST(Storage, CacheWrongPin) {
    ConfigFlash config;
    SessionState session;
    memset(&session, 0, sizeof(session));

    storage_reset_impl(&session, &config);
    config.storage.has_sec = true;
    strcpy(config.storage.sec.mnemonic, "sekret");
    storage_setPin_impl(&session, &config.storage, "1234");

    // Attempt to cache the wrong pin
    session_cachePin_impl(&session, &config.storage, "1111");

    // Check that secrets were wiped from the session
    ASSERT_FALSE(config.storage.has_sec);
    ASSERT_EQ(std::string(config.storage.sec.mnemonic), "");
}

TEST(Storage, Reset) {
    ConfigFlash config;
    SessionState session;
    memset(&session, 0, sizeof(session));

    storage_reset_impl(&session, &config);

    ASSERT_TRUE(storage_isPinCorrect_impl("",
                                          config.storage.pub.wrapped_storage_key,
                                          config.storage.pub.storage_key_fingerprint,
                                          session.storageKey));

    uint8_t old_storage_key[64];
    memcpy(old_storage_key, session.storageKey, sizeof(old_storage_key));
    storage_setPin_impl(&session, &config.storage, "1234");

    ASSERT_TRUE(memcmp(session.storageKey, old_storage_key, 64) != 0)
        << "RNG broken?";

    uint8_t new_storage_key[64];
    ASSERT_TRUE(storage_isPinCorrect_impl("1234",
                                          config.storage.pub.wrapped_storage_key,
                                          config.storage.pub.storage_key_fingerprint,
                                          new_storage_key));

    ASSERT_TRUE(memcmp(session.storageKey, new_storage_key, 64) == 0);
}
