extern "C" {
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/policy.h"
#include "keepkey/board/keepkey_board.h"
#include "types.pb.h"
#include "storage.h"
}

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include <cstring>
#include <string>

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
    const char src[483] =
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
        /* 482 */ "\x01";            // policies[0].enabled

    Storage dst;
    memset(&dst, 0xCC, sizeof(dst));

    storage_readStorageV1(&dst, &src[0], sizeof(src));

    // Check a few, don't need to check them all.
    EXPECT_EQ(dst.version, 10);
    EXPECT_TRUE(dst.sec.has_node);
    EXPECT_EQ(dst.sec.node.depth, 3);
    EXPECT_EQ(dst.sec.node.fingerprint, 42);
    EXPECT_EQ(dst.sec.node.child_num, 17);
    EXPECT_EQ(dst.sec.node.chain_code.size, 32);
    EXPECT_TRUE(memcmp(dst.sec.node.chain_code.bytes, "XMRXMRXMRXMRXMRXMRXMRXMRXMRXMRX\0", 32) == 0);
    EXPECT_EQ(dst.sec.node.has_private_key, true);
    EXPECT_EQ(dst.sec.node.public_key.size, 33);
    EXPECT_TRUE(memcmp(dst.sec.node.public_key.bytes, "Who is Satoshi Nakomoto?????????\0", 32) == 0);
    EXPECT_EQ(dst.sec.has_mnemonic, true);
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
    StorageHDNode src = {
      .depth = 42,
      .fingerprint = 37,
      .child_num = 11,
      .chain_code = { 4, { 1, 2, 3, 4 } },
      .has_private_key = true,
      .private_key = { 3, { 5, 6, 7 } },
      .has_public_key = true,
      .public_key = { 1, { 74 } },
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
    EXPECT_EQ(dst.fingerprint, src.fingerprint);
    EXPECT_EQ(dst.child_num, src.child_num);
    EXPECT_EQ(dst.chain_code.size, src.chain_code.size);
    EXPECT_EQ(dst.chain_code.bytes[0], src.chain_code.bytes[0]);
    EXPECT_EQ(dst.has_private_key, src.has_private_key);
    EXPECT_EQ(dst.private_key.size, src.private_key.size);
    EXPECT_EQ(dst.private_key.bytes[0], src.private_key.bytes[0]);
    EXPECT_EQ(dst.has_public_key, src.has_public_key);
    EXPECT_EQ(dst.public_key.size, src.public_key.size);
    EXPECT_EQ(dst.public_key.bytes[0], src.public_key.bytes[0]);

    memset(&dst, 0, sizeof(dst));
    src.has_private_key = false;
    storage_dumpNode(&dst, &src);

    EXPECT_EQ(dst.depth, src.depth);
    EXPECT_EQ(dst.fingerprint, src.fingerprint);
    EXPECT_EQ(dst.child_num, src.child_num);
    EXPECT_EQ(dst.chain_code.size, src.chain_code.size);
    EXPECT_EQ(dst.chain_code.bytes[0], src.chain_code.bytes[0]);
    EXPECT_EQ(dst.has_private_key, src.has_private_key);
    EXPECT_EQ(dst.private_key.size, 0);
    EXPECT_EQ(dst.private_key.bytes[0], 0);
    EXPECT_EQ(dst.has_public_key, src.has_public_key);
    EXPECT_EQ(dst.public_key.size, src.public_key.size);
    EXPECT_EQ(dst.public_key.bytes[0], src.public_key.bytes[0]);

    memset(&dst, 0, sizeof(dst));
    src.has_public_key = false;
    storage_dumpNode(&dst, &src);

    EXPECT_EQ(dst.depth, src.depth);
    EXPECT_EQ(dst.fingerprint, src.fingerprint);
    EXPECT_EQ(dst.child_num, src.child_num);
    EXPECT_EQ(dst.chain_code.size, src.chain_code.size);
    EXPECT_EQ(dst.chain_code.bytes[0], src.chain_code.bytes[0]);
    EXPECT_EQ(dst.has_private_key, src.has_private_key);
    EXPECT_EQ(dst.private_key.size, 0);
    EXPECT_EQ(dst.private_key.bytes[0], 0);
    EXPECT_EQ(dst.has_public_key, src.has_public_key);
    EXPECT_EQ(dst.public_key.size, 0);
    EXPECT_EQ(dst.public_key.bytes[0], 0);
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


    ConfigFlash shadow;
    ASSERT_EQ(storage_fromFlash(&shadow, flash), SUS_Updated);

    EXPECT_EQ(shadow.storage.version, STORAGE_VERSION);
    EXPECT_EQ(shadow.storage.sec.node.depth, 3);
    EXPECT_EQ(memcmp(shadow.meta.magic, "stor", 4), 0);
    EXPECT_EQ(std::string(shadow.storage.pub.policies[0].policy_name), "ShapeShift");
}

TEST(Storage, StorageUpgrade_Vec) {
    const struct {
        int version;
        StorageUpdateStatus update;
        uint8_t root_seed_cache_status;
    } vec[] = {
        { 0,                   SUS_Invalid, 0xCC },
        { 1,                   SUS_Updated, 0x00 },
        { 2,                   SUS_Updated, 0xAB },
        { 10,                  SUS_Updated, 0xAB },
        { STORAGE_VERSION,     SUS_Valid,   0xAB },
        { STORAGE_VERSION + 1, SUS_Invalid, 0xCC }
    };

    for (const auto &v : vec) {
        ConfigFlash start;
        memset(&start, 0xAB, sizeof(start));
        memcpy(start.meta.magic, "stor", 4);
        start.storage.version = v.version;
        start.storage.sec.node.fingerprint = 42;

        std::vector<char> flash(STORAGE_SECTOR_LEN);

        storage_writeV3(&flash[0], flash.size(), &start);

        ConfigFlash end;
        memset(&end, 0xCC, sizeof(end));
        EXPECT_EQ(storage_fromFlash(&end, &flash[0]), v.update)
            << v.version;

        if (v.update != SUS_Invalid) {
            EXPECT_EQ(end.storage.version, STORAGE_VERSION);
        }

        EXPECT_EQ(end.storage.sec.cache.root_seed_cache_status,
                  v.root_seed_cache_status)
            << "v.version: "       << v.version << "\n"
            << "STORAGE_VERSION: " << STORAGE_VERSION;
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

TEST(Storage, WrappingKey) {
    using ::testing::ElementsAreArray;

    const struct {
        char pin[17];
        uint8_t key[64];
        uint8_t wrapping[64];
        uint8_t wrapped[64];
    } vec[] = {
        {
            .pin = "0123456789",
            .key = "\x00\x01\x02\x03\x04\x05\x06\x07"
                   "\x00\x01\x02\x03\x04\x05\x06\x07"
                   "\x00\x01\x02\x03\x04\x05\x06\x07"
                   "\x00\x01\x02\x03\x04\x05\x06\x07"
                   "\x00\x01\x02\x03\x04\x05\x06\x07"
                   "\x00\x01\x02\x03\x04\x05\x06\x07"
                   "\x00\x01\x02\x03\x04\x05\x06\x07"
                   "\x00\x01\x02\x03\x04\x05\x06",
            .wrapping = { 0x7d, 0xd4, 0xc9, 0xbe, 0xb0, 0xbd, 0x1a, 0x5c, 0x0a, 0x1f, 0xc8, 0xad, 0x88, 0xaf, 0xae, 0x5a, 0x09, 0x35, 0x1a, 0xba, 0x0e, 0xf9, 0x48, 0x38, 0xa9, 0xae, 0x46, 0xad, 0x7f, 0x30, 0x3e, 0xbc, 0x93, 0x64, 0xa1, 0x23, 0xf5, 0x8e, 0x54, 0xd3, 0x7e, 0x00, 0x7b, 0x47, 0xca, 0x97, 0xc1, 0x38, 0x5b, 0xb1, 0xc5, 0x6a, 0x7d, 0xb6, 0xb3, 0x52, 0x69, 0x55, 0xea, 0x2d, 0x8d, 0x7a, 0xfb, 0x1c },
            .wrapped = { 0x41, 0xf3, 0xb2, 0x18, 0x54, 0xa0, 0xfc, 0xb2, 0x72, 0x45, 0xa6, 0x8c, 0xff, 0x23, 0xda, 0xfc, 0x5f, 0xc2, 0x60, 0x00, 0x59, 0xdd, 0xe1, 0x1c, 0x15, 0x7d, 0x96, 0xa4, 0x07, 0x99, 0x9c, 0xcf, 0x08, 0x44, 0x97, 0xe7, 0xbc, 0xfa, 0x1c, 0x42, 0x77, 0x82, 0x5e, 0xf2, 0xad, 0x8c, 0x6b, 0x5c, 0x1e, 0xb6, 0x35, 0x36, 0xe6, 0xa3, 0xb9, 0xb9, 0x7b, 0xa8, 0x5e, 0x20, 0x3c, 0x7f, 0x47, 0xae },
        },
        {
            .pin = "",
            .key = "Quick Shifty Fox",
            .wrapping = { 0x8b, 0x2b, 0x2e, 0x25, 0x42, 0xd7, 0xad, 0x5d, 0xc4, 0xf1, 0xfc, 0xfb, 0x77, 0x23, 0xb5, 0xe8, 0x7c, 0x78, 0x85, 0x6d, 0x7c, 0xb6, 0xfa, 0x69, 0xae, 0xaf, 0x90, 0x53, 0xcd, 0xc1, 0x1a, 0x98, 0xee, 0x7d, 0xa8, 0x55, 0xd9, 0xd2, 0x2c, 0x60, 0x03, 0xab, 0xb3, 0x71, 0x0e, 0x1c, 0x9e, 0xc6, 0xdf, 0x82, 0xa6, 0x86, 0x87, 0xec, 0x3d, 0xdb, 0x3a, 0xe2, 0x2d, 0xf1, 0xac, 0x43, 0x3c, 0x56 },
            .wrapped = { 0xfd, 0xb2, 0xa9, 0xcc, 0x94, 0x26, 0xf5, 0xe1, 0x29, 0x3d, 0x68, 0xa8, 0x86, 0x19, 0x0c, 0x51, 0x1c, 0xff, 0x29, 0xa4, 0x7c, 0xe7, 0xd7, 0xc5, 0x7d, 0x20, 0x57, 0xc8, 0x41, 0x35, 0x79, 0x96, 0xeb, 0x85, 0x16, 0x7d, 0x3f, 0xb4, 0x28, 0xc3, 0xb8, 0xa8, 0xc3, 0x6f, 0x76, 0x2e, 0xaa, 0x7b, 0x56, 0xf9, 0xaa, 0x8f, 0x75, 0x5b, 0x78, 0xc0, 0xbb, 0xe2, 0x22, 0x04, 0xd0, 0x69, 0x22, 0x8f },
        },
        {
            .pin = "11111111",
            .key = { 0 },
            .wrapping = { 0xac, 0x42, 0xbb, 0xc7, 0x0b, 0x81, 0x0d, 0xbf, 0x8e, 0xea, 0xd2, 0xa2, 0xb8, 0x44, 0x53, 0xb9, 0x79, 0x30, 0xde, 0x58, 0xd4, 0xad, 0xed, 0xb5, 0x16, 0x18, 0x73, 0x4c, 0x23, 0x87, 0xe0, 0xbd, 0xac, 0x38, 0xac, 0xce, 0x9b, 0xbb, 0xc9, 0x0f, 0xcb, 0xb8, 0x47, 0xc0, 0x23, 0x73, 0x3a, 0xa2, 0x96, 0x98, 0x90, 0x6e, 0x6c, 0xab, 0xd7, 0x06, 0x44, 0x4b, 0x74, 0xee, 0x53, 0x04, 0x14, 0xee },
            .wrapped = { 0x01, 0x28, 0xa9, 0x34, 0x6c, 0x1a, 0x4e, 0x8f, 0xd3, 0xd2, 0x2b, 0xa8, 0xe7, 0x5c, 0xa1, 0x9c, 0x6b, 0x06, 0x34, 0x78, 0xcf, 0x61, 0x8e, 0x0f, 0x38, 0x3c, 0x5b, 0x2d, 0xca, 0x8b, 0x0a, 0x8b, 0x9a, 0x87, 0x7a, 0x6d, 0x19, 0xee, 0xfb, 0xb7, 0x44, 0xda, 0x84, 0x3e, 0x03, 0x66, 0xd1, 0x17, 0x6c, 0x5e, 0x4e, 0x37, 0x53, 0x40, 0xe7, 0xc8, 0x1c, 0xe3, 0x48, 0x94, 0x47, 0x70, 0xe5, 0xdf },
        },
    };

    for (const auto &v : vec) {
        uint8_t wrapping_key[64];
        storage_deriveWrappingKey(v.pin, wrapping_key);
        EXPECT_THAT(wrapping_key, ElementsAreArray(v.wrapping));

        uint8_t wrapped_key[64];
        storage_wrapStorageKey(wrapping_key, v.key, wrapped_key);
        EXPECT_THAT(wrapped_key, ElementsAreArray(v.wrapped));

        uint8_t unwrapped_key[64];
        EXPECT_TRUE(storage_unwrapStorageKey(wrapping_key, wrapped_key, unwrapped_key));
        EXPECT_THAT(unwrapped_key, ElementsAreArray(v.key));
    }
}

