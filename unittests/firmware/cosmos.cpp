extern "C"
{
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/cosmos.h"
}

#include "gtest/gtest.h"
#include <cstring>

TEST(Cosmos, CosmosGetAddress)
{
    HDNode node = {
        0,
        0,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0x03, 0xb7, 0x32, 0x9f, 0x67, 0x8e, 0x0a, 0xc1, 0x21, 0x4b, 0x77, 0x23, 0x57, 0x54, 0x66, 0x21, 0x9c, 0x77, 0xfe, 0xdb, 0xdd, 0x95, 0x5c, 0x33, 0x29, 0x1a, 0x74, 0xf1, 0x8b, 0xf5, 0xc8, 0xa4, 0xe2},
        &secp256k1_info};
    char addr[46];
    ASSERT_TRUE(cosmos_getAddress(&node, addr));
    EXPECT_EQ(std::string("cosmos1am058pdux3hyulcmfgj4m3hhrlfn8nzm88u80q"), addr);
}

TEST(Cosmos, CosmosSignTx)
{
    HDNode node = {
        0,
        0,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        { 0x04, 0xde, 0xc0, 0xcc, 0x01, 0x3c, 0xd8, 0xab, 0x70, 0x87, 0xca, 0x14, 0x96, 0x0b, 0x76, 0x8c, 0x3d, 0x83, 0x45, 0x24, 0x48, 0xaa, 0x00, 0x64, 0xda, 0xe6, 0xfb, 0x04, 0xb5, 0xd9, 0x34, 0x76 },
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        &secp256k1_info
    };
    hdnode_fill_public_key(&node);
    const uint8_t *privkey = (uint8_t *)"\x04\xde\xc0\xcc\x01\x3c\xd8\xab\x70\x87\xca\x14\x96\x0b\x76\x8c\x3d\x83\x45\x24\x48\xaa\x00\x64\xda\xe6\xfb\x04\xb5\xd9\x34\x76";
    const uint8_t *expected = (uint8_t *)"\x41\x99\x66\x30\x08\xef\xea\x75\x93\x56\x35\xe6\x1a\x11\xdf\xa3\x3c\xeb\xeb\x91\xc1\xca\xed\xc6\x0e\x5e\xef\x3c\xa2\xc0\x1f\x83\x48\x08\x36\xe6\x21\x89\x51\x14\x36\x64\x7f\xac\x5a\xbd\xc2\x9f\x54\xae\x3d\x7e\x47\x56\x43\xca\x33\xc7\xad\x2c\x8a\x53\x2b\x39";
    const uint32_t address_n[5] = {0x80000000|44, 0x80000000|118, 0x80000000, 0, 0};
    ASSERT_TRUE(cosmos_signTxInit(&node, address_n, 5, 0, "cosmoshub-2", strlen("cosmoshub-2"), 5000, 200000, "", 0, 0, 1));
    ASSERT_TRUE(cosmos_signTxUpdateMsgSend(100000, "cosmos18vhdczjut44gpsy804crfhnd5nq003nz0nf20v"));
    uint8_t public_key[33];
    uint8_t signature[64];
    ASSERT_TRUE(cosmos_signTxFinalize(public_key, signature));
    EXPECT_TRUE(memcmp(expected, signature, 64) == 0);
}
