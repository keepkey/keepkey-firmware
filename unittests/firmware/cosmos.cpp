extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/cosmos.h"
}

#include "gtest/gtest.h"
#include <cstring>


TEST(Cosmos, CosmosGetAddress) {
    const uint8_t* pubkey = (uint8_t *)"\x03\xb7\x32\x9f\x67\x8e\x0a\xc1\x21\x4b\x77\x23\x57\x54\x66\x21\x9c\x77\xfe\xdb\xdd\x95\x5c\x33\x29\x1a\x74\xf1\x8b\xf5\xc8\xa4\xe2";
    char addr[46];
    ASSERT_TRUE(cosmos_getAddress(pubkey, addr));
    EXPECT_EQ(std::string("cosmos1am058pdux3hyulcmfgj4m3hhrlfn8nzm88u80q"), addr);
}

TEST(Cosmos, CosmosSignTx) {
   const uint8_t* privkey = (uint8_t*)"\x04\xde\xc0\xcc\x01\x3c\xd8\xab\x70\x87\xca\x14\x96\x0b\x76\x8c\x3d\x83\x45\x24\x48\xaa\x00\x64\xda\xe6\xfb\x04\xb5\xd9\x34\x76";
   uint8_t signature[64];
   const uint8_t* expected = (uint8_t*)"\x41\x99\x66\x30\x08\xef\xea\x75\x93\x56\x35\xe6\x1a\x11\xdf\xa3\x3c\xeb\xeb\x91\xc1\xca\xed\xc6\x0e\x5e\xef\x3c\xa2\xc0\x1f\x83\x48\x08\x36\xe6\x21\x89\x51\x14\x36\x64\x7f\xac\x5a\xbd\xc2\x9f\x54\xae\x3d\x7e\x47\x56\x43\xca\x33\xc7\xad\x2c\x8a\x53\x2b\x39";
   ASSERT_TRUE(cosmos_signTx(privkey, 0, "cosmoshub-2", strlen("cosmoshub-2"), 5000, 200000, "", 0, 100000, "cosmos1am058pdux3hyulcmfgj4m3hhrlfn8nzm88u80q", "cosmos18vhdczjut44gpsy804crfhnd5nq003nz0nf20v", 0, signature));
   EXPECT_TRUE(memcmp(expected, signature, 64) == 0);
}
