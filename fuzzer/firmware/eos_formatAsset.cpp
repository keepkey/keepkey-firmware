extern "C" {
#include "keepkey/firmware/eos.h"
#include "messages-eos.pb.h"
}

#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size != 16)
        return 0;

    EosAsset asset;
    asset.has_amount = true;
    asset.amount = *(const uint64_t*)&data[0];
    asset.has_symbol = true;
    asset.symbol = *(const uint64_t*)&data[8];

    char str[EOS_ASSET_STR_SIZE];
    eos_formatAsset(&asset, str);
    asm volatile("" : : "g"(str) : "memory");

    return 0;
}
