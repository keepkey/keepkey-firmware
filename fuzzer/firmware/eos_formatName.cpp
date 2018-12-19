extern "C" {
#include "keepkey/firmware/eos.h"
}

#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size != 4)
        return 0;

    char str[EOS_NAME_STR_SIZE];
    eos_formatName(*(const uint32_t*)data, str);
    asm volatile("" : : "g"(str) : "memory");

    return 0;
}
