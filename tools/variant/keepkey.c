#include "keepkey/variant/variant.h"

const VariantInfo kk_variant_info __attribute__((section("variant_info"))) = {
    .magic = VARIANT_INFO_MAGIC,
    .version = 1,
    .name = "KeepKey",
    .home_screen = 0,
    .screensaver = 0,
};

