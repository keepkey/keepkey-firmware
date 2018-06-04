#include "keepkey/variant/keepkey.h"

#include "keepkey/variant/variant.h"
#include "keepkey/variant/logo.h"


const VariantInfo variant_keepkey __attribute__((section("variant_info"))) = {
    .magic = "KPWL",
    .version = 1,
    .name = "KeepKey",
    .logo = &kk_logo,
    .logo_reversed = &kk_logo_reversed
};


