#include "keepkey/variant/variant.h"
#include "keepkey/variant/logo.h"

VariantInfo variant_salt = {
    .magic = "KPWL",
    .version = 1,
    .name = "SALT",
    .logo = &salt_logo,
    .logo_reversed = &salt_logo_reversed
};

