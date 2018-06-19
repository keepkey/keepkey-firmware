#include "keepkey/variant/salt.h"

#include "keepkey/board/timer.h"
#include "keepkey/board/variant.h"

SignedVariantInfo salt_svi __attribute__((section("variant_info"))) = {
    .sigindex = 0, // to be filled in by the signing script
    .sig = {0},    // to be filled in by the signing script
    .length = 0,   // to be filled in by the signing script
    .info = { VARIANTINFO_SALT }
};
