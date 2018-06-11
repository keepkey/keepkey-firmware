#include "keepkey/variant/keepkey.h"
#include "keepkey/variant/variant.h"
#include "keepkey/board/timer.h"

SignedVariantInfo keepkey_svi __attribute__((section("variant_info"))) = {
    .sigindex = 0, // to be filled in by the signing script
    .sig = {0},    // to be filled in by the signing script
    .length = 0,   // to be filled in by the signing script
    .info = { VARIANTINFO_KEEPKEY }
};
