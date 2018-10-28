#include "keepkey/variant/keepkey.h"

#include "keepkey/board/timer.h"
#include "keepkey/board/variant.h"

VariantInfo keepkey_svi __attribute__((section("variant_info"))) = {
    VARIANTINFO_KEEPKEY
};
