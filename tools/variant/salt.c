#include "keepkey/variant/salt.h"

#include "keepkey/board/timer.h"
#include "keepkey/board/variant.h"

VariantInfo salt_svi
    __attribute__((section("variant_info"))) = {VARIANTINFO_SALT};
