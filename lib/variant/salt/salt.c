#include "keepkey/variant/salt.h"

#include "keepkey/variant/variant.h"
#include "keepkey/board/timer.h"

const VariantInfo variant_salt __attribute__((section("variant_info"))) = {
    .magic = "KPWL",
    .version = 1,
    .name = "SALT",
    .logo = &salt_logo,
    .logo_reversed = &salt_logo_reversed,
    .screensaver_timeout = ONE_SEC * 60 * 10,
    .screensaver = &salt_screensaver,
};

