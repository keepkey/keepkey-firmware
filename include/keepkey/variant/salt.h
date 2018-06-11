#ifndef KEEPKEY_VARIANT_SALT_H
#define KEEPKEY_VARIANT_SALT_H

#include "keepkey/variant/variant.h"

#define VARIANTINFO_SALT \
    .magic = "KPWL", \
    .version = 1, \
    .name = "SALT", \
    .logo = &salt_logo, \
    .logo_reversed = &salt_logo_reversed, \
    .screensaver_timeout = ONE_SEC * 60 * 10, \
    .screensaver = &salt_screensaver,

extern const VariantInfo variant_salt;
extern const VariantAnimation salt_logo;
extern const VariantAnimation salt_logo_reversed;
extern const VariantAnimation salt_screensaver;

#endif
