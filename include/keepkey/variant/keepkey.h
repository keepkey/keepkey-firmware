#ifndef KEEPKEY_VARIANT_KEEPKEY_H
#define KEEPKEY_VARIANT_KEEPKEY_H

#include "keepkey/board/variant.h"

#define VARIANTINFO_KEEPKEY \
    .magic = VARIANTINFO_MAGIC, \
    .version = 1, \
    .name = "KeepKey", \
    .logo = &kk_logo, \
    .logo_reversed = &kk_logo_reversed, \
    .screensaver_timeout = ONE_SEC * 60 * 10, \
    .screensaver = &kk_screensaver,

extern const VariantInfo variant_keepkey;
extern const VariantAnimation kk_logo;
extern const VariantAnimation kk_logo_reversed;
extern const VariantAnimation kk_screensaver;

#endif
