#ifndef KEEPKEY_VARIANT_POWERED_BY_H
#define KEEPKEY_VARIANT_POWERED_BY_H

#include "keepkey/board/variant.h"

#define VARIANTINFO_POWERED_BY                                 \
  .version = 1, .name = "POWERED_BY", .logo = &poweredBy_logo, \
  .logo_reversed = &poweredBy_logo_reversed,                   \
  .screensaver_timeout = ONE_SEC * 60 * 10, .screensaver = &poweredBy_logo,

extern const VariantInfo variant_poweredBy;
extern const VariantAnimation poweredBy_logo;
extern const VariantAnimation poweredBy_logo_reversed;
extern const VariantAnimation poweredBy_screensaver;

#endif
