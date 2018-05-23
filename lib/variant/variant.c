#include "keepkey/variant/variant.h"

#include <string.h>

#define VARIANT_INFO_FLASH (VariantInfo*)(0x8010000)

static VariantAnimation *screensaver;
static VariantImage *home_screen;

const VariantInfo *variant_getInfo(void) {
#ifndef EMULATOR
    const VariantInfo *flash = VARIANT_INFO_FLASH;

    if (0 == memcmp(flash->magic, VARIANT_INFO_MAGIC, sizeof(flash->magic)))
        return flash;
#endif

    // FIXME: implement fallback for when there isn't anything in sector 4
    return NULL;
}

const VariantAnimation *variant_getScreensaver(void) {
    if (screensaver)
        return screensaver;

    screensaver = variant_getInfo()->screensaver;
    return screensaver;
}

const VariantImage *variant_getHomeScreen(void) {
    if (home_screen)
        return home_screen;

    home_screen = variant_getInfo()->home_screen;
    return home_screen;
}
