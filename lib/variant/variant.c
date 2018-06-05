#include "keepkey/variant/variant.h"

#include "keepkey/variant/keepkey.h" 
#include "keepkey/variant/salt.h" 
#include "keepkey/board/keepkey_flash.h"

#include <string.h>

#define VARIANT_INFO_FLASH (VariantInfo*)(0x8010000)

static const VariantAnimation *screensaver;
static const VariantAnimation *logo;
static const VariantAnimation *logo_reversed;
static const char *name;
static const uint32_t *screensaver_timeout;

const VariantInfo *variant_getInfo(void) {
#ifndef EMULATOR
    const VariantInfo *flash = VARIANT_INFO_FLASH;

    if (0 == memcmp(flash->magic, VARIANT_INFO_MAGIC, sizeof(flash->magic)))
        return flash;
#endif

    const char *model = flash_getModel();
    if (!model)
        return &variant_salt;

    // FIXME: implement fallback for when there isn't anything in sector 4
    return &variant_salt;
}

const VariantAnimation *variant_getScreensaver(void) {
    if (screensaver)
        return screensaver;

    screensaver = variant_getInfo()->screensaver;
    return screensaver;
}

const VariantAnimation *variant_getLogo(bool reversed) {
    if (reversed && logo_reversed)
        return logo_reversed;
    if (!reversed && logo)
        return logo;

    logo = variant_getInfo()->logo;
    logo_reversed = variant_getInfo()->logo_reversed;

    return reversed ? logo_reversed : logo;
}

const char *variant_getName(void) {
    if (name) {
        return name;
    }

    name = variant_getInfo()->name;
    return name;
}

uint32_t variant_getScreensaverTimeout(void) {
    if (screensaver_timeout) {
        return *screensaver_timeout;
    }

    screensaver_timeout = &variant_getInfo()->screensaver_timeout;
    return *screensaver_timeout;
}

