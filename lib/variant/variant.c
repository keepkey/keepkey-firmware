#include "keepkey/variant/variant.h"

#include "keepkey/board/keepkey_flash.h"
#include "keepkey/crypto/secp256k1.h"
#include "keepkey/crypto/ecdsa.h"
#include "keepkey/crypto/sha2.h"
#include "keepkey/variant/keepkey.h"
#include "keepkey/variant/salt.h"

#include <string.h>

#define SIGNEDVARIANTINFO_FLASH (SignedVariantInfo*)(0x8010000)

static const VariantAnimation *screensaver;
static const VariantAnimation *logo;
static const VariantAnimation *logo_reversed;
static const char *name;
static const uint32_t *screensaver_timeout;

const VariantInfo *variant_getInfo(void) {
#ifndef EMULATOR
    const SignedVariantInfo *flash = SIGNEDVARIANTINFO_FLASH;

    if (0 == memcmp(flash->info.magic, VARIANT_INFO_MAGIC, sizeof(flash->info.magic))) {
#  ifndef DEBUG_ON
        uint8_t info_fingerprint[32];
        sha256_Raw((uint8_t *)SIGNEDVARIANTINFO_FLASH + offsetof(SignedVariantInfo, length),
                   flash->length, info_fingerprint);

        if(ecdsa_verify_digest(&secp256k1, pubkey[flash->sigindex - 1], flash->sig,
                                info_fingerprint) == 0)
        {
            return &flash->info;
        }
#  else
        return &flash->info;
#  endif
    }
#endif

    const char *model = flash_getModel();
    if (!model)
        return &variant_keepkey;

    return &variant_keepkey;
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

