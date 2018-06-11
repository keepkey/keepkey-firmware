#ifndef KEEPKEY_VARIANT_VARIANT_H
#define KEEPKEY_VARIANT_VARIANT_H

#include <inttypes.h>
#include <stdbool.h>

#define VARIANTINFO_MAGIC "KKWL"

typedef struct VariantImage_ {
    uint16_t w;
    uint16_t h;
    uint32_t length;
    const uint8_t *data;
} VariantImage;

typedef struct VariantFrame_ {
    uint16_t x;
    uint16_t y;
    uint16_t duration;
    uint8_t color;
    const VariantImage *image;
} VariantFrame;

typedef struct VariantAnimation_ {
    uint16_t count;
    VariantFrame frames[];
} VariantAnimation;

typedef struct VariantInfo_ {
    char magic[4];
    uint16_t version;
    const char *name;
    const VariantAnimation *logo;
    const VariantAnimation *logo_reversed;
    uint32_t screensaver_timeout;
    const VariantAnimation *screensaver;
} VariantInfo;

typedef struct SignedVariantInfo_ {
    uint8_t sigindex;
    uint8_t sig[64];
    uint32_t length;
    VariantInfo info;
} SignedVariantInfo;

/// Get the VariantInfo from sector 4 of flash (if it exists), otherwise
/// fallback on keepkey imagery.
const VariantInfo *variant_getInfo(void);

/// Get the Screensaver.
const VariantAnimation *variant_getScreensaver(void);

/// Get the HomeScreen.
const VariantAnimation *variant_getLogo(bool reverse);

#endif
