#ifndef KEEPKEY_VARIANT_VARIANT_H
#define KEEPKEY_VARIANT_VARIANT_H

#include "keepkey/board/memory.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#define VARIANTINFO_MAGIC "KKWL"

typedef struct Image_ {
    uint16_t w;
    uint16_t h;
    uint32_t length;
    const uint8_t *data;
} Image;

typedef struct AnimationFrame_ {
    uint16_t x;
    uint16_t y;
    uint16_t duration;
    uint8_t color;
    const Image *image;
} AnimationFrame;

typedef struct VariantAnimation_ {
    uint16_t count;
    AnimationFrame frames[];
} VariantAnimation;

typedef struct VariantInfo_ {
    uint16_t version;
    const char *name;
    const VariantAnimation *logo;
    const VariantAnimation *logo_reversed;
    uint32_t screensaver_timeout; // DEPRECATED
    const VariantAnimation *screensaver;
} VariantInfo;

typedef struct SignedVariantInfo_ {
    app_meta_td meta;
    VariantInfo info;
} SignedVariantInfo;

typedef enum Model_ {
    MODEL_UNKNOWN,
    #define MODEL_ENTRY(STRING, ENUM) \
        MODEL_ ##ENUM,
    #include "keepkey/board/models.def"
} Model;

/// Get the model of the device (Keepkey/SALT/etc)
Model getModel(void);

/// Get the VariantInfo from sector 4 of flash (if it exists), otherwise
/// fallback on keepkey imagery.
const VariantInfo *variant_getInfo(void) __attribute__((weak));

/// Get the Screensaver.
const VariantAnimation *variant_getScreensaver(void);

/// Get the HomeScreen.
const VariantAnimation *variant_getLogo(bool reverse);

#endif
