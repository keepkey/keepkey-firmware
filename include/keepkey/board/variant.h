#ifndef KEEPKEY_VARIANT_VARIANT_H
#define KEEPKEY_VARIANT_VARIANT_H

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
const VariantInfo *variant_getInfo(void) __attribute__((weak));

/// Get the Screensaver.
const VariantAnimation *variant_getScreensaver(void);

/// Get the HomeScreen.
const VariantAnimation *variant_getLogo(bool reverse);

/// \returns true iff this is a Manufacturing firmware.
bool variant_isMFR(void);

/// \brief Writes a buffer to flash.
///
/// \param address[in]   Where to write the data.
/// \param data[in]      The data to write.
/// \param data_len[in]  How much data to write.
/// \param erase[in]     Whether to clear the sector first.
bool variant_mfr_flashWrite(uint8_t *address, uint8_t *data, size_t data_len,
                             bool erase) __attribute__((weak));

/// \brief Hashes the data stored in the requested areas of flash.
///
/// \param address[in]       The address to start the hash at.
/// \param address_len[in]   The length of data to hash.
/// \param challenge[in]     The challenge to hash with.
/// \param challenge_len[in] The length of the challenge buffer in bytes.
/// \param hash[out]         The contents of the hash.
/// \param hash_len[in]      The number of bytes allowed to be written into hash.
///
/// \returns false iff there was a problem calculating the hash (e.g. permissions, etc)
bool variant_mfr_flashHash(uint8_t *address, size_t address_len,
                                   uint8_t *challenge, size_t challenge_len,
                                   uint8_t *hash, size_t hash_len) __attribute__((weak));

/// Dump chunks of flash. Behaves like memcpy.
void variant_mfr_flashDump(uint8_t *dst, uint8_t *src, size_t len) __attribute__((weak));

/// Get the sector number for an address.
uint8_t variant_mfr_sectorFromAddress(uint8_t *address) __attribute__((weak));

/// Get the starting address of a sector.
void *variant_mfr_sectorStart(uint8_t sector) __attribute__((weak));

/// Get the length of a sector.
uint32_t variant_mfr_sectorLength(uint8_t sector) __attribute__((weak));

#endif
