#include "keepkey/board/variant.h"

#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/pubkeys.h"
#include "hwcrypto/crypto/secp256k1.h"
#include "hwcrypto/crypto/ecdsa.h"
#include "hwcrypto/crypto/sha2.h"
#include "keepkey/variant/keepkey.h"
#include "keepkey/variant/salt.h"

#include <string.h>

#define SIGNEDVARIANTINFO_FLASH (SignedVariantInfo *)(0x8010000)

static const VariantAnimation *screensaver;
static const VariantAnimation *logo;
static const VariantAnimation *logo_reversed;
static const char *name;

// Retrieves model information from storage
Model getModel(void) {
  const char *model = flash_getModel();
  if (!model) return MODEL_UNKNOWN;
#define MODEL_ENTRY_KK(STRING, ENUM)  \
  if (0 == strcmp(model, (STRING))) { \
    return MODEL_KEEPKEY;             \
  }
#define MODEL_ENTRY_SALT(STRING, ENUM) \
  if (0 == strcmp(model, (STRING))) {  \
    return MODEL_SALT;                 \
  }
#define MODEL_ENTRY_FOX(STRING, ENUM) \
  if (0 == strcmp(model, (STRING))) { \
    return MODEL_FOX;                 \
  }
#define MODEL_ENTRY_KASPERSKY(STRING, ENUM) \
  if (0 == strcmp(model, (STRING))) {       \
    return MODEL_KASPERSKY;                 \
  }
#define MODEL_ENTRY_BLOCKPIT(STRING, ENUM) \
  if (0 == strcmp(model, (STRING))) {      \
    return MODEL_BLOCKPIT;                 \
  }
#define MODEL_ENTRY_DASH(STRING, ENUM) \
  if (0 == strcmp(model, (STRING))) {  \
    return MODEL_DASH;                 \
  }

#include "keepkey/board/models.def"

  return MODEL_UNKNOWN;
}

#if !defined(EMULATOR)
static int variant_signature_check(const SignedVariantInfo *svi) {
  uint8_t sigindex1 = svi->meta.sig_index1;
  uint8_t sigindex2 = svi->meta.sig_index2;
  uint8_t sigindex3 = svi->meta.sig_index3;

  if (sigindex1 < 1 || sigindex1 > PUBKEYS) {
    return SIG_FAIL;
  } /* Invalid index */

  if (sigindex2 < 1 || sigindex2 > PUBKEYS) {
    return SIG_FAIL;
  } /* Invalid index */

  if (sigindex3 < 1 || sigindex3 > PUBKEYS) {
    return SIG_FAIL;
  } /* Invalid index */

  if (sigindex1 == sigindex2) {
    return SIG_FAIL;
  } /* Duplicate use */

  if (sigindex1 == sigindex3) {
    return SIG_FAIL;
  } /* Duplicate use */

  if (sigindex2 == sigindex3) {
    return SIG_FAIL;
  } /* Duplicate use */

  uint8_t info_fingerprint[32];
  sha256_Raw((void *)&svi->info, svi->meta.code_len, info_fingerprint);

  if (ecdsa_verify_digest(&secp256k1, pubkey[sigindex1 - 1], &svi->meta.sig1[0],
                          info_fingerprint) != 0)
    return SIG_FAIL;

  if (ecdsa_verify_digest(&secp256k1, pubkey[sigindex2 - 1], &svi->meta.sig2[0],
                          info_fingerprint) != 0)
    return SIG_FAIL;

  if (ecdsa_verify_digest(&secp256k1, pubkey[sigindex3 - 1], &svi->meta.sig3[0],
                          info_fingerprint) != 0)
    return SIG_FAIL;

  return SIG_OK;
}
#endif

const VariantInfo *__attribute__((weak)) variant_getInfo(void) {
#ifndef EMULATOR
  const SignedVariantInfo *flash = SIGNEDVARIANTINFO_FLASH;
  if (memcmp(&flash->meta.magic, VARIANTINFO_MAGIC,
             sizeof(flash->meta.magic)) == 0) {
    if (SIG_OK == variant_signature_check(flash)) {
      return &flash->info;
    }
#ifdef DEBUG_ON
    return &flash->info;
#endif
  }
#endif

  switch (getModel()) {
    case MODEL_KEEPKEY:
      return &variant_keepkey;
    case MODEL_SALT:
#ifndef BITCOIN_ONLY
      return &variant_salt;
#else 
      return &variant_keepkey;
#endif
    case MODEL_FOX:
      return &variant_keepkey;
    case MODEL_KASPERSKY:
      return &variant_keepkey;
    case MODEL_BLOCKPIT:
      return &variant_keepkey;
    case MODEL_DASH:
      return &variant_keepkey;
    case MODEL_UNKNOWN:
      return &variant_keepkey;
  }
  return &variant_keepkey;
}

const VariantAnimation *variant_getScreensaver(void) {
  if (screensaver) return screensaver;

  screensaver = variant_getInfo()->screensaver;
  return screensaver;
}

const VariantAnimation *variant_getLogo(bool reversed) {
  if (reversed && logo_reversed) return logo_reversed;
  if (!reversed && logo) return logo;

  logo = variant_getInfo()->logo;
  logo_reversed = variant_getInfo()->logo_reversed;

  return reversed ? logo_reversed : logo;
}

const char *variant_getName(void) {
#ifdef EMULATOR
  #ifdef BITCOIN_ONLY
    return "EmulatorBTC";
  #else
    return "Emulator";
  #endif
#else
  if (name) {
    return name;
  }

  name = variant_getInfo()->name;
  return name;
#endif
}
