/*
 * Copyright (C) 2022 markrypto
 *
 * TOPT generation as described in https://www.rfc-editor.org/rfc/rfc3238
 * 
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "keepkey/board/layout.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/firmware/crypto.h"
#include "trezor/crypto/aes/aes.h"
#include "trezor/crypto/base32.h"
#include "trezor/crypto/hmac.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/sha2.h"

#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/app_layout.h"

#include <string.h>
#include <stdio.h>

typedef struct _HMAC_SHA1_CTX {
  uint8_t o_key_pad[SHA1_BLOCK_LENGTH];
  SHA1_CTX ctx;
} HMAC_SHA1_CTX;

void hmac_sha1_Init(HMAC_SHA1_CTX *hctx, const uint8_t *key,
                      const uint32_t keylen);
void hmac_sha1_Update(HMAC_SHA1_CTX *hctx, const uint8_t *msg,
                        const uint32_t msglen);
void hmac_sha1_Final(HMAC_SHA1_CTX *hctx, uint8_t *hmac);
void hmac_sha1(const uint8_t *key, const uint32_t keylen, const uint8_t *msg,
                 const uint32_t msglen, uint8_t *hmac);


static char AuthenticatorSecret[32];
static uint32_t AuthSecretSize;
static bool AuthenticatorHasSecret = false;

bool initializeAuthenticator(char *seedStr) {

  char bufStr[65] = {0}, tmpStr[3];

  AuthenticatorHasSecret = (NULL != base32_decode((const char *)seedStr, strlen(seedStr), 
                            (uint8_t *)AuthenticatorSecret, 
                            sizeof(AuthenticatorSecret), BASE32_ALPHABET_RFC4648));
  
  AuthSecretSize = strlen(AuthenticatorSecret);
  AuthSecretSize > 64 ? AuthSecretSize=64 : true ;
  for (unsigned i=0; i<AuthSecretSize; i++) {
    snprintf(tmpStr, 3, "%02x", AuthenticatorSecret[i]);
    strncat(bufStr, tmpStr, 2);
  }
    
  confirm(ButtonRequestType_ButtonRequest_Other, "Authenticator Initialization", 
          "Confirm seed value: %s", seedStr);

  return AuthenticatorHasSecret;
}

bool generateAuthenticator(char msgStr[], size_t len, char *digestStr) {

  char bufStr[33]={0}, tmpStr[3];
  uint8_t hmac[SHA1_DIGEST_LENGTH];           // hmac-sha1 digest length is 160 bits

  bufStr[32] = 0;

  for (unsigned i=0; i<len; i++) {
    snprintf(tmpStr, 3, "%02x", msgStr[i]);
    strncat(bufStr, tmpStr, 2);
  }

  confirm_with_custom_layout(&layout_notification_no_title_no_bold,
                                    ButtonRequestType_ButtonRequest_Other, "", "Hexval: %s",
                                    bufStr);

  {
  hmac_sha1((const uint8_t*)AuthenticatorSecret, (const uint32_t)AuthSecretSize, 
                  (const uint8_t*)msgStr, (const uint32_t)len, (uint8_t *)hmac);
  }


  for (unsigned i=0; i<SHA1_DIGEST_LENGTH; i++) {
    snprintf(tmpStr, 3, "%02x", hmac[i]);
    strncat(digestStr, tmpStr, 2);
  }

  confirm_with_custom_layout(&layout_notification_no_title_no_bold,
                                    ButtonRequestType_ButtonRequest_Other, "", "hmac-sha1: %s",
                                    digestStr);



  // TODO: Truncate to 6 digits and display

  DEBUG_DISPLAY("TRY TO RETURN");
  return true;
}

void hmac_sha1_Init(HMAC_SHA1_CTX *hctx, const uint8_t *key,
                      const uint32_t keylen) {
  static CONFIDENTIAL uint8_t i_key_pad[SHA1_BLOCK_LENGTH];
  memzero(i_key_pad, SHA1_BLOCK_LENGTH);
  if (keylen > SHA1_BLOCK_LENGTH) {
    sha1_Raw(key, keylen, i_key_pad);
  } else {
    memcpy(i_key_pad, key, keylen);
  }
  for (int i = 0; i < SHA1_BLOCK_LENGTH; i++) {
    hctx->o_key_pad[i] = i_key_pad[i] ^ 0x5c;
    i_key_pad[i] ^= 0x36;
  }
  sha1_Init(&(hctx->ctx));
  sha1_Update(&(hctx->ctx), i_key_pad, SHA1_BLOCK_LENGTH);
  memzero(i_key_pad, sizeof(i_key_pad));
}

void hmac_sha1_Update(HMAC_SHA1_CTX *hctx, const uint8_t *msg,
                        const uint32_t msglen) {
  sha1_Update(&(hctx->ctx), msg, msglen);
}

void hmac_sha1_Final(HMAC_SHA1_CTX *hctx, uint8_t *hmac) {
  sha1_Final(&(hctx->ctx), hmac);
  sha1_Init(&(hctx->ctx));
  sha1_Update(&(hctx->ctx), hctx->o_key_pad, SHA1_BLOCK_LENGTH);
  sha1_Update(&(hctx->ctx), hmac, SHA1_DIGEST_LENGTH);
  sha1_Final(&(hctx->ctx), hmac);
  memzero(hctx, sizeof(HMAC_SHA1_CTX));
}

void hmac_sha1(const uint8_t *key, const uint32_t keylen, const uint8_t *msg,
                 const uint32_t msglen, uint8_t *hmac) {
  static CONFIDENTIAL HMAC_SHA1_CTX hctx;
  hmac_sha1_Init(&hctx, key, keylen);
  hmac_sha1_Update(&hctx, msg, msglen);
  hmac_sha1_Final(&hctx, hmac);
}


