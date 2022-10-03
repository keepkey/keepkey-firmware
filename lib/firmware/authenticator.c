/*
 * Copyright (C) 2022 markrypto
 *
 * TOPT generation as described in https://www.rfc-editor.org/rfc/rfc6238
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
#include "keepkey/firmware/authenticator.h"
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


static authStruct authData[AUTHDATA_SIZE] = {0};

unsigned addAuthSeed(char *accountWithSeed) {
  char *account, *seedStr;
  unsigned ctr;
  char authSecret[20];          // 128-bit key len is the recommended minimum, this is room for 160-bit

  // accountWithSeed should be of the form "account:seedStr"
  account = strtok(accountWithSeed, ":");   // get the account string token
  if (0 == strlen(account) || (ACCOUNT_SIZE <= strlen(account))) {
    return 3;
  }
  seedStr = strtok(NULL, "");   // get the seed string string token
  if (0 == strlen(seedStr)) {
    return 3;
  }

  // look for first empty slot
  for (ctr=0; ctr<AUTHDATA_SIZE; ctr++) {
    if (authData[ctr].secretSize == 0) {
      break;
    }
  }
  if (ctr == AUTHDATA_SIZE) {
    return 1;       // no empty slots
  }

  if (NULL == base32_decode((const char *)seedStr, strlen(seedStr), (uint8_t *)authSecret,
                            sizeof(authSecret), BASE32_ALPHABET_RFC4648)) {
    return 2;       // bad decode
  }

  // {
  //   char bufStr[65] = {0}, tmpStr[3];
  //   for (unsigned i=0; i<authData[ctr].secretSize; i++) {
  //     snprintf(tmpStr, 3, "%02x", authSecret[i]);
  //     strncat(bufStr, tmpStr, 2);
  //   }
  // }

  confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Auth Initialization",
          "Account: %.*s\nSeed value: %s", ACCOUNT_SIZE, account, seedStr);

  authData[ctr].secretSize = strlen(authSecret);
  strncpy(authData[ctr].authSecret, authSecret, authData[ctr].secretSize);
  strlcpy(authData[ctr].account, account, ACCOUNT_SIZE);

  return 0;   // success
}

unsigned generateAuthenticator(char *accountWithMsg, char otpStr[]) {

  char *account, *msgStr;
  size_t len = 0;
  char tmpStr[3]={0};
  uint8_t hmac[SHA1_DIGEST_LENGTH];           // hmac-sha1 digest length is 160 bits
  unsigned ctr;

  // accountWithSeed should be of the form "account:msgStr"
  account = strtok(accountWithMsg, ":");   // get the account string token
  if (0 == strlen(account) || (ACCOUNT_SIZE <= strlen(account))) {
    return 3;
  }
  msgStr = strtok(NULL, "");   // get the message string string token
  if (0 == (len = strlen(msgStr))) {
    return 3;
  }

  uint8_t msgVal[len/2];
  char bufStr[len];
  memzero(bufStr, len);

  for (unsigned i=0; i<len/2; i++) {
    strncpy(tmpStr, &msgStr[i*2], 2);
    msgVal[i] = (uint8_t)(strtol(tmpStr, NULL, 16));
  }

  for (unsigned i=0; i<len/2; i++) {
    snprintf(tmpStr, 3, "%02x", msgVal[i]);
    strncat(bufStr, tmpStr, 2);
  }

  // confirm_with_custom_layout(&layout_notification_no_title_no_bold,
  //                                   ButtonRequestType_ButtonRequest_Other, "", "message: %s",
  //                                   bufStr);

  // look for account
  for (ctr=0; ctr<AUTHDATA_SIZE; ctr++) {
    if (0 == strncmp(authData[ctr].account, account, ACCOUNT_SIZE-1)) {
      break;
    }
  }
  if (ctr == AUTHDATA_SIZE) {
    return 1;       // account not found
  }


  hmac_sha1((const uint8_t*)authData[ctr].authSecret, (const uint32_t)authData[ctr].secretSize,
                  (const uint8_t*)msgVal, (const uint32_t)len/2, (uint8_t *)hmac);

  // for (unsigned i=0; i<SHA1_DIGEST_LENGTH; i++) {
  //   snprintf(tmpStr, 3, "%02x", hmac[i]);
  //   strncat(digestStr, tmpStr, 2);
  // }

  // confirm_with_custom_layout(&layout_notification_no_title_no_bold,
  //                                   ButtonRequestType_ButtonRequest_Other, "", "hmac-sha1: %s",
  //                                   digestStr);

  // extract the otp code  https://www.rfc-editor.org/rfc/rfc4226#section-5.4
  unsigned offset = 0x0f & hmac[SHA1_DIGEST_LENGTH-1];
  unsigned bin_code = (hmac[offset] & 0x7f) << 24
                    | (hmac[offset+1] & 0xff) << 16
                    | (hmac[offset+2] & 0xff) << 8
                    | (hmac[offset+3] & 0xff);
  unsigned digits = 6;  // number of otp digits desired, e.g., 6,7,8
  unsigned modnum = 1;
  // simplified pow(10, 6)
  for (unsigned i=0; i<digits; i++) {
    modnum *= 10;
  }
  unsigned otp = bin_code % (unsigned long)modnum;

  snprintf(otpStr, 9, "%06d", otp);
  char otpStrLarge[10] = {0};
  snprintf(otpStrLarge, 9, "\x19%06d", otp);
  (void)review(ButtonRequestType_ButtonRequest_Other, otpStrLarge, "\n%s", authData[ctr].account);

  return 0;
}

unsigned removeAuthAccount(char *account) {
  unsigned ctr;

  // look for account
  for (ctr=0; ctr<AUTHDATA_SIZE; ctr++) {
    if (0 == strncmp(authData[ctr].account, account, ACCOUNT_SIZE-1)) {
      break;
    }
  }
  if (ctr == AUTHDATA_SIZE) {
    return 1;       // account not found
  }

  confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Delete Account",
          "PERMANENTLY delete account %.*s?", ACCOUNT_SIZE-1, account);

  memzero((void *)&authData[ctr], sizeof(authStruct));
  return 0;   // success
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


