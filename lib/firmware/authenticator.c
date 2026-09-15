/*
 * Copyright (C) 2023 markrypto
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
#include "keepkey/board/timer.h"
#include "keepkey/firmware/authenticator.h"
#include "keepkey/firmware/crypto.h"
#include "keepkey/firmware/storage.h"
#include "trezor/crypto/aes/aes.h"
#include "trezor/crypto/base32.h"
#include "trezor/crypto/hmac.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/sha2.h"

#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/app_layout.h"

#include <string.h>
#include <stdio.h>

static CONFIDENTIAL authType authData[AUTHDATA_SIZE] = {0};

// getAuthData() gets the storage version of authData and updates the local
// version setAuthData() updates the storage version with the local version

static bool localAuthdataUpdate =
    true; /* initialization trick, only need to fetch a local copy once
             successfully */

void authenticator_clear_cache(void) {
  memzero(authData, sizeof(authData));
  localAuthdataUpdate = true;
}

#if DEBUG_LINK
bool authenticator_cache_is_empty(void) {
  const uint8_t* bytes = (const uint8_t*)authData;
  uint8_t aggregate = 0;
  for (size_t i = 0; i < sizeof(authData); i++) aggregate |= bytes[i];
  return aggregate == 0 && localAuthdataUpdate;
}

void authenticator_test_seed_cache(void) {
  memset(authData, 0xA5, sizeof(authData));
  localAuthdataUpdate = false;
}
#endif

static bool getAuthData(void) {
  if (localAuthdataUpdate) {
    if (storage_getAuthData(authData)) {
      localAuthdataUpdate = false;
    } else {
      // a return of false means the authdata fingerprint did not match
      return false;
    }
  }
  return true;
}

static void setAuthData(void) { storage_setAuthData(authData); }

static unsigned authenticator_cancel(void) {
  /* A nested confirmation refusal does not pass through fsm_msgCancel(), so it
   * must revoke the decrypted authenticator cache itself. */
  authenticator_clear_cache();
  return CANCELED;
}

#if DEBUG_LINK
static unsigned _otpSlot = 0;
void getAuthSlot(char* authSlotData) {
  snprintf(authSlotData, 30, ":slot=%2u:secsiz=%2u:", _otpSlot,
           authData[_otpSlot].secretSize);
  strncat(authSlotData, authData[_otpSlot].domain, DOMAIN_SIZE);
  strncat(authSlotData, ":", 2);
  strncat(authSlotData, authData[_otpSlot].account, ACCOUNT_SIZE);
  strncat(authSlotData, ":", 2);

  char str[40 + 1];
  int ctr;
  for (ctr = 0; ctr < 40 / 2; ctr++) {
    snprintf(&str[2 * ctr], 3, "%02x", authData[_otpSlot].authSecret[ctr]);
  }
  strncat(authSlotData, str, 41);
  return;
}
#endif

unsigned wipeAuthData(void) {
  if (!confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Wipe Authdata",
               "Do you want to PERMANENTLY delete all authenticator "
               "accounts?")) {
    return authenticator_cancel();
  }

  // wipe storage and reset authdata encryption flag
  storage_wipeAuthData();
  // wipe local copy
  authenticator_clear_cache();
  return NOERR;
}

unsigned addAuthAccount(char* accountWithSeed) {
  if (accountWithSeed == NULL) return TOKERR;

  /* strtok() inserts NULs into the caller's protobuf string, so retain the
   * original extent before parsing.  Every exit wipes that whole credential
   * suffix, including the Base32 source, rather than leaving it in the static
   * message decode buffer until another USB message arrives. */
  const size_t sourceLen = strlen(accountWithSeed);
  char *domain, *account, *seedStr;
  unsigned slot = AUTHDATA_SIZE;
  char authSecret[AUTHSECRET_SIZE_MAX] = {0};
  size_t authSecretLen = 0;
  unsigned result = UNKERR;

  // accountWithSeed should be of the form "domain:account:seedStr"
  domain = strtok(accountWithSeed, ":");  // get the domain string token
  if (NULL == domain) {
    result = TOKERR;
    goto cleanup;
  }

  account = strtok(NULL, ":");  // get the account string token
  if (NULL == account) {
    result = TOKERR;
    goto cleanup;
  }
  if (0 == strlen(account)) {
    result = TOKERR;
    goto cleanup;
  }

  seedStr = strtok(NULL, "");  // get the seed string string token
  if (NULL == seedStr) {
    result = TOKERR;
    goto cleanup;
  }
  if (0 == strlen(seedStr)) {
    result = TOKERR;
    goto cleanup;
  }

  authSecretLen = base32_decoded_length(strlen(seedStr));
  if (AUTHSECRET_SIZE_MAX < authSecretLen) {
    result = LARGESEED;
    goto cleanup;
  }

  if (!getAuthData()) {
    result = BADPASS;  // fingerprint did not match, passphrase incorrect
    goto cleanup;
  }

  // look for first empty slot
  for (slot = 0; slot < AUTHDATA_SIZE; slot++) {
    if (authData[slot].secretSize == 0) {
      break;
    }
  }
  if (slot == AUTHDATA_SIZE) {
    result = NOSLOT;  // no empty slots
    goto cleanup;
  }

  if (NULL == base32_decode((const char*)seedStr, strlen(seedStr),
                            (uint8_t*)authSecret, sizeof(authSecret),
                            BASE32_ALPHABET_RFC4648)) {
    result = BADSECRET;
    goto cleanup;
  }

  if (!confirm(ButtonRequestType_ButtonRequest_Other, "Confirm add account",
               "Domain: %.*s\nAccount: %.*s\nSecret: %s", DOMAIN_SIZE, domain,
               ACCOUNT_SIZE, account, seedStr)) {
    result = CANCELED;
    goto cleanup;
  }

  authData[slot].secretSize = authSecretLen;
  memcpy(authData[slot].authSecret, authSecret, authData[slot].secretSize);
  strlcpy(authData[slot].domain, domain, DOMAIN_SIZE);
  strlcpy(authData[slot].account, account, ACCOUNT_SIZE);

  setAuthData();
  result = NOERR;

cleanup:
  memzero(authSecret, sizeof(authSecret));
  memzero(accountWithSeed, sourceLen);
  if (result == CANCELED) authenticator_clear_cache();
  return result;
}

unsigned generateOTP(char* accountWithMsg, char otpStr[]) {
  const char *domain, *account, *tIntervalStr, *tRemainStr;
  uint8_t hmac[SHA1_DIGEST_LENGTH] = {0};
  uint8_t tIntervalBytes[8] = {0};
  char otp_candidate[9] = {0};
  char otp_display[10] = {0};
  char account_display[DOMAIN_SIZE + ACCOUNT_SIZE + 2] = {0};
  unsigned slot = AUTHDATA_SIZE;
  uint32_t t0 = getSysTime();
  unsigned result = TOKERR;

  memzero(otpStr, 9);

  // accountWithSeed should be of the form "domain:account:msgStr"

  domain = strtok(accountWithMsg, ":");  // get the domain string token
  if (NULL == domain) {
    goto cleanup;
  }
  account = strtok(NULL, ":");  // get the account string token
  if (NULL == account) {
    goto cleanup;
  }
  if (0 == strlen(account)) {
    goto cleanup;
  }
  tIntervalStr = strtok(NULL, ":");  // get the message string string token
  if (NULL == tIntervalStr) {
    goto cleanup;
  }
  if (0 == strlen(tIntervalStr)) {
    goto cleanup;
  }
  tRemainStr = strtok(NULL, "");  // get the message string string token
  if (NULL == tRemainStr) {
    goto cleanup;
  }
  if (0 == (strlen(tRemainStr))) {
    goto cleanup;
  }

  // convert time interval string to long int
  long tIntervalVal = strtol(tIntervalStr, NULL, 10);
  // get big endian representation
  tIntervalBytes[4] = (tIntervalVal >> 24) & 0xff;
  tIntervalBytes[5] = (tIntervalVal >> 16) & 0xff;
  tIntervalBytes[6] = (tIntervalVal >> 8) & 0xff;
  tIntervalBytes[7] = tIntervalVal & 0xff;

  // convert time remaining to int
  long tRemainVal = (strtol(tRemainStr, NULL, 10));

  if (!getAuthData()) {  // in theory an OTP could be requested on a dirty local
                         // copy
    result = BADPASS;
    goto cleanup;
  }

  // look for account
  for (slot = 0; slot < AUTHDATA_SIZE; slot++) {
    if ((0 == strncmp(authData[slot].domain, domain, DOMAIN_SIZE - 1)) &&
        (0 == strncmp(authData[slot].account, account, ACCOUNT_SIZE - 1))) {
      break;
    }
  }

  if (slot == AUTHDATA_SIZE) {
    result = NOACC;
    goto cleanup;
  }

#if DEBUG_LINK
  _otpSlot = slot;  // used to get slot data
#endif

  hmac_sha1((const uint8_t*)authData[slot].authSecret,
            (const uint32_t)authData[slot].secretSize,
            (const uint8_t*)tIntervalBytes,
            (const uint32_t)sizeof(tIntervalBytes), (uint8_t*)hmac);

  // totp: https://www.rfc-editor.org/rfc/rfc6238
  // extract the otp code  https://www.rfc-editor.org/rfc/rfc4226#section-5.4
  unsigned offset = 0x0f & hmac[SHA1_DIGEST_LENGTH - 1];
  unsigned bin_code =
      (hmac[offset] & 0x7f) << 24 | (hmac[offset + 1] & 0xff) << 16 |
      (hmac[offset + 2] & 0xff) << 8 | (hmac[offset + 3] & 0xff);
  unsigned digits = 6;  // number of otp digits desired, e.g., 6,7,8
  unsigned modnum = 1;
  // simplified pow(10, 6)
  for (unsigned i = 0; i < digits; i++) {
    modnum *= 10;
  }
  unsigned otp = bin_code % (unsigned long)modnum;

  snprintf(otp_candidate, sizeof(otp_candidate), "%06u", otp);
  snprintf(otp_display, sizeof(otp_display), "%06u", otp);
  if (!review_immediate(ButtonRequestType_ButtonRequest_Other, "display OTP",
                        "Press button to display OTP")) {
    result = CANCELED;
    goto cleanup;
  }

  // Check to see if user needs to regenerate OTP
  tRemainVal -=
      (getSysTime() - t0) / 1000;  // time since kk received time value
  if (tRemainVal < 4) {
    if (!review_immediate(ButtonRequestType_ButtonRequest_Other, "OTP Timeout",
                          "OTP time slice timed out, regenerate OTP")) {
      result = CANCELED;
      goto cleanup;
    }
  } else {
    strncpy(account_display, authData[slot].domain, DOMAIN_SIZE);
    strcat(account_display, " ");
    strncat(account_display, authData[slot].account, ACCOUNT_SIZE);
    unsigned remainingdmSec = tRemainVal * 10;  // how many 1/10 secs remaining
    layoutProgressForAuth(otp_display, account_display,
                          (1000 * remainingdmSec) / 300);
    for (; remainingdmSec > 0; remainingdmSec--) {
      delay_ms(100);
      layoutProgressForAuth(otp_display, account_display,
                            (1000 * remainingdmSec) / 300);
    }
  }
  strlcpy(otpStr, otp_candidate, 9);
  result = NOERR;

cleanup:
  memzero(hmac, sizeof(hmac));
  memzero(tIntervalBytes, sizeof(tIntervalBytes));
  memzero(otp_candidate, sizeof(otp_candidate));
  memzero(otp_display, sizeof(otp_display));
  memzero(account_display, sizeof(account_display));
  if (result == CANCELED) authenticator_clear_cache();
  return result;
}

unsigned getAuthAccount(const char* slotStr, char acc[]) {
  uint8_t val;
  val = (uint8_t)(strtol(slotStr, NULL, 10));

  if (!getAuthData()) {
    return BADPASS;  // fingerprint did not match, passphrase incorrect
  }

  if (val >= AUTHDATA_SIZE) {
    return NOSLOT;  // slot index error, has to be less than size of struct
  }

  if (authData[val].secretSize == 0) {
    return NOACC;  // no account in slot
  }

  snprintf(acc, DOMAIN_SIZE + ACCOUNT_SIZE + 2, "%s:%s", authData[val].domain,
           authData[val].account);
  return NOERR;
}

unsigned removeAuthAccount(char* domAcc) {
  char *domain, *account;
  unsigned slot;

  // accountWithSeed should be of the form "domain:account"
  domain = strtok(domAcc, ":");  // get the domain string token
  if (NULL == domain) {
    return TOKERR;
  }
  account = strtok(NULL, "");  // get the account string token
  if (NULL == account) {
    return TOKERR;
  }
  if (0 == strlen(account)) {
    return TOKERR;
  }

  if (!getAuthData()) {
    return BADPASS;  // fingerprint did not match, passphrase incorrect
  }

  // find slot for account
  for (slot = 0; slot < AUTHDATA_SIZE; slot++) {
    if ((0 == strncmp(authData[slot].domain, domain, DOMAIN_SIZE - 1)) &&
        (0 == strncmp(authData[slot].account, account, ACCOUNT_SIZE - 1))) {
      break;
    }
  }

  if (slot == AUTHDATA_SIZE) {
    return NOACC;  // account not found
  }

  if (!confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Delete Account",
               "Do you want to PERMANENTLY delete account %.*s:%.*s?",
               DOMAIN_SIZE - 1, domain, ACCOUNT_SIZE - 1, account)) {
    return authenticator_cancel();
  }

  memzero((void*)&authData[slot], sizeof(authType));
  setAuthData();
  return NOERR;  // success
}

void hmac_sha1_Init(HMAC_SHA1_CTX* hctx, const uint8_t* key,
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

void hmac_sha1_Update(HMAC_SHA1_CTX* hctx, const uint8_t* msg,
                      const uint32_t msglen) {
  sha1_Update(&(hctx->ctx), msg, msglen);
}

void hmac_sha1_Final(HMAC_SHA1_CTX* hctx, uint8_t* hmac) {
  sha1_Final(&(hctx->ctx), hmac);
  sha1_Init(&(hctx->ctx));
  sha1_Update(&(hctx->ctx), hctx->o_key_pad, SHA1_BLOCK_LENGTH);
  sha1_Update(&(hctx->ctx), hmac, SHA1_DIGEST_LENGTH);
  sha1_Final(&(hctx->ctx), hmac);
  memzero(hctx, sizeof(HMAC_SHA1_CTX));
}

void hmac_sha1(const uint8_t* key, const uint32_t keylen, const uint8_t* msg,
               const uint32_t msglen, uint8_t* hmac) {
  static CONFIDENTIAL HMAC_SHA1_CTX hctx;
  hmac_sha1_Init(&hctx, key, keylen);
  hmac_sha1_Update(&hctx, msg, msglen);
  hmac_sha1_Final(&hctx, hmac);
}
