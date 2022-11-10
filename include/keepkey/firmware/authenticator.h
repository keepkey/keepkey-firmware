/*
 * Copyright (C) 2022 markrypto (cryptoakorn@gmail.com)
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

#ifndef __AUTHENTICATOR_H__
#define __AUTHENTICATOR_H__

#define ACCOUNT_SIZE 12
#define AUTHDATA_SIZE 3

typedef struct _HMAC_SHA1_CTX {
  uint8_t o_key_pad[SHA1_BLOCK_LENGTH];
  SHA1_CTX ctx;
} HMAC_SHA1_CTX;

typedef struct {
  char account[12];             // allow 11 chars for issuer string
  char authSecret[20];          // 128-bit key len is the recommended minimum, this is room for 160-bit
  uint8_t secretSize;          // this is zero if slot is not filled
} authStruct;

void hmac_sha1_Init(HMAC_SHA1_CTX *hctx, const uint8_t *key,
                      const uint32_t keylen);
void hmac_sha1_Update(HMAC_SHA1_CTX *hctx, const uint8_t *msg,
                        const uint32_t msglen);
void hmac_sha1_Final(HMAC_SHA1_CTX *hctx, uint8_t *hmac);
void hmac_sha1(const uint8_t *key, const uint32_t keylen, const uint8_t *msg,
                 const uint32_t msglen, uint8_t *hmac);

unsigned generateAuthenticator(char *accountWithMsg, char otpStr[]);
unsigned addAuthAccount(char *accountWithSeed);
unsigned removeAuthAccount(char *account);

#endif
