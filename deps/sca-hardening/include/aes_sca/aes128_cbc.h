#ifndef AES128_CBC_H
#define AES128_CBC_H

#include "hwcrypto/crypto/aes/aes.h"

AES_RETURN aes128_cbc_sca_encrypt(
    const unsigned char *key,
    const unsigned char *ibuf,
    unsigned char *obuf,
    int len,
    unsigned char *iv);

AES_RETURN aes128_cbc_sca_decrypt(
    const unsigned char *key,
    const unsigned char *ibuf,
    unsigned char *obuf,
    int len,
    unsigned char *iv);

#endif