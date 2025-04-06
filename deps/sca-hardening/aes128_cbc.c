#include "aes_sca/aes.h"
#include "hwcrypto/crypto/aes/aes.h"
#include "hwcrypto/crypto/memzero.h"

#include <string.h>

AES_RETURN aes128_cbc_sca_encrypt(const unsigned char *key, const unsigned char *ibuf, unsigned char *obuf,
                    int len, unsigned char *iv)
{   
#ifdef EMULATOR
#   warning "aes128 encryption is not SCA-hardened in this build."
    aes_encrypt_ctx ctx;
    aes_encrypt_key128(key, &ctx);
    aes_cbc_encrypt(ibuf, obuf, len, iv, &ctx);
    memzero(&ctx, sizeof(ctx));
    return EXIT_SUCCESS;
#else
	int nb = len >> AES_BLOCK_SIZE_P2;
	STRUCT_AES fctx;
	unsigned char out[16];

    if(len & (AES_BLOCK_SIZE - 1))
        return EXIT_FAILURE;

    while(nb--)
    {
        iv[ 0] ^= ibuf[ 0]; iv[ 1] ^= ibuf[ 1];
        iv[ 2] ^= ibuf[ 2]; iv[ 3] ^= ibuf[ 3];
        iv[ 4] ^= ibuf[ 4]; iv[ 5] ^= ibuf[ 5];
        iv[ 6] ^= ibuf[ 6]; iv[ 7] ^= ibuf[ 7];
        iv[ 8] ^= ibuf[ 8]; iv[ 9] ^= ibuf[ 9];
        iv[10] ^= ibuf[10]; iv[11] ^= ibuf[11];
        iv[12] ^= ibuf[12]; iv[13] ^= ibuf[13];
        iv[14] ^= ibuf[14]; iv[15] ^= ibuf[15];

//        if(aes_encrypt(iv, iv, ctx) != EXIT_SUCCESS)
        if(aes(MODE_KEYINIT|MODE_AESINIT_ENC|MODE_ENC, &fctx, key, iv, out, NULL, NULL) != NO_ERROR)
            return EXIT_FAILURE;
        memcpy(iv, out, AES_BLOCK_SIZE);

        memcpy(obuf, iv, AES_BLOCK_SIZE);
        ibuf += AES_BLOCK_SIZE;
        obuf += AES_BLOCK_SIZE;
    }

    return EXIT_SUCCESS;
#endif
}

AES_RETURN aes128_cbc_sca_decrypt(const unsigned char *key, const unsigned char *ibuf, unsigned char *obuf,
                    int len, unsigned char *iv)
{
#ifdef EMULATOR
#   warning "aes128 decryption is not SCA-hardened in this build."
    aes_decrypt_ctx ctx;
    aes_decrypt_key128(key, &ctx);
    aes_cbc_decrypt(ibuf, obuf, len, iv, &ctx);
    memzero(&ctx, sizeof(ctx));
    return EXIT_SUCCESS;
#else
    unsigned char tmp[AES_BLOCK_SIZE];
    int nb = len >> AES_BLOCK_SIZE_P2;
    STRUCT_AES fctx;


    if(len & (AES_BLOCK_SIZE - 1))
        return EXIT_FAILURE;

    while(nb--)
    {
        memcpy(tmp, ibuf, AES_BLOCK_SIZE);

//        if(aes_decrypt(ibuf, obuf, ctx) != EXIT_SUCCESS)
        if(aes(MODE_KEYINIT|MODE_AESINIT_DEC|MODE_DEC, &fctx, key, ibuf, obuf, NULL, NULL) != NO_ERROR)
            return EXIT_FAILURE;

        obuf[ 0] ^= iv[ 0]; obuf[ 1] ^= iv[ 1];
        obuf[ 2] ^= iv[ 2]; obuf[ 3] ^= iv[ 3];
        obuf[ 4] ^= iv[ 4]; obuf[ 5] ^= iv[ 5];
        obuf[ 6] ^= iv[ 6]; obuf[ 7] ^= iv[ 7];
        obuf[ 8] ^= iv[ 8]; obuf[ 9] ^= iv[ 9];
        obuf[10] ^= iv[10]; obuf[11] ^= iv[11];
        obuf[12] ^= iv[12]; obuf[13] ^= iv[13];
        obuf[14] ^= iv[14]; obuf[15] ^= iv[15];
        memcpy(iv, tmp, AES_BLOCK_SIZE);
        ibuf += AES_BLOCK_SIZE;
        obuf += AES_BLOCK_SIZE;
    }

    return EXIT_SUCCESS;
#endif 
}