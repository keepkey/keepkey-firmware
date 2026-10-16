/* Compile the real storage implementation into the unit binary with observers
 * at its AES/memzero boundaries. The archive's storage.o is then not pulled in.
 * Firmware builds still compile storage.c normally, without these observers.
 * Observe wipes while objects are alive; never inspect abandoned stack memory.
 */
#include "storage_cipher_probe.h"
#include <stdint.h>
#include <string.h>

#include "trezor/crypto/aes/aes.h"
#include "trezor/crypto/memzero.h"

static void observe_memzero(void* p, size_t len);
static AES_RETURN observe_encrypt(const unsigned char* in, unsigned char* out,
                                  int len, unsigned char* iv,
                                  const aes_encrypt_ctx ctx[1]);
static AES_RETURN observe_decrypt(const unsigned char* in, unsigned char* out,
                                  int len, unsigned char* iv,
                                  const aes_decrypt_ctx ctx[1]);

#define memzero observe_memzero
#define aes_cbc_encrypt observe_encrypt
#define aes_cbc_decrypt observe_decrypt
#include "../../lib/firmware/storage.c"
#undef aes_cbc_decrypt
#undef aes_cbc_encrypt
#undef memzero

static bool observing;
static void* observed_iv;
static const void* observed_ctx;
static size_t observed_ctx_size;
static unsigned observed;

static void observe_memzero(void* p, size_t len) {
  memzero(p, len);
  if (!observing) return;
  unsigned bit = 0;
  if (p == observed_iv && len == 64) {
    bit = STORAGE_IV_WIPED;
    observed_iv = NULL;
  }
  if (p == observed_ctx && len == observed_ctx_size) {
    bit = STORAGE_CTX_WIPED;
    observed_ctx = NULL;
  }
  if (bit) {
    const uint8_t* bytes = p;
    for (size_t i = 0; i < len; ++i) {
      if (bytes[i] != 0) return;
    }
    observed |= bit;
  }
}

static void observe_cipher(unsigned char* iv, const void* ctx, size_t size) {
  if (!observing) return;
  observed_iv = iv - 32; /* Both storage helpers use bytes 32..47 of iv[64]. */
  observed_ctx = ctx;
  observed_ctx_size = size;
  observed |= STORAGE_CIPHER_CALLED;
}

static AES_RETURN observe_encrypt(const unsigned char* in, unsigned char* out,
                                  int len, unsigned char* iv,
                                  const aes_encrypt_ctx ctx[1]) {
  observe_cipher(iv, ctx, sizeof(*ctx));
  return aes_cbc_encrypt(in, out, len, iv, ctx);
}

static AES_RETURN observe_decrypt(const unsigned char* in, unsigned char* out,
                                  int len, unsigned char* iv,
                                  const aes_decrypt_ctx ctx[1]) {
  observe_cipher(iv, ctx, sizeof(*ctx));
  return aes_cbc_decrypt(in, out, len, iv, ctx);
}

/* Return named observations for complete wiping and cipher round trips. */
unsigned storage_test_cipher_cleanup(bool migrate, bool encrypt) {
  observed = 0;
  observed_iv = NULL;
  observed_ctx = NULL;
  observed_ctx_size = 0;
  observing = false;

  if (migrate) {
    SessionState ss = {0};
    Storage data = {0};
    memset(ss.storageKey, 0xA5, sizeof(ss.storageKey));
    data.has_sec = true;
    strcpy(data.sec.mnemonic, "storage cleanup compatibility control");
    memset(&data.sec.authBlock, 0x5A, sizeof(data.sec.authBlock));
    if (!encrypt) storage_secMigrate(&ss, &data, true);
    observing = true;
    storage_secMigrate(&ss, &data, encrypt);
    observing = false;
    if (encrypt) storage_secMigrate(&ss, &data, false);
    if (strcmp(data.sec.mnemonic, "storage cleanup compatibility control") ==
            0 &&
        ((uint8_t*)&data.sec.authBlock)[0] == 0x5A) {
      observed |= STORAGE_ROUND_TRIP_OK;
    }
    memzero(&ss, sizeof(ss));
    memzero(&data, sizeof(data));
  } else {
    uint8_t key[64], plain[512], cipher[512], expected[512];
    memset(key, 0xA5, sizeof(key));
    for (size_t i = 0; i < sizeof(plain); ++i) plain[i] = (uint8_t)i;
    memcpy(expected, plain, sizeof(plain));
    if (!encrypt) {
      storage_cipherBlock(true, key, plain, cipher, sizeof(plain));
      memset(plain, 0, sizeof(plain));
    }
    observing = true;
    storage_cipherBlock(encrypt, key, plain, cipher, sizeof(plain));
    observing = false;
    if (encrypt) {
      memset(plain, 0, sizeof(plain));
      storage_cipherBlock(false, key, plain, cipher, sizeof(plain));
    }
    if (memcmp(plain, expected, sizeof(plain)) == 0)
      observed |= STORAGE_ROUND_TRIP_OK;
    memzero(key, sizeof(key));
    memzero(plain, sizeof(plain));
  }
  observed_iv = NULL;
  observed_ctx = NULL;
  return observed;
}
