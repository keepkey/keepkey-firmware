#include "keepkey/firmware/tendermint.h"

#include "keepkey/firmware/fsm.h"
#include "hwcrypto/crypto/segwit_addr.h"
#include "hwcrypto/crypto/sha2.h"

#include <stdarg.h>
#include <stdio.h>

static int convert_bits(uint8_t* out, size_t* outlen, int outbits, const uint8_t* in, size_t inlen, int inbits, int pad) {
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t)1) << outbits) - 1;
    while (inlen--) {
        val = (val << inbits) | *(in++);
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[(*outlen)++] = (val >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) {
            out[(*outlen)++] = (val << (outbits - bits)) & maxv;
        }
    } else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
        return 0;
    }
    return 1;
}


bool tendermint_pathMismatched(const CoinType *coin, const uint32_t *address_n,
                               const uint32_t address_n_count) {
  // m / 44' / coin' / account' / 0 / 0
  bool mismatch = false;
  mismatch |= address_n_count != 5;
  mismatch |= address_n_count > 0 && (address_n[0] != (0x80000000 + 44));
  mismatch |= address_n_count > 1 && (address_n[1] != coin->bip44_account_path);
  mismatch |= address_n_count > 2 && (address_n[2] & 0x80000000) == 0;
  mismatch |= address_n_count > 3 && address_n[3] != 0;
  mismatch |= address_n_count > 4 && address_n[4] != 0;
  return mismatch;
}

/**
 * Gets the address
 *
 * \param node    HDNode from which the address is to be derived
 * \param prefix  bech32 prefix
 * \param address Output buffer
 *
 * \returns true if successful
 */
bool tendermint_getAddress(const HDNode *node, const char *prefix,
                           char *address) {
  uint8_t hash160Buf[RIPEMD160_DIGEST_LENGTH];
  ecdsa_get_pubkeyhash(node->public_key, HASHER_SHA2_RIPEMD, hash160Buf);

  uint8_t fiveBitExpanded[RIPEMD160_DIGEST_LENGTH * 8 / 5];
  size_t len = 0;
  convert_bits(fiveBitExpanded, &len, 5, hash160Buf, 20, 8, 1);
  return bech32_encode(address, prefix, fiveBitExpanded, len, BECH32_ENCODING_BECH32) == 1;
}

void tendermint_sha256UpdateEscaped(SHA256_CTX *ctx, const char *s,
                                    size_t len) {
  for (size_t i = 0; i != len; i++) {
    if (s[i] == '"') {
      sha256_Update(ctx, (const uint8_t *)"\\\"", 2);
    } else if (s[i] == '\\') {
      sha256_Update(ctx, (const uint8_t *)"\\\\", 2);
    } else {
      // The copy here is required (as opposed to a cast), since the
      // source is a character array, and sha256_Update uses it as if it
      // were an array of uint8_t, which would violate the strict aliasing
      // rule.
      const uint8_t c = s[i];
      sha256_Update(ctx, &c, 1);
    }
  }
}

bool tendermint_snprintf(SHA256_CTX *ctx, char *temp, size_t len,
                         const char *format, ...) {
  va_list vl;
  va_start(vl, format);
  int n = vsnprintf(temp, len, format, vl);
  va_end(vl);

  if (n < 0 || (size_t)n >= len) return false;

  sha256_Update(ctx, (const uint8_t *)temp, n);
  return true;
}
