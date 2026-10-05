#include "keepkey/firmware/tendermint.h"

#include "keepkey/firmware/fsm.h"
#include "trezor/crypto/segwit_addr.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/sha2.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int convert_bits(uint8_t* out, size_t* outlen, int outbits,
                        const uint8_t* in, size_t inlen, int inbits, int pad) {
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

bool tendermint_pathMismatched(const CoinType* coin, const uint32_t* address_n,
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
bool tendermint_getAddress(const HDNode* node, const char* prefix,
                           char* address) {
  uint8_t hash160Buf[RIPEMD160_DIGEST_LENGTH];
  ecdsa_get_pubkeyhash(node->public_key, HASHER_SHA2_RIPEMD, hash160Buf);

  uint8_t fiveBitExpanded[RIPEMD160_DIGEST_LENGTH * 8 / 5];
  size_t len = 0;
  convert_bits(fiveBitExpanded, &len, 5, hash160Buf, 20, 8, 1);
  return bech32_encode(address, prefix, fiveBitExpanded, len,
                       BECH32_ENCODING_BECH32) == 1;
}

bool tendermint_validateSafeText(const char* value) {
  if (!value || value[0] == '\0') return false;

  for (const unsigned char* p = (const unsigned char*)value; *p; ++p) {
    if (*p < 0x21 || *p > 0x7e || *p == '"' || *p == '\\') return false;
  }
  return true;
}

/* A Tendermint account address is the 20-byte RIPEMD-160 of the public key,
   carried as base32: 20 * 8 / 5 == 32 five-bit groups. */
#define TENDERMINT_ACCOUNT_ADDRESS_GROUPS 32

/* The longest bech32 string this firmware will look at. The widest address
   field any protobuf message can deliver is 52 characters (Cosmos and Osmosis
   `receiver`/`to_address`, max_size 53); 90 is the bech32 spec's own limit and
   leaves room without inviting a larger buffer. */
#define TENDERMINT_BECH32_MAX_INPUT 90

/* Decode into buffers big enough for anything bech32_decode() can write.
 *
 * bech32_decode() takes NO capacity argument. It writes one byte per data
 * character into `data`, and its header states the required size as
 * strlen(input) - 8; the only length it ever rejects is an HRP longer than
 * BECH32_MAX_HRP_LEN, which is 83. Every call site in this firmware declared
 * `char hrp[45]` and `uint8_t decoded[38]`, so both buffers were undersized
 * against what a host can send:
 *
 *   - an address whose HRP is 45..83 characters overwrites `hrp`;
 *   - a 52-character address with a short HRP yields 44 groups and overwrites
 *     `decoded`.
 *
 * Both are stack overwrites with host-chosen content, reachable directly from
 * a signing message. Gate the length first, then decode into buffers sized for
 * the worst case that survives that gate. */
static bool tendermint_bech32DecodeChecked(const char* address, char* hrp_out,
                                           size_t* groups) {
  if (!address) return false;
  const size_t len = strnlen(address, TENDERMINT_BECH32_MAX_INPUT + 1);
  if (len < 8 || len > TENDERMINT_BECH32_MAX_INPUT) return false;

  uint8_t decoded[TENDERMINT_BECH32_MAX_INPUT] = {0};
  size_t decoded_len = 0;
  if (bech32_decode(hrp_out, decoded, &decoded_len, address) !=
      BECH32_ENCODING_BECH32) {
    memzero(decoded, sizeof(decoded));
    return false;
  }
  memzero(decoded, sizeof(decoded));
  if (groups) *groups = decoded_len;
  return true;
}

/* Well-formedness only: correct charset, length and checksum, nothing about
   which network the address belongs to. For the one case where an arbitrary
   HRP is the point -- an IBC receiver on a counterparty chain this device has
   no prefix for. Everywhere the network IS known, use
   tendermint_validateBech32Address() instead. */
bool tendermint_bech32IsWellFormed(const char* address) {
  char hrp[BECH32_MAX_HRP_LEN + 1] = {0};
  return tendermint_bech32DecodeChecked(address, hrp, NULL);
}

bool tendermint_validateBech32Address(const char* address,
                                      const char* expected_prefix) {
  if (!address || !expected_prefix || expected_prefix[0] == '\0') return false;

  char hrp[BECH32_MAX_HRP_LEN + 1] = {0};
  size_t decoded_len = 0;
  if (!tendermint_bech32DecodeChecked(address, hrp, &decoded_len)) return false;
  if (strcmp(hrp, expected_prefix) != 0) return false;

  /* A correct checksum and the right HRP still do not make it an ACCOUNT
     address. bech32_decode() hands back the raw five-bit groups and succeeds
     for any payload length, so a validator-operator address, a longer module
     address, or an arbitrary blob under the same prefix all passed -- and the
     THORChain and MAYAChain deposit paths accept the result as a signer.
     tendermint_getAddress() above encodes a 20-byte RIPEMD-160 hash, which is
     exactly 20 * 8 / 5 == 32 groups; require the same of anything the device
     is asked to treat as an account. */
  return decoded_len == TENDERMINT_ACCOUNT_ADDRESS_GROUPS;
}

/* A validator OPERATOR address: the same 20-byte account payload as a normal
   address, under the "<chain>valoper" prefix rather than "<chain>".

   Every MsgDelegate / MsgUndelegate / MsgBeginRedelegate / MsgWithdrawReward
   serializer interpolates these with a bare "%s" into the document it hashes,
   exactly as it does the delegator -- but only the delegator was ever checked.
   A wrong-network operator, a plain account address where an operator belongs,
   or a value carrying JSON punctuation therefore reached the signed bytes. */
bool tendermint_validateValidatorAddress(const char* address,
                                         const char* chain_prefix) {
  if (!address || !chain_prefix || chain_prefix[0] == '\0') return false;

  char expected[BECH32_MAX_HRP_LEN + 1];
  const int n = snprintf(expected, sizeof(expected), "%svaloper", chain_prefix);
  if (n < 0 || (size_t)n >= sizeof(expected)) return false;

  return tendermint_validateBech32Address(address, expected);
}

void tendermint_sha256UpdateEscaped(SHA256_CTX* ctx, const char* s,
                                    size_t len) {
  static const char kHexDigits[] = "0123456789abcdef";

  for (size_t i = 0; i != len; i++) {
    const uint8_t c = (uint8_t)s[i];

    if (c == '"') {
      sha256_Update(ctx, (const uint8_t*)"\\\"", 2);
    } else if (c == '\\') {
      sha256_Update(ctx, (const uint8_t*)"\\\\", 2);
    } else if (c < 0x20) {
      /* RFC 8259 forbids a raw byte below 0x20 inside a JSON string, but this
         escaper only ever handled the quote and the backslash and passed every
         control byte through untouched. Memos are not run through
         tendermint_validateSafeText(), so a host-supplied newline or tab was
         hashed verbatim: the device signed a document that is not valid JSON,
         after showing the owner a screen whose layout that same newline had
         already altered.

         Emit the escapes the format requires -- the five short forms, then
         \u00XX for the rest. Only memos that already produced invalid JSON
         change shape here; anything a chain would have accepted hashes exactly
         as before. */
      switch (c) {
        case '\b':
          sha256_Update(ctx, (const uint8_t*)"\\b", 2);
          break;
        case '\f':
          sha256_Update(ctx, (const uint8_t*)"\\f", 2);
          break;
        case '\n':
          sha256_Update(ctx, (const uint8_t*)"\\n", 2);
          break;
        case '\r':
          sha256_Update(ctx, (const uint8_t*)"\\r", 2);
          break;
        case '\t':
          sha256_Update(ctx, (const uint8_t*)"\\t", 2);
          break;
        default: {
          const uint8_t esc[6] = {'\\',
                                  'u',
                                  '0',
                                  '0',
                                  (uint8_t)kHexDigits[(c >> 4) & 0x0f],
                                  (uint8_t)kHexDigits[c & 0x0f]};
          sha256_Update(ctx, esc, sizeof(esc));
          break;
        }
      }
    } else {
      // The copy here is required (as opposed to a cast), since the
      // source is a character array, and sha256_Update uses it as if it
      // were an array of uint8_t, which would violate the strict aliasing
      // rule.
      const uint8_t b = c;
      sha256_Update(ctx, &b, 1);
    }
  }
}

bool tendermint_snprintf(SHA256_CTX* ctx, char* temp, size_t len,
                         const char* format, ...) {
  va_list vl;
  va_start(vl, format);
  int n = vsnprintf(temp, len, format, vl);
  va_end(vl);

  if (n < 0 || (size_t)n >= len) return false;

  sha256_Update(ctx, (const uint8_t*)temp, n);
  return true;
}
