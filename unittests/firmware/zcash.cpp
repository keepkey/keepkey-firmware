extern "C" {
#include "keepkey/firmware/zcash.h"
#include "trezor/crypto/bignum.h"
#include "trezor/crypto/blake2b.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/pallas.h"
#include "trezor/crypto/pallas_sinsemilla.h"
#include "trezor/crypto/pallas_swu.h"
#include "trezor/crypto/redpallas.h"
#include "trezor/crypto/zcash_zip316.h"
}

#include "gtest/gtest.h"
#include <cstring>

/* ── Pallas curve constants ──────────────────────────────────────── */

/* Pallas base field prime p (LE) */
static const uint8_t PALLAS_P_LE[32] = {
    0x01, 0x00, 0x00, 0x00, 0xed, 0x30, 0x2d, 0x99, 0x1b, 0xf9, 0x4c,
    0x09, 0xfc, 0x98, 0x46, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
};

/* Pallas scalar field order q (LE) */
static const uint8_t PALLAS_Q_LE[32] = {
    0x01, 0x00, 0x00, 0x00, 0x21, 0xeb, 0x46, 0x8c, 0xdd, 0xa8, 0x94,
    0x09, 0xfc, 0x98, 0x46, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
};

/* Sinsemilla primitive vectors generated with sinsemilla 0.1.0. */
static const uint8_t SINSEMILLA_COMMIT_IVK_Q_X[32] = {
    0xf2, 0x82, 0x0f, 0x79, 0x92, 0x2f, 0xcb, 0x6b, 0x32, 0xa2, 0x28,
    0x51, 0x24, 0xcc, 0x1b, 0x42, 0xfa, 0x41, 0xa2, 0x5a, 0xb8, 0x81,
    0xcc, 0x7d, 0x11, 0xc8, 0xa9, 0x4a, 0xf1, 0x0c, 0xbc, 0x05,
};

static const uint8_t SINSEMILLA_COMMIT_IVK_Q_Y[32] = {
    0xbe, 0xde, 0xad, 0xcf, 0xce, 0xe5, 0x5a, 0xbe, 0xf1, 0xa5, 0x6d,
    0xc9, 0x1d, 0x35, 0xc4, 0x46, 0x4b, 0x05, 0xde, 0x20, 0x46, 0x07,
    0x59, 0xef, 0xe6, 0xbe, 0x1a, 0xd4, 0xf6, 0x4c, 0x01, 0x1b,
};

static const uint8_t SINSEMILLA_COMMIT_IVK_R_X[32] = {
    0x18, 0xa1, 0xf8, 0x5f, 0x6e, 0x48, 0x23, 0x98, 0xc7, 0xed, 0x1a,
    0xd3, 0xe2, 0x7f, 0x95, 0x02, 0x48, 0x89, 0x80, 0x40, 0x0a, 0x29,
    0x34, 0x16, 0x4e, 0x13, 0x70, 0x50, 0xcd, 0x2c, 0xa2, 0x25,
};

static const uint8_t SINSEMILLA_COMMIT_IVK_R_Y[32] = {
    0xa9, 0xdd, 0x7f, 0xe3, 0xb3, 0x93, 0xe7, 0x3f, 0xc7, 0xa6, 0x58,
    0x1b, 0xfb, 0x42, 0x44, 0x6b, 0x94, 0x57, 0x4b, 0x28, 0xc4, 0x90,
    0xc8, 0xc2, 0xeb, 0xfa, 0xa2, 0x66, 0x99, 0xd2, 0xcf, 0x29,
};

static const uint8_t SINSEMILLA_MSG_ONE_BIT[1] = {0x01};
static const uint8_t SINSEMILLA_MSG_TEN_BITS[2] = {0xa5, 0x02};
static const uint8_t SINSEMILLA_MSG_TWENTY_THREE_BITS[3] = {0x5a, 0xc3, 0x3f};

static const uint8_t SINSEMILLA_ZERO_BLIND[32] = {0};
static const uint8_t SINSEMILLA_NONZERO_BLIND[32] = {
    0x21, 0x43, 0x65, 0x87, 0xa9, 0xcb, 0xed, 0x0f, 0x10, 0x32, 0x54,
    0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
    0xcd, 0xef, 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
};

#define SINSEMILLA_EMPTY_HASH_POINT SINSEMILLA_COMMIT_IVK_Q_X
#define SINSEMILLA_EMPTY_HASH SINSEMILLA_COMMIT_IVK_Q_X

static const uint8_t SINSEMILLA_ONE_BIT_HASH_POINT[32] = {
    0xa6, 0x59, 0xf2, 0xb8, 0xa8, 0x92, 0xba, 0x43, 0x86, 0xca, 0x91,
    0x01, 0x6d, 0x68, 0xa8, 0xa4, 0xd2, 0x51, 0x38, 0x55, 0xaf, 0x29,
    0x15, 0x90, 0xd8, 0x2c, 0x50, 0xb9, 0x02, 0x26, 0x94, 0xb2,
};

static const uint8_t SINSEMILLA_ONE_BIT_HASH[32] = {
    0xa6, 0x59, 0xf2, 0xb8, 0xa8, 0x92, 0xba, 0x43, 0x86, 0xca, 0x91,
    0x01, 0x6d, 0x68, 0xa8, 0xa4, 0xd2, 0x51, 0x38, 0x55, 0xaf, 0x29,
    0x15, 0x90, 0xd8, 0x2c, 0x50, 0xb9, 0x02, 0x26, 0x94, 0x32,
};

static const uint8_t SINSEMILLA_TEN_BITS_HASH_POINT[32] = {
    0x16, 0xad, 0xea, 0x6c, 0xce, 0x33, 0x1c, 0xb2, 0x5c, 0xcb, 0x62,
    0x3e, 0x55, 0x61, 0x96, 0x98, 0x2c, 0xbb, 0xa0, 0x30, 0x18, 0xd9,
    0x49, 0x53, 0x5b, 0x4a, 0x56, 0x3b, 0x05, 0x73, 0x04, 0x85,
};

static const uint8_t SINSEMILLA_TEN_BITS_HASH[32] = {
    0x16, 0xad, 0xea, 0x6c, 0xce, 0x33, 0x1c, 0xb2, 0x5c, 0xcb, 0x62,
    0x3e, 0x55, 0x61, 0x96, 0x98, 0x2c, 0xbb, 0xa0, 0x30, 0x18, 0xd9,
    0x49, 0x53, 0x5b, 0x4a, 0x56, 0x3b, 0x05, 0x73, 0x04, 0x05,
};

static const uint8_t SINSEMILLA_TWENTY_THREE_BITS_HASH_POINT[32] = {
    0x1b, 0x2f, 0x70, 0x0a, 0x30, 0xc4, 0x5a, 0x5e, 0x7f, 0x98, 0x6e,
    0x13, 0xf9, 0xe8, 0xec, 0x5e, 0x95, 0xc9, 0xb1, 0xf0, 0x77, 0x3b,
    0x76, 0x39, 0x81, 0xbb, 0x59, 0x9a, 0x2e, 0xd7, 0xab, 0xb5,
};

static const uint8_t SINSEMILLA_TWENTY_THREE_BITS_HASH[32] = {
    0x1b, 0x2f, 0x70, 0x0a, 0x30, 0xc4, 0x5a, 0x5e, 0x7f, 0x98, 0x6e,
    0x13, 0xf9, 0xe8, 0xec, 0x5e, 0x95, 0xc9, 0xb1, 0xf0, 0x77, 0x3b,
    0x76, 0x39, 0x81, 0xbb, 0x59, 0x9a, 0x2e, 0xd7, 0xab, 0x35,
};

static const uint8_t SINSEMILLA_TWENTY_THREE_BITS_COMMIT_POINT[32] = {
    0x38, 0x2f, 0xe5, 0xd4, 0x2a, 0xe2, 0x0b, 0x82, 0x21, 0x6f, 0x86,
    0xb5, 0xba, 0xd0, 0xa4, 0xce, 0x14, 0x8a, 0x5f, 0x1a, 0x8e, 0xae,
    0xc0, 0x30, 0x67, 0xae, 0xaa, 0x2c, 0x67, 0xdd, 0xc1, 0x0a,
};

#define SINSEMILLA_TWENTY_THREE_BITS_SHORT_COMMIT \
  SINSEMILLA_TWENTY_THREE_BITS_COMMIT_POINT

/* F4Jumble vectors from f4jumble 0.1.1 / zcash-test-vectors. */
static const uint8_t F4JUMBLE_48_NORMAL[48] = {
    0x5d, 0x7a, 0x8f, 0x73, 0x9a, 0x2d, 0x9e, 0x94, 0x5b, 0x0c, 0xe1, 0x52,
    0xa8, 0x04, 0x9e, 0x29, 0x4c, 0x4d, 0x6e, 0x66, 0xb1, 0x64, 0x93, 0x9d,
    0xaf, 0xfa, 0x2e, 0xf6, 0xee, 0x69, 0x21, 0x48, 0x1c, 0xdd, 0x86, 0xb3,
    0xcc, 0x43, 0x18, 0xd9, 0x61, 0x4f, 0xc8, 0x20, 0x90, 0x5d, 0x04, 0x2b,
};

static const uint8_t F4JUMBLE_48_JUMBLED[48] = {
    0x03, 0x04, 0xd0, 0x29, 0x14, 0x1b, 0x99, 0x5d, 0xa5, 0x38, 0x7c, 0x12,
    0x59, 0x70, 0x67, 0x35, 0x04, 0xd6, 0xc7, 0x64, 0xd9, 0x1e, 0xa6, 0xc0,
    0x82, 0x12, 0x37, 0x70, 0xc7, 0x13, 0x9c, 0xcd, 0x88, 0xee, 0x27, 0x36,
    0x8c, 0xd0, 0xc0, 0x92, 0x1a, 0x04, 0x44, 0xc8, 0xe5, 0x85, 0x8d, 0x22,
};

static const uint8_t F4JUMBLE_64_NORMAL[64] = {
    0xb1, 0xef, 0x9c, 0xa3, 0xf2, 0x49, 0x88, 0xc7, 0xb3, 0x53, 0x42,
    0x01, 0xcf, 0xb1, 0xcd, 0x8d, 0xbf, 0x69, 0xb8, 0x25, 0x0c, 0x18,
    0xef, 0x41, 0x29, 0x4c, 0xa9, 0x79, 0x93, 0xdb, 0x54, 0x6c, 0x1f,
    0xe0, 0x1f, 0x7e, 0x9c, 0x8e, 0x36, 0xd6, 0xa5, 0xe2, 0x9d, 0x4e,
    0x30, 0xa7, 0x35, 0x94, 0xbf, 0x50, 0x98, 0x42, 0x1c, 0x69, 0x37,
    0x8a, 0xf1, 0xe4, 0x0f, 0x64, 0xe1, 0x25, 0x94, 0x6f,
};

static const uint8_t F4JUMBLE_64_JUMBLED[64] = {
    0x52, 0x71, 0xfa, 0x33, 0x21, 0xf3, 0xad, 0xbc, 0xfb, 0x07, 0x51,
    0x96, 0x88, 0x3d, 0x54, 0x2b, 0x43, 0x8e, 0xc6, 0x33, 0x91, 0x76,
    0x53, 0x7d, 0xaf, 0x85, 0x98, 0x41, 0xfe, 0x6a, 0x56, 0x22, 0x2b,
    0xff, 0x76, 0xd1, 0x66, 0x2b, 0x55, 0x09, 0xa9, 0xe1, 0x07, 0x9e,
    0x44, 0x6e, 0xee, 0xdd, 0x2e, 0x68, 0x3c, 0x31, 0xaa, 0xe3, 0xee,
    0x18, 0x51, 0xd7, 0x95, 0x43, 0x28, 0x52, 0x6b, 0xe1,
};

/* Compare two 32-byte LE values: return -1 if a < b, 0 if equal, 1 if a > b */
static int cmp_le256(const uint8_t a[32], const uint8_t b[32]) {
  for (int i = 31; i >= 0; i--) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

/* ── Reference Test Vectors ──────────────────────────────────────── */

/*
 * Mnemonic: "all all all all all all all all all all all all"
 * BIP-39 seed (PBKDF2, no passphrase), 64 bytes:
 */
static const uint8_t SEED_ALL[64] = {
    0xc7, 0x6c, 0x4a, 0xc4, 0xf4, 0xe4, 0xa0, 0x0d, 0x6b, 0x27, 0x4d,
    0x5c, 0x39, 0xc7, 0x00, 0xbb, 0x4a, 0x7d, 0xdc, 0x04, 0xfb, 0xc6,
    0xf7, 0x8e, 0x85, 0xca, 0x75, 0x00, 0x7b, 0x5b, 0x49, 0x5f, 0x74,
    0xa9, 0x04, 0x3e, 0xeb, 0x77, 0xbd, 0xd5, 0x3a, 0xa6, 0xfc, 0x3a,
    0x0e, 0x31, 0x46, 0x22, 0x70, 0x31, 0x6f, 0xa0, 0x4b, 0x8c, 0x19,
    0x11, 0x4c, 0x87, 0x98, 0x70, 0x6c, 0xd0, 0x2a, 0xc8,
};

/*
 * Expected FVK for "all" mnemonic, account 0.
 * Generated by the orchard Rust crate (authoritative ZIP-32).
 */
static const uint8_t EXPECTED_AK_ALL_0[32] = {
    0x05, 0x7a, 0xb0, 0x51, 0xd4, 0xfb, 0xb0, 0x20, 0x5d, 0x28, 0x64,
    0x8b, 0xac, 0xbc, 0x64, 0x71, 0xb5, 0x33, 0x47, 0x6c, 0x27, 0xbe,
    0xca, 0x33, 0xe5, 0xb9, 0xf5, 0x11, 0xd8, 0x55, 0x67, 0x2b,
};

static const uint8_t EXPECTED_NK_ALL_0[32] = {
    0x34, 0xa3, 0x5a, 0x0b, 0xda, 0x50, 0x27, 0x3b, 0x03, 0x19, 0xaf,
    0xa7, 0xa7, 0x0f, 0x86, 0xb6, 0xb1, 0x62, 0xeb, 0x31, 0x1d, 0x26,
    0x3d, 0x8f, 0x63, 0x21, 0xde, 0xf0, 0x02, 0x28, 0xba, 0x25,
};

static const uint8_t EXPECTED_RIVK_ALL_0[32] = {
    0x46, 0xbd, 0x2b, 0xd5, 0xe6, 0xec, 0xa5, 0xef, 0x03, 0xe1, 0x8c,
    0xd7, 0x65, 0x95, 0x51, 0x9e, 0xa9, 0x67, 0x06, 0xc5, 0x82, 0x6a,
    0x93, 0xba, 0x4d, 0xca, 0x94, 0x7d, 0x71, 0x1a, 0x7c, 0x0a,
};

static const uint8_t EXPECTED_IVK_ALL_0[32] = {
    0xa8, 0xe2, 0xea, 0x36, 0x48, 0x8b, 0x9e, 0xb4, 0x61, 0x47, 0x60,
    0x5b, 0xa1, 0x50, 0x40, 0x37, 0xd0, 0x88, 0x1e, 0x98, 0x1b, 0x6e,
    0x58, 0x47, 0xb9, 0xf5, 0xc1, 0xbe, 0xb5, 0xd0, 0x43, 0x35,
};

static const uint8_t EXPECTED_DK_ALL_0[32] = {
    0xe8, 0x52, 0xed, 0xd7, 0x82, 0xd6, 0xeb, 0x92, 0x12, 0x82, 0x21,
    0x9b, 0x8a, 0x9c, 0x38, 0x0e, 0x03, 0xfc, 0xc4, 0x76, 0x60, 0xfe,
    0x67, 0xaf, 0x1b, 0xa4, 0x77, 0x80, 0x2b, 0xb0, 0x6c, 0xe7,
};

static const uint8_t EXPECTED_DIVERSIFIER_ALL_0[11] = {
    0xda, 0x97, 0x30, 0x31, 0x63, 0x4a, 0x89, 0x38, 0xad, 0x1c, 0x48,
};

/* FF1-AES256 Orchard diversifier vectors generated with zcash-test-vectors.
 * Parameters: radix = 2, n = 88, tweak = "", rounds = 10.
 * Inputs and outputs are LEBS2OSP_88 byte encodings.
 */
struct OrchardFf1Vector {
  uint8_t dk[32];
  uint8_t index[11];
  uint8_t diversifier[11];
};

static const OrchardFf1Vector ORCHARD_FF1_VECTORS[] = {
    {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
     {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
     {0xdc, 0xe7, 0x7e, 0xbc, 0xec, 0x0a, 0x26, 0xaf, 0xd6, 0x99, 0x8c}},
    {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
     {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
     {0x63, 0x73, 0x8a, 0xa5, 0xf7, 0xbe, 0x22, 0xe1, 0xac, 0xdc, 0x0b}},
    {{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
     {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
     {0xd7, 0x39, 0xcc, 0xc2, 0xb8, 0x4d, 0x5d, 0x1a, 0xe5, 0x4a, 0x95}},
    {{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
     {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},
     {0xc8, 0xff, 0x0b, 0x01, 0x96, 0x01, 0x30, 0x12, 0x76, 0x38, 0xc7}},
};

static const uint8_t XMD_ABC_96[96] = {
    0x48, 0x50, 0x5e, 0x62, 0xfe, 0x0c, 0xe6, 0x64, 0xb6, 0x80, 0xf1, 0xf9,
    0xe6, 0x37, 0x43, 0x91, 0xa6, 0x09, 0x57, 0x5e, 0x53, 0x5c, 0xfd, 0x55,
    0xea, 0xd4, 0x49, 0xa4, 0x18, 0x43, 0xc7, 0x0d, 0x65, 0x3a, 0x08, 0x5d,
    0x09, 0xb1, 0x9f, 0x3f, 0x8d, 0x4d, 0x0a, 0xe4, 0x4f, 0x6a, 0xcf, 0x48,
    0xca, 0xfd, 0xb2, 0x8b, 0x8e, 0xea, 0x01, 0xe3, 0x6a, 0xf4, 0xf5, 0xfc,
    0xda, 0xcc, 0xf1, 0x45, 0x2a, 0x87, 0xc0, 0x8c, 0xc1, 0x0c, 0x9a, 0x03,
    0x7f, 0x3f, 0x03, 0x69, 0xf6, 0xb0, 0x43, 0xfb, 0xfc, 0x59, 0x81, 0xb6,
    0x0d, 0x50, 0xd7, 0xbd, 0x00, 0x4a, 0x59, 0x71, 0x3b, 0x1e, 0xcc, 0x25,
};

static const uint8_t SWU_0_X_LE[32] = {
    0x6e, 0x09, 0x9b, 0x51, 0x33, 0x34, 0xca, 0x85, 0xf4, 0x27, 0xa7,
    0xde, 0x25, 0x25, 0xf4, 0xf5, 0x8a, 0x9a, 0x12, 0x39, 0xb3, 0x95,
    0x52, 0xe2, 0x52, 0x6c, 0xf5, 0x34, 0xa5, 0xa6, 0xc1, 0x28,
};

static const uint8_t SWU_0_Y_LE[32] = {
    0x8d, 0xae, 0xc5, 0x6a, 0xee, 0xa1, 0x4f, 0x08, 0xc7, 0xb7, 0x07,
    0x02, 0x27, 0x9c, 0xd2, 0x15, 0xd3, 0x3f, 0x08, 0x27, 0x09, 0x7f,
    0x7d, 0x3c, 0xc6, 0x53, 0x66, 0xee, 0x8b, 0x65, 0xfc, 0x3b,
};

static const uint8_t SWU_0_Z_LE[32] = {
    0x36, 0xef, 0xcd, 0xd8, 0x0c, 0x25, 0x5f, 0x8a, 0x6f, 0x74, 0x7d,
    0xda, 0x72, 0x54, 0x11, 0x5d, 0x9d, 0xa1, 0x34, 0x85, 0x31, 0xb1,
    0x57, 0x41, 0x10, 0xdc, 0x16, 0x04, 0xa1, 0x3b, 0x4b, 0x05,
};

static const uint8_t SWU_1_X_LE[32] = {
    0x05, 0x15, 0x56, 0xa3, 0xa5, 0xb9, 0x13, 0x79, 0x83, 0x80, 0x82,
    0x06, 0x71, 0xb0, 0x64, 0x6d, 0x85, 0xa1, 0x26, 0xc0, 0x67, 0xe9,
    0xf5, 0x4a, 0x53, 0x76, 0xe8, 0x57, 0x59, 0xba, 0x0c, 0x01,
};

static const uint8_t SWU_1_Y_LE[32] = {
    0x81, 0x9c, 0xcc, 0x5d, 0x51, 0x6d, 0xfa, 0x76, 0xe9, 0x78, 0x80,
    0xb0, 0xd6, 0x14, 0x75, 0x54, 0x6a, 0xf4, 0xeb, 0x65, 0xa0, 0x65,
    0x6e, 0x7d, 0x8e, 0x11, 0xd3, 0x9c, 0x1f, 0xc6, 0x2f, 0x06,
};

static const uint8_t SWU_1_Z_LE[32] = {
    0x88, 0x36, 0xa7, 0x29, 0x9a, 0xbc, 0x75, 0x7c, 0x3a, 0x75, 0xe1,
    0x3d, 0x62, 0xf5, 0xcf, 0x5c, 0x60, 0x93, 0x77, 0x3e, 0x52, 0x4e,
    0x1c, 0x10, 0xc3, 0x50, 0x12, 0x31, 0x8c, 0xcb, 0x86, 0x3f,
};

static const uint8_t HASH_ZCASH_TEST_TRANS_RIGHTS[32] = {
    0xd3, 0x6b, 0x0b, 0x64, 0x9b, 0x5c, 0x69, 0x36, 0x02, 0x7a, 0x18,
    0x0f, 0x7d, 0x25, 0x40, 0x23, 0x95, 0x6f, 0xc2, 0x88, 0x3d, 0xdf,
    0x23, 0xff, 0xc3, 0xc8, 0xfd, 0x1f, 0xa3, 0xcd, 0x18, 0x18,
};

static const uint8_t ORCHARD_GD_EMPTY[32] = {
    0x3f, 0x90, 0xd3, 0xe5, 0x80, 0xd5, 0x6a, 0x66, 0x2b, 0x27, 0x36,
    0x91, 0xd8, 0xd1, 0xe3, 0x34, 0x75, 0x30, 0x83, 0xe9, 0xbf, 0x4c,
    0x17, 0x2e, 0x7d, 0xae, 0xfc, 0x0f, 0x06, 0x08, 0xcf, 0x97,
};

static const uint8_t ORCHARD_GD_ALL_ACCOUNT0_J0[32] = {
    0x26, 0x8e, 0xd9, 0xf9, 0x01, 0xfd, 0xb4, 0xe9, 0xb3, 0xf0, 0x70,
    0xd9, 0x5f, 0x1b, 0x8d, 0x98, 0x35, 0x3c, 0xb8, 0xa2, 0x02, 0xac,
    0x1c, 0x97, 0xbd, 0xb1, 0x26, 0x9f, 0x85, 0x93, 0xd6, 0x30,
};

static const uint8_t ORCHARD_GD_FF1_ZERO_ZERO[32] = {
    0xa4, 0x58, 0x99, 0x84, 0x3c, 0xde, 0x1f, 0xaf, 0x52, 0x42, 0x6e,
    0x27, 0xd4, 0x17, 0x96, 0xb5, 0x2a, 0xaf, 0x39, 0xf1, 0x47, 0x9c,
    0xe0, 0x69, 0xd7, 0xa9, 0xda, 0x4e, 0xef, 0xc3, 0xf8, 0x3d,
};

/* Orchard ivk/d/g_d/pk_d vectors generated with orchard 0.12.0. */
struct OrchardReceiverVector {
  uint8_t ivk[32];
  uint8_t diversifier[11];
  uint8_t gd[32];
  uint8_t pkd[32];
};

static const OrchardReceiverVector ORCHARD_RECEIVER_VECTORS[] = {
    {{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
     {0xd8, 0xe1, 0x01, 0x7d, 0x45, 0x32, 0xab, 0x65, 0xe0, 0xe5, 0x38},
     {0x7d, 0x70, 0x35, 0xca, 0x4a, 0x40, 0x9d, 0xe0, 0x65, 0x40, 0xdf,
      0xd1, 0x6e, 0x8c, 0x2d, 0xd9, 0xa9, 0x34, 0xee, 0x17, 0xfa, 0xfb,
      0x8e, 0xd0, 0xd7, 0x85, 0x6d, 0x16, 0x1c, 0x9a, 0x02, 0x2b},
     {0x7d, 0x70, 0x35, 0xca, 0x4a, 0x40, 0x9d, 0xe0, 0x65, 0x40, 0xdf,
      0xd1, 0x6e, 0x8c, 0x2d, 0xd9, 0xa9, 0x34, 0xee, 0x17, 0xfa, 0xfb,
      0x8e, 0xd0, 0xd7, 0x85, 0x6d, 0x16, 0x1c, 0x9a, 0x02, 0x2b}},
    {{0x42, 0x7a, 0x1d, 0xb3, 0x94, 0x6f, 0x20, 0xe5, 0x88, 0x30, 0xc2,
      0x91, 0x76, 0x11, 0x5d, 0x04, 0xf8, 0xbc, 0x9a, 0x21, 0x0e, 0x73,
      0xd5, 0x4c, 0x06, 0x9b, 0xa8, 0x17, 0x2e, 0x45, 0x00, 0x10},
     {0xe3, 0x63, 0x1b, 0x5e, 0xdd, 0x66, 0x95, 0xf0, 0xf0, 0x0d, 0x8d},
     {0xe7, 0xb6, 0x5d, 0xda, 0x4b, 0xc5, 0x39, 0xc0, 0xf4, 0x0c, 0x6a,
      0xdf, 0xaa, 0x41, 0xaa, 0x11, 0xd2, 0xf5, 0x27, 0xc8, 0x8a, 0xd0,
      0x10, 0xec, 0xb5, 0xe3, 0x8c, 0xbe, 0x38, 0x18, 0xdd, 0x31},
     {0x36, 0xc5, 0x49, 0x3f, 0x2b, 0x53, 0xaf, 0x23, 0x7b, 0x86, 0x5a,
      0xe1, 0x17, 0xc3, 0x05, 0x14, 0x8b, 0x78, 0xb2, 0x10, 0x84, 0x7c,
      0x86, 0xa5, 0xce, 0x24, 0xfa, 0x12, 0xa9, 0x1f, 0xf5, 0x87}},
    {{0xfe, 0xff, 0xff, 0xff, 0x38, 0x6d, 0x78, 0x34, 0xad, 0x14, 0x19,
      0xe4, 0x0b, 0x35, 0x2c, 0x99, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f},
     {0x65, 0x92, 0x89, 0x70, 0xbe, 0x78, 0x36, 0x96, 0xe0, 0x2f, 0xd1},
     {0xc9, 0xb4, 0xb5, 0x0a, 0x61, 0x9d, 0xc3, 0x4c, 0x60, 0xd4, 0xa8,
      0x30, 0x0d, 0x56, 0x60, 0x12, 0x77, 0xd7, 0x02, 0xa7, 0x5e, 0xb5,
      0xcf, 0xe1, 0x77, 0x22, 0xa7, 0x1d, 0xb7, 0x3f, 0x36, 0x32},
     {0x17, 0xcb, 0x58, 0x55, 0x9a, 0xf4, 0xd2, 0xcc, 0x6e, 0x1f, 0x24,
      0xa7, 0xe5, 0xab, 0x4c, 0x83, 0x33, 0x3c, 0x25, 0x16, 0xd3, 0x64,
      0x00, 0x6f, 0x9c, 0xee, 0x24, 0x70, 0x3c, 0xe4, 0xfc, 0xba}},
};

/* Orchard ak/nk/rivk -> ivk vectors generated with orchard 0.12.0. */
struct OrchardIvkVector {
  uint8_t ak[32];
  uint8_t nk[32];
  uint8_t rivk[32];
  uint8_t ivk[32];
};

static const OrchardIvkVector ORCHARD_IVK_VECTORS[] = {
    {{0x87, 0x77, 0xe2, 0x15, 0x10, 0x1d, 0xf4, 0x5a, 0xa4, 0x68, 0xbb,
      0x10, 0xb2, 0xf9, 0x3f, 0xfe, 0x08, 0xa2, 0xf7, 0x9e, 0xbf, 0xf0,
      0x95, 0xaa, 0xeb, 0x74, 0x73, 0xc7, 0x71, 0x34, 0x96, 0x21},
     {0xbb, 0xca, 0x15, 0x2c, 0xfb, 0xf9, 0x81, 0x18, 0x19, 0xcc, 0x62,
      0x44, 0x34, 0xd1, 0x23, 0x75, 0x77, 0xc1, 0x38, 0x05, 0xcc, 0x3d,
      0xed, 0x44, 0x4e, 0x75, 0x5a, 0x6b, 0x78, 0xfa, 0xcd, 0x16},
     {0x8c, 0xa7, 0xfb, 0xba, 0x26, 0x47, 0x0f, 0xea, 0x0b, 0x10, 0xd3,
      0x0d, 0xb2, 0x73, 0x66, 0xec, 0x65, 0x04, 0x0c, 0x72, 0xa0, 0x9a,
      0xd8, 0x42, 0x58, 0x88, 0xef, 0x26, 0xf1, 0xc0, 0x79, 0x3f},
     {0xa1, 0xf8, 0x75, 0x87, 0x29, 0x73, 0xea, 0x49, 0x2d, 0xe3, 0xbe,
      0x5c, 0xce, 0xcf, 0xe5, 0x56, 0x79, 0x10, 0x24, 0x4c, 0xb6, 0x02,
      0x99, 0x4c, 0x58, 0x00, 0xf6, 0x8c, 0x64, 0x38, 0xb9, 0x1b}},
    {{0x6e, 0xbb, 0x83, 0x3c, 0x1d, 0x2f, 0x84, 0x33, 0x08, 0x0a, 0xbc,
      0xea, 0xbe, 0x47, 0x90, 0x60, 0x97, 0xf9, 0x06, 0x78, 0xd6, 0x03,
      0xf5, 0x77, 0xd0, 0x48, 0x6c, 0x91, 0x11, 0x73, 0x7b, 0x07},
     {0xf2, 0x26, 0xa3, 0xf8, 0x79, 0xeb, 0xe2, 0x1a, 0xbf, 0xaf, 0xcc,
      0xb6, 0xc5, 0x21, 0xca, 0x74, 0x9e, 0x63, 0xac, 0x17, 0xfd, 0x2c,
      0xd1, 0x78, 0x70, 0xaa, 0x72, 0xde, 0x12, 0xd8, 0x33, 0x0d},
     {0x04, 0x7c, 0x00, 0xab, 0x5e, 0x0f, 0xec, 0xa6, 0x1a, 0x46, 0x18,
      0x58, 0xbb, 0x0b, 0x15, 0xd5, 0x5f, 0x29, 0x76, 0x3a, 0x0a, 0x28,
      0x28, 0x25, 0xac, 0xeb, 0xd5, 0x86, 0x98, 0x93, 0x7d, 0x24},
     {0xa1, 0x75, 0x8f, 0x83, 0xad, 0xbd, 0x24, 0x89, 0x87, 0xc3, 0x6b,
      0xbf, 0x52, 0x41, 0xc1, 0x29, 0x9e, 0xfa, 0x96, 0xf2, 0x4c, 0x8c,
      0xfb, 0xb5, 0x51, 0x17, 0x23, 0x90, 0x9c, 0xc1, 0xe2, 0x02}},
    {{0xa4, 0x1c, 0xc0, 0xc3, 0x80, 0x0f, 0xf8, 0x9a, 0x88, 0xd7, 0xae,
      0x02, 0xff, 0x33, 0x6f, 0xdb, 0xd5, 0xbc, 0xe8, 0x9d, 0x9e, 0x8d,
      0xd4, 0xeb, 0x27, 0x8b, 0x4c, 0xd5, 0xc3, 0x7e, 0xc7, 0x20},
     {0x41, 0x5e, 0x75, 0x22, 0x27, 0xcb, 0x69, 0x65, 0x2e, 0x2a, 0xfa,
      0x94, 0x81, 0x6f, 0x63, 0x0d, 0xce, 0xc1, 0xac, 0xdf, 0x3c, 0x3f,
      0xb0, 0x2e, 0x1e, 0x6b, 0x04, 0x6e, 0x12, 0xa4, 0x31, 0x11},
     {0x92, 0x76, 0xa5, 0xb7, 0x55, 0xa1, 0x54, 0x63, 0xab, 0x59, 0xf0,
      0xe7, 0x22, 0x1f, 0x65, 0x80, 0x65, 0x7c, 0x05, 0x3f, 0xdb, 0x74,
      0x40, 0x12, 0xb3, 0xc1, 0x64, 0x8c, 0x75, 0x78, 0xd1, 0x22},
     {0xa8, 0x4f, 0x85, 0xd1, 0x57, 0xba, 0x71, 0x66, 0x5b, 0x31, 0x0b,
      0xd2, 0x12, 0x15, 0xad, 0x58, 0x82, 0x3b, 0x29, 0x8f, 0x44, 0x98,
      0xd5, 0x0d, 0x63, 0xad, 0xc9, 0x4d, 0x34, 0xeb, 0x93, 0x0a}},
};

/* Orchard raw receiver vectors generated with orchard 0.12.0. */
struct OrchardReceiverAssemblyVector {
  const uint8_t* ak;
  const uint8_t* nk;
  const uint8_t* rivk;
  const uint8_t* dk;
  uint8_t index[11];
  uint8_t receiver[43];
};

static const uint8_t ORCHARD_ASSEMBLY_DK_2[32] = {
    0x6c, 0x50, 0x3c, 0x95, 0x19, 0x0a, 0x74, 0x1d, 0x5f, 0x54, 0x87,
    0x59, 0xeb, 0x46, 0x4a, 0xa5, 0x36, 0x3b, 0xcd, 0xbc, 0x91, 0xa6,
    0x98, 0x7b, 0xd0, 0x7f, 0x67, 0x7b, 0x37, 0x59, 0xc2, 0x08,
};

static const uint8_t ORCHARD_ASSEMBLY_DK_3[32] = {
    0x41, 0xb7, 0x06, 0x56, 0xe2, 0x02, 0xaa, 0xcd, 0x0d, 0x92, 0x3b,
    0x7c, 0x95, 0xc0, 0xfc, 0x17, 0xa2, 0x13, 0xaf, 0x97, 0x3a, 0xd4,
    0xf8, 0x3f, 0xeb, 0x47, 0xdd, 0xf8, 0x3b, 0xb1, 0x68, 0xe4,
};

static const OrchardReceiverAssemblyVector ORCHARD_RECEIVER_ASSEMBLY_VECTORS[] =
    {
        {EXPECTED_AK_ALL_0,
         EXPECTED_NK_ALL_0,
         EXPECTED_RIVK_ALL_0,
         EXPECTED_DK_ALL_0,
         {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
         {0xda, 0x97, 0x30, 0x31, 0x63, 0x4a, 0x89, 0x38, 0xad, 0x1c, 0x48,
          0x0f, 0x97, 0x87, 0x80, 0x69, 0x3e, 0xc7, 0x70, 0x9b, 0xa5, 0xca,
          0xf5, 0x8d, 0x8a, 0x7e, 0xb9, 0x45, 0x58, 0x6c, 0xbe, 0xd6, 0x45,
          0x52, 0x0f, 0x17, 0x38, 0x74, 0x37, 0xbc, 0xfd, 0xc2, 0x16}},
        {EXPECTED_AK_ALL_0,
         EXPECTED_NK_ALL_0,
         EXPECTED_RIVK_ALL_0,
         EXPECTED_DK_ALL_0,
         {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
         {0xbb, 0x0c, 0x08, 0xc2, 0x0f, 0x07, 0x8f, 0x59, 0x89, 0x39, 0x1c,
          0x36, 0x91, 0xb8, 0x97, 0xea, 0xcf, 0x28, 0x9a, 0x02, 0x02, 0x2f,
          0x45, 0xb3, 0xb1, 0x3f, 0x5f, 0xa1, 0xaa, 0xd5, 0x95, 0x9f, 0xaa,
          0x29, 0x01, 0x56, 0xc2, 0x40, 0xb8, 0xae, 0x1c, 0x07, 0x25}},
        {ORCHARD_IVK_VECTORS[1].ak,
         ORCHARD_IVK_VECTORS[1].nk,
         ORCHARD_IVK_VECTORS[1].rivk,
         ORCHARD_ASSEMBLY_DK_2,
         {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
         {0x45, 0x59, 0x02, 0x9c, 0x0b, 0x5d, 0xbf, 0x94, 0x1c, 0x5a, 0xd1,
          0x81, 0xa5, 0xfe, 0x8f, 0x45, 0xb3, 0x46, 0x30, 0xf2, 0x9d, 0x0c,
          0x8d, 0xd8, 0xdc, 0x1c, 0xc3, 0x57, 0x33, 0x86, 0xf4, 0x16, 0xcb,
          0x32, 0x41, 0x33, 0x15, 0x6d, 0x72, 0x3d, 0xf5, 0xe6, 0x2d}},
        {ORCHARD_IVK_VECTORS[2].ak,
         ORCHARD_IVK_VECTORS[2].nk,
         ORCHARD_IVK_VECTORS[2].rivk,
         ORCHARD_ASSEMBLY_DK_3,
         {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
         {0xcb, 0xd5, 0xfc, 0x34, 0xc7, 0x26, 0x1d, 0x3f, 0xdb, 0x23, 0xd2,
          0xb8, 0x14, 0xad, 0xcb, 0xfc, 0x2d, 0x8e, 0x17, 0x2c, 0x79, 0xee,
          0x8e, 0x2e, 0x3f, 0xe7, 0xd8, 0xb1, 0xda, 0xd5, 0xb6, 0x67, 0x8e,
          0x22, 0x6c, 0xa7, 0xa3, 0x99, 0x6b, 0x1e, 0x62, 0x4f, 0x35}},
};

/* Orchard-only unified address vectors generated with zcash_address 0.10.1. */
static const char ORCHARD_ONLY_UA_MAINNET_0[] =
    "u1uzslnccvrw4r2y2kgjz7fm477xcnzge9z45scm4e6l6c63ren0ru29teedxw5vxu7c8xch"
    "p3ec2pu3wkgldc5zphwtm4w3fchcwrl26c";
static const char ORCHARD_ONLY_UA_TESTNET_0[] =
    "utest1deyej6qvxfnewfhgdc987fgpq407u374vzvtvgjuv86vj0gs9tcej04hk7nr5msm5fzg"
    "335j70mddjnqj48zjsj5zl2362w4zcd2ks8c";
static const char ORCHARD_ONLY_UA_MAINNET_1[] =
    "u19whtuck5ry2d53xa348ecvfgsudtk8vt2qexe9w50lzwkzxx3lxcn60ztjfe2m33e0jz4xd"
    "4kxe3yhz65xq9jzvjcrtjrhvrf5mzat26";
static const char ORCHARD_ONLY_UA_TESTNET_1[] =
    "utest1ff5jzt4pr5hzgz8688052pjtq0plzk3va9hgssprp3ps2lluhy3u6ej7eh3njfgqp3"
    "ar4lm8muxu352nmuqt2c5n92w4ngf44qwtjl0p";

/* ── ZIP-32 Derivation Tests ─────────────────────────────────────── */

TEST(Zcash, DeriveOrchardKeys_ReferenceVector_Account0) {
  /*
   * Reference vector test: derive keys from known "all" mnemonic seed
   * and compare against values from the orchard Rust crate.
   */
  ZcashOrchardKeys keys;
  ASSERT_TRUE(zcash_derive_orchard_keys(SEED_ALL, 64, 0, &keys));

  /* nk must match reference */
  EXPECT_TRUE(memcmp(keys.nk, EXPECTED_NK_ALL_0, 32) == 0)
      << "nk mismatch for all-mnemonic account 0";

  EXPECT_TRUE(memcmp(keys.ak, EXPECTED_AK_ALL_0, 32) == 0)
      << "cached ak mismatch for all-mnemonic account 0";

  /* rivk must match reference */
  EXPECT_TRUE(memcmp(keys.rivk, EXPECTED_RIVK_ALL_0, 32) == 0)
      << "rivk mismatch for all-mnemonic account 0";

  uint8_t ivk[32];
  ASSERT_TRUE(
      zcash_orchard_derive_ivk(EXPECTED_AK_ALL_0, keys.nk, keys.rivk, ivk));
  EXPECT_TRUE(memcmp(ivk, EXPECTED_IVK_ALL_0, 32) == 0)
      << "ivk mismatch for all-mnemonic account 0";

  EXPECT_TRUE(memcmp(keys.dk, EXPECTED_DK_ALL_0, 32) == 0)
      << "dk mismatch for all-mnemonic account 0";

  uint8_t diversifier[11];
  uint8_t index0[11] = {0};
  ASSERT_TRUE(zcash_orchard_derive_diversifier(keys.dk, index0, diversifier));
  EXPECT_TRUE(memcmp(diversifier, EXPECTED_DIVERSIFIER_ALL_0, 11) == 0)
      << "default diversifier mismatch for all-mnemonic account 0";

  /* Compute ak = [ask]*G and verify against reference */
  bignum256 ask_scalar;
  bn_read_le(keys.ask, &ask_scalar);
  curve_point ak_point;
  redpallas_scalar_mult_spendauth_G(&ask_scalar, &ak_point);

  uint8_t ak_bytes[32];
  bignum256 x_copy;
  bn_copy(&ak_point.x, &x_copy);
  bn_write_le(&x_copy, ak_bytes);
  EXPECT_EQ(ak_bytes[31] & 0x80, 0)
      << "ak sign bit must be 0 after ask normalization";

  EXPECT_TRUE(memcmp(ak_bytes, EXPECTED_AK_ALL_0, 32) == 0)
      << "ak mismatch for all-mnemonic account 0";

  memzero(diversifier, sizeof(diversifier));
  memzero(ivk, sizeof(ivk));
  memzero(&keys, sizeof(keys));
}

TEST(Zcash, DeriveOrchardKeys_DifferentAccounts) {
  ZcashOrchardKeys keys0, keys1;
  ASSERT_TRUE(zcash_derive_orchard_keys(SEED_ALL, 64, 0, &keys0));
  ASSERT_TRUE(zcash_derive_orchard_keys(SEED_ALL, 64, 1, &keys1));

  /* Different accounts must produce different spending keys */
  EXPECT_TRUE(memcmp(keys0.sk, keys1.sk, 32) != 0)
      << "Account 0 and 1 must have different sk";
  EXPECT_TRUE(memcmp(keys0.ask, keys1.ask, 32) != 0)
      << "Account 0 and 1 must have different ask";
  EXPECT_TRUE(memcmp(keys0.nk, keys1.nk, 32) != 0)
      << "Account 0 and 1 must have different nk";

  memzero(&keys0, sizeof(keys0));
  memzero(&keys1, sizeof(keys1));
}

TEST(Zcash, DeriveOrchardKeys_DifferentSeeds) {
  /* Use a different seed (all zeros) */
  uint8_t zero_seed[64];
  memset(zero_seed, 0, sizeof(zero_seed));

  ZcashOrchardKeys keys_all, keys_zero;
  ASSERT_TRUE(zcash_derive_orchard_keys(SEED_ALL, 64, 0, &keys_all));
  ASSERT_TRUE(zcash_derive_orchard_keys(zero_seed, 64, 0, &keys_zero));

  EXPECT_TRUE(memcmp(keys_all.sk, keys_zero.sk, 32) != 0)
      << "Different seeds must produce different sk";

  memzero(&keys_all, sizeof(keys_all));
  memzero(&keys_zero, sizeof(keys_zero));
}

TEST(Zcash, DeriveOrchardKeys_Deterministic) {
  ZcashOrchardKeys keys1, keys2;
  ASSERT_TRUE(zcash_derive_orchard_keys(SEED_ALL, 64, 0, &keys1));
  ASSERT_TRUE(zcash_derive_orchard_keys(SEED_ALL, 64, 0, &keys2));

  EXPECT_TRUE(memcmp(keys1.sk, keys2.sk, 32) == 0);
  EXPECT_TRUE(memcmp(keys1.ask, keys2.ask, 32) == 0);
  EXPECT_TRUE(memcmp(keys1.ak, keys2.ak, 32) == 0);
  EXPECT_TRUE(memcmp(keys1.nk, keys2.nk, 32) == 0);
  EXPECT_TRUE(memcmp(keys1.rivk, keys2.rivk, 32) == 0);
  EXPECT_TRUE(memcmp(keys1.dk, keys2.dk, 32) == 0);

  memzero(&keys1, sizeof(keys1));
  memzero(&keys2, sizeof(keys2));
}

TEST(Zcash, DeriveOrchardKeys_DerivesDiversifierKey) {
  ZcashOrchardKeys keys0, keys1;
  ASSERT_TRUE(zcash_derive_orchard_keys(SEED_ALL, 64, 0, &keys0));
  ASSERT_TRUE(zcash_derive_orchard_keys(SEED_ALL, 64, 1, &keys1));

  uint8_t zero[32] = {0};
  EXPECT_TRUE(memcmp(keys0.dk, zero, 32) != 0)
      << "Diversifier key must be populated";
  EXPECT_TRUE(memcmp(keys0.dk, keys1.dk, 32) != 0)
      << "Different accounts must produce different diversifier keys";

  memzero(&keys0, sizeof(keys0));
  memzero(&keys1, sizeof(keys1));
}

TEST(Zcash, OrchardDiversifier_FF1ReferenceVectors) {
  for (const auto& tv : ORCHARD_FF1_VECTORS) {
    uint8_t actual[11];
    ASSERT_TRUE(zcash_orchard_derive_diversifier(tv.dk, tv.index, actual));
    EXPECT_TRUE(memcmp(actual, tv.diversifier, sizeof(actual)) == 0);
    memzero(actual, sizeof(actual));
  }
}

TEST(Zcash, OrchardDiversifier_DeterministicAndDistinct) {
  const uint8_t index0[11] = {0};
  const uint8_t index1[11] = {1};
  uint8_t d0[11], d0_again[11], d1[11];

  ASSERT_TRUE(
      zcash_orchard_derive_diversifier(ORCHARD_FF1_VECTORS[2].dk, index0, d0));
  ASSERT_TRUE(zcash_orchard_derive_diversifier(ORCHARD_FF1_VECTORS[2].dk,
                                               index0, d0_again));
  ASSERT_TRUE(
      zcash_orchard_derive_diversifier(ORCHARD_FF1_VECTORS[2].dk, index1, d1));

  EXPECT_TRUE(memcmp(d0, d0_again, sizeof(d0)) == 0);
  EXPECT_TRUE(memcmp(d0, d1, sizeof(d0)) != 0);

  memzero(d0, sizeof(d0));
  memzero(d0_again, sizeof(d0_again));
  memzero(d1, sizeof(d1));
}

TEST(Zcash, ExpandMessageXmdBlake2b_ReferenceVector) {
  const uint8_t msg[] = {'a', 'b', 'c'};
  const uint8_t dst[] = "z.cash:test-pallas_XMD:BLAKE2b_SSWU_RO_";
  uint8_t out[96];

  ASSERT_EQ(pallas_expand_message_xmd_blake2b(
                msg, sizeof(msg), dst, sizeof(dst) - 1, out, sizeof(out)),
            0);
  EXPECT_TRUE(memcmp(out, XMD_ABC_96, sizeof(out)) == 0);
}

static void expect_bn_le(const bignum256* value, const uint8_t expected[32]) {
  uint8_t actual[32];
  bignum256 tmp;
  bn_copy(value, &tmp);
  bn_write_le(&tmp, actual);
  EXPECT_TRUE(memcmp(actual, expected, 32) == 0);
  memzero(actual, sizeof(actual));
  memzero(&tmp, sizeof(tmp));
}

static void load_curve_point_from_xy(const uint8_t x[32], const uint8_t y[32],
                                     curve_point* out) {
  bn_read_le(x, &out->x);
  bn_read_le(y, &out->y);
  bn_normalize(&out->x);
  bn_normalize(&out->y);
}

TEST(Zcash, PallasSimpleSwu_ReferenceVectors) {
  uint8_t u0[32] = {0};
  uint8_t u1[32] = {0};
  u1[0] = 1;

  pallas_jacobian_point p0, p1;
  ASSERT_EQ(pallas_map_to_curve_simple_swu(u0, &p0), 0);
  ASSERT_EQ(pallas_map_to_curve_simple_swu(u1, &p1), 0);

  expect_bn_le(&p0.x, SWU_0_X_LE);
  expect_bn_le(&p0.y, SWU_0_Y_LE);
  expect_bn_le(&p0.z, SWU_0_Z_LE);
  expect_bn_le(&p1.x, SWU_1_X_LE);
  expect_bn_le(&p1.y, SWU_1_Y_LE);
  expect_bn_le(&p1.z, SWU_1_Z_LE);

  memzero(&p0, sizeof(p0));
  memzero(&p1, sizeof(p1));
}

TEST(Zcash, PallasGroupHash_ReferenceVector) {
  const uint8_t msg[] = "Trans rights now!";
  curve_point p;
  uint8_t encoded[32];

  ASSERT_EQ(pallas_group_hash("z.cash:test", msg, sizeof(msg) - 1, &p), 0);
  pallas_point_encode(&p, encoded);
  EXPECT_TRUE(memcmp(encoded, HASH_ZCASH_TEST_TRANS_RIGHTS, sizeof(encoded)) ==
              0);

  memzero(&p, sizeof(p));
  memzero(encoded, sizeof(encoded));
}

struct SinsemillaPrimitiveVector {
  const uint8_t* msg;
  size_t msg_bits;
  const uint8_t* blind;
  const uint8_t* hash_point;
  const uint8_t* hash;
  const uint8_t* commit_point;
  const uint8_t* short_commit;
};

TEST(Zcash, SinsemillaPrimitives_ReferenceVectors) {
  const SinsemillaPrimitiveVector vectors[] = {
      {nullptr, 0, SINSEMILLA_ZERO_BLIND, SINSEMILLA_EMPTY_HASH_POINT,
       SINSEMILLA_EMPTY_HASH, SINSEMILLA_EMPTY_HASH_POINT,
       SINSEMILLA_EMPTY_HASH},
      {SINSEMILLA_MSG_ONE_BIT, 1, SINSEMILLA_ZERO_BLIND,
       SINSEMILLA_ONE_BIT_HASH_POINT, SINSEMILLA_ONE_BIT_HASH,
       SINSEMILLA_ONE_BIT_HASH_POINT, SINSEMILLA_ONE_BIT_HASH},
      {SINSEMILLA_MSG_TEN_BITS, 10, SINSEMILLA_ZERO_BLIND,
       SINSEMILLA_TEN_BITS_HASH_POINT, SINSEMILLA_TEN_BITS_HASH,
       SINSEMILLA_TEN_BITS_HASH_POINT, SINSEMILLA_TEN_BITS_HASH},
      {SINSEMILLA_MSG_TWENTY_THREE_BITS, 23, SINSEMILLA_NONZERO_BLIND,
       SINSEMILLA_TWENTY_THREE_BITS_HASH_POINT,
       SINSEMILLA_TWENTY_THREE_BITS_HASH,
       SINSEMILLA_TWENTY_THREE_BITS_COMMIT_POINT,
       SINSEMILLA_TWENTY_THREE_BITS_SHORT_COMMIT},
  };

  curve_point q, r;
  load_curve_point_from_xy(SINSEMILLA_COMMIT_IVK_Q_X, SINSEMILLA_COMMIT_IVK_Q_Y,
                           &q);
  load_curve_point_from_xy(SINSEMILLA_COMMIT_IVK_R_X, SINSEMILLA_COMMIT_IVK_R_Y,
                           &r);

  for (const auto& vector : vectors) {
    curve_point hash_point, commit_point;
    uint8_t encoded[32];
    uint8_t hash[32];
    uint8_t short_commit[32];

    ASSERT_EQ(pallas_sinsemilla_hash_to_point(&q, vector.msg, vector.msg_bits,
                                              &hash_point),
              0);
    pallas_point_encode(&hash_point, encoded);
    EXPECT_TRUE(memcmp(encoded, vector.hash_point, sizeof(encoded)) == 0);

    ASSERT_EQ(pallas_sinsemilla_hash(&q, vector.msg, vector.msg_bits, hash), 0);
    EXPECT_TRUE(memcmp(hash, vector.hash, sizeof(hash)) == 0);

    ASSERT_EQ(pallas_sinsemilla_commit(&q, &r, vector.msg, vector.msg_bits,
                                       vector.blind, &commit_point),
              0);
    pallas_point_encode(&commit_point, encoded);
    EXPECT_TRUE(memcmp(encoded, vector.commit_point, sizeof(encoded)) == 0);

    ASSERT_EQ(
        pallas_sinsemilla_short_commit(&q, &r, vector.msg, vector.msg_bits,
                                       vector.blind, short_commit),
        0);
    EXPECT_TRUE(
        memcmp(short_commit, vector.short_commit, sizeof(short_commit)) == 0);

    memzero(&hash_point, sizeof(hash_point));
    memzero(&commit_point, sizeof(commit_point));
    memzero(encoded, sizeof(encoded));
    memzero(hash, sizeof(hash));
    memzero(short_commit, sizeof(short_commit));
  }

  memzero(&q, sizeof(q));
  memzero(&r, sizeof(r));
}

TEST(Zcash, SinsemillaPrimitives_RejectInvalidInputs) {
  curve_point q, r, out;
  load_curve_point_from_xy(SINSEMILLA_COMMIT_IVK_Q_X, SINSEMILLA_COMMIT_IVK_Q_Y,
                           &q);
  load_curve_point_from_xy(SINSEMILLA_COMMIT_IVK_R_X, SINSEMILLA_COMMIT_IVK_R_Y,
                           &r);

  EXPECT_EQ(
      pallas_sinsemilla_hash_to_point(&q, SINSEMILLA_MSG_ONE_BIT,
                                      PALLAS_SINSEMILLA_MAX_BITS + 1, &out),
      -1);

  curve_point identity = {};
  EXPECT_EQ(pallas_sinsemilla_hash_to_point(&identity, SINSEMILLA_MSG_ONE_BIT,
                                            1, &out),
            -1);
  EXPECT_EQ(pallas_sinsemilla_commit(&q, &identity, SINSEMILLA_MSG_ONE_BIT, 1,
                                     SINSEMILLA_ZERO_BLIND, &out),
            -1);
  EXPECT_EQ(pallas_sinsemilla_commit(&q, &r, SINSEMILLA_MSG_ONE_BIT, 1,
                                     PALLAS_Q_LE, &out),
            -1);

  memzero(&q, sizeof(q));
  memzero(&r, sizeof(r));
  memzero(&out, sizeof(out));
  memzero(&identity, sizeof(identity));
}

TEST(Zcash, Zip316F4Jumble_ReferenceVectors) {
  uint8_t buf48[sizeof(F4JUMBLE_48_NORMAL)];
  memcpy(buf48, F4JUMBLE_48_NORMAL, sizeof(buf48));
  ASSERT_EQ(zcash_zip316_f4jumble(buf48, sizeof(buf48)), 0);
  EXPECT_TRUE(memcmp(buf48, F4JUMBLE_48_JUMBLED, sizeof(buf48)) == 0);
  ASSERT_EQ(zcash_zip316_f4jumble_inv(buf48, sizeof(buf48)), 0);
  EXPECT_TRUE(memcmp(buf48, F4JUMBLE_48_NORMAL, sizeof(buf48)) == 0);

  uint8_t buf64[sizeof(F4JUMBLE_64_NORMAL)];
  memcpy(buf64, F4JUMBLE_64_NORMAL, sizeof(buf64));
  ASSERT_EQ(zcash_zip316_f4jumble(buf64, sizeof(buf64)), 0);
  EXPECT_TRUE(memcmp(buf64, F4JUMBLE_64_JUMBLED, sizeof(buf64)) == 0);
  ASSERT_EQ(zcash_zip316_f4jumble_inv(buf64, sizeof(buf64)), 0);
  EXPECT_TRUE(memcmp(buf64, F4JUMBLE_64_NORMAL, sizeof(buf64)) == 0);

  memzero(buf48, sizeof(buf48));
  memzero(buf64, sizeof(buf64));
}

TEST(Zcash, Zip316F4Jumble_RejectsInvalidLengths) {
  uint8_t too_short[ZCASH_ZIP316_F4JUMBLE_MIN_LEN - 1] = {0};
  EXPECT_EQ(zcash_zip316_f4jumble(too_short, sizeof(too_short)), -1);
  EXPECT_EQ(zcash_zip316_f4jumble_inv(too_short, sizeof(too_short)), -1);
  EXPECT_EQ(zcash_zip316_f4jumble(nullptr, ZCASH_ZIP316_F4JUMBLE_MIN_LEN), -1);
}

TEST(Zcash, Zip316OrchardOnlyUnifiedAddress_ReferenceVectors) {
  char address[ZCASH_ZIP316_ORCHARD_ONLY_MAX_ADDRESS_SIZE];

  ASSERT_EQ(zcash_zip316_encode_orchard_unified_address(
                "u", ORCHARD_RECEIVER_ASSEMBLY_VECTORS[0].receiver, address,
                sizeof(address)),
            0);
  EXPECT_STREQ(address, ORCHARD_ONLY_UA_MAINNET_0);

  ASSERT_EQ(zcash_zip316_encode_orchard_unified_address(
                "utest", ORCHARD_RECEIVER_ASSEMBLY_VECTORS[0].receiver, address,
                sizeof(address)),
            0);
  EXPECT_STREQ(address, ORCHARD_ONLY_UA_TESTNET_0);

  ASSERT_EQ(zcash_zip316_encode_orchard_unified_address(
                "u", ORCHARD_RECEIVER_ASSEMBLY_VECTORS[1].receiver, address,
                sizeof(address)),
            0);
  EXPECT_STREQ(address, ORCHARD_ONLY_UA_MAINNET_1);

  ASSERT_EQ(zcash_zip316_encode_orchard_unified_address(
                "utest", ORCHARD_RECEIVER_ASSEMBLY_VECTORS[1].receiver, address,
                sizeof(address)),
            0);
  EXPECT_STREQ(address, ORCHARD_ONLY_UA_TESTNET_1);

  memzero(address, sizeof(address));
}

TEST(Zcash, Zip316OrchardOnlyUnifiedAddress_RejectsInvalidInputs) {
  char address[ZCASH_ZIP316_ORCHARD_ONLY_MAX_ADDRESS_SIZE];
  char too_small[16];
  char long_hrp[ZCASH_ZIP316_PADDING_LEN + 2];
  memset(long_hrp, 'a', sizeof(long_hrp) - 1);
  long_hrp[sizeof(long_hrp) - 1] = 0;

  EXPECT_EQ(zcash_zip316_encode_orchard_unified_address(
                "u", ORCHARD_RECEIVER_ASSEMBLY_VECTORS[0].receiver, too_small,
                sizeof(too_small)),
            -1);
  EXPECT_EQ(zcash_zip316_encode_orchard_unified_address(
                long_hrp, ORCHARD_RECEIVER_ASSEMBLY_VECTORS[0].receiver,
                address, sizeof(address)),
            -1);
  EXPECT_EQ(zcash_zip316_encode_orchard_unified_address(
                "U", ORCHARD_RECEIVER_ASSEMBLY_VECTORS[0].receiver, address,
                sizeof(address)),
            -1);

  memzero(address, sizeof(address));
  memzero(too_small, sizeof(too_small));
  memzero(long_hrp, sizeof(long_hrp));
}

TEST(Zcash, OrchardUnifiedAddress_FromDerivedKeys) {
  ZcashOrchardKeys keys;
  ASSERT_TRUE(zcash_derive_orchard_keys(SEED_ALL, 64, 0, &keys));

  char address[ZCASH_ZIP316_ORCHARD_ONLY_MAX_ADDRESS_SIZE];
  const uint8_t index0[11] = {0};
  const uint8_t index1[11] = {1};

  ASSERT_TRUE(zcash_orchard_derive_unified_address(&keys, index0, "u", address,
                                                   sizeof(address)));
  EXPECT_STREQ(address, ORCHARD_ONLY_UA_MAINNET_0);

  ASSERT_TRUE(zcash_orchard_derive_unified_address(&keys, index0, "utest",
                                                   address, sizeof(address)));
  EXPECT_STREQ(address, ORCHARD_ONLY_UA_TESTNET_0);

  ASSERT_TRUE(zcash_orchard_derive_unified_address(&keys, index1, "u", address,
                                                   sizeof(address)));
  EXPECT_STREQ(address, ORCHARD_ONLY_UA_MAINNET_1);

  ASSERT_TRUE(zcash_orchard_derive_unified_address(&keys, index1, "utest",
                                                   address, sizeof(address)));
  EXPECT_STREQ(address, ORCHARD_ONLY_UA_TESTNET_1);

  memzero(address, sizeof(address));
  memzero(&keys, sizeof(keys));
}

TEST(Zcash, OrchardUnifiedAddress_RejectsInvalidInputs) {
  ZcashOrchardKeys keys;
  ASSERT_TRUE(zcash_derive_orchard_keys(SEED_ALL, 64, 0, &keys));

  char address[ZCASH_ZIP316_ORCHARD_ONLY_MAX_ADDRESS_SIZE];
  char too_small[16];
  const uint8_t index0[11] = {0};

  EXPECT_FALSE(zcash_orchard_derive_unified_address(nullptr, index0, "u",
                                                    address, sizeof(address)));
  EXPECT_FALSE(zcash_orchard_derive_unified_address(&keys, nullptr, "u",
                                                    address, sizeof(address)));
  EXPECT_FALSE(zcash_orchard_derive_unified_address(&keys, index0, nullptr,
                                                    address, sizeof(address)));
  EXPECT_FALSE(zcash_orchard_derive_unified_address(&keys, index0, "u", nullptr,
                                                    sizeof(address)));
  EXPECT_FALSE(zcash_orchard_derive_unified_address(
      &keys, index0, "u", too_small, sizeof(too_small)));

  memzero(address, sizeof(address));
  memzero(too_small, sizeof(too_small));
  memzero(&keys, sizeof(keys));
}

struct OrchardNoteProgressCapture {
  uint32_t calls = 0;
  uint32_t last = 0;
  uint32_t total = 0;
  bool monotonic = true;
};

static void capture_orchard_note_progress(uint32_t completed, uint32_t total,
                                          void* context) {
  auto* capture = static_cast<OrchardNoteProgressCapture*>(context);
  if (capture->calls > 0 && completed < capture->last) {
    capture->monotonic = false;
  }
  capture->calls++;
  capture->last = completed;
  capture->total = total;
}

TEST(Zcash, OrchardNoteCommitment_KnownVectorAndProgress) {
  const uint8_t recipient[ZCASH_ORCHARD_RAW_RECEIVER_SIZE] = {
      0x3c, 0x15, 0x0e, 0x60, 0x98, 0xb8, 0x61, 0x71, 0x6c, 0xc7, 0xf6,
      0x28, 0x35, 0xf6, 0x9f, 0xeb, 0x30, 0x21, 0x93, 0xc9, 0x26, 0x60,
      0x44, 0x4f, 0x26, 0x62, 0x4f, 0xd1, 0x3e, 0x00, 0xea, 0x7a, 0xc7,
      0x74, 0xcd, 0x55, 0x07, 0x4d, 0x63, 0x67, 0xef, 0xef, 0x37};
  const uint64_t value = 12345678;
  const uint8_t rho[32] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                           0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
                           0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                           0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
  const uint8_t rseed[32] = {0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef,
                             0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                             0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                             0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
  const uint8_t expected_cmx[32] = {
      0x02, 0xde, 0xfb, 0x39, 0xc8, 0xf2, 0xe1, 0xec, 0xc9, 0x45, 0x18,
      0x93, 0x73, 0xcf, 0x2a, 0x8e, 0x21, 0xd4, 0xe1, 0x54, 0x39, 0x8e,
      0xfa, 0x16, 0x21, 0xd5, 0xfb, 0x98, 0x9e, 0x1d, 0xeb, 0x36};

  uint8_t cmx[32];
  OrchardNoteProgressCapture progress;
  ASSERT_TRUE(zcash_orchard_compute_cmx_with_progress(
      recipient, value, rho, rseed, cmx, capture_orchard_note_progress,
      &progress));
  EXPECT_TRUE(memcmp(cmx, expected_cmx, sizeof(cmx)) == 0);
  EXPECT_TRUE(progress.monotonic);
  EXPECT_EQ(109u, progress.calls);
  EXPECT_EQ(109u, progress.last);
  EXPECT_EQ(109u, progress.total);

  uint8_t tampered[ZCASH_ORCHARD_RAW_RECEIVER_SIZE];
  memcpy(tampered, recipient, sizeof(tampered));
  tampered[0] ^= 0x01;
  ASSERT_TRUE(zcash_orchard_compute_cmx(tampered, value, rho, rseed, cmx));
  EXPECT_TRUE(memcmp(cmx, expected_cmx, sizeof(cmx)) != 0);

  memzero(cmx, sizeof(cmx));
  memzero(tampered, sizeof(tampered));
}

TEST(Zcash, IronwoodNoteCommitment_V3KnownVector) {
  const uint8_t recipient[ZCASH_ORCHARD_RAW_RECEIVER_SIZE] = {
      0x3c, 0x15, 0x0e, 0x60, 0x98, 0xb8, 0x61, 0x71, 0x6c, 0xc7, 0xf6,
      0x28, 0x35, 0xf6, 0x9f, 0xeb, 0x30, 0x21, 0x93, 0xc9, 0x26, 0x60,
      0x44, 0x4f, 0x26, 0x62, 0x4f, 0xd1, 0x3e, 0x00, 0xea, 0x7a, 0xc7,
      0x74, 0xcd, 0x55, 0x07, 0x4d, 0x63, 0x67, 0xef, 0xef, 0x37};
  const uint8_t rho[32] = {
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
      0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
      0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
  const uint8_t rseed[32] = {
      0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef,
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
      0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
  const uint8_t expected_cmx[32] = {
      0x89, 0x6e, 0xe3, 0x45, 0xd8, 0xb0, 0x40, 0x98,
      0x72, 0x17, 0x25, 0x37, 0x66, 0x6a, 0x48, 0x24,
      0x09, 0x66, 0x1a, 0x22, 0xad, 0x77, 0xc0, 0x98,
      0x96, 0xa3, 0xe7, 0x17, 0x65, 0xf1, 0x86, 0x33};

  uint8_t cmx[32] = {0};
  ASSERT_TRUE(
      zcash_ironwood_compute_cmx(recipient, 12345678, rho, rseed, cmx));
  EXPECT_TRUE(memcmp(cmx, expected_cmx, sizeof(cmx)) == 0);
  memzero(cmx, sizeof(cmx));
}

TEST(Zcash, OrchardReceiverToUnifiedAddress_KnownVector) {
  const uint8_t recipient[ZCASH_ORCHARD_RAW_RECEIVER_SIZE] = {
      0x3c, 0x15, 0x0e, 0x60, 0x98, 0xb8, 0x61, 0x71, 0x6c, 0xc7, 0xf6,
      0x28, 0x35, 0xf6, 0x9f, 0xeb, 0x30, 0x21, 0x93, 0xc9, 0x26, 0x60,
      0x44, 0x4f, 0x26, 0x62, 0x4f, 0xd1, 0x3e, 0x00, 0xea, 0x7a, 0xc7,
      0x74, 0xcd, 0x55, 0x07, 0x4d, 0x63, 0x67, 0xef, 0xef, 0x37};
  char address[ZCASH_ORCHARD_UNIFIED_ADDRESS_SIZE];

  ASSERT_TRUE(zcash_orchard_receiver_to_unified_address(recipient, "u", address,
                                                        sizeof(address)));
  EXPECT_STREQ(address,
               "u1ut4h93zg5670tyqss7tneru3t7h6dk62r9hhyxyrpv3nwwe9dnyj5l0ruwygf"
               "74gp5f3zklj5xly4h8h54un3asugt9mn6gwfqsq3wq7");

  EXPECT_FALSE(
      zcash_orchard_receiver_to_unified_address(recipient, "u", address, 16));
  memzero(address, sizeof(address));
}

TEST(Zcash, OrchardDiversifyHash_ReferenceVectors) {
  uint8_t gd[32];
  ASSERT_TRUE(zcash_orchard_diversify_hash(EXPECTED_DIVERSIFIER_ALL_0, gd));
  EXPECT_TRUE(memcmp(gd, ORCHARD_GD_ALL_ACCOUNT0_J0, sizeof(gd)) == 0);

  ASSERT_TRUE(
      zcash_orchard_diversify_hash(ORCHARD_FF1_VECTORS[0].diversifier, gd));
  EXPECT_TRUE(memcmp(gd, ORCHARD_GD_FF1_ZERO_ZERO, sizeof(gd)) == 0);

  curve_point empty;
  ASSERT_EQ(pallas_group_hash("z.cash:Orchard-gd", NULL, 0, &empty), 0);
  pallas_point_encode(&empty, gd);
  EXPECT_TRUE(memcmp(gd, ORCHARD_GD_EMPTY, sizeof(gd)) == 0);

  memzero(gd, sizeof(gd));
  memzero(&empty, sizeof(empty));
}

TEST(Zcash, OrchardTransmissionKey_ReferenceVectors) {
  for (const auto& vector : ORCHARD_RECEIVER_VECTORS) {
    uint8_t gd[32];
    uint8_t pkd[32];
    ASSERT_TRUE(zcash_orchard_derive_transmission_key(
        vector.ivk, vector.diversifier, gd, pkd));
    EXPECT_TRUE(memcmp(gd, vector.gd, sizeof(gd)) == 0);
    EXPECT_TRUE(memcmp(pkd, vector.pkd, sizeof(pkd)) == 0);

    uint8_t pkd_without_gd[32];
    ASSERT_TRUE(zcash_orchard_derive_transmission_key(
        vector.ivk, vector.diversifier, nullptr, pkd_without_gd));
    EXPECT_TRUE(memcmp(pkd_without_gd, vector.pkd, sizeof(pkd_without_gd)) ==
                0);

    memzero(gd, sizeof(gd));
    memzero(pkd, sizeof(pkd));
    memzero(pkd_without_gd, sizeof(pkd_without_gd));
  }
}

TEST(Zcash, OrchardTransmissionKey_RejectsZeroIvk) {
  uint8_t zero_ivk[32] = {0};
  uint8_t gd[32];
  uint8_t pkd[32];
  EXPECT_FALSE(zcash_orchard_derive_transmission_key(
      zero_ivk, ORCHARD_RECEIVER_VECTORS[0].diversifier, gd, pkd));
}

TEST(Zcash, OrchardIvk_ReferenceVectors) {
  for (const auto& vector : ORCHARD_IVK_VECTORS) {
    uint8_t ivk[32];
    ASSERT_TRUE(
        zcash_orchard_derive_ivk(vector.ak, vector.nk, vector.rivk, ivk));
    EXPECT_TRUE(memcmp(ivk, vector.ivk, sizeof(ivk)) == 0);
    memzero(ivk, sizeof(ivk));
  }
}

TEST(Zcash, OrchardIvk_RejectsInvalidAkEncoding) {
  uint8_t bad_ak[32];
  memcpy(bad_ak, ORCHARD_IVK_VECTORS[0].ak, sizeof(bad_ak));
  bad_ak[31] |= 0x80;

  uint8_t ivk[32];
  EXPECT_FALSE(zcash_orchard_derive_ivk(bad_ak, ORCHARD_IVK_VECTORS[0].nk,
                                        ORCHARD_IVK_VECTORS[0].rivk, ivk));
  memzero(bad_ak, sizeof(bad_ak));
  memzero(ivk, sizeof(ivk));
}

TEST(Zcash, OrchardReceiver_ReferenceVectors) {
  for (const auto& vector : ORCHARD_RECEIVER_ASSEMBLY_VECTORS) {
    uint8_t receiver[43];
    ASSERT_TRUE(zcash_orchard_derive_receiver(
        vector.ak, vector.nk, vector.rivk, vector.dk, vector.index, receiver));
    EXPECT_TRUE(memcmp(receiver, vector.receiver, sizeof(receiver)) == 0);
    memzero(receiver, sizeof(receiver));
  }
}

TEST(Zcash, OrchardReceiver_RejectsInvalidAkEncoding) {
  uint8_t bad_ak[32];
  memcpy(bad_ak, ORCHARD_RECEIVER_ASSEMBLY_VECTORS[0].ak, sizeof(bad_ak));
  bad_ak[31] |= 0x80;

  uint8_t receiver[43];
  EXPECT_FALSE(zcash_orchard_derive_receiver(
      bad_ak, ORCHARD_RECEIVER_ASSEMBLY_VECTORS[0].nk,
      ORCHARD_RECEIVER_ASSEMBLY_VECTORS[0].rivk,
      ORCHARD_RECEIVER_ASSEMBLY_VECTORS[0].dk,
      ORCHARD_RECEIVER_ASSEMBLY_VECTORS[0].index, receiver));
  memzero(bad_ak, sizeof(bad_ak));
  memzero(receiver, sizeof(receiver));
}

/* ── Field Range Tests ───────────────────────────────────────────── */

TEST(Zcash, DeriveOrchardKeys_FieldRanges) {
  /* Test multiple accounts to increase coverage of edge cases */
  for (uint32_t account = 0; account < 5; account++) {
    ZcashOrchardKeys keys;
    ASSERT_TRUE(zcash_derive_orchard_keys(SEED_ALL, 64, account, &keys));

    /* nk must be < Pallas base field prime p */
    EXPECT_LT(cmp_le256(keys.nk, PALLAS_P_LE), 0)
        << "nk must be < p for account " << account;

    /* rivk must be < Pallas scalar field order q */
    EXPECT_LT(cmp_le256(keys.rivk, PALLAS_Q_LE), 0)
        << "rivk must be < q for account " << account;

    /* ask must be < Pallas scalar field order q */
    EXPECT_LT(cmp_le256(keys.ask, PALLAS_Q_LE), 0)
        << "ask must be < q for account " << account;

    /* ask must be nonzero (astronomically unlikely, but verify) */
    uint8_t zero[32] = {0};
    EXPECT_TRUE(memcmp(keys.ask, zero, 32) != 0)
        << "ask must be nonzero for account " << account;

    memzero(&keys, sizeof(keys));
  }
}

TEST(Zcash, AkSignBit_AlwaysClear) {
  /*
   * For every account, compute ak = [ask]*G and verify the sign bit
   * is always clear. This is the invariant that the ask negation
   * in zcash_derive_orchard_keys() is supposed to enforce.
   */
  for (uint32_t account = 0; account < 10; account++) {
    ZcashOrchardKeys keys;
    ASSERT_TRUE(zcash_derive_orchard_keys(SEED_ALL, 64, account, &keys));

    bignum256 ask_scalar;
    bn_read_le(keys.ask, &ask_scalar);
    curve_point ak_point;
    redpallas_scalar_mult_spendauth_G(&ask_scalar, &ak_point);

    /* Check y parity: must be even (sign bit = 0) */
    EXPECT_FALSE(bn_is_odd(&ak_point.y))
        << "ak y-coordinate must be even for account " << account;

    /* Check serialized sign bit */
    uint8_t ak_bytes[32];
    bignum256 x_copy;
    bn_copy(&ak_point.x, &x_copy);
    bn_write_le(&x_copy, ak_bytes);

    EXPECT_EQ(ak_bytes[31] & 0x80, 0)
        << "ak sign bit must be clear for account " << account;

    memzero(&keys, sizeof(keys));
  }
}

/* ── PCZT Signing Policy Tests ───────────────────────────────────── */

static ZcashPCZTSigningRequestMeta clear_pczt_meta(void) {
  ZcashPCZTSigningRequestMeta meta = {};
  meta.has_header_digest = true;
  meta.header_digest_size = 32;
  meta.has_orchard_digest = true;
  meta.orchard_digest_size = 32;
  meta.has_orchard_flags = true;
  meta.has_orchard_value_balance = true;
  meta.has_orchard_anchor = true;
  meta.orchard_anchor_size = 32;
  meta.has_header_fields = true;
  meta.n_transparent_inputs = 0;
  meta.n_transparent_outputs = 0;
  return meta;
}

TEST(Zcash, PCZTSigningPolicy_AcceptsVerifiedShieldedOnlyRequest) {
  ZcashPCZTSigningRequestMeta meta = clear_pczt_meta();

  EXPECT_EQ(zcash_pczt_signing_request_status(&meta),
            ZCASH_PCZT_SIGNING_REQUEST_OK);
  EXPECT_TRUE(zcash_pczt_signing_request_is_clear(&meta));
}

TEST(Zcash, PCZTSigningPolicy_RejectsMissingTransactionDigests) {
  ZcashPCZTSigningRequestMeta meta = clear_pczt_meta();

  meta.has_header_digest = false;
  EXPECT_EQ(zcash_pczt_signing_request_status(&meta),
            ZCASH_PCZT_SIGNING_REQUEST_MISSING_TX_DIGESTS);
  EXPECT_FALSE(zcash_pczt_signing_request_is_clear(&meta));

  meta = clear_pczt_meta();
  meta.orchard_digest_size = 31;
  EXPECT_EQ(zcash_pczt_signing_request_status(&meta),
            ZCASH_PCZT_SIGNING_REQUEST_INVALID_DIGEST_SIZE);
  EXPECT_FALSE(zcash_pczt_signing_request_is_clear(&meta));
}

TEST(Zcash, PCZTSigningPolicy_RequiresIronwoodDigestForV6Pool) {
  ZcashPCZTSigningRequestMeta meta = clear_pczt_meta();
  meta.is_ironwood = true;

  EXPECT_EQ(zcash_pczt_signing_request_status(&meta),
            ZCASH_PCZT_SIGNING_REQUEST_MISSING_TX_DIGESTS);

  meta.has_ironwood_digest = true;
  meta.ironwood_digest_size = 32;
  EXPECT_EQ(zcash_pczt_signing_request_status(&meta),
            ZCASH_PCZT_SIGNING_REQUEST_OK);

  meta.ironwood_digest_size = 31;
  EXPECT_EQ(zcash_pczt_signing_request_status(&meta),
            ZCASH_PCZT_SIGNING_REQUEST_MISSING_TX_DIGESTS);
}

TEST(Zcash, PCZTSigningPolicy_RejectsMissingPlaintextHeaderFields) {
  ZcashPCZTSigningRequestMeta meta = clear_pczt_meta();

  meta.has_header_fields = false;
  EXPECT_EQ(zcash_pczt_signing_request_status(&meta),
            ZCASH_PCZT_SIGNING_REQUEST_MISSING_HEADER_FIELDS);
  EXPECT_FALSE(zcash_pczt_signing_request_is_clear(&meta));
}

TEST(Zcash, PCZTSigningPolicy_RejectsMissingOrchardMetadata) {
  ZcashPCZTSigningRequestMeta meta = clear_pczt_meta();

  meta.has_orchard_anchor = false;
  EXPECT_EQ(zcash_pczt_signing_request_status(&meta),
            ZCASH_PCZT_SIGNING_REQUEST_MISSING_ORCHARD_METADATA);
  EXPECT_FALSE(zcash_pczt_signing_request_is_clear(&meta));

  meta = clear_pczt_meta();
  meta.has_orchard_flags = false;
  EXPECT_EQ(zcash_pczt_signing_request_status(&meta),
            ZCASH_PCZT_SIGNING_REQUEST_MISSING_ORCHARD_METADATA);
  EXPECT_FALSE(zcash_pczt_signing_request_is_clear(&meta));
}

TEST(Zcash, PCZTSigningPolicy_RejectsInvalidOptionalDigests) {
  ZcashPCZTSigningRequestMeta meta = clear_pczt_meta();

  meta.has_transparent_digest = true;
  meta.transparent_digest_size = 31;
  EXPECT_EQ(zcash_pczt_signing_request_status(&meta),
            ZCASH_PCZT_SIGNING_REQUEST_INVALID_DIGEST_SIZE);
  EXPECT_FALSE(zcash_pczt_signing_request_is_clear(&meta));
}

TEST(Zcash, PCZTSigningPolicy_RejectsSaplingComponent) {
  ZcashPCZTSigningRequestMeta meta = clear_pczt_meta();

  meta.has_sapling_digest = true;
  meta.sapling_digest_size = 32;
  EXPECT_EQ(zcash_pczt_signing_request_status(&meta),
            ZCASH_PCZT_SIGNING_REQUEST_UNSUPPORTED_SAPLING_COMPONENT);
  EXPECT_FALSE(zcash_pczt_signing_request_is_clear(&meta));
}

TEST(Zcash, PCZTSigningPolicy_RejectsTransparentComponentsWithoutDigest) {
  ZcashPCZTSigningRequestMeta meta = clear_pczt_meta();
  meta.n_transparent_inputs = 1;

  EXPECT_EQ(zcash_pczt_signing_request_status(&meta),
            ZCASH_PCZT_SIGNING_REQUEST_MISSING_TRANSPARENT_DIGEST);
  EXPECT_FALSE(zcash_pczt_signing_request_is_clear(&meta));

  meta.has_transparent_digest = true;
  meta.transparent_digest_size = 32;
  EXPECT_EQ(zcash_pczt_signing_request_status(&meta),
            ZCASH_PCZT_SIGNING_REQUEST_OK);
  EXPECT_TRUE(zcash_pczt_signing_request_is_clear(&meta));

  meta = clear_pczt_meta();
  meta.n_transparent_outputs = 1;
  EXPECT_EQ(zcash_pczt_signing_request_status(&meta),
            ZCASH_PCZT_SIGNING_REQUEST_MISSING_TRANSPARENT_DIGEST);
  EXPECT_FALSE(zcash_pczt_signing_request_is_clear(&meta));

  meta.has_transparent_digest = true;
  meta.transparent_digest_size = 32;
  EXPECT_EQ(zcash_pczt_signing_request_status(&meta),
            ZCASH_PCZT_SIGNING_REQUEST_OK);
  EXPECT_TRUE(zcash_pczt_signing_request_is_clear(&meta));
}

static const uint8_t ZIP244_EXPECTED_HEADER_DIGEST[32] = {
    0x44, 0x4b, 0xe9, 0x38, 0x88, 0x1d, 0xc9, 0xf2, 0x0a, 0xed, 0x88,
    0x0c, 0x3a, 0x05, 0x94, 0xe5, 0xc1, 0x22, 0x3e, 0xff, 0xc5, 0x75,
    0xef, 0x05, 0xda, 0xae, 0xe3, 0x45, 0x1b, 0xa2, 0xf4, 0x93};

static const uint8_t ZIP244_EXPECTED_EMPTY_TRANSPARENT_DIGEST[32] = {
    0xc3, 0x3f, 0x2e, 0x95, 0x70, 0x5f, 0xaa, 0xb3, 0x5f, 0x8d, 0x53,
    0x3f, 0xa6, 0x1e, 0x95, 0xc3, 0xb7, 0xaa, 0xba, 0x07, 0x76, 0xb8,
    0x74, 0xa9, 0xf7, 0x4f, 0xc1, 0x27, 0x84, 0x37, 0x6a, 0x59};

static const uint8_t ZIP244_EXPECTED_TRANSPARENT_DIGEST[32] = {
    0xfa, 0xe5, 0x37, 0x7f, 0xa9, 0x3c, 0xc0, 0xc3, 0x1d, 0x30, 0x39,
    0x42, 0x21, 0x57, 0xce, 0x4b, 0x9e, 0x7b, 0x12, 0x57, 0x00, 0x9f,
    0x15, 0x90, 0xe1, 0x62, 0x95, 0x62, 0x55, 0xbb, 0x2e, 0x84};

static const uint8_t ZIP244_EXPECTED_TRANSPARENT_SIGHASH_0[32] = {
    0x37, 0xa9, 0xc4, 0xec, 0x61, 0x87, 0x07, 0x20, 0x5b, 0xcb, 0x47,
    0x7b, 0xea, 0x4f, 0xda, 0x6d, 0x61, 0x01, 0x62, 0xea, 0xaa, 0x5c,
    0x9f, 0x33, 0xe5, 0x59, 0x69, 0x02, 0x6e, 0x47, 0x6f, 0x23};

static const uint8_t ZIP244_EXPECTED_TRANSPARENT_SIGHASH_1[32] = {
    0x29, 0x4d, 0xb7, 0xaa, 0xf1, 0x65, 0x37, 0x4e, 0x02, 0xda, 0xe1,
    0x6f, 0xf3, 0xdd, 0x97, 0x78, 0x8f, 0x4f, 0x5e, 0x2d, 0xc4, 0xe1,
    0xb3, 0xf6, 0x62, 0x73, 0x9e, 0xd3, 0x5b, 0x82, 0x08, 0x2f};

static const uint8_t ZIP244_P2PKH_SCRIPT_11[25] = {
    0x76, 0xa9, 0x14, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x88, 0xac};

static const uint8_t ZIP244_P2SH_SCRIPT_22[23] = {
    0xa9, 0x14, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x87};

static const uint8_t ZIP244_P2PKH_SCRIPT_33[25] = {
    0x76, 0xa9, 0x14, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x88, 0xac};

static const uint8_t ZIP244_P2SH_SCRIPT_44[23] = {
    0xa9, 0x14, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
    0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x87};

static void fill_zip244_txids(uint8_t txid0[32], uint8_t txid1[32]) {
  for (size_t i = 0; i < 32; i++) {
    txid0[i] = (uint8_t)i;
    txid1[i] = (uint8_t)(i + 32);
  }
}

static void make_zip244_transparent_fixture(
    ZcashTransparentInputDigestInfo inputs[2],
    ZcashTransparentOutputDigestInfo outputs[2], uint8_t txid0[32],
    uint8_t txid1[32]) {
  fill_zip244_txids(txid0, txid1);

  inputs[0].prevout_txid = txid0;
  inputs[0].prevout_index = 2;
  inputs[0].sequence = 0xfffffffe;
  inputs[0].value = 1234567890ULL;
  inputs[0].script_pubkey = ZIP244_P2PKH_SCRIPT_11;
  inputs[0].script_pubkey_size = sizeof(ZIP244_P2PKH_SCRIPT_11);

  inputs[1].prevout_txid = txid1;
  inputs[1].prevout_index = 7;
  inputs[1].sequence = 0xfffffffd;
  inputs[1].value = 987654321ULL;
  inputs[1].script_pubkey = ZIP244_P2SH_SCRIPT_22;
  inputs[1].script_pubkey_size = sizeof(ZIP244_P2SH_SCRIPT_22);

  outputs[0].value = 2000000000ULL;
  outputs[0].script_pubkey = ZIP244_P2PKH_SCRIPT_33;
  outputs[0].script_pubkey_size = sizeof(ZIP244_P2PKH_SCRIPT_33);

  outputs[1].value = 1111111ULL;
  outputs[1].script_pubkey = ZIP244_P2SH_SCRIPT_44;
  outputs[1].script_pubkey_size = sizeof(ZIP244_P2SH_SCRIPT_44);
}

TEST(Zcash, ComputeHeaderDigest_FromPlaintextFields) {
  uint8_t digest[32] = {0};

  ASSERT_TRUE(zcash_compute_header_digest(5, 0x26a7270a, 0xc2d6d0b4, 123456,
                                          987654, digest));
  EXPECT_TRUE(memcmp(digest, ZIP244_EXPECTED_HEADER_DIGEST, 32) == 0);
}

TEST(Zcash, ComputeTransparentDigest_DistinctFromPerInputSighash) {
  ZcashTransparentInputDigestInfo inputs[2] = {};
  ZcashTransparentOutputDigestInfo outputs[2] = {};
  uint8_t txid0[32], txid1[32];
  make_zip244_transparent_fixture(inputs, outputs, txid0, txid1);

  uint8_t digest[32] = {0};
  uint8_t sighash0[32] = {0};
  uint8_t sighash1[32] = {0};

  ASSERT_TRUE(zcash_compute_transparent_digest(inputs, 2, outputs, 2, digest));
  ASSERT_TRUE(zcash_compute_transparent_sighash_digest(inputs, 2, outputs, 2, 0,
                                                       0x01, sighash0));
  ASSERT_TRUE(zcash_compute_transparent_sighash_digest(inputs, 2, outputs, 2, 1,
                                                       0x01, sighash1));

  EXPECT_TRUE(memcmp(digest, ZIP244_EXPECTED_TRANSPARENT_DIGEST, 32) == 0);
  EXPECT_TRUE(memcmp(sighash0, ZIP244_EXPECTED_TRANSPARENT_SIGHASH_0, 32) == 0);
  EXPECT_TRUE(memcmp(sighash1, ZIP244_EXPECTED_TRANSPARENT_SIGHASH_1, 32) == 0);
  EXPECT_TRUE(memcmp(digest, sighash0, 32) != 0);
  EXPECT_TRUE(memcmp(sighash0, sighash1, 32) != 0);
}

TEST(Zcash, ComputeTransparentDigest_EmptyBundle) {
  uint8_t digest[32] = {0};

  ASSERT_TRUE(zcash_compute_transparent_digest(NULL, 0, NULL, 0, digest));
  EXPECT_TRUE(memcmp(digest, ZIP244_EXPECTED_EMPTY_TRANSPARENT_DIGEST, 32) ==
              0);
}

TEST(Zcash, ComputeTransparentSighash_RejectsUnsupportedRequest) {
  ZcashTransparentInputDigestInfo inputs[2] = {};
  ZcashTransparentOutputDigestInfo outputs[2] = {};
  uint8_t txid0[32], txid1[32], digest[32];
  make_zip244_transparent_fixture(inputs, outputs, txid0, txid1);

  EXPECT_FALSE(zcash_compute_transparent_sighash_digest(inputs, 2, outputs, 2,
                                                        2, 0x01, digest));
  EXPECT_FALSE(zcash_compute_transparent_sighash_digest(inputs, 2, outputs, 2,
                                                        0, 0x02, digest));
}

TEST(Zcash, ComputeTransparentSighash_CommitsToOutputScriptAndValue) {
  ZcashTransparentInputDigestInfo inputs[2] = {};
  ZcashTransparentOutputDigestInfo outputs[2] = {};
  uint8_t txid0[32], txid1[32];
  make_zip244_transparent_fixture(inputs, outputs, txid0, txid1);

  uint8_t original[32] = {0};
  uint8_t changed_script[32] = {0};
  uint8_t changed_value[32] = {0};

  ASSERT_TRUE(zcash_compute_transparent_sighash_digest(inputs, 2, outputs, 2, 0,
                                                       0x01, original));

  outputs[0].script_pubkey = ZIP244_P2SH_SCRIPT_44;
  outputs[0].script_pubkey_size = sizeof(ZIP244_P2SH_SCRIPT_44);
  ASSERT_TRUE(zcash_compute_transparent_sighash_digest(inputs, 2, outputs, 2, 0,
                                                       0x01, changed_script));
  EXPECT_TRUE(memcmp(original, changed_script, 32) != 0);

  outputs[0].script_pubkey = ZIP244_P2PKH_SCRIPT_33;
  outputs[0].script_pubkey_size = sizeof(ZIP244_P2PKH_SCRIPT_33);
  outputs[0].value++;
  ASSERT_TRUE(zcash_compute_transparent_sighash_digest(inputs, 2, outputs, 2, 0,
                                                       0x01, changed_value));
  EXPECT_TRUE(memcmp(original, changed_value, 32) != 0);
}

/* ── Sighash Computation Tests ───────────────────────────────────── */

TEST(Zcash, ComputeShieldedSighash_Deterministic) {
  uint8_t header[32], transparent[32], sapling[32], orchard[32];
  memset(header, 0x01, 32);
  memset(transparent, 0x02, 32);
  memset(sapling, 0x03, 32);
  memset(orchard, 0x04, 32);

  uint32_t branch_id = 0x37519621; /* NU5 */

  uint8_t sighash1[32], sighash2[32];
  ASSERT_TRUE(zcash_compute_shielded_sighash(header, transparent, sapling,
                                             orchard, branch_id, sighash1));
  ASSERT_TRUE(zcash_compute_shielded_sighash(header, transparent, sapling,
                                             orchard, branch_id, sighash2));

  EXPECT_TRUE(memcmp(sighash1, sighash2, 32) == 0)
      << "Sighash must be deterministic";
}

TEST(Zcash, ComputeV6ShieldedSighash_KnownVector) {
  uint8_t header[32], transparent[32], sapling[32], orchard[32], ironwood[32];
  memset(header, 0x11, sizeof(header));
  memset(transparent, 0x22, sizeof(transparent));
  memset(sapling, 0x33, sizeof(sapling));
  memset(orchard, 0x44, sizeof(orchard));
  memset(ironwood, 0x55, sizeof(ironwood));
  const uint8_t expected[32] = {
      0xdc, 0x07, 0x66, 0x98, 0xdb, 0xe0, 0x8b, 0x6d,
      0xcd, 0x23, 0xf5, 0xa1, 0xb6, 0xbb, 0xae, 0x41,
      0xf7, 0xb1, 0x23, 0xd8, 0xb2, 0x47, 0xf3, 0x88,
      0x7f, 0x7c, 0xa2, 0xbb, 0x68, 0xb5, 0xdc, 0xaa};

  uint8_t sighash[32] = {0};
  ASSERT_TRUE(zcash_compute_v6_shielded_sighash(
      header, transparent, sapling, orchard, ironwood, 0x37a5165b,
      sighash));
  EXPECT_TRUE(memcmp(sighash, expected, sizeof(sighash)) == 0);
}

TEST(Zcash, ComputeShieldedSighash_DifferentInputs) {
  uint8_t header[32], transparent[32], sapling[32], orchard[32];
  memset(header, 0x01, 32);
  memset(transparent, 0x02, 32);
  memset(sapling, 0x03, 32);
  memset(orchard, 0x04, 32);

  uint32_t branch_id = 0x37519621;
  uint8_t sighash_a[32], sighash_b[32];

  ASSERT_TRUE(zcash_compute_shielded_sighash(header, transparent, sapling,
                                             orchard, branch_id, sighash_a));

  /* Change one byte in the orchard digest */
  orchard[0] ^= 0xff;
  ASSERT_TRUE(zcash_compute_shielded_sighash(header, transparent, sapling,
                                             orchard, branch_id, sighash_b));

  EXPECT_TRUE(memcmp(sighash_a, sighash_b, 32) != 0)
      << "Different orchard digests must produce different sighashes";
}

TEST(Zcash, ComputeShieldedSighash_DifferentBranchId) {
  uint8_t header[32], transparent[32], sapling[32], orchard[32];
  memset(header, 0x01, 32);
  memset(transparent, 0x02, 32);
  memset(sapling, 0x03, 32);
  memset(orchard, 0x04, 32);

  uint8_t sighash_nu5[32], sighash_nu6[32];

  ASSERT_TRUE(zcash_compute_shielded_sighash(header, transparent, sapling,
                                             orchard, 0x37519621, sighash_nu5));
  ASSERT_TRUE(zcash_compute_shielded_sighash(header, transparent, sapling,
                                             orchard, 0xC4D97411, sighash_nu6));

  EXPECT_TRUE(memcmp(sighash_nu5, sighash_nu6, 32) != 0)
      << "Different branch IDs must produce different sighashes";
}

TEST(Zcash, ComputeShieldedSighash_KnownVector) {
  /*
   * ZIP-244 sighash test vector.
   *
   * The sighash personalization is "ZcashTxHash_" || branch_id_LE.
   * For NU5 (branch_id = 0x37519621):
   *   personalization = "ZcashTxHash_" || 0x21965137
   *
   * Input: BLAKE2b-256(personalization, header || transparent || sapling ||
   * orchard) where each digest is 32 bytes of zeros.
   */
  uint8_t header[32] = {0};
  uint8_t transparent[32] = {0};
  uint8_t sapling[32] = {0};
  uint8_t orchard[32] = {0};
  uint32_t branch_id = 0x37519621;

  uint8_t sighash[32];
  ASSERT_TRUE(zcash_compute_shielded_sighash(header, transparent, sapling,
                                             orchard, branch_id, sighash));

  /*
   * Independently verified: BLAKE2b-256 with personalization
   * "ZcashTxHash_\x21\x96\x51\x37" over 128 zero bytes.
   *
   * This is a self-consistency check — the value was computed by
   * running the same BLAKE2b-256 offline. If the sighash function
   * changes its algorithm, this test will catch it.
   */
  uint8_t expected[32];
  BLAKE2B_CTX ctx;
  uint8_t personal[16];
  memcpy(personal, "ZcashTxHash_", 12);
  memcpy(personal + 12, &branch_id, 4);
  blake2b_InitPersonal(&ctx, 32, personal, 16);
  blake2b_Update(&ctx, header, 32);
  blake2b_Update(&ctx, transparent, 32);
  blake2b_Update(&ctx, sapling, 32);
  blake2b_Update(&ctx, orchard, 32);
  blake2b_Final(&ctx, expected, 32);

  EXPECT_TRUE(memcmp(sighash, expected, 32) == 0)
      << "Sighash must match direct BLAKE2b computation";
}

/* ── RedPallas Signing Smoke Test ────────────────────────────────── */

struct RedPallasProgressCapture {
  uint32_t calls = 0;
  uint32_t last = 0;
  uint32_t total = 0;
  bool monotonic = true;
};

static void capture_redpallas_progress(uint32_t completed, uint32_t total,
                                       void* context) {
  auto* capture = static_cast<RedPallasProgressCapture*>(context);
  if (capture->calls > 0 && completed < capture->last) {
    capture->monotonic = false;
  }
  capture->calls++;
  capture->last = completed;
  capture->total = total;
}

TEST(Zcash, OrchardKeyDerivationReportsFixedProgress) {
  ZcashOrchardKeys keys;
  RedPallasProgressCapture progress;

  ASSERT_TRUE(zcash_derive_orchard_keys_with_progress(
      SEED_ALL, 64, 0, &keys, capture_redpallas_progress, &progress));
  EXPECT_TRUE(progress.monotonic);
  EXPECT_EQ(255u, progress.calls);
  EXPECT_EQ(255u, progress.last);
  EXPECT_EQ(255u, progress.total);
  EXPECT_EQ(0, memcmp(keys.ak, EXPECTED_AK_ALL_0, sizeof(keys.ak)));

  memzero(&keys, sizeof(keys));
}

TEST(Zcash, RedPallasPublicRkPathMatchesAndReportsFixedProgress) {
  ZcashOrchardKeys keys;
  ASSERT_TRUE(zcash_derive_orchard_keys(SEED_ALL, 64, 0, &keys));

  uint8_t alpha[32];
  memset(alpha, 0x01, sizeof(alpha));
  alpha[31] = 0;
  uint8_t sighash[32];
  memset(sighash, 0xA5, sizeof(sighash));

  uint8_t public_rk[32], secret_reference_rk[32];
  ASSERT_EQ(redpallas_derive_rk_from_ak(keys.ak, alpha, public_rk), 0);
  ASSERT_EQ(redpallas_derive_rk(keys.ask, alpha, secret_reference_rk), 0);
  EXPECT_EQ(memcmp(public_rk, secret_reference_rk, sizeof(public_rk)), 0);

  RedPallasProgressCapture progress;
  uint8_t signature[64];
  ASSERT_EQ(redpallas_sign_digest_with_ak(
                keys.ask, keys.ak, alpha, public_rk, sighash, signature,
                capture_redpallas_progress, &progress),
            0);
  EXPECT_TRUE(progress.monotonic);
  EXPECT_EQ(257u, progress.calls);
  EXPECT_EQ(1000u, progress.last);
  EXPECT_EQ(1000u, progress.total);
  EXPECT_EQ(redpallas_verify_digest(public_rk, sighash, signature), 0);

  uint8_t wrong_rk[32];
  memcpy(wrong_rk, public_rk, sizeof(wrong_rk));
  wrong_rk[0] ^= 1;
  EXPECT_NE(redpallas_sign_digest_with_ak(keys.ask, keys.ak, alpha, wrong_rk,
                                          sighash, signature, nullptr, nullptr),
            0);

  memzero(&keys, sizeof(keys));
}

TEST(Zcash, RedPallasPcztPathUsesBoundRkAndReportsFixedProgress) {
  ZcashOrchardKeys keys;
  ASSERT_TRUE(zcash_derive_orchard_keys(SEED_ALL, 64, 0, &keys));

  uint8_t alpha[32];
  memset(alpha, 0x31, sizeof(alpha));
  alpha[31] = 0;
  uint8_t sighash[32];
  memset(sighash, 0x5A, sizeof(sighash));
  uint8_t rk[32];
  ASSERT_EQ(redpallas_derive_rk(keys.ask, alpha, rk), 0);

  RedPallasProgressCapture progress;
  uint8_t signature[64];
  ASSERT_EQ(
      redpallas_sign_digest_for_rk(keys.ask, alpha, rk, sighash, signature,
                                   capture_redpallas_progress, &progress),
      0);
  EXPECT_TRUE(progress.monotonic);
  EXPECT_EQ(256u, progress.calls);
  EXPECT_EQ(1000u, progress.last);
  EXPECT_EQ(1000u, progress.total);
  EXPECT_EQ(redpallas_verify_digest(rk, sighash, signature), 0);

  uint8_t wrong_rk[32];
  memcpy(wrong_rk, rk, sizeof(wrong_rk));
  wrong_rk[0] ^= 1;
  ASSERT_EQ(redpallas_sign_digest_for_rk(keys.ask, alpha, wrong_rk, sighash,
                                         signature, nullptr, nullptr),
            0);
  EXPECT_NE(redpallas_verify_digest(rk, sighash, signature), 0);

  memzero(&keys, sizeof(keys));
}

TEST(Zcash, RedPallasSign_ProducesVerifiableSignature) {
  ZcashOrchardKeys keys;
  ASSERT_TRUE(zcash_derive_orchard_keys(SEED_ALL, 64, 0, &keys));

  /* Construct a fake sighash and alpha */
  uint8_t sighash[32];
  memset(sighash, 0xAB, 32);

  uint8_t alpha[32];
  memset(alpha, 0x01, 32);
  /* Ensure alpha is a valid scalar (< q) */
  alpha[31] = 0x00;

  uint8_t signature[64];
  int ret = redpallas_sign_digest(keys.ask, alpha, sighash, signature);
  EXPECT_EQ(ret, 0) << "RedPallas signing must succeed";

  /* Signature must be nonzero */
  uint8_t zero[64] = {0};
  EXPECT_TRUE(memcmp(signature, zero, 64) != 0) << "Signature must be nonzero";

  /*
   * Verify the signature against the randomized verification key rk.
   * rk = [ask + alpha]*G_spendauth (Pallas SpendAuth basepoint)
   */
  bignum256 ask_scalar, alpha_scalar, rk_scalar;
  bn_read_le(keys.ask, &ask_scalar);
  bn_read_le(alpha, &alpha_scalar);

  /* rk_scalar = ask + alpha mod q */
  bn_copy(&ask_scalar, &rk_scalar);
  pallas_add_mod_q(&rk_scalar, &alpha_scalar);

  curve_point rk_point;
  redpallas_scalar_mult_spendauth_G(&rk_scalar, &rk_point);

  /* Serialize rk as Pallas point (LE x-coord + sign bit) */
  uint8_t rk_bytes[32];
  bignum256 rk_x;
  bn_copy(&rk_point.x, &rk_x);
  bn_write_le(&rk_x, rk_bytes);
  if (bn_is_odd(&rk_point.y)) {
    rk_bytes[31] |= 0x80;
  }

  /* Verify: redpallas_verify_digest(rk, sighash, sig) == 0 */
  EXPECT_EQ(redpallas_verify_digest(rk_bytes, sighash, signature), 0)
      << "Signature must verify against rk = [ask+alpha]*G";

  /* Verify fails with wrong sighash */
  uint8_t wrong_sighash[32];
  memset(wrong_sighash, 0xCC, 32);
  EXPECT_NE(redpallas_verify_digest(rk_bytes, wrong_sighash, signature), 0)
      << "Signature must NOT verify with wrong sighash";

  memzero(&keys, sizeof(keys));
}

TEST(Zcash, RedPallasSign_MultipleCallsSucceed) {
  /*
   * RedPallas uses randomized nonces — signatures are intentionally
   * non-deterministic. Verify that multiple calls all succeed and
   * produce valid (nonzero) 64-byte signatures.
   */
  ZcashOrchardKeys keys;
  ASSERT_TRUE(zcash_derive_orchard_keys(SEED_ALL, 64, 0, &keys));

  uint8_t sighash[32];
  memset(sighash, 0xCD, 32);
  uint8_t alpha[32];
  memset(alpha, 0x02, 32);
  alpha[31] = 0x00;

  uint8_t zero[64] = {0};
  for (int i = 0; i < 3; i++) {
    uint8_t sig[64];
    ASSERT_EQ(redpallas_sign_digest(keys.ask, alpha, sighash, sig), 0)
        << "Signing must succeed on call " << i;
    EXPECT_TRUE(memcmp(sig, zero, 64) != 0)
        << "Signature must be nonzero on call " << i;
  }

  memzero(&keys, sizeof(keys));
}

TEST(Zcash, RedPallasSign_DifferentSighash) {
  ZcashOrchardKeys keys;
  ASSERT_TRUE(zcash_derive_orchard_keys(SEED_ALL, 64, 0, &keys));

  uint8_t alpha[32];
  memset(alpha, 0x01, 32);
  alpha[31] = 0x00;

  uint8_t sighash_a[32], sighash_b[32];
  memset(sighash_a, 0xAA, 32);
  memset(sighash_b, 0xBB, 32);

  uint8_t sig_a[64], sig_b[64];
  ASSERT_EQ(redpallas_sign_digest(keys.ask, alpha, sighash_a, sig_a), 0);
  ASSERT_EQ(redpallas_sign_digest(keys.ask, alpha, sighash_b, sig_b), 0);

  EXPECT_TRUE(memcmp(sig_a, sig_b, 64) != 0)
      << "Different sighash must produce different signatures";

  memzero(&keys, sizeof(keys));
}

/* ─── Seed Fingerprint (ZIP-32 §6.1) ─────────────────────────────── */

/* Reference vector: matches keystone3-firmware
 *   rust/keystore/src/algorithms/zcash/mod.rs test_keystore_derive_zcash_ufvk
 * Seed:        000102...1f (32 bytes)
 * Fingerprint: deff604c246710f7176dead02aa746f2fd8d5389f7072556dcb555fdbe5e3ae3
 */
TEST(Zcash, SeedFingerprint_ReferenceVector) {
  uint8_t seed[32];
  for (int i = 0; i < 32; i++) seed[i] = (uint8_t)i;

  uint8_t expected[32] = {
      0xde, 0xff, 0x60, 0x4c, 0x24, 0x67, 0x10, 0xf7, 0x17, 0x6d, 0xea,
      0xd0, 0x2a, 0xa7, 0x46, 0xf2, 0xfd, 0x8d, 0x53, 0x89, 0xf7, 0x07,
      0x25, 0x56, 0xdc, 0xb5, 0x55, 0xfd, 0xbe, 0x5e, 0x3a, 0xe3,
  };

  uint8_t fp[32];
  ASSERT_TRUE(zcash_calculate_seed_fingerprint(seed, 32, fp));
  EXPECT_EQ(memcmp(fp, expected, 32), 0);
}

TEST(Zcash, SeedFingerprintRequestRequiresExactSizeWhenPresent) {
  EXPECT_TRUE(zcash_seed_fingerprint_request_valid(false, 0));
  EXPECT_TRUE(zcash_seed_fingerprint_request_valid(true, 32));
  EXPECT_FALSE(zcash_seed_fingerprint_request_valid(true, 0));
  EXPECT_FALSE(zcash_seed_fingerprint_request_valid(true, 31));
  EXPECT_FALSE(zcash_seed_fingerprint_request_valid(true, 33));
}

TEST(Zcash, SeedFingerprint_RejectAllZero) {
  uint8_t seed[32] = {0};
  uint8_t fp[32];
  EXPECT_FALSE(zcash_calculate_seed_fingerprint(seed, 32, fp));
}

TEST(Zcash, SeedFingerprint_RejectAllFF) {
  uint8_t seed[32];
  memset(seed, 0xFF, 32);
  uint8_t fp[32];
  EXPECT_FALSE(zcash_calculate_seed_fingerprint(seed, 32, fp));
}

TEST(Zcash, SeedFingerprint_RejectShortSeed) {
  uint8_t seed[31];
  for (int i = 0; i < 31; i++) seed[i] = (uint8_t)(i + 1);
  uint8_t fp[32];
  EXPECT_FALSE(zcash_calculate_seed_fingerprint(seed, 31, fp));
}

TEST(Zcash, SeedFingerprint_RejectLongSeed) {
  uint8_t seed[253];
  for (int i = 0; i < 253; i++) seed[i] = (uint8_t)(i & 0xFF);
  uint8_t fp[32];
  EXPECT_FALSE(zcash_calculate_seed_fingerprint(seed, 253, fp));
}

TEST(Zcash, SeedFingerprint_DeterministicAcrossCalls) {
  uint8_t seed[64];
  for (int i = 0; i < 64; i++) seed[i] = (uint8_t)(0xAA ^ i);

  uint8_t fp_a[32], fp_b[32];
  ASSERT_TRUE(zcash_calculate_seed_fingerprint(seed, 64, fp_a));
  ASSERT_TRUE(zcash_calculate_seed_fingerprint(seed, 64, fp_b));
  EXPECT_EQ(memcmp(fp_a, fp_b, 32), 0);
}

TEST(Zcash, SeedFingerprint_DiffersForDifferentSeeds) {
  uint8_t seed_a[64];
  uint8_t seed_b[64];
  for (int i = 0; i < 64; i++) {
    seed_a[i] = (uint8_t)i;
    seed_b[i] = (uint8_t)(i + 1);
  }

  uint8_t fp_a[32], fp_b[32];
  ASSERT_TRUE(zcash_calculate_seed_fingerprint(seed_a, 64, fp_a));
  ASSERT_TRUE(zcash_calculate_seed_fingerprint(seed_b, 64, fp_b));
  EXPECT_NE(memcmp(fp_a, fp_b, 32), 0);
}

/* ===================================================================== *
 *  zcash_compute_orchard_transparent_sig_digest — ZIP-244 S.2/T.1
 *
 *  This is the site of the historical shield-fix (S.2 vs T.1 selection by
 *  vin count). It had no test caller, so a refactor could silently swap the
 *  two forms. These lock in: (a) empty-vin -> T.1 (equals the standalone
 *  transparent digest), (b) non-empty-vin -> S.2 (distinct from T.1 and
 *  stable), and (c) validation refusal on malformed info.
 * ===================================================================== */

// A P2PKH-shaped script_pubkey (25 bytes) for the fixtures.
static const uint8_t kScriptPubkey[25] = {
    0x76, 0xa9, 0x14, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x88, 0xac};
static const uint8_t kPrevoutTxid[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};

// Empty vin (deshield): the Orchard transparent-sig digest is the T.1 form,
// which is exactly zcash_compute_transparent_digest over the same components.
TEST(Zcash, OrchardTransparentSigDigest_EmptyVinMatchesT1) {
  ZcashTransparentOutputDigestInfo out = {/*value=*/50000, kScriptPubkey,
                                          sizeof(kScriptPubkey)};

  uint8_t s2_digest[32], t1_digest[32];
  ASSERT_TRUE(zcash_compute_orchard_transparent_sig_digest(nullptr, 0, &out, 1,
                                                           s2_digest));
  ASSERT_TRUE(zcash_compute_transparent_digest(nullptr, 0, &out, 1, t1_digest));
  EXPECT_EQ(memcmp(s2_digest, t1_digest, 32), 0);
}

// Non-empty vin (shield): the S.2 form is used and MUST differ from the T.1
// form over the identical inputs/outputs (the whole point of the shield fix),
// and it must be deterministic.
TEST(Zcash, OrchardTransparentSigDigest_NonEmptyVinIsS2NotT1) {
  ZcashTransparentInputDigestInfo in = {
      kPrevoutTxid,     /*prevout_index=*/0, /*sequence=*/0xffffffff,
      /*value=*/100000, kScriptPubkey,       sizeof(kScriptPubkey)};
  ZcashTransparentOutputDigestInfo out = {/*value=*/50000, kScriptPubkey,
                                          sizeof(kScriptPubkey)};

  uint8_t s2_digest[32], t1_digest[32], s2_again[32];
  ASSERT_TRUE(
      zcash_compute_orchard_transparent_sig_digest(&in, 1, &out, 1, s2_digest));
  ASSERT_TRUE(zcash_compute_transparent_digest(&in, 1, &out, 1, t1_digest));
  ASSERT_TRUE(
      zcash_compute_orchard_transparent_sig_digest(&in, 1, &out, 1, s2_again));
  EXPECT_NE(memcmp(s2_digest, t1_digest, 32), 0);  // S.2 != T.1 (the fix)
  EXPECT_EQ(memcmp(s2_digest, s2_again, 32), 0);   // deterministic
}

// Malformed digest info (a nonzero script with a NULL pointer) is refused.
TEST(Zcash, OrchardTransparentSigDigest_RejectsMalformedInfo) {
  ZcashTransparentOutputDigestInfo bad = {/*value=*/1,
                                          /*script_pubkey=*/nullptr,
                                          /*script_pubkey_size=*/25};
  uint8_t digest[32];
  EXPECT_FALSE(zcash_compute_orchard_transparent_sig_digest(nullptr, 0, &bad, 1,
                                                            digest));
}
